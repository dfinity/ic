use std::io;
use std::time::Duration;

mod hsm;
mod misc;
mod upgrade;

use crate::protocol::{Command, HostOSVsockVersion, MAX_MESSAGE_SIZE, Request, Response};
use hsm::{attach_hsm, detach_hsm};
use misc::{get_hostos_version, get_hostos_vsock_version, notify};
use upgrade::{start_upgrade_guest_vm, upgrade_hostos};

use ic_http_utils::file_downloader::FileDownloadError;

use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    time::{error::Elapsed, sleep, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

const VSOCK_VERSION: HostOSVsockVersion = HostOSVsockVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

// The first CID available for guests to use. This is used later to enforce
// that only the first guest is able to connect over VSOCK, for now.
const VIR_VSOCK_GUEST_CID_MIN: u32 = 3;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

pub struct VsockServer {
    listener: VsockListener,
}

#[derive(Error, Debug)]
pub enum VsockServerError {
    #[error("unable to parse client request: {request:?}")]
    InvalidRequest {
        request: String,
        source: serde_json::Error,
    },
    #[error("unable to parse host response: {response:#?}")]
    InvalidResponse {
        response: Response,
        source: serde_json::Error,
    },
    #[error("a type4 host only accepts VSOCK connections from the first VM")]
    ConnectionRefused,
    #[error("the actual sender CID did not match the sender CID in the request object")]
    InvalidCid,
    #[error("command {command} failed: {stderr:?}")]
    CommandFailed { command: String, stderr: String },
    #[error("could not start guestos upgrader service, status: {0:?}")]
    UpgraderService(String),
    #[error("no HSM device found")]
    HsmNotFound,
    #[error(transparent)]
    FileDownload(#[from] FileDownloadError),
    #[error("with usb device")]
    Usb(#[from] rusb::Error),
    #[error("timeout: {context}")]
    Timeout { context: String, source: Elapsed },
    #[error("io failure: {context}")]
    Io { context: String, source: io::Error },
}

impl VsockServerError {
    pub fn io(context: String) -> impl FnOnce(io::Error) -> Self {
        move |source| Self::Io { context, source }
    }

    pub fn timeout(context: String) -> impl FnOnce(Elapsed) -> Self {
        move |source| Self::Timeout { context, source }
    }
}

impl VsockServer {
    pub const DEFAULT_PORT: u32 = 19090;

    pub fn with_port(port: u32) -> Result<Self, VsockServerError> {
        let addr = VsockAddr::new(VMADDR_CID_ANY, port);
        let listener = VsockListener::bind(addr).map_err(VsockServerError::io(format!(
            "binding to VSOCK addr '{addr}'"
        )))?;

        Ok(Self { listener })
    }

    pub async fn listen(self, cancellation_token: CancellationToken) {
        let tracker = TaskTracker::new();

        while let Some(res) = cancellation_token
            .run_until_cancelled(self.listener.accept())
            .await
        {
            let (stream, peer) = match res {
                Ok(v) => v,
                Err(e) => {
                    println!("Unable to accept connection: {e:#}");
                    // Throttle a bit to avoid busy loop when accept() fails
                    sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            let tracker_handle = tracker.clone();
            tracker.spawn(async move {
                match timeout(REQUEST_TIMEOUT, process_connection(stream, tracker_handle)).await {
                    Err(e) => println!("Connection {peer} timed out: {e:#}"),
                    Ok(Err(e)) => println!("Connection {peer} failed: {e:#}"),
                    Ok(Ok(())) => {}
                }
            });
        }

        // Drop the socket early so that no more clients connect while we drain the tracker.
        drop(self.listener);
        tracker.close();

        select! {
            biased;
            () = tracker.wait() => {},
            // Allow remaining connections to close
            () = sleep(REQUEST_TIMEOUT + Duration::from_secs(5)) => {
                println!("Some tasks didn't finish, shutting down anyway");
            }
        }
    }
}

async fn process_connection(
    mut stream: VsockStream,
    tracker: TaskTracker,
) -> Result<(), VsockServerError> {
    let mut buffer = Vec::new();
    timeout(
        CONNECTION_TIMEOUT,
        (&mut stream)
            .take(MAX_MESSAGE_SIZE)
            .read_to_end(&mut buffer),
    )
    .await
    .map_err(VsockServerError::timeout(
        "waiting to read from client".to_string(),
    ))?
    .map_err(VsockServerError::io("reading from client".to_string()))?;
    let request = match serde_json::from_slice::<Request>(&buffer) {
        Ok(request) => request,
        Err(source) => {
            let error = VsockServerError::InvalidRequest {
                request: String::from_utf8_lossy(&buffer).into_owned(),
                source,
            };

            write_response(&mut stream, Err(error.to_string())).await?;

            return Err(error);
        }
    };
    println!("Received vsock request: {request}");

    // Only listen for the first GuestOS VM. Only type4.* nodes will have more
    // than one VM that uses VSOCK. We treat the first GuestOS as the leader in
    // charge of HostOS.
    if request.guest_cid != VIR_VSOCK_GUEST_CID_MIN {
        let error = VsockServerError::ConnectionRefused;

        write_response(&mut stream, Err(error.to_string())).await?;

        return Err(error);
    };

    if let Err(error) = verify_sender_cid(&mut stream, request.guest_cid) {
        write_response(&mut stream, Err(error.to_string())).await?;

        return Err(error);
    };

    let response = match &request.command {
        Command::AttachHSM => attach_hsm(),
        Command::DetachHSM => detach_hsm(),
        Command::Upgrade(upgrade_data) => upgrade_hostos(upgrade_data).await,
        Command::Notify(notify_data) => notify(notify_data, tracker).await,
        Command::GetVsockProtocol => get_hostos_vsock_version(),
        Command::GetHostOSVersion => get_hostos_version(),
        Command::StartUpgradeGuestVM => start_upgrade_guest_vm(),
    }
    .map_err(|e| {
        // We don't return any errors from command execution up the stack. Log
        // the error on the server, and write the `Response` to the client, and
        // continue.
        let error = e.to_string();
        println!("{error:#}");

        error
    });

    write_response(&mut stream, response).await
}

async fn write_response(
    stream: &mut VsockStream,
    response: Response,
) -> Result<(), VsockServerError> {
    timeout(
        CONNECTION_TIMEOUT,
        stream.write_all(
            // Make sure we put the right type on the wire
            &serde_json::to_vec::<Response>(&response)
                .map_err(|source| VsockServerError::InvalidResponse { response, source })?,
        ),
    )
    .await
    .map_err(VsockServerError::timeout(
        "waiting to write to client".to_string(),
    ))?
    .map_err(VsockServerError::io("writing to client".to_string()))
}

// As a sanity check, we request that the sender adds its own CID to the message, and that CID must match the CID in the stream peer address.
// NOTE: The kernel vhost driver also enforces this. Any packet with a forged source is dropped.
fn verify_sender_cid(stream: &mut VsockStream, guest_cid: u32) -> Result<(), VsockServerError> {
    if stream
        .peer_addr()
        .map_err(VsockServerError::io("checking VSOCK peer addr".to_string()))?
        .cid()
        != guest_cid
    {
        Err(VsockServerError::InvalidCid)
    } else {
        Ok(())
    }
}
