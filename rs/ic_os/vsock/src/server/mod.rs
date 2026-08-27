use std::io;
use std::time::Duration;

mod command_utilities;
mod hsm;
mod misc;
mod upgrade;

use crate::protocol::{Command, HostOSVsockVersion, Request, Response};
use hsm::{attach_hsm, detach_hsm};
use misc::{get_hostos_version, get_hostos_vsock_version, notify};
use upgrade::{start_upgrade_guest_vm, upgrade_hostos};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    time::{sleep, timeout},
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

impl VsockServer {
    pub const DEFAULT_PORT: u32 = 19090;

    pub fn with_port(port: u32) -> io::Result<Self> {
        let addr = VsockAddr::new(VMADDR_CID_ANY, port);
        let listener = VsockListener::bind(addr)?;

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
                    println!("unable to accept connection: {e:#}");
                    // Throttle a bit to avoid busy loop when accept() fails
                    sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            tracker.spawn(async move {
                match timeout(REQUEST_TIMEOUT, process_connection(stream)).await {
                    Err(e) => println!("{peer}: timed out {e:#}"),
                    Ok(Err(e)) => println!("{peer}: failed {e:#}"),
                    Ok(Ok(())) => {}
                }
            });
        }

        drop(self.listener);
        tracker.close();

        select! {
            biased;
            () = tracker.wait() => {},
            // Allow remaining connections to close
            () = sleep(REQUEST_TIMEOUT + Duration::from_secs(5)) => {
                println!("Some connections didn't close, shutting down anyway");
            }
        }
    }
}

async fn process_connection(mut stream: VsockStream) -> io::Result<()> {
    let mut buffer = [0; 4096];
    let bytes_read = timeout(CONNECTION_TIMEOUT, stream.read(&mut buffer)).await??;
    let json_request: String = match std::str::from_utf8(&buffer[..bytes_read]) {
        Ok(json_str_request) => json_str_request.to_string(),
        Err(error) => {
            println!("Error converting bytes to string: {error}");
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
    };

    let request = match serde_json::from_str::<Request>(&json_request) {
        Ok(request) => request,
        Err(err) => {
            let error = io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unable to parse guest request: {json_request}: {err}"),
            );
            timeout(
                CONNECTION_TIMEOUT,
                stream.write_all(
                    serde_json::to_string::<Response>(&Err(error.to_string()))?.as_bytes(),
                ),
            )
            .await??;
            return Err(error);
        }
    };
    println!("Received vsock request: {request}");

    // Only listen for the first GuestOS VM. Only type4.* nodes will have more
    // than one VM that uses VSOCK. We treat the first GuestOS as the leader in
    // charge of HostOS.
    if request.guest_cid != VIR_VSOCK_GUEST_CID_MIN {
        let err = io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "A type4 host only accepts VSOCK connections from the first VM.",
        );
        timeout(
            CONNECTION_TIMEOUT,
            stream.write_all(serde_json::to_string::<Response>(&Err(err.to_string()))?.as_bytes()),
        )
        .await??;
        return Err(err);
    };

    if let Err(err) = verify_sender_cid(&mut stream, request.guest_cid) {
        timeout(
            CONNECTION_TIMEOUT,
            stream.write_all(serde_json::to_string::<Response>(&Err(err.to_string()))?.as_bytes()),
        )
        .await??;
        return Err(err);
    };

    let response: Response = match &request.command {
        Command::AttachHSM => attach_hsm(),
        Command::DetachHSM => detach_hsm(),
        Command::Upgrade(upgrade_data) => upgrade_hostos(upgrade_data).await,
        Command::Notify(notify_data) => notify(notify_data).await,
        Command::GetVsockProtocol => get_hostos_vsock_version(),
        Command::GetHostOSVersion => get_hostos_version(),
        Command::StartUpgradeGuestVM => start_upgrade_guest_vm(),
    };

    timeout(
        CONNECTION_TIMEOUT,
        stream.write_all(serde_json::to_string::<Response>(&response)?.as_bytes()),
    )
    .await?
}

// As a sanity check, we request that the sender adds its own CID to the message, and that CID must match the CID in the stream peer address.
// NOTE: The kernel vhost driver also enforces this. Any packet with a forged source is dropped.
fn verify_sender_cid(stream: &mut VsockStream, guest_cid: u32) -> io::Result<()> {
    let peer_address = match stream.peer_addr() {
        Ok(peer_address) => peer_address,
        Err(err) => {
            let error = format!("Error: could not verify the sender_cid. {err}");
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
    };

    if peer_address.cid() == guest_cid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "The actual sender CID did not match the sender CID in the request object",
        ))
    }
}
