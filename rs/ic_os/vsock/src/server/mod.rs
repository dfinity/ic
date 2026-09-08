use std::time::Duration;

mod hsm;
mod misc;
mod upgrade;

use crate::error::*;
use crate::protocol::{
    Command, HostOSVsockVersion, MAX_MESSAGE_SIZE, NotifyData, Payload, Request, Response,
    UpgradeData,
};
use hsm::{attach_hsm, detach_hsm};
use misc::{get_hostos_version, get_hostos_vsock_version, notify};
use upgrade::{start_upgrade_guest_vm, upgrade_hostos};

use mockall::automock;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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
                match timeout(
                    REQUEST_TIMEOUT,
                    process_connection(stream, HostDispatcher, peer.cid(), tracker_handle),
                )
                .await
                {
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

trait Transport: AsyncRead + AsyncWrite + Unpin {}
impl Transport for VsockStream {}

#[automock]
trait Dispatcher {
    fn attach_hsm(&self) -> Result<Payload, VsockServerError>;
    fn detach_hsm(&self) -> Result<Payload, VsockServerError>;
    fn upgrade_hostos(
        &self,
        upgrade_data: &UpgradeData,
    ) -> impl std::future::Future<Output = Result<Payload, VsockServerError>> + Send;
    fn notify(
        &self,
        notify_data: &NotifyData,
        tracker: TaskTracker,
    ) -> impl std::future::Future<Output = Result<Payload, VsockServerError>> + Send;
    fn get_hostos_vsock_version(&self) -> Result<Payload, VsockServerError>;
    fn get_hostos_version(&self) -> Result<Payload, VsockServerError>;
    fn start_upgrade_guest_vm(&self) -> Result<Payload, VsockServerError>;
}
struct HostDispatcher;
impl Dispatcher for HostDispatcher {
    fn attach_hsm(&self) -> Result<Payload, VsockServerError> {
        attach_hsm()
    }
    fn detach_hsm(&self) -> Result<Payload, VsockServerError> {
        detach_hsm()
    }
    async fn upgrade_hostos(
        &self,
        upgrade_data: &UpgradeData,
    ) -> Result<Payload, VsockServerError> {
        upgrade_hostos(upgrade_data).await
    }
    async fn notify(
        &self,
        notify_data: &NotifyData,
        tracker: TaskTracker,
    ) -> Result<Payload, VsockServerError> {
        notify(notify_data, tracker).await
    }
    fn get_hostos_vsock_version(&self) -> Result<Payload, VsockServerError> {
        get_hostos_vsock_version()
    }
    fn get_hostos_version(&self) -> Result<Payload, VsockServerError> {
        get_hostos_version()
    }
    fn start_upgrade_guest_vm(&self) -> Result<Payload, VsockServerError> {
        start_upgrade_guest_vm()
    }
}

async fn process_connection<T: Transport, U: Dispatcher>(
    mut stream: T,
    dispatcher: U,
    peer_cid: u32,
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

    if let Err(error) = verify_sender_cid(peer_cid, request.guest_cid) {
        write_response(&mut stream, Err(error.to_string())).await?;

        return Err(error);
    };

    let response = match &request.command {
        Command::AttachHSM => dispatcher.attach_hsm(),
        Command::DetachHSM => dispatcher.detach_hsm(),
        Command::Upgrade(upgrade_data) => dispatcher.upgrade_hostos(upgrade_data).await,
        Command::Notify(notify_data) => dispatcher.notify(notify_data, tracker).await,
        Command::GetVsockProtocol => dispatcher.get_hostos_vsock_version(),
        Command::GetHostOSVersion => dispatcher.get_hostos_version(),
        Command::StartUpgradeGuestVM => dispatcher.start_upgrade_guest_vm(),
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

async fn write_response<T: Transport>(
    stream: &mut T,
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
fn verify_sender_cid(peer_cid: u32, guest_cid: u32) -> Result<(), VsockServerError> {
    if peer_cid != guest_cid {
        Err(VsockServerError::InvalidCid)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{DuplexStream, duplex};
    impl Transport for DuplexStream {}

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    async fn round_trip<U: Dispatcher + Send + 'static>(
        dispatcher: U,
        request: &[u8],
        peer_cid: u32,
    ) -> (Result<(), VsockServerError>, Vec<u8>) {
        let tracker = TaskTracker::new();
        let (mut client, server) = duplex(4 * MAX_MESSAGE_SIZE as usize);

        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let server_handle = tokio::spawn(process_connection(
            server,
            dispatcher,
            peer_cid,
            tracker.clone(),
        ));

        let mut response = Vec::new();
        timeout(TEST_TIMEOUT, client.read_to_end(&mut response))
            .await
            .expect("timed out waiting for a response")
            .unwrap();

        tracker.close();
        select! {
            biased;
            () = tracker.wait() => {},
            // Allow remaining connections to close
            () = sleep(REQUEST_TIMEOUT + Duration::from_secs(5)) => {
                println!("Some tasks didn't finish, shutting down anyway");
            }
        }

        (server_handle.await.unwrap(), response)
    }

    #[tokio::test]
    async fn round_trip_attach_hsm() {
        let mut dispatcher = MockDispatcher::new();

        let command = Command::AttachHSM;
        dispatcher
            .expect_attach_hsm()
            .times(1)
            .returning(|| Ok(Payload::NoPayload));

        let (server_result, server_response) = round_trip(
            dispatcher,
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Ok(Payload::NoPayload),
        );
    }

    #[tokio::test]
    async fn round_trip_detattach_hsm() {
        let mut dispatcher = MockDispatcher::new();

        let command = Command::DetachHSM;
        dispatcher
            .expect_detach_hsm()
            .times(1)
            .returning(|| Ok(Payload::NoPayload));

        let (server_result, server_response) = round_trip(
            dispatcher,
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Ok(Payload::NoPayload),
        );
    }

    #[tokio::test]
    async fn round_trip_upgrade_hostos() {
        let mut dispatcher = MockDispatcher::new();

        let command = Command::Upgrade(UpgradeData {
            url: "https://dfinity.org".to_string(),
            target_hash: "0xdeadbeef".to_string(),
        });
        dispatcher
            .expect_upgrade_hostos()
            .times(1)
            .returning(|_| Box::pin(async { Ok(Payload::NoPayload) }));

        let (server_result, server_response) = round_trip(
            dispatcher,
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Ok(Payload::NoPayload)
        );
    }

    #[tokio::test]
    async fn round_trip_notify() {
        let mut dispatcher = MockDispatcher::new();

        let command = Command::Notify(NotifyData {
            count: 1,
            message: "Yo!".to_string(),
        });
        dispatcher
            .expect_notify()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(Payload::NoPayload) }));

        let (server_result, server_response) = round_trip(
            dispatcher,
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Ok(Payload::NoPayload),
        );
    }

    #[tokio::test]
    async fn round_trip_vsock_version() {
        let command = Command::GetVsockProtocol;
        // NOTE: This test doesn't need a MockDispatcher

        let (server_result, server_response) = round_trip(
            HostDispatcher,
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Ok(Payload::HostOSVsockVersion(VSOCK_VERSION))
        );
    }

    #[tokio::test]
    async fn round_trip_get_hostos_version() {
        let mut dispatcher = MockDispatcher::new();

        let command = Command::GetHostOSVersion;
        dispatcher
            .expect_get_hostos_version()
            .times(1)
            .returning(|| Ok(Payload::HostOSVersion("hostos_version".to_string())));

        let (server_result, server_response) = round_trip(
            dispatcher,
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Ok(Payload::HostOSVersion("hostos_version".to_string()))
        );
    }

    #[tokio::test]
    async fn round_trip_start_upgrade_guest_vm() {
        let mut dispatcher = MockDispatcher::new();

        let command = Command::StartUpgradeGuestVM;
        dispatcher
            .expect_start_upgrade_guest_vm()
            .times(1)
            .returning(|| Ok(Payload::NoPayload));

        let (server_result, server_response) = round_trip(
            dispatcher,
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Ok(Payload::NoPayload)
        );
    }

    #[tokio::test]
    async fn server_error() {
        let mut dispatcher = MockDispatcher::new();

        dispatcher
            .expect_attach_hsm()
            .times(1)
            .returning(|| Err(VsockServerError::HsmNotFound));

        let (server_result, server_response) = round_trip(
            dispatcher,
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command: Command::AttachHSM,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(server_result.is_ok(), "{server_result:?}");
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Err(VsockServerError::HsmNotFound.to_string())
        );
    }

    #[tokio::test]
    async fn server_transport_error() {
        let request = &serde_json::to_vec(&Request {
            guest_cid: VIR_VSOCK_GUEST_CID_MIN,
            command: Command::AttachHSM,
        })
        .unwrap();

        let tracker = TaskTracker::new();
        let (mut client, server) = duplex(4 * MAX_MESSAGE_SIZE as usize);

        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        // Drop the client to simulate a server read error.
        drop(client);

        let server_handle = tokio::spawn(process_connection(
            server,
            HostDispatcher,
            VIR_VSOCK_GUEST_CID_MIN,
            tracker.clone(),
        ));

        tracker.close();
        select! {
            biased;
            () = tracker.wait() => {},
            // Allow remaining connections to close
            () = sleep(REQUEST_TIMEOUT + Duration::from_secs(5)) => {
                println!("Some tasks didn't finish, shutting down anyway");
            }
        }

        let server_result = server_handle.await.unwrap();

        assert!(
            matches!(server_result, Err(VsockServerError::Io { .. })),
            "{server_result:?}"
        );
    }

    #[tokio::test]
    async fn invalid_request() {
        let (server_result, server_response) = round_trip(
            MockDispatcher::new(),
            b"{ not json",
            VIR_VSOCK_GUEST_CID_MIN,
        )
        .await;

        assert!(
            matches!(server_result, Err(VsockServerError::InvalidRequest { .. })),
            "{server_result:?}"
        );
        assert!(
            serde_json::from_slice::<Response>(&server_response)
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    async fn only_accept_first_guest() {
        let (server_result, server_response) = round_trip(
            MockDispatcher::new(),
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN + 1,
                command: Command::GetVsockProtocol,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN + 1,
        )
        .await;

        assert!(
            matches!(server_result, Err(VsockServerError::ConnectionRefused)),
            "{server_result:?}"
        );
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Err(VsockServerError::ConnectionRefused.to_string())
        );
    }

    #[tokio::test]
    async fn reject_forged_cid() {
        let (server_result, server_response) = round_trip(
            MockDispatcher::new(),
            &serde_json::to_vec(&Request {
                guest_cid: VIR_VSOCK_GUEST_CID_MIN,
                command: Command::GetVsockProtocol,
            })
            .unwrap(),
            VIR_VSOCK_GUEST_CID_MIN + 1,
        )
        .await;

        assert!(
            matches!(server_result, Err(VsockServerError::InvalidCid)),
            "{server_result:?}"
        );
        assert_eq!(
            serde_json::from_slice::<Response>(&server_response).unwrap(),
            Err(VsockServerError::InvalidCid.to_string())
        );
    }
}
