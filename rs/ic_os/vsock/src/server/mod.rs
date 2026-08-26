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

// The first CID available for guests to use. This is used later to enforce
// that only the first guest is able to connect over VSOCK, for now.
const VIR_VSOCK_GUEST_CID_MIN: u32 = 3;
const DEFAULT_PORT: u32 = 19090;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

const VSOCK_VERSION: HostOSVsockVersion = HostOSVsockVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

/// Runs the vsock server and awaits incoming vsock connections.
pub async fn run_server() -> io::Result<()> {
    let addr = VsockAddr::new(VMADDR_CID_ANY, DEFAULT_PORT);
    let vsock_listener = VsockListener::bind(addr)?;

    println!("Listening for vsock connection.\n");

    let cancellation_token = CancellationToken::new();
    let mut join_handle = tokio::spawn(listen(vsock_listener, cancellation_token.clone()));

    let result = select! {
        () = shutdown_signal() => {
            println!("Shutting down VSOCK server...");
            cancellation_token.cancel();
            join_handle.await
        },
        result = &mut join_handle => result,
    };

    match result {
        Err(ref err) if err.is_panic() => {
            println!("VSOCK server panicked: '{err}'")
        }
        _ => {
            println!("VSOCK server shutdown gracefully")
        }
    }

    Ok(result?)
}

async fn listen(listener: VsockListener, cancellation_token: CancellationToken) {
    let tracker = TaskTracker::new();

    while let Some(res) = cancellation_token
        .run_until_cancelled(listener.accept())
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
                Err(e) => println!("{peer}: timed out"),
                Ok(Err(e)) => println!("{peer}: failed"),
                Ok(Ok(())) => {}
            }
        });
    }

    drop(listener);
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

pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sig_int =
        signal(SignalKind::interrupt()).expect("failed to install SIGINT signal handler");
    let mut sig_term =
        signal(SignalKind::terminate()).expect("failed to install SIGTERM signal handler");

    tokio::select! {
        _ = sig_int.recv() => {
            println!("Caught SIGINT");
        }
        _ = sig_term.recv() => {
            println!("Caught SIGTERM");
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

    let request = match parse_request(json_request.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    {
        Ok(request) => request,
        Err(err) => {
            timeout(
                CONNECTION_TIMEOUT,
                stream.write_all(
                    serde_json::to_string::<Response>(&Err(err.to_string()))?.as_bytes(),
                ),
            )
            .await??;
            return Err(err);
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
        Command::Upgrade(upgrade_data) => upgrade_hostos(upgrade_data),
        Command::Notify(notify_data) => notify(notify_data),
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

pub fn parse_request(json_str: &str) -> Result<Request, String> {
    serde_json::from_str::<Request>(json_str)
        .map_err(|error| format!("Unable to parse guest request: {json_str}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        // Test AttachHSM command
        let json_str = r#"{"sender_cid": 123, "message": "attach-hsm"}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.command, Command::AttachHSM);

        // Test DetachHSM command
        let json_str = r#"{"sender_cid": 123, "message": "detach-hsm"}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.command, Command::DetachHSM);

        // Test Upgrade command
        let json_str = r#"{"sender_cid": 123, "message": {"upgrade": {"url": "http://example.com/upgrade", "target-hash": "abcd1234hash"}}}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.guest_cid, 123);
        match request.command {
            Command::Upgrade(data) => {
                assert_eq!(data.url, "http://example.com/upgrade");
                assert_eq!(data.target_hash, "abcd1234hash");
            }
            _ => panic!("Expected Upgrade command"),
        }

        // Test Notify command
        let json_str = r#"{"sender_cid": 123, "message": {"notify": {"message": "System update required", "count": 2}}}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.guest_cid, 123);
        match request.command {
            Command::Notify(data) => {
                assert_eq!(data.count, 2);
                assert_eq!(data.message, "System update required");
            }
            _ => panic!("Expected Notify command"),
        }

        // Test GetVsockProtocol command
        let json_str = r#"{"sender_cid": 123, "message": "GetVsockProtocol"}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.guest_cid, 123);
        assert_eq!(request.command, Command::GetVsockProtocol);

        // Test GetHostOSVersion command
        let json_str = r#"{"sender_cid": 123, "message": "GetHostOSVersion"}"#;
        let request = parse_request(json_str);
        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.guest_cid, 123);
        assert_eq!(request.command, Command::GetHostOSVersion);

        // Test malformed command
        let json_str = r#"{"sender_cid": 123, "message": "attach-hsm"#; // Missing closing brace
        let request = parse_request(json_str);
        assert!(request.is_err());
    }
}
