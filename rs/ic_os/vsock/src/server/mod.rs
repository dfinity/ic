use std::io::{self, Read, Write};

mod command_utilities;
mod hsm;
mod misc;
mod upgrade;

use crate::protocol::{Command, HostOSVsockVersion, Request, Response};
use hsm::{attach_hsm, detach_hsm};
use misc::{get_hostos_version, get_hostos_vsock_version, notify};
use upgrade::{start_upgrade_guest_vm, upgrade_hostos};

use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

// The first CID available for guests to use. This is used later to enforce
// that only the first guest is able to connect over VSOCK, for now.
const VIR_VSOCK_GUEST_CID_MIN: u32 = 3;
const DEFAULT_PORT: u32 = 19090;

const VSOCK_VERSION: HostOSVsockVersion = HostOSVsockVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

/// Runs the vsock server and awaits incoming vsock connections.
pub fn run_server() -> io::Result<()> {
    // Only listen for the first GuestOS VM. Only type4.* nodes will have more
    // than one VM that uses VSOCK. We treat the first GuestOS as the leader in
    // charge of HostOS.
    let addr = VsockAddr::new(VMADDR_CID_ANY, DEFAULT_PORT);
    let vsock_listener = VsockListener::bind(&addr)?;

    println!("Listening for vsock connection.\n");

    for stream in vsock_listener.incoming() {
        let mut stream: VsockStream = stream?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        std::thread::spawn(move || -> io::Result<()> { process_connection(&mut stream) });
    }

    Ok(())
}

fn process_connection(stream: &mut VsockStream) -> io::Result<()> {
    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer)?;
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
            stream
                .write_all(serde_json::to_string::<Response>(&Err(err.to_string()))?.as_bytes())?;
            return Err(err);
        }
    };
    println!("Received vsock request: {request}");

    if request.guest_cid != VIR_VSOCK_GUEST_CID_MIN {
        let err = io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "A type4 host only accepts VSOCK connections from the first VM.",
        );
        stream.write_all(serde_json::to_string::<Response>(&Err(err.to_string()))?.as_bytes())?;
        return Err(err);
    };

    if let Err(err) = verify_sender_cid(stream, request.guest_cid) {
        stream.write_all(serde_json::to_string::<Response>(&Err(err.to_string()))?.as_bytes())?;
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

    stream.write_all(serde_json::to_string::<Response>(&response)?.as_bytes())
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
