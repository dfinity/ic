use crate::protocol::{Command, Response};
use mockall::automock;

#[automock]
pub trait VSockClient {
    fn send_command(&self, command: Command) -> Response;
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::protocol::{Request, Response};
    use std::io::{Read, Write};
    use vsock::{VMADDR_CID_HOST, VsockStream};

    pub struct LinuxVSockClient {
        port: u32,
    }

    impl LinuxVSockClient {
        pub const DEFAULT_PORT: u32 = 19090;

        pub fn with_port(port: u32) -> Self {
            Self { port }
        }
    }

    impl Default for LinuxVSockClient {
        fn default() -> Self {
            Self::with_port(Self::DEFAULT_PORT)
        }
    }

    impl VSockClient for LinuxVSockClient {
        fn send_command(&self, command: Command) -> Response {
            let guest_cid = vsock::get_local_cid().map_err(|e| e.to_string())?;

            let request = Request { guest_cid, command };

            let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, self.port)
                .map_err(|e| e.to_string())?;
            // Set a long timeout, so HostOS has enough time to upgrade.
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(60 * 5)))
                .map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(60 * 5)))
                .map_err(|e| e.to_string())?;

            let json_request = serde_json::to_string(&request).map_err(|e| e.to_string())?;
            stream
                .write_all(json_request.as_bytes())
                .map_err(|e| e.to_string())?;

            // 64 KiB - generous for current responses (typically <1 KiB) while
            // preventing unbounded allocation from a misbehaving host.
            const MAX_RESPONSE_SIZE: u64 = 64 * 1024;
            let mut response_str = String::new();
            stream
                .take(MAX_RESPONSE_SIZE)
                .read_to_string(&mut response_str)
                .map_err(|e| e.to_string())?;

            parse_response(response_str.as_str())
        }
    }
}

/// Parse a response in a json string to a `Response` struct.
pub fn parse_response(json_str: &str) -> Response {
    if let Ok(response) = serde_json::from_str::<Response>(json_str) {
        return response;
    }
    Err("Unable to parse host response: ".to_string() + json_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{HostOSVsockVersion, Payload};

    #[test]
    fn test_parse_response() {
        assert_eq!(
            Ok(Payload::NoPayload),
            parse_response("{\"Ok\":\"NoPayload\"}")
        );
        assert_eq!(
            Ok(Payload::HostOSVersion("123".to_string())),
            parse_response("{\"Ok\":{\"HostOSVersion\":\"123\"}}")
        );
        assert_eq!(
            Ok(Payload::HostOSVsockVersion(HostOSVsockVersion {
                major: 1,
                minor: 0,
                patch: 0,
            })),
            parse_response(
                "{\"Ok\":{\"HostOSVsockVersion\":{\"major\":1,\"minor\":0,\"patch\":0}}}"
            )
        );
        assert_eq!(
            Err("Unable to parse host response: Error response".to_string()),
            parse_response("Error response")
        );

        let json_str = r#"{"Ok":"NoPayload"#; // Missing closing brace
        let response = parse_response(json_str);
        assert!(response.is_err());
    }
}
