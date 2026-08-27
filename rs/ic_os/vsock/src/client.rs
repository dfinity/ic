use crate::protocol::{Command, Response};

use mockall::automock;

#[automock]
pub trait VsockClient {
    fn send_command(&self, command: Command) -> Response;
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    use std::io::{Read, Write};

    use crate::protocol::{Request, Response};

    use vsock::{VMADDR_CID_HOST, VsockStream};

    pub struct LinuxVsockClient {
        port: u32,
    }

    impl LinuxVsockClient {
        pub const DEFAULT_PORT: u32 = 19090;

        pub fn with_port(port: u32) -> Self {
            Self { port }
        }
    }

    impl Default for LinuxVsockClient {
        fn default() -> Self {
            Self::with_port(Self::DEFAULT_PORT)
        }
    }

    impl VsockClient for LinuxVsockClient {
        fn send_command(&self, command: Command) -> Response {
            let guest_cid = vsock::get_local_cid().map_err(|e| e.to_string())?;

            let request = Request { guest_cid, command };

            let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, self.port)
                .map_err(|e| e.to_string())?;
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            // Set a long timeout, so HostOS has enough time to upgrade.
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

            serde_json::from_str::<Response>(&response_str)
                .map_err(|_| format!("Unable to parse host response: {response_str}"))?
        }
    }
}
