#[cfg(target_os = "linux")]
mod client;

use crate::protocol::{Command, Request, Response};
use mockall::automock;

#[cfg(target_os = "linux")]
pub use linux::*;

#[automock]
pub trait VSockClient {
    fn send_command(&self, command: Command) -> Response;
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// Send a command to the host vsock server
    pub fn send_command(command: Command, port: u32) -> Response {
        let guest_cid = vsock::get_local_cid().map_err(|e| e.to_string())?;

        let request = Request { guest_cid, command };

        client::send_request_to_host_and_parse_response(&request, &port)
    }

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
            send_command(command, self.port)
        }
    }
}
