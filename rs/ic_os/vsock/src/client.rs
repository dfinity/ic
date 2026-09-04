use std::io;

use crate::protocol::{Command, MAX_MESSAGE_SIZE, Request, Response};

use mockall::automock;
use thiserror::Error;

#[automock]
pub trait VsockClient {
    fn send_command(&self, command: Command) -> Result<Response, VsockClientError>;
}

#[derive(Error, Debug)]
pub enum VsockClientError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("unable to serialize request: {request:#?}")]
    InvalidRequest {
        request: Request,
        source: serde_json::Error,
    },
    #[error("unable to parse server response: {response:?}")]
    InvalidResponse {
        response: String,
        source: serde_json::Error,
    },
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    use crate::protocol::{Request, Response};
    use std::io::{Read, Write};
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
        fn send_command(&self, command: Command) -> Result<Response, VsockClientError> {
            let guest_cid = vsock::get_local_cid()?;
            let request = Request { guest_cid, command };

            let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, self.port)?;
            stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
            // Set a long timeout, so HostOS has enough time to upgrade.
            stream.set_read_timeout(Some(std::time::Duration::from_secs(60 * 5)))?;

            stream.write_all(
                &serde_json::to_vec(&request)
                    .map_err(|source| VsockClientError::InvalidRequest { request, source })?,
            )?;
            stream.shutdown(std::net::Shutdown::Write)?;

            let mut buffer = Vec::new();
            stream.take(MAX_MESSAGE_SIZE).read_to_end(&mut buffer)?;

            serde_json::from_slice::<Response>(&buffer).map_err(|source| {
                VsockClientError::InvalidResponse {
                    response: String::from_utf8_lossy(&buffer).into_owned(),
                    source,
                }
            })
        }
    }
}
