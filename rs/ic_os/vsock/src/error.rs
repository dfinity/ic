use std::io;

use crate::protocol::Request;

use thiserror::Error;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    use crate::protocol::Response;
    use ic_http_utils::file_downloader::FileDownloadError;
    use tokio::time::error::Elapsed;

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
}

#[derive(Error, Debug)]
pub enum VsockClientError {
    #[error("io failure: {context}")]
    Io { context: String, source: io::Error },
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

impl VsockClientError {
    pub fn io(context: String) -> impl FnOnce(io::Error) -> Self {
        move |source| Self::Io { context, source }
    }
}
