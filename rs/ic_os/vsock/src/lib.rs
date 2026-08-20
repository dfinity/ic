mod client;
#[cfg(target_os = "linux")]
pub use client::LinuxVSockClient;
pub use client::{MockVSockClient, VSockClient};

#[cfg(target_os = "linux")]
mod host;
#[cfg(target_os = "linux")]
pub use host::server::run_server;

pub mod protocol;
