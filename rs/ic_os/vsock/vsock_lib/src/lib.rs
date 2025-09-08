mod guest;
#[cfg(target_os = "linux")]
pub use guest::LinuxVSockClient;
pub use guest::{MockVSockClient, VSockClient};

#[cfg(target_os = "linux")]
mod host;
#[cfg(target_os = "linux")]
pub use host::server::run_server;

pub mod protocol;
