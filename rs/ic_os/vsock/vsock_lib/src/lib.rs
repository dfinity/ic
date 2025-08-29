mod guest;
#[cfg(target_os = "linux")]
pub use guest::{send_command, LinuxVSockClient};
pub use guest::{MockVSockClient, VSockClient};

#[cfg(target_os = "linux")]
mod host;
#[cfg(target_os = "linux")]
pub use host::server::run_server;

pub mod protocol;
