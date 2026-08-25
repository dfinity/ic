mod client;
#[cfg(target_os = "linux")]
pub use client::LinuxVSockClient;
pub use client::{MockVSockClient, VSockClient};

#[cfg(target_os = "linux")]
mod server;
#[cfg(target_os = "linux")]
pub use server::run_server;

pub mod protocol;
