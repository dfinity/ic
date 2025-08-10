#![cfg(target_os = "linux")]

mod guest;
pub use guest::send_command;

mod host;
pub use host::server::run_server;

pub mod protocol;
