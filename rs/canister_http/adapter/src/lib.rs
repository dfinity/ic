//! The HTTP adapter makes http calls to the outside on behalf of the replica
//! This is part of the http calls from canister feature

mod cli;
/// Main module of HTTP adapter. Receives gRPC calls from replica and makes outgoing requests
mod rpc_server;

/// This module contains the basic configuration struct used to start up an adapter instance.
mod config;

pub use cli::Cli;
pub use config::{get_canister_http_logger, Config};
pub use rpc_server::CanisterHttp;
