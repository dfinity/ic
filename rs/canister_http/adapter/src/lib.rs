//! The HTTP adapter makes http calls to the outside on behalf of the replica
//! This is part of the http calls from canister feature

/// Main module of HTTP adapter. Receives gRPC calls from replica and makes outgoing requests
mod rpc_server;
pub use rpc_server::HttpFromCanister;
