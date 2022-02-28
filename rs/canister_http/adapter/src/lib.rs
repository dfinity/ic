//! The HTTP adapter makes http calls to the outside on behalf of the replica
//! This is part of the http calls from canister feature

/// Main module of HTTP adapter. Receives gRPC calls from replica and makes outgoing requests
mod rpc_server;

/// This module contains the protobuf structs to send
/// messages between the replica and the adapter.
pub mod proto {
    tonic::include_proto!("http_adapter");
}

pub use rpc_server::HttpFromCanister;
