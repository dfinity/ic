//! A client to interface with canisters via HTTP.
mod agent;
mod cbor;
mod http_client;

pub use agent::{query_path, read_state_path, update_path, Agent};
/// Exported functions from the 'cbor' module contain lower level
/// parsing and conversion utilities. Ideally users of this crate should
/// mainly use the 'Agent'.
pub use cbor::{
    parse_read_state_response, parse_subnet_read_state_response, prepare_read_state, prepare_update,
};
pub use http_client::{HttpClient, HttpClientConfig};
pub use ic_canister_client_sender::{Ed25519KeyPair, Sender};
