//! A client to interface with canisters via HTTP.
mod agent;
mod cbor;
mod http_client;

pub use agent::{get_backoff_policy, query_path, read_state_path, update_path, Agent};
pub use cbor::parse_read_state_response;
pub use http_client::{HttpClient, HttpClientConfig};
pub use ic_canister_client_sender::{Ed25519KeyPair, Sender};
