use candid::{CandidType, Deserialize};
use serde::Serialize;

pub mod guard;
pub mod lifecycle;
pub mod metrics;
pub mod state;
pub mod updates;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct ECDSAPublicKey {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}
