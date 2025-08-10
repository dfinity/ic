use candid::{CandidType, Principal};
use serde::Deserialize;

#[derive(CandidType, Deserialize)]
pub struct ForwardParams {
    pub receiver: Principal,
    pub method: String,
    pub cycles: u128,
    pub payload: Vec<u8>,
}
