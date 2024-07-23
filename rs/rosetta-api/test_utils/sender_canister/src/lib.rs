use candid::{CandidType, Principal};
use ic_cdk::api::call::RejectionCode;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct SendArg {
    pub to: Principal,
    pub method: String,
    pub arg: Vec<u8>,
    pub payment: u128,
}

pub type SendError = (RejectionCode, String);
pub type SendResult = Result<Vec<u8>, SendError>;
