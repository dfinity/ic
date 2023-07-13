use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArg {
    pub ecdsa_key_name: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum MinterArg {
    InitArg(InitArg),
    UpgradeArg,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct DisplayLogsRequest {
    pub address: String,
    pub from: String,
    pub to: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct ReceivedEthEvent {
    pub from_address: String,
    pub value: candid::Nat,
    pub principal: candid::Principal,
}
