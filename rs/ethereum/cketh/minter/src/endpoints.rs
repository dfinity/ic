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
