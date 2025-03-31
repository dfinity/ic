use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InitArgs {}

#[derive(CandidType, Deserialize)]
pub struct UpgradeArgs {}
