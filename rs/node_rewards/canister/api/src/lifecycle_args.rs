use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize)]
pub struct InitArgs {}

#[derive(CandidType, Deserialize)]
pub struct UpgradeArgs {}
