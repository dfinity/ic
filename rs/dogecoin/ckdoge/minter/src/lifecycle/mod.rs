use crate::lifecycle::{init::InitArgs, upgrade::UpgradeArgs};
use candid::CandidType;

pub mod init;
pub mod upgrade;

#[derive(CandidType, serde::Deserialize)]
pub enum MinterArg {
    Init(InitArgs),
    Upgrade(Option<UpgradeArgs>),
}
