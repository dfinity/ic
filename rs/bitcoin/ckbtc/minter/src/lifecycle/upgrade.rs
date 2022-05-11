use candid::{CandidType, Deserialize};
use ic_ckbtc_minter::runtime::Runtime;
use serde::Serialize;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct UpgradeArgs {}

pub fn pre_upgrade(_runtime: &mut dyn Runtime) {
    ic_cdk::println!("Executing pre upgrade");
}

pub fn post_upgrade(_args: UpgradeArgs, _runtime: &mut dyn Runtime) {
    ic_cdk::println!("Executing post upgrade");
}
