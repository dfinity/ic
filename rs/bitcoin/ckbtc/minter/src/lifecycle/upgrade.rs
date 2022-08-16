use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct UpgradeArgs {}

pub fn pre_upgrade() {
    ic_cdk::println!("Executing pre upgrade");
    todo!()
}

pub fn post_upgrade(_args: UpgradeArgs) {
    ic_cdk::println!("Executing post upgrade");
    todo!()
}
