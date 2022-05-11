use candid::{CandidType, Deserialize};
use ic_ckbtc_minter::runtime::Runtime;
use serde::Serialize;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct InitArgs {}

pub fn init(_args: InitArgs, _runtime: &mut dyn Runtime) {}
