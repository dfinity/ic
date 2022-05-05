use candid::{CandidType, Deserialize};
use serde::Serialize;

/// The arguments of the ckBTC Minter canister init function.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct InitArgs {}

/// The arguments of the ckBTC Minter canister (post-)upgrade function.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct UpgradeArgs {}

/// The state of the ckBTC Minter.
///
/// Every piece of state of the Minter should be stored as field of this struct.
#[derive(Clone)]
pub struct CkBtcMinterState {}
