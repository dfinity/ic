//! Provisional functions only available in local development instances.
use candid::{CandidType, Nat};
use serde::{Deserialize, Serialize};

pub use crate::{CanisterId, CanisterIdRecord, CanisterSettings};

/// Argument type of [provisional_create_canister_with_cycles].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
pub struct ProvisionalCreateCanisterWithCyclesArgument {
    /// The created canister will have this amount of cycles.
    pub amount: Option<Nat>,
    /// See [CanisterSettings].
    pub settings: Option<CanisterSettings>,
}

/// Argument type of [provisional_top_up_canister].
#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct ProvisionalTopUpCanisterArgument {
    /// Canister ID.
    pub canister_id: CanisterId,
    /// Amount of cycles to be added.
    pub amount: Nat,
}
