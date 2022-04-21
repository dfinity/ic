use crate::{CanisterSettingsArgs, Payload};
use candid::{CandidType, Deserialize};
use ic_base_types::{CanisterId, PrincipalId};
use num_traits::ToPrimitive;

/// Struct used for encoding/decoding `(record { amount : opt nat; })`
#[derive(CandidType, Deserialize, Debug)]
pub struct ProvisionalCreateCanisterWithCyclesArgs {
    pub amount: Option<candid::Nat>,
    pub settings: Option<CanisterSettingsArgs>,
}

impl ProvisionalCreateCanisterWithCyclesArgs {
    pub fn new(amount: Option<u128>) -> Self {
        Self {
            amount: amount.map(candid::Nat::from),
            settings: None,
        }
    }

    pub fn to_u128(&self) -> Option<u128> {
        match &self.amount {
            Some(amount) => amount.0.to_u128(),
            None => None,
        }
    }
}

impl Payload<'_> for ProvisionalCreateCanisterWithCyclesArgs {}

/// Struct used for encoding/decoding
/// `(record {
///     canister_id : principal;
///     amount: nat;
/// })`
#[derive(CandidType, Deserialize, Debug)]
pub struct ProvisionalTopUpCanisterArgs {
    canister_id: PrincipalId,
    amount: candid::Nat,
}

impl ProvisionalTopUpCanisterArgs {
    pub fn new(canister_id: CanisterId, amount: u128) -> Self {
        Self {
            canister_id: canister_id.get(),
            amount: candid::Nat::from(amount),
        }
    }

    pub fn to_u128(&self) -> Option<u128> {
        self.amount.0.to_u128()
    }

    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }
}

impl Payload<'_> for ProvisionalTopUpCanisterArgs {}
