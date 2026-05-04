use crate::{CanisterSettingsArgs, Payload};
use candid::{CandidType, Deserialize};
use ic_base_types::{CanisterId, PrincipalId};
use num_traits::ToPrimitive;

/// Struct used for encoding/decoding
/// ```text
/// record {
///   amount : opt nat;
///   settings : opt canister_settings;
///   specified_id : opt principal;
///   sender_canister_version : opt nat64;
/// }
/// ```
#[derive(Debug, CandidType, Deserialize)]
pub struct ProvisionalCreateCanisterWithCyclesArgs {
    pub amount: Option<candid::Nat>,
    pub settings: Option<CanisterSettingsArgs>,
    pub specified_id: Option<PrincipalId>,
    pub sender_canister_version: Option<u64>,
}

impl ProvisionalCreateCanisterWithCyclesArgs {
    pub fn new(amount: Option<u128>, specified_id: Option<PrincipalId>) -> Self {
        Self {
            amount: amount.map(candid::Nat::from),
            settings: None,
            specified_id,
            sender_canister_version: None,
        }
    }

    pub fn to_u128(&self) -> Option<u128> {
        match &self.amount {
            Some(amount) => amount.0.to_u128(),
            None => None,
        }
    }

    pub fn get_sender_canister_version(&self) -> Option<u64> {
        self.sender_canister_version
    }
}

impl Payload<'_> for ProvisionalCreateCanisterWithCyclesArgs {}

/// Struct used for encoding/decoding
/// ```text
/// record {
///   canister_id : principal;
///   amount : nat;
/// }
/// ```
#[derive(Debug, CandidType, Deserialize)]
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
        CanisterId::unchecked_from_principal(self.canister_id)
    }
}

impl Payload<'_> for ProvisionalTopUpCanisterArgs {}
