use candid::{CandidType, Deserialize};
use dfn_core::api::{call, CanisterId};
use serde::Serialize;

use std::fmt;
use std::fmt::Formatter;

use ic_base_types::PrincipalId;
use ic_ic00_types::{CanisterIdRecord, CanisterStatusResultV2, IC_00};

pub mod export_build_metadata_via_candid;
pub mod ledger;
pub mod stable_mem_utils;

/// A general purpose error indicating something went wrong.
#[derive(Default)]
pub struct NervousSystemError {
    pub error_message: String,
}

impl NervousSystemError {
    pub fn new() -> Self {
        NervousSystemError {
            ..Default::default()
        }
    }

    pub fn new_with_message(message: impl ToString) -> Self {
        NervousSystemError {
            error_message: message.to_string(),
        }
    }
}

impl fmt::Display for NervousSystemError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl fmt::Debug for NervousSystemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

/// Description of a change to the authz of a specific method on a specific
/// canister that must happen for a given canister change/add/remove
/// to be viable
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct MethodAuthzChange {
    pub canister: CanisterId,
    pub method_name: String,
    pub principal: Option<PrincipalId>,
    pub operation: AuthzChangeOp,
}

/// The operation to execute. Varible names in comments refer to the fields
/// of AuthzChange.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum AuthzChangeOp {
    /// 'canister' must add a principal to the authorized list of 'method_name'.
    /// If 'add_self' is true, the canister_id to be authorized is the canister
    /// being added/changed, if it's false, 'principal' is used instead, which
    /// must be Some in that case..
    Authorize { add_self: bool },
    /// 'canister' must remove 'principal' from the authorized list of
    /// 'method_name'. 'principal' must always be Some.
    Deauthorize,
}

/// Return the status of the given canister. The caller must control the given canister.
pub async fn get_canister_status(canister_id: PrincipalId) -> CanisterStatusResultV2 {
    let canister_id_record: CanisterIdRecord = CanisterId::new(canister_id).unwrap().into();

    call(
        IC_00,
        "canister_status",
        dfn_candid::candid,
        (canister_id_record,),
    )
    .await
    .unwrap()
}
