use crate::Request;
use candid::{CandidType, Encode, Nat, Principal};
use cycles_minting_canister::CreateCanister;
use ic_base_types::PrincipalId;
use serde::Deserialize;

pub type BlockIndex = Nat;

#[derive(CandidType, Deserialize, Debug, Clone)]
pub enum CreateCanisterError {
    InsufficientFunds {
        balance: Nat,
    },
    TooOld,
    CreatedInFuture {
        ledger_time: u64,
    },
    TemporarilyUnavailable,
    Duplicate {
        duplicate_of: Nat,
        // If the original transaction created a canister then this field will contain the canister id.
        canister_id: Option<Principal>,
    },
    FailedToCreate {
        fee_block: Option<BlockIndex>,
        refund_block: Option<BlockIndex>,
        error: String,
    },
    GenericError {
        message: String,
        error_code: Nat,
    },
}

// ```candid
// type CreateCanisterArgs = record {
//     from_subaccount : opt vec nat8;
//     created_at_time : opt nat64;
//     amount : nat;
//     creation_args : opt CmcCreateCanisterArgs;
// };
// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CreateCanisterArgs {
    pub from_subaccount: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
    pub amount: Nat,
    pub creation_args: Option<CreateCanister>,
}

// ```candid
// type CreateCanisterSuccess = record {
//     block_id : BlockIndex;
//     canister_id : principal;
// };
// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct CreateCanisterSuccess {
    pub block_id: BlockIndex,
    pub canister_id: PrincipalId,
}

impl Request for CreateCanisterArgs {
    fn method(&self) -> &'static str {
        "create_canister"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> std::result::Result<Vec<u8>, candid::Error> {
        Encode!(self)
    }

    type Response = Result<CreateCanisterSuccess, CreateCanisterError>;
}

// ```
// type Account = record { owner : principal; subaccount : opt vec nat8 };
// ```
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct Account {
    pub owner: PrincipalId,
    pub subaccount: Option<Vec<u8>>,
}

impl Request for Account {
    fn method(&self) -> &'static str {
        "icrc1_balance_of"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        Encode!(self)
    }

    type Response = Nat;
}
