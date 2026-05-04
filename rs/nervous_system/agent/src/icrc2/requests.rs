use crate::Request;
use candid::Nat;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};

impl Request for ApproveArgs {
    fn method(&self) -> &'static str {
        "icrc2_approve"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = Result<Nat, ApproveError>;
}
