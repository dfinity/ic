use crate::Request;
use icp_ledger::{
    BinaryAccountBalanceArgs, Tokens, TransferArgs, TransferError as ICPTransferError,
};
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};

impl Request for TransferArg {
    fn method(&self) -> &'static str {
        "icrc1_transfer"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = Result<BlockIndex, TransferError>;
}

impl Request for TransferArgs {
    fn method(&self) -> &'static str {
        "transfer"
    }

    fn update(&self) -> bool {
        true
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = Result<u64, ICPTransferError>;
}

impl Request for BinaryAccountBalanceArgs {
    fn method(&self) -> &'static str {
        "account_balance"
    }

    fn update(&self) -> bool {
        false
    }

    fn payload(&self) -> Result<Vec<u8>, candid::Error> {
        candid::encode_one(self)
    }

    type Response = Tokens;
}
