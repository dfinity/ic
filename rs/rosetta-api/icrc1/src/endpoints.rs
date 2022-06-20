use crate::{Account, Subaccount};
use candid::CandidType;
use ic_base_types::PrincipalId;
use ic_ledger_core::block::BlockHeight;
use ic_ledger_core::ledger::TransferError as CoreTransferError;
use serde::Deserialize;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum TransferError {
    BadFee { expected_fee: u64 },
    InsufficientFunds { balance: u64 },
    TxTooOld { allowed_window_nanos: u64 },
    TxCreatedInFuture,
    TxThrottled,
    TxDuplicate { duplicate_of: BlockHeight },
    GenericError { error_code: u64, message: String },
}

impl From<CoreTransferError> for TransferError {
    fn from(err: CoreTransferError) -> Self {
        use ic_ledger_core::ledger::TransferError as LTE;
        use TransferError as TE;

        match err {
            LTE::BadFee { expected_fee } => TE::BadFee {
                expected_fee: expected_fee.get_e8s(),
            },
            LTE::InsufficientFunds { balance } => TE::InsufficientFunds {
                balance: balance.get_e8s(),
            },
            LTE::TxTooOld {
                allowed_window_nanos,
            } => TE::TxTooOld {
                allowed_window_nanos,
            },
            LTE::TxCreatedInFuture => TE::TxCreatedInFuture,
            LTE::TxThrottled => TE::TxThrottled,
            LTE::TxDuplicate { duplicate_of } => TE::TxDuplicate { duplicate_of },
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct TransferArg {
    pub from_subaccount: Option<Subaccount>,
    pub to_principal: PrincipalId,
    pub to_subaccount: Option<Subaccount>,
    pub fee: Option<u64>,
    pub amount: u64,
}

impl TransferArg {
    pub fn to_account(&self) -> Account {
        Account {
            of: self.to_principal,
            subaccount: self.to_subaccount,
        }
    }
}
