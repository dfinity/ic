use candid::CandidType;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::{Account, Subaccount};
use ic_ledger_core::block::BlockHeight;
use ic_ledger_core::ledger::TransferError as CoreTransferError;
use serde::Deserialize;

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub enum TransferError {
    BadFee { expected_fee: u64 },
    BadBurn { min_burn_amount: u64 },
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

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
pub struct ArchiveInfo {
    pub canister_id: CanisterId,
    pub block_range_start: u64,
    pub block_range_end: u64,
}
