use crate::ledger_client::LedgerBurnError;
use crate::state::transactions::Erc20WithdrawalRequest;
use candid::{CandidType, Deserialize, Nat, Principal};

#[derive(CandidType, Deserialize)]
pub struct WithdrawErc20Arg {
    pub amount: Nat,
    pub ckerc20_ledger_id: Principal,
    pub recipient: String,
}

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub struct RetrieveErc20Request {
    pub cketh_block_index: Nat,
    pub ckerc20_block_index: Nat,
}

impl From<Erc20WithdrawalRequest> for RetrieveErc20Request {
    fn from(value: Erc20WithdrawalRequest) -> Self {
        Self {
            cketh_block_index: candid::Nat::from(value.cketh_ledger_burn_index.get()),
            ckerc20_block_index: candid::Nat::from(value.ckerc20_ledger_burn_index.get()),
        }
    }
}

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub enum WithdrawErc20Error {
    TokenNotSupported {
        supported_tokens: Vec<crate::endpoints::CkErc20Token>,
    },
    RecipientAddressBlocked {
        address: String,
    },
    CkEthLedgerError {
        error: LedgerError,
    },
    CkErc20LedgerError {
        cketh_block_index: Nat,
        error: LedgerError,
    },
    TemporarilyUnavailable(String),
}

#[derive(Clone, PartialEq, Debug, CandidType, Deserialize)]
pub enum LedgerError {
    InsufficientFunds {
        balance: Nat,
        failed_burn_amount: Nat,
        token_symbol: String,
        ledger_id: Principal,
    },
    AmountTooLow {
        minimum_burn_amount: Nat,
        failed_burn_amount: Nat,
        token_symbol: String,
        ledger_id: Principal,
    },
    InsufficientAllowance {
        allowance: Nat,
        failed_burn_amount: Nat,
        token_symbol: String,
        ledger_id: Principal,
    },
    TemporarilyUnavailable(String),
}

impl From<LedgerBurnError> for LedgerError {
    fn from(error: LedgerBurnError) -> Self {
        match error {
            LedgerBurnError::TemporarilyUnavailable { message, .. } => {
                LedgerError::TemporarilyUnavailable(message)
            }
            LedgerBurnError::InsufficientFunds {
                balance,
                failed_burn_amount,
                ledger,
            } => LedgerError::InsufficientFunds {
                balance,
                failed_burn_amount,
                token_symbol: ledger.token_symbol.to_string(),
                ledger_id: ledger.id,
            },
            LedgerBurnError::InsufficientAllowance {
                allowance,
                failed_burn_amount,
                ledger,
            } => LedgerError::InsufficientAllowance {
                allowance,
                failed_burn_amount,
                token_symbol: ledger.token_symbol.to_string(),
                ledger_id: ledger.id,
            },
            LedgerBurnError::AmountTooLow {
                minimum_burn_amount,
                failed_burn_amount,
                ledger,
            } => LedgerError::AmountTooLow {
                minimum_burn_amount,
                failed_burn_amount,
                token_symbol: ledger.token_symbol.to_string(),
                ledger_id: ledger.id,
            },
        }
    }
}
