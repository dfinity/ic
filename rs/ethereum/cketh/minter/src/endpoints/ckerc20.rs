use crate::ledger_client::LedgerBurnError;
use crate::state::transactions::Erc20WithdrawalRequest;
use candid::{CandidType, Deserialize, Nat, Principal};

#[derive(CandidType, Deserialize)]
pub struct WithdrawErc20Arg {
    pub amount: Nat,
    pub ckerc20_token_symbol: String,
    pub recipient: String,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq)]
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

#[derive(CandidType, Deserialize, Debug, PartialEq)]
pub enum WithdrawErc20Error {
    TokenNotSupported {
        supported_tokens: Vec<String>,
    },
    InsufficientFunds {
        balance: Nat,
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
    RecipientAddressBlocked {
        address: String,
    },
    TemporarilyUnavailable(String),
}

impl From<LedgerBurnError> for WithdrawErc20Error {
    fn from(error: LedgerBurnError) -> Self {
        match error {
            LedgerBurnError::TemporarilyUnavailable { message, .. } => {
                WithdrawErc20Error::TemporarilyUnavailable(message)
            }
            LedgerBurnError::InsufficientFunds {
                balance,
                failed_burn_amount,
                ledger,
            } => WithdrawErc20Error::InsufficientFunds {
                balance,
                failed_burn_amount,
                token_symbol: ledger.token_symbol.to_string(),
                ledger_id: ledger.id,
            },
            LedgerBurnError::InsufficientAllowance {
                allowance,
                failed_burn_amount,
                ledger,
            } => WithdrawErc20Error::InsufficientAllowance {
                allowance,
                failed_burn_amount,
                token_symbol: ledger.token_symbol.to_string(),
                ledger_id: ledger.id,
            },
        }
    }
}
