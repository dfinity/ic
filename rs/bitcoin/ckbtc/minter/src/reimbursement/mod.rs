use crate::state;
use crate::state::LedgerMintIndex;
use candid::{CandidType, Deserialize};
use icrc_ledger_types::icrc1::account::Account;
use serde::Serialize;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Serialize, serde::Deserialize)]
pub struct ReimburseWithdrawalTask {
    pub account: Account,
    pub amount: u64,
    pub reason: WithdrawalReimbursementReason,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Serialize, serde::Deserialize)]
pub struct ReimbursedWithdrawal {
    pub account: Account,
    pub amount: u64,
    pub reason: WithdrawalReimbursementReason,
    pub mint_block_index: LedgerMintIndex,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub enum WithdrawalReimbursementReason {
    InvalidTransaction(InvalidTransactionError),
    // CancelledByUser TODO XC-451: user should be able to cancel own withdrawals
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub enum InvalidTransactionError {
    /// The transaction contains too many inputs.
    /// If such a transaction where signed, there is a risk that the resulting transaction will have a size
    /// over 100k vbytes and therefore be *non-standard*.
    TooManyInputs {
        num_inputs: usize,
        max_num_inputs: usize,
    },
}

/// Reimburse withdrawals that were canceled.
pub async fn reimburse_withdrawals() {
    if state::read_state(|s| s.pending_withdrawal_reimbursements.is_empty()) {
        return;
    }
    todo!()
}
