use crate::state::LedgerMintIndex;
use crate::{state, CanisterRuntime};
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

pub type ReimbursedWithdrawalResult = Result<ReimbursedWithdrawal, ReimbursedError>;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ReimbursedError {
    /// Whether reimbursement was minted or not is unknown,
    /// most likely because there was an unexpected panic in the callback.
    /// The reimbursement request is quarantined to avoid any double minting and
    /// will not be further processed without manual intervention.
    Quarantined,
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

/// Reimburse withdrawals that were cancelled.
pub async fn reimburse_withdrawals<R: CanisterRuntime>(runtime: &R) {
    if state::read_state(|s| s.pending_withdrawal_reimbursements.is_empty()) {
        return;
    }
    let pending_reimbursements = state::read_state(|s| s.pending_withdrawal_reimbursements.clone());
    for (index, pending_reimbursement) in pending_reimbursements {
        // Ensure that even if we were to panic in the callback, after having contacted the ledger to mint the tokens,
        // this reimbursement request will not be processed again.
        let prevent_double_minting_guard = scopeguard::guard(index.clone(), |index| {
            state::mutate_state(|s| {
                state::audit::quarantine_withdrawal_reimbursement(s, index, runtime)
            });
        });
    }
}
