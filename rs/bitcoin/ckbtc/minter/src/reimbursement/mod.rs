use crate::Priority;
use crate::memo::MintMemo;
use crate::state::LedgerMintIndex;
use crate::{CanisterRuntime, state};
use candid::{CandidType, Deserialize};
use canlog::log;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use serde::Serialize;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Serialize, serde::Deserialize)]
pub struct ReimburseWithdrawalTask {
    pub account: Account,
    /// The amount that should be reimbursed in the smallest denomination.
    pub amount: u64,
    pub reason: WithdrawalReimbursementReason,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Serialize, serde::Deserialize)]
pub struct ReimbursedWithdrawal {
    pub account: Account,
    /// The amount that was reimbursed in the smallest denomination.
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

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub enum WithdrawalReimbursementReason {
    #[serde(rename = "invalid_transaction")]
    InvalidTransaction(InvalidTransactionError),
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub enum InvalidTransactionError {
    /// The transaction contains too many inputs.
    /// If such a transaction were signed, there is a risk that the resulting transaction will have a size of
    /// over 100k vbytes and therefore be *non-standard*.
    #[serde(rename = "too_many_inputs")]
    TooManyInputs {
        num_inputs: usize,
        max_num_inputs: usize,
    },
}

/// Reimburse withdrawals that were canceled.
pub async fn reimburse_withdrawals<R: CanisterRuntime>(runtime: &R) {
    if state::read_state(|s| s.pending_withdrawal_reimbursements.is_empty()) {
        return;
    }
    let pending_reimbursements = state::read_state(|s| s.pending_withdrawal_reimbursements.clone());
    let mut error_count = 0;
    for (burn_index, reimbursement) in pending_reimbursements {
        // Ensure that even if we were to panic in the callback, after having contacted the ledger to mint the tokens,
        // this reimbursement request will not be processed again.
        let prevent_double_minting_guard = scopeguard::guard(burn_index, |index| {
            state::mutate_state(|s| {
                state::audit::quarantine_withdrawal_reimbursement(s, index, runtime)
            });
        });
        let memo = MintMemo::ReimburseWithdrawal {
            withdrawal_id: burn_index,
        };
        match runtime
            .mint_ckbtc(
                reimbursement.amount,
                reimbursement.account,
                Memo::from(crate::memo::encode(&memo)),
            )
            .await
        {
            Ok(mint_index) => {
                log!(
                    Priority::Debug,
                    "[reimburse_withdrawals]: Successfully reimbursed {:?} at mint block index {}",
                    reimbursement,
                    mint_index
                );
                state::mutate_state(|s| {
                    state::audit::reimburse_withdrawal_completed(s, burn_index, mint_index, runtime)
                });
            }
            Err(err) => {
                log!(
                    Priority::Info,
                    "[reimburse_withdrawals]: Failed to reimburse {:?}: {:?}. Will retry later",
                    reimbursement,
                    err
                );
                error_count += 1;
            }
        }
        // Defuse the guard. Note that in case of a panic in the callback (either before or after this point)
        // the defuse will not be effective (due to state rollback), and the guard that was
        // setup before the `mint_ckbtc` async call will be invoked.
        scopeguard::ScopeGuard::into_inner(prevent_double_minting_guard);
    }

    if error_count > 0 {
        log!(
            Priority::Info,
            "[reimburse_withdrawals] Failed to reimburse {error_count} withdrawal requests, retrying later."
        );
    }
}
