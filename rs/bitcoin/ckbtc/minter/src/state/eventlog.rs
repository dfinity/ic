use crate::WithdrawalFee;
use crate::lifecycle::init::InitArgs;
use crate::lifecycle::upgrade::UpgradeArgs;
use crate::reimbursement::ReimburseWithdrawalTask;
use crate::state::invariants::CheckInvariants;
use crate::state::{
    ChangeOutput, CkBtcMinterState, ConsolidateUtxosRequest, FinalizedBtcRequest, FinalizedStatus,
    Overdraft, RetrieveBtcRequest, SubmittedBtcTransaction, SubmittedWithdrawalRequests,
    SuspendedReason,
};
use crate::state::{ReimburseDepositTask, ReimbursedDeposit, ReimbursementReason};
use candid::Principal;
pub use event::{EventType, ReplacedReason};
use ic_btc_interface::{Txid, Utxo};
use icrc_ledger_types::icrc1::account::Account;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Deserialize, candid::CandidType)]
pub struct GetEventsArg {
    pub start: u64,
    pub length: u64,
}

// Some event types are deprecated and this doesn't play well with generated code via `derive`
// that triggers some deprecation warnings that cannot be whitelisted.
// The trick is to put the whole EventType definition under a module and allow usage of deprecated
// code inside that module.
// For convenience, the module is not visible to the outside.
#[allow(deprecated)]
mod event {
    use super::*;
    use crate::reimbursement::WithdrawalReimbursementReason;
    use crate::state::SuspendedReason;

    #[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
    pub enum ReplacedReason {
        /// Indicates the old transaction has to be resend with a higher fee.
        #[serde(rename = "to_retry")]
        ToRetry,
        /// Indicates the old transaction has to be to canceled.
        #[serde(rename = "to_cancel")]
        ToCancel {
            /// Reason why the old transaction has to be canceled.
            reason: WithdrawalReimbursementReason,
        },
    }

    #[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
    pub enum EventType {
        /// Indicates the minter initialization with the specified arguments.  Must be
        /// the first event in the event log.
        #[serde(rename = "init")]
        Init(InitArgs),

        /// Indicates the minter upgrade with specified arguments.
        #[serde(rename = "upgrade")]
        Upgrade(UpgradeArgs),

        /// Indicates that the minter received new UTXOs to the specified account.
        /// The minter emits this event _after_ it minted ckBTC.
        #[serde(rename = "received_utxos")]
        ReceivedUtxos {
            /// The index of the transaction that mints ckBTC corresponding to the
            /// received UTXOs.
            #[serde(rename = "mint_txid")]
            #[serde(skip_serializing_if = "Option::is_none")]
            mint_txid: Option<u64>,
            /// That minter's account owning the UTXOs.
            #[serde(rename = "to_account")]
            to_account: Account,
            #[serde(rename = "utxos")]
            utxos: Vec<Utxo>,
        },

        /// Indicates that the minter accepted a new retrieve_btc request.
        /// The minter emits this event _after_ it burnt ckBTC.
        #[serde(rename = "accepted_retrieve_btc_request")]
        AcceptedRetrieveBtcRequest(RetrieveBtcRequest),

        /// Indicates that the minter removed a previous retrieve_btc request
        /// because the retrieval amount was not enough to cover the transaction
        /// fees.
        #[serde(rename = "removed_retrieve_btc_request")]
        RemovedRetrieveBtcRequest {
            #[serde(rename = "block_index")]
            block_index: u64,
        },

        /// Indicates that the minter sent out a new transaction to the Bitcoin
        /// network.
        #[serde(rename = "sent_transaction")]
        SentBtcTransaction {
            /// Block indices of retrieve_btc requests that caused the transaction.
            #[serde(rename = "requests")]
            request_block_indices: Vec<u64>,
            /// The Txid of the Bitcoin transaction.
            #[serde(rename = "txid")]
            txid: Txid,
            /// UTXOs used for the transaction.
            #[serde(rename = "utxos")]
            utxos: Vec<Utxo>,
            /// The output with the minter's change, if any.
            #[serde(rename = "change_output")]
            #[serde(skip_serializing_if = "Option::is_none")]
            change_output: Option<ChangeOutput>,
            /// The IC time at which the minter submitted the transaction.
            #[serde(rename = "submitted_at")]
            submitted_at: u64,
            /// The fee per vbyte (in millisatoshi) that we used for the transaction.
            #[serde(rename = "fee")]
            #[serde(skip_serializing_if = "Option::is_none")]
            fee_per_vbyte: Option<u64>,
            /// The total fee for this transaction
            #[serde(rename = "withdrawal_fee")]
            #[serde(skip_serializing_if = "Option::is_none")]
            withdrawal_fee: Option<WithdrawalFee>,
        },

        /// Indicates that the minter sent out a new transaction to replace an older transaction
        /// because the old transaction did not appear on the Bitcoin blockchain.
        #[serde(rename = "replaced_transaction")]
        ReplacedBtcTransaction {
            /// The Txid of the old Bitcoin transaction.
            #[serde(rename = "old_txid")]
            old_txid: Txid,
            /// The Txid of the new Bitcoin transaction.
            #[serde(rename = "new_txid")]
            new_txid: Txid,
            /// The output with the minter's change.
            #[serde(rename = "change_output")]
            change_output: ChangeOutput,
            /// The IC time at which the minter submitted the transaction.
            #[serde(rename = "submitted_at")]
            submitted_at: u64,
            /// The fee per vbyte (in millisatoshi) that we used for the transaction.
            #[serde(rename = "fee")]
            fee_per_vbyte: u64,
            /// The total fee for this transaction
            #[serde(rename = "withdrawal_fee")]
            #[serde(skip_serializing_if = "Option::is_none")]
            withdrawal_fee: Option<WithdrawalFee>,
            /// The reason why it was replaced
            reason: Option<ReplacedReason>,
            /// The UTXOs of the new transaction. If not available, we'll use the same
            /// UTXOs from the old transaction it replaces.
            #[serde(rename = "new_utxos")]
            #[serde(skip_serializing_if = "Option::is_none")]
            new_utxos: Option<Vec<Utxo>>,
        },

        /// Indicates that the minter received enough confirmations for a bitcoin
        /// transaction.
        #[serde(rename = "confirmed_transaction")]
        ConfirmedBtcTransaction {
            #[serde(rename = "txid")]
            txid: Txid,
        },

        /// Indicates that the given UTXO went through a KYT check.
        #[serde(rename = "checked_utxo")]
        #[deprecated(note = "Use CheckedUtxoV2")]
        CheckedUtxo {
            utxo: Utxo,
            uuid: String,
            clean: bool,
            kyt_provider: Option<Principal>,
        },

        #[serde(rename = "checked_utxo_v2")]
        CheckedUtxoV2 { utxo: Utxo, account: Account },

        /// Indicates that the given UTXO's value is too small to pay for a Bitcoin check.
        #[serde(rename = "ignored_utxo")]
        #[deprecated(note = "Use SuspendedUtxo")]
        IgnoredUtxo { utxo: Utxo },

        #[serde(rename = "suspended_utxo")]
        SuspendedUtxo {
            utxo: Utxo,
            account: Account,
            reason: SuspendedReason,
        },

        /// Indicates that the given KYT provider received owed fees.
        #[serde(rename = "distributed_kyt_fee")]
        DistributedKytFee {
            /// The beneficiary.
            #[serde(rename = "kyt_provider")]
            kyt_provider: Principal,
            /// The token amount minted.
            #[serde(rename = "amount")]
            amount: u64,
            /// The mint block on the ledger.
            #[serde(rename = "block_index")]
            block_index: u64,
        },

        /// Indicates that the KYT check for the specified address failed.
        #[serde(rename = "retrieve_btc_kyt_failed")]
        #[deprecated]
        RetrieveBtcKytFailed {
            /// The owner of the address.
            owner: Principal,
            /// The address that failed the KYT check.
            address: String,
            /// The amount associated with the failed KYT check.
            amount: u64,
            /// Unique identifier for the failed check.
            uuid: String,
            /// The KYT provider responsible for the failed check.
            kyt_provider: Principal,
            /// The block index where the failed check occurred.
            block_index: u64,
        },

        /// Indicates a reimbursement.
        #[serde(rename = "schedule_deposit_reimbursement")]
        ScheduleDepositReimbursement {
            /// The beneficiary.
            account: Account,
            /// The token amount to reimburse.
            amount: u64,
            /// The reason of the reimbursement.
            reason: ReimbursementReason,
            /// The corresponding burn block on the ledger.
            burn_block_index: u64,
        },

        /// Indicates that a reimbursement has been executed.
        #[serde(rename = "reimbursed_failed_deposit")]
        ReimbursedFailedDeposit {
            /// The burn block on the ledger.
            burn_block_index: u64,
            /// The mint block on the ledger.
            mint_block_index: u64,
        },

        /// Indicates an UTXO is checked to be clean and pre-mint
        #[serde(rename = "checked_utxo_mint_unknown")]
        CheckedUtxoMintUnknown { account: Account, utxo: Utxo },

        /// Indicates a reimbursement.
        #[serde(rename = "schedule_withdrawal_reimbursement")]
        ScheduleWithdrawalReimbursement {
            /// The beneficiary.
            account: Account,
            /// The token amount to reimburse.
            amount: u64,
            /// The reason of the reimbursement.
            reason: WithdrawalReimbursementReason,
            /// The corresponding burn block on the ledger.
            burn_block_index: u64,
        },

        /// The minter unexpectedly panicked while processing a reimbursement.
        /// The reimbursement is quarantined to prevent any double minting and
        /// will not be processed without further manual intervention.
        #[serde(rename = "quarantined_withdrawal_reimbursement")]
        QuarantinedWithdrawalReimbursement {
            /// The burn block on the ledger for that withdrawal that should have been reimbursed
            burn_block_index: u64,
        },
        /// Indicates that a reimbursement has been executed.
        #[serde(rename = "reimbursed_withdrawal")]
        ReimbursedWithdrawal {
            /// The burn block on the ledger.
            burn_block_index: u64,
            /// The mint block on the ledger.
            mint_block_index: u64,
        },
        /// Indicates that the minter consolidates UTXOs with transaction
        /// fee corresponding to burning ckbtc from the fee subaccount
        /// at the given ledger index.
        #[serde(rename = "accepted_consolidate_utxos_request")]
        CreatedConsolidateUtxosRequest(ConsolidateUtxosRequest),
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub struct Event {
    /// The canister time at which the minter generated this event.
    pub timestamp: Option<u64>,
    /// The event type.
    pub payload: EventType,
}

#[derive(Debug)]
pub enum ReplayLogError {
    /// There are no events in the event log.
    EmptyLog,
    /// The event log is inconsistent.
    InconsistentLog(String),
}

/// Reconstructs the minter state from an event log.
#[allow(deprecated)]
pub fn replay<I: CheckInvariants>(
    mut events: impl Iterator<Item = Event>,
) -> Result<CkBtcMinterState, ReplayLogError> {
    let mut state = match events.next() {
        Some(event) => match event.payload {
            EventType::Init(args) => CkBtcMinterState::from(args),
            payload => {
                return Err(ReplayLogError::InconsistentLog(format!(
                    "The first event is not Init: {payload:?}"
                )));
            }
        },
        None => return Err(ReplayLogError::EmptyLog),
    };

    // Because `kyt_principal` was previously used as a default
    // substitute for `kyt_provider` during kyt_fee accounting,
    // we need to keep track of this value so that `distribute_kyt_fee`
    // knows when to skip giving fees to `btc_checker_principal`.
    let mut kyt_principal = None;
    for event in events {
        match event.payload {
            EventType::Init(args) => {
                if args.kyt_principal.is_some() {
                    kyt_principal = args.kyt_principal.map(Principal::from);
                }
                state.reinit(args);
            }
            EventType::Upgrade(args) => {
                if args.kyt_principal.is_some() {
                    kyt_principal = args.kyt_principal.map(Principal::from);
                }
                state.upgrade(args);
            }
            EventType::ReceivedUtxos {
                to_account, utxos, ..
            } => state.add_utxos::<I>(to_account, utxos),
            EventType::AcceptedRetrieveBtcRequest(req) => {
                if let Some(account) = req.reimbursement_account {
                    state
                        .retrieve_btc_account_to_block_indices
                        .entry(account)
                        .and_modify(|entry| entry.push(req.block_index))
                        .or_insert(vec![req.block_index]);
                }
                state.push_back_pending_retrieve_btc_request(req);
            }
            EventType::RemovedRetrieveBtcRequest { block_index } => {
                let request = state
                    .remove_pending_retrieve_btc_request(block_index)
                    .ok_or_else(|| {
                        ReplayLogError::InconsistentLog(format!(
                            "Attempted to remove a non-pending retrieve_btc request {block_index}"
                        ))
                    })?;

                state.push_finalized_request(FinalizedBtcRequest {
                    request: request.into(),
                    state: FinalizedStatus::AmountTooLow,
                })
            }
            EventType::SentBtcTransaction {
                request_block_indices,
                txid,
                utxos,
                fee_per_vbyte,
                change_output,
                submitted_at,
                withdrawal_fee,
            } => {
                let mut retrieve_btc_requests = BTreeSet::new();
                let mut consolidate_utxos_request = None;
                for block_index in request_block_indices {
                    if let Some(request) = state.remove_pending_retrieve_btc_request(block_index) {
                        retrieve_btc_requests.insert(request);
                    }
                    if let Some(request) = state.get_consolidate_utxos_request(block_index) {
                        consolidate_utxos_request = Some(request.clone());
                    } else {
                        return Err(ReplayLogError::InconsistentLog(format!(
                            "Attempted to send a non-pending retrieve_btc request {block_index}"
                        )));
                    }
                }
                let requests = if let Some(request) = consolidate_utxos_request {
                    assert!(retrieve_btc_requests.is_empty());
                    SubmittedWithdrawalRequests::ToConsolidate { request }
                } else {
                    assert!(consolidate_utxos_request.is_none());
                    SubmittedWithdrawalRequests::ToConfirm {
                        requests: retrieve_btc_requests,
                    }
                };
                for utxo in utxos.iter() {
                    state.available_utxos.remove(utxo);
                }
                state.push_submitted_transaction(SubmittedBtcTransaction {
                    requests,
                    txid,
                    used_utxos: utxos,
                    fee_per_vbyte,
                    change_output,
                    submitted_at,
                    withdrawal_fee,
                    signed_tx: None,
                });
            }
            EventType::ReplacedBtcTransaction {
                old_txid,
                new_txid,
                change_output,
                submitted_at,
                fee_per_vbyte,
                withdrawal_fee,
                reason,
                new_utxos,
            } => {
                let (old_requests, old_utxos) = match state
                    .submitted_transactions
                    .iter()
                    .find(|tx| tx.txid == old_txid)
                {
                    Some(tx) => (tx.requests.clone(), tx.used_utxos.clone()),
                    None => {
                        return Err(ReplayLogError::InconsistentLog(format!(
                            "Cannot replace a non-existent transaction {}",
                            &old_txid
                        )));
                    }
                };
                let requests = match reason {
                    Some(ReplacedReason::ToCancel { reason }) => match old_requests {
                        SubmittedWithdrawalRequests::ToConsolidate { .. } => {
                            panic!("Cannot cancel a consolidation request")
                        }
                        SubmittedWithdrawalRequests::ToCancel { .. } => {
                            panic!("Cannot cancel a cancelation request")
                        }
                        SubmittedWithdrawalRequests::ToConfirm { requests } => {
                            assert!(
                                new_utxos.is_some(),
                                "BUG: Cancel transaction {new_txid} must have `new_utxos` to use different UTXOs than the transaction it tries to cancel"
                            );
                            debug_assert!(
                                new_utxos
                                    .as_ref()
                                    .unwrap()
                                    .iter()
                                    .collect::<BTreeSet<_>>()
                                    .is_subset(&old_utxos.iter().collect::<BTreeSet<_>>()),
                                "BUG: UTXOs from cancel transaction must be a subset of the UTXOS from the transaction to cancel. New UTXOs {new_utxos:?}. Old UTXOs: {old_utxos:?}"
                            );
                            SubmittedWithdrawalRequests::ToCancel { requests, reason }
                        }
                    },
                    Some(ReplacedReason::ToRetry) | None => old_requests,
                };

                state.replace_transaction(
                    &old_txid,
                    SubmittedBtcTransaction {
                        txid: new_txid,
                        requests,
                        used_utxos: new_utxos.unwrap_or(old_utxos),
                        change_output: Some(change_output),
                        submitted_at,
                        fee_per_vbyte: Some(fee_per_vbyte),
                        withdrawal_fee,
                        signed_tx: None,
                    },
                );
            }
            EventType::ConfirmedBtcTransaction { txid } => {
                state.finalize_transaction(&txid);
            }
            #[allow(deprecated)] //need to replay past events
            EventType::CheckedUtxo {
                utxo,
                uuid,
                clean,
                kyt_provider,
            } => {
                if clean {
                    state.mark_utxo_checked(
                        utxo,
                        if uuid.is_empty() { None } else { Some(uuid) },
                        kyt_provider,
                    );
                } else {
                    state.discard_utxo_without_account(utxo, SuspendedReason::Quarantined);
                }
            }
            EventType::CheckedUtxoV2 { utxo, account } => {
                state.mark_utxo_checked_v2(utxo, &account);
            }
            #[allow(deprecated)] //need to replay past events
            EventType::IgnoredUtxo { utxo } => {
                state.discard_utxo_without_account(utxo, SuspendedReason::ValueTooSmall);
            }
            EventType::SuspendedUtxo {
                utxo,
                account,
                reason,
            } => {
                state.suspended_utxos.insert(account, utxo, reason, None);
            }
            EventType::DistributedKytFee {
                kyt_provider,
                amount,
                ..
            } => {
                if Some(kyt_provider) != kyt_principal
                    && let Err(Overdraft(overdraft)) =
                        state.distribute_kyt_fee(kyt_provider, amount)
                {
                    return Err(ReplayLogError::InconsistentLog(format!(
                        "Attempted to distribute {amount} to {kyt_provider}, causing an overdraft of {overdraft}"
                    )));
                }
            }
            #[allow(deprecated)]
            EventType::RetrieveBtcKytFailed { kyt_provider, .. } => {
                *state.owed_kyt_amount.entry(kyt_provider).or_insert(0) += state.check_fee;
            }
            EventType::ScheduleDepositReimbursement {
                account,
                amount,
                burn_block_index,
                reason,
            } => {
                state.schedule_deposit_reimbursement(
                    burn_block_index,
                    ReimburseDepositTask {
                        account,
                        amount,
                        reason,
                    },
                );
            }
            EventType::ReimbursedFailedDeposit {
                burn_block_index,
                mint_block_index,
            } => {
                let reimbursed_tx = state
                    .pending_reimbursements
                    .remove(&burn_block_index)
                    .expect("bug: reimbursement task should be present");
                state.reimbursed_transactions.insert(
                    burn_block_index,
                    ReimbursedDeposit {
                        account: reimbursed_tx.account,
                        amount: reimbursed_tx.amount,
                        reason: reimbursed_tx.reason,
                        mint_block_index,
                    },
                );
            }
            EventType::CheckedUtxoMintUnknown { utxo, account } => {
                state.mark_utxo_checked_mint_unknown(utxo, &account);
            }
            EventType::ScheduleWithdrawalReimbursement {
                account,
                amount,
                reason,
                burn_block_index,
            } => state.schedule_withdrawal_reimbursement(
                burn_block_index,
                ReimburseWithdrawalTask {
                    account,
                    amount,
                    reason,
                },
            ),
            EventType::QuarantinedWithdrawalReimbursement { burn_block_index } => {
                state.quarantine_withdrawal_reimbursement(burn_block_index);
            }
            EventType::ReimbursedWithdrawal {
                burn_block_index,
                mint_block_index,
            } => {
                state.reimburse_withdrawal_completed(burn_block_index, mint_block_index);
            }
            EventType::CreatedConsolidateUtxosRequest(req) => {
                state.push_consolidate_utxos_request(req)
            }
        }
    }

    Ok(state)
}
