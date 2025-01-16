//! State modifications that should end up in the event log.

use super::{
    eventlog::EventType, CkBtcMinterState, FinalizedBtcRetrieval, FinalizedStatus,
    RetrieveBtcRequest, SubmittedBtcTransaction, SuspendedReason,
};
use crate::state::invariants::CheckInvariantsImpl;
use crate::storage::record_event;
use crate::{CanisterRuntime, Timestamp};
use candid::Principal;
use ic_btc_interface::{Txid, Utxo};
use icrc_ledger_types::icrc1::account::Account;

pub fn accept_retrieve_btc_request<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    request: RetrieveBtcRequest,
    runtime: &R,
) {
    record_event(
        EventType::AcceptedRetrieveBtcRequest(request.clone()),
        runtime,
    );
    state.pending_retrieve_btc_requests.push(request.clone());
    if let Some(account) = request.reimbursement_account {
        state
            .retrieve_btc_account_to_block_indices
            .entry(account)
            .and_modify(|entry| entry.push(request.block_index))
            .or_insert(vec![request.block_index]);
    }
    if let Some(kyt_provider) = request.kyt_provider {
        *state.owed_kyt_amount.entry(kyt_provider).or_insert(0) += state.check_fee;
    }
}

pub fn add_utxos<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    mint_txid: Option<u64>,
    account: Account,
    utxos: Vec<Utxo>,
    runtime: &R,
) {
    record_event(
        EventType::ReceivedUtxos {
            mint_txid,
            to_account: account,
            utxos: utxos.clone(),
        },
        runtime,
    );

    state.add_utxos::<CheckInvariantsImpl>(account, utxos);
}

pub fn remove_retrieve_btc_request<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    request: RetrieveBtcRequest,
    runtime: &R,
) {
    record_event(
        EventType::RemovedRetrieveBtcRequest {
            block_index: request.block_index,
        },
        runtime,
    );

    state.push_finalized_request(FinalizedBtcRetrieval {
        request,
        state: FinalizedStatus::AmountTooLow,
    });
}

pub fn sent_transaction<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    tx: SubmittedBtcTransaction,
    runtime: &R,
) {
    record_event(
        EventType::SentBtcTransaction {
            request_block_indices: tx.requests.iter().map(|r| r.block_index).collect(),
            txid: tx.txid,
            utxos: tx.used_utxos.clone(),
            change_output: tx.change_output.clone(),
            submitted_at: tx.submitted_at,
            fee_per_vbyte: tx.fee_per_vbyte,
        },
        runtime,
    );

    state.push_submitted_transaction(tx);
}

pub fn confirm_transaction<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    txid: &Txid,
    runtime: &R,
) {
    record_event(EventType::ConfirmedBtcTransaction { txid: *txid }, runtime);
    state.finalize_transaction(txid);
}

pub fn mark_utxo_checked<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    utxo: Utxo,
    account: Account,
    runtime: &R,
) {
    record_event(
        EventType::CheckedUtxoV2 {
            utxo: utxo.clone(),
            account,
        },
        runtime,
    );
    state.mark_utxo_checked_v2(utxo, &account);
}

pub fn quarantine_utxo<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    utxo: Utxo,
    account: Account,
    now: Timestamp,
    runtime: &R,
) {
    discard_utxo(
        state,
        utxo,
        account,
        SuspendedReason::Quarantined,
        now,
        runtime,
    );
}

pub fn ignore_utxo<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    utxo: Utxo,
    account: Account,
    now: Timestamp,
    runtime: &R,
) {
    discard_utxo(
        state,
        utxo,
        account,
        SuspendedReason::ValueTooSmall,
        now,
        runtime,
    );
}

fn discard_utxo<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    utxo: Utxo,
    account: Account,
    reason: SuspendedReason,
    now: Timestamp,
    runtime: &R,
) {
    // ignored UTXOs are periodically re-evaluated and should not trigger
    // an event if they are still ignored.
    if state.suspend_utxo(utxo.clone(), account, reason, now) {
        record_event(
            EventType::SuspendedUtxo {
                utxo,
                account,
                reason,
            },
            runtime,
        )
    }
}

pub fn replace_transaction<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    old_txid: Txid,
    new_tx: SubmittedBtcTransaction,
    runtime: &R,
) {
    record_event(
        EventType::ReplacedBtcTransaction {
            old_txid,
            new_txid: new_tx.txid,
            change_output: new_tx
                .change_output
                .clone()
                .expect("bug: all replacement transactions must have the change output"),
            submitted_at: new_tx.submitted_at,
            fee_per_vbyte: new_tx
                .fee_per_vbyte
                .expect("bug: all replacement transactions must have the fee"),
        },
        runtime,
    );
    state.replace_transaction(&old_txid, new_tx);
}

pub fn distributed_kyt_fee<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    kyt_provider: Principal,
    amount: u64,
    block_index: u64,
    runtime: &R,
) -> Result<(), super::Overdraft> {
    record_event(
        EventType::DistributedKytFee {
            kyt_provider,
            amount,
            block_index,
        },
        runtime,
    );
    state.distribute_kyt_fee(kyt_provider, amount)
}
