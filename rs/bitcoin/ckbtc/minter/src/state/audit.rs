//! State modifications that should end up in the event log.

use super::{
    eventlog::Event, CkBtcMinterState, FinalizedBtcRetrieval, FinalizedStatus, RetrieveBtcRequest,
    SubmittedBtcTransaction,
};
use crate::storage::record_event;
use ic_btc_types::Utxo;
use ic_icrc1::Account;

pub fn accept_retrieve_btc_request(state: &mut CkBtcMinterState, request: RetrieveBtcRequest) {
    record_event(&Event::AcceptedRetrieveBtcRequest(request.clone()));
    state.pending_retrieve_btc_requests.push(request);
}

pub fn add_utxos(
    state: &mut CkBtcMinterState,
    mint_txid: Option<u64>,
    account: Account,
    utxos: Vec<Utxo>,
) {
    record_event(&Event::ReceivedUtxos {
        mint_txid,
        to_account: account.clone(),
        utxos: utxos.clone(),
    });

    state.add_utxos(account, utxos);
}

pub fn remove_retrieve_btc_request(state: &mut CkBtcMinterState, request: RetrieveBtcRequest) {
    record_event(&Event::RemovedRetrieveBtcRequest {
        block_index: request.block_index,
    });

    state.push_finalized_request(FinalizedBtcRetrieval {
        request,
        state: FinalizedStatus::AmountTooLow,
    });
}

pub fn sent_transaction(state: &mut CkBtcMinterState, tx: SubmittedBtcTransaction) {
    record_event(&Event::SentBtcTransaction {
        request_block_indices: tx.requests.iter().map(|r| r.block_index).collect(),
        txid: tx.txid,
        utxos: tx.used_utxos.clone(),
        change_output: tx.change_output.clone(),
        submitted_at: tx.submitted_at,
    });

    state.push_submitted_transaction(tx);
}

pub fn confirm_transaction(state: &mut CkBtcMinterState, txid: &[u8; 32]) {
    record_event(&Event::ConfirmedBtcTransaction { txid: *txid });
    state.finalize_transaction(txid);
}
