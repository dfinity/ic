use crate::state::CkBtcMinterState;
use ic_utils_ensure::{ensure, ensure_eq};

pub trait CheckInvariants {
    fn check_invariants(state: &CkBtcMinterState) -> Result<(), String>;
}

pub enum CheckInvariantsImpl {}

impl CheckInvariants for CheckInvariantsImpl {
    fn check_invariants(state: &CkBtcMinterState) -> Result<(), String> {
        for utxo in state.available_utxos.iter() {
            ensure!(
                state.outpoint_account.contains_key(&utxo.outpoint),
                "the output_account map is missing an entry for {:?}",
                utxo.outpoint
            );

            ensure!(
                state
                    .utxos_state_addresses
                    .iter()
                    .any(|(_, utxos)| utxos.contains(utxo)),
                "available utxo {:?} does not belong to any account",
                utxo
            );
        }

        for (addr, utxos) in state.utxos_state_addresses.iter() {
            for utxo in utxos.iter() {
                ensure_eq!(
                    state.outpoint_account.get(&utxo.outpoint),
                    Some(addr),
                    "missing outpoint account for {:?}",
                    utxo.outpoint
                );
            }
        }

        for (l, r) in state
            .pending_btc_requests
            .iter()
            .zip(state.pending_btc_requests.iter().skip(1))
        {
            ensure!(
                l.received_at() <= r.received_at(),
                "pending retrieve_btc requests are not sorted by receive time"
            );
        }

        for tx in &state.stuck_transactions {
            ensure!(
                state.replacement_txid.contains_key(&tx.txid),
                "stuck transaction {} does not have a replacement id",
                &tx.txid,
            );
        }

        for (old_txid, new_txid) in &state.replacement_txid {
            ensure!(
                state
                    .stuck_transactions
                    .iter()
                    .any(|tx| &tx.txid == old_txid),
                "not found stuck transaction {}",
                old_txid,
            );

            ensure!(
                state
                    .submitted_transactions
                    .iter()
                    .chain(state.stuck_transactions.iter())
                    .any(|tx| &tx.txid == new_txid),
                "not found replacement transaction {}",
                new_txid,
            );
        }

        ensure_eq!(
            state.replacement_txid.len(),
            state.rev_replacement_txid.len(),
            "direct and reverse TX replacement links don't match"
        );
        for (old_txid, new_txid) in &state.replacement_txid {
            ensure_eq!(
                state.rev_replacement_txid.get(new_txid),
                Some(old_txid),
                "no back link for {} -> {} TX replacement",
                old_txid,
                new_txid,
            );
        }

        Ok(())
    }
}
