use candid::{CandidType, Deserialize};
use ic_btc_types::Utxo;
use serde::Serialize;
use std::collections::BTreeSet;

pub mod guard;
pub mod lifecycle;
pub mod metrics;
pub mod state;
pub mod updates;

#[cfg(test)]
mod tests;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct ECDSAPublicKey {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

pub async fn heartbeat() {
    if state::read_state(|s| s.is_heartbeat_running) {
        return;
    }

    state::mutate_state(|s| {
        s.is_heartbeat_running = true;
    });

    // Do Stuff

    state::mutate_state(|s| {
        s.is_heartbeat_running = false;
    });
}

#[allow(dead_code)]
/// Selects a subset of UTXOs with the specified total target value and removes
/// the selected UTXOs from the available set.
///
/// If there are no UTXOs matching the criteria, returns an empty vector.
///
/// PROPERTY: sum(u.value for u in available_set) ≥ target ⇒ !solution.is_empty()
/// POSTCONDITION: !solution.is_empty() ⇒ sum(u.value for u in solution) ≥ target
/// POSTCONDITION:  solution.is_empty() ⇒ available_utxos did not change.
fn greedy(target: u64, available_utxos: &mut BTreeSet<Utxo>) -> Vec<Utxo> {
    let mut solution = vec![];
    let mut goal = target;
    while goal > 0 {
        let utxo = match available_utxos.iter().max_by_key(|u| u.value) {
            Some(max_utxo) if max_utxo.value < goal => max_utxo.clone(),
            Some(_) => available_utxos
                .iter()
                .filter(|u| u.value >= goal)
                .min_by_key(|u| u.value)
                .cloned()
                .expect("bug: there must be at least one UTXO matching the criteria"),
            None => {
                // Not enough available UTXOs to satisfy the request.
                for u in solution {
                    available_utxos.insert(u);
                }
                return vec![];
            }
        };
        goal = goal.saturating_sub(utxo.value);
        assert!(available_utxos.remove(&utxo));
        solution.push(utxo);
    }

    debug_assert!(solution.is_empty() || solution.iter().map(|u| u.value).sum::<u64>() >= target);

    solution
}
