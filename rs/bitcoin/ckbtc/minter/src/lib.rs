use candid::{CandidType, Deserialize};
use ic_btc_types::{Satoshi, Utxo};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

pub mod guard;
pub mod lifecycle;
pub mod metrics;
pub mod state;
pub mod tx;
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

fn signed_transaction_length(unsigned_tx: &tx::UnsignedTransaction) -> usize {
    tx::SignedTransaction {
        inputs: unsigned_tx
            .inputs
            .iter()
            .map(|unsigned_input| tx::SignedInput {
                previous_output: unsigned_input.previous_output.clone(),
                sequence: unsigned_input.sequence,
                signature: ByteBuf::from(vec![0u8; tx::SIGNATURE_LEN]),
                pubkey: ByteBuf::from(vec![0u8; tx::PUBKEY_LEN]),
            })
            .collect(),
        outputs: unsigned_tx.outputs.clone(),
        lock_time: unsigned_tx.lock_time,
    }
    .serialized_len()
}

#[derive(Debug, PartialEq)]
pub enum BuildTxError {
    /// The minter does not have enough UTXOs to make the transfer
    /// Try again later after pending transactions have settled.
    NotEnoughFunds,
    /// The requested fee is too low.
    UserFeeTooLow,
    /// The amount is too low to pay the transfer fee.
    AmountTooLow,
}

/// Builds a transaction that moves the specified BTC `amount` to the specified
/// destination using the UTXOs that the minter owns. The receiver pays the fee.
///
/// Sends the change back to the specified minter main address.
///
/// # Arguments
///
/// * `minter_utxos` - The set of all UTXOs minter owns
/// * `dst_pubkey` - The public key of the receiver
/// * `main_pubkey` - The public key of the main account of the minter
/// * `amount` - The amount to transfer to the `dst_pubkey`.
/// * `user_fee` - The fee user is willing to pay.
/// * `fee_per_vbyte` - The current 50th percentile of BTC fees, in millisatoshi/byte
///
/// # Success case properties
///
/// * Transaction fee does not exceed the user fee and the amount.
/// ```text
/// fee(tx) < min(user_fee, amount)
/// ```
///
/// * The total value of minter UTXOs decreases at least by the amount.
/// ```text
/// sum([u.value | u ∈ minter_utxos']) ≤ sum([u.value | u ∈ minter_utxos]) - amount
/// ```
///
/// * If the transaction inputs exceed the amount, the minter gets the change.
/// ```text
/// inputs_value(tx) > amount ⇒ out_value(tx, main_pubkey) >= inputs_value(tx) - amount
/// ```
///
/// * If the transaction inputs are equal to the amount, all tokens go to the receiver.
/// ```text
/// sum([value(in) | in ∈ tx.inputs]) = amount ⇒ tx.outputs == { value = amount - fee(tx); pubkey = dst_pubkey }
/// ```
///
/// # Error case properties
///
/// * In case of errors, the function does not modify the inputs.
/// ```text
/// result.is_err() => minter_utxos' == minter_utxos
/// ```
///
pub fn build_unsigned_transaction(
    minter_utxos: &mut BTreeSet<Utxo>,
    dst_pubkey: Vec<u8>,
    main_pubkey: Vec<u8>,
    amount: Satoshi,
    user_fee: Option<Satoshi>,
    fee_per_vbyte: u64,
) -> Result<tx::UnsignedTransaction, BuildTxError> {
    const DUST_THRESHOLD: Satoshi = 300;

    let input_utxos = greedy(amount, minter_utxos);

    if input_utxos.is_empty() {
        return Err(BuildTxError::NotEnoughFunds);
    }

    let inputs_value = input_utxos.iter().map(|u| u.value).sum::<u64>();

    debug_assert!(inputs_value >= amount);

    let change = inputs_value - amount;
    let outputs = if change == 0 {
        vec![tx::TxOut {
            value: amount,
            pubkey: dst_pubkey.clone(),
        }]
    } else {
        let send_to_main = change.max(DUST_THRESHOLD + 1);

        vec![
            tx::TxOut {
                value: inputs_value - send_to_main,
                pubkey: dst_pubkey.clone(),
            },
            tx::TxOut {
                value: send_to_main,
                pubkey: main_pubkey,
            },
        ]
    };

    debug_assert_eq!(
        outputs.iter().map(|out| out.value).sum::<u64>(),
        inputs_value
    );

    let mut unsigned_tx = tx::UnsignedTransaction {
        inputs: input_utxos
            .iter()
            .map(|utxo| tx::UnsignedInput {
                previous_output: utxo.outpoint.clone(),
                sequence: 0xffffffff,
            })
            .collect(),
        outputs,
        lock_time: 0,
    };

    let tx_len = signed_transaction_length(&unsigned_tx);
    let expected_fee = (tx_len as u64 * fee_per_vbyte) / 1000;

    if expected_fee > amount {
        for utxo in input_utxos {
            minter_utxos.insert(utxo);
        }
        return Err(BuildTxError::AmountTooLow);
    }

    match user_fee {
        Some(fee) if fee < expected_fee => {
            for utxo in input_utxos {
                minter_utxos.insert(utxo);
            }
            return Err(BuildTxError::UserFeeTooLow);
        }
        _ => (),
    }

    // NB. The receiver (always the first output) pays the fee.
    debug_assert_eq!(unsigned_tx.outputs[0].pubkey, dst_pubkey);
    unsigned_tx.outputs[0].value -= user_fee.unwrap_or(expected_fee);

    Ok(unsigned_tx)
}
