use crate::address::BitcoinAddress;
use candid::{CandidType, Deserialize};
use ic_btc_types::{MillisatoshiPerByte, Network, OutPoint, Satoshi, Utxo};
use ic_icrc1::Account;
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};

pub mod address;
pub mod guard;
pub mod lifecycle;
pub mod management;
pub mod metrics;
pub mod queries;
pub mod signature;
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

struct SignTxRequest {
    key_name: String,
    network: Network,
    ecdsa_public_key: ECDSAPublicKey,
    unsigned_tx: tx::UnsignedTransaction,
    outpoint_account: BTreeMap<OutPoint, Account>,
    /// The original request that we keep around to place it back to the queue
    /// if the signature fails.
    original_request: state::RetrieveBtcRequest,
    /// The list of UTXOs we use as transaction inputs.
    utxos: Vec<Utxo>,
}

/// Undoes changes we make to the ckBTC state when we construct a pending transaction.
/// We call this function if we fail to sign or send a Bitcoin transaction.
fn undo_sign_request(req: state::RetrieveBtcRequest, utxos: Vec<Utxo>) {
    state::mutate_state(|s| {
        for utxo in utxos {
            assert!(s.available_utxos.insert(utxo));
        }
        s.push_pending_request(req);
    })
}

/// Updates the UTXOs for the main account of the minter to pick up change from
/// previous retrieve BTC requests.
async fn fetch_main_utxos(main_account: &Account, main_address: &BitcoinAddress) {
    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    let utxos = match management::get_utxos(
        btc_network,
        &main_address.display(btc_network),
        min_confirmations,
    )
    .await
    {
        Ok(utxos) => utxos,
        Err(e) => {
            ic_cdk::print(format!(
                "[heartbeat]: failed to fetch UTXOs for the main address {}: {}",
                main_address.display(btc_network),
                e
            ));
            return;
        }
    };

    let new_utxos = state::read_state(|s| match s.utxos_state_addresses.get(main_account) {
        Some(known_utxos) => utxos
            .into_iter()
            .filter(|u| !known_utxos.contains(u))
            .collect(),
        None => utxos,
    });

    state::mutate_state(|s| s.add_utxos(main_account.clone(), new_utxos));
}

/// Returns an estimate for transaction fees in millisatoshi per vbyte.  Returns
/// None if the bitcoin canister is unavailable or does not have enough data for
/// an estimate yet.
async fn estimate_fee_per_vbyte() -> Option<MillisatoshiPerByte> {
    /// The default fee we use on regtest networks if there are not enough data
    /// to compute the median fee.
    const DEFAULT_FEE: MillisatoshiPerByte = 5_000;

    let btc_network = state::read_state(|s| s.btc_network);
    match management::get_current_fees(btc_network).await {
        Ok(fees) => {
            if btc_network == Network::Regtest {
                return Some(DEFAULT_FEE);
            }
            if fees.len() >= 100 {
                Some(fees[49])
            } else {
                ic_cdk::print(format!(
                    "[heartbeat]: not enough data points ({}) to compute the fee",
                    fees.len()
                ));
                None
            }
        }
        Err(err) => {
            ic_cdk::print(format!(
                "[heartbeat]: failed to get median fee per vbyte: {}",
                err
            ));
            None
        }
    }
}

/// Constructs and sends out signed bitcoin transactions for pending retrieve
/// requests.
async fn submit_pending_requests() {
    if state::read_state(|s| s.pending_retrieve_btc_requests.is_empty()) {
        return;
    }

    let main_account = Account {
        owner: ic_cdk::id().into(),
        subaccount: None,
    };

    let (main_address, ecdsa_public_key) = match state::read_state(|s| {
        s.ecdsa_public_key.clone().map(|key| {
            (
                address::account_to_bitcoin_address(&key, &main_account),
                key,
            )
        })
    }) {
        Some((key, address)) => (key, address),
        None => {
            ic_cdk::print(
                "unreachable: have retrieve BTC requests but the ECDSA key is not initialized",
            );
            return;
        }
    };

    let fee_millisatoshi_per_vbyte = match estimate_fee_per_vbyte().await {
        Some(fee) => fee,
        None => return,
    };

    fetch_main_utxos(&main_account, &main_address).await;

    let maybe_sign_request = state::mutate_state(|s| {
        match s.pending_retrieve_btc_requests.pop_front() {
            Some(req) => {
                match build_unsigned_transaction(
                    &mut s.available_utxos,
                    req.address.clone(),
                    main_address,
                    req.amount,
                    fee_millisatoshi_per_vbyte,
                ) {
                    Ok((unsigned_tx, utxos)) => {
                        s.push_in_flight_request(req.block_index, state::InFlightStatus::Signing);

                        Some(SignTxRequest {
                            key_name: s.ecdsa_key_name.clone(),
                            ecdsa_public_key,
                            outpoint_account: filter_output_accounts(s, &unsigned_tx),
                            network: s.btc_network,
                            unsigned_tx,
                            original_request: req,
                            utxos,
                        })
                    }
                    Err(BuildTxError::AmountTooLow) => {
                        ic_cdk::print(format!(
                            "[heartbeat]: dropping a request for BTC amount {} to {} too low to cover the fees",
                            req.amount,
                            req.address.display(s.btc_network)
                        ));
                        // There is no point in retrying the request because the
                        // amount is too low.
                        s.push_finalized_request(state::FinalizedBtcRetrieval {
                            request: req,
                            state: state::FinalizedStatus::AmountTooLow,
                        });
                        None
                    }
                    Err(BuildTxError::NotEnoughFunds) => {
                        ic_cdk::print(format!(
                            "[heartbeat]: not enough funds to unsigned transaction for request {:?}",
                            req
                        ));
                        // Push the transaction to the end of the queue so that
                        // we have a chance to handle other requests.
                        s.pending_retrieve_btc_requests.push_back(req);
                        None
                    }
                }
            }
            None => None,
        }
    });

    if let Some(req) = maybe_sign_request {
        ic_cdk::print(format!(
            "[heartbeat]: signing a new transaction: {}",
            hex::encode(tx::encode_into(&req.unsigned_tx, Vec::new()))
        ));

        let txid = req.unsigned_tx.txid();

        match sign_transaction(
            req.key_name,
            &req.ecdsa_public_key,
            &req.outpoint_account,
            req.unsigned_tx,
        )
        .await
        {
            Ok(signed_tx) => {
                state::mutate_state(|s| {
                    s.push_in_flight_request(
                        req.original_request.block_index,
                        state::InFlightStatus::Sending { txid },
                    );
                });

                ic_cdk::print(format!(
                    "[heartbeat]: sending a signed transaction {}",
                    hex::encode(tx::encode_into(&signed_tx, Vec::new()))
                ));
                match management::send_transaction(&signed_tx, req.network).await {
                    Ok(()) => {
                        ic_cdk::print(format!(
                            "[heartbeat]: successfully sent transaction {}",
                            hex::encode(txid)
                        ));
                        state::mutate_state(|s| {
                            s.push_submitted_request(state::SubmittedBtcRetrieval {
                                request: req.original_request,
                                txid,
                                used_utxos: req.utxos,
                            });
                        });
                    }
                    Err(err) => {
                        ic_cdk::print(format!(
                            "[heartbeat]: failed to send a bitcoin transaction: {}",
                            err
                        ));
                        undo_sign_request(req.original_request, req.utxos);
                    }
                }
            }
            Err(err) => {
                ic_cdk::print(format!(
                    "[heartbeat]: failed to sign a BTC transaction: {}",
                    err
                ));
                undo_sign_request(req.original_request, req.utxos);
            }
        }
    }
}

pub async fn heartbeat() {
    let _heartbeat_guard = match guard::HeartbeatGuard::new() {
        Some(guard) => guard,
        None => return,
    };

    submit_pending_requests().await;
}

/// Builds the minimal OutPoint -> Account map required to sign a transaction.
fn filter_output_accounts(
    state: &state::CkBtcMinterState,
    unsigned_tx: &tx::UnsignedTransaction,
) -> BTreeMap<OutPoint, Account> {
    unsigned_tx
        .inputs
        .iter()
        .map(|input| {
            (
                input.previous_output.clone(),
                state
                    .outpoint_account
                    .get(&input.previous_output)
                    .unwrap()
                    .clone(),
            )
        })
        .collect()
}

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

/// Gathers ECDSA signatures for all the inputs in the specified unsigned
/// transaction.
///
/// # Panics
///
/// This function panics if the `output_account` map does not have an entry for
/// at least one of the transaction previous output points.
pub async fn sign_transaction(
    key_name: String,
    ecdsa_public_key: &ECDSAPublicKey,
    output_account: &BTreeMap<tx::OutPoint, Account>,
    unsigned_tx: tx::UnsignedTransaction,
) -> Result<tx::SignedTransaction, management::CallError> {
    use crate::address::{derivation_path, derive_public_key};

    let mut signed_inputs = Vec::with_capacity(unsigned_tx.inputs.len());
    let sighasher = tx::TxSigHasher::new(&unsigned_tx);
    for (i, input) in unsigned_tx.inputs.iter().enumerate() {
        let outpoint = &input.previous_output;

        let account = output_account
            .get(outpoint)
            .unwrap_or_else(|| panic!("bug: no account for outpoint {:?}", outpoint));

        let path = derivation_path(account);
        let pubkey = ByteBuf::from(derive_public_key(ecdsa_public_key, account).public_key);
        let pkhash = tx::hash160(&pubkey);

        let sighash = sighasher.sighash(i, &pkhash);
        let sec1_signature = management::sign_with_ecdsa(key_name.clone(), path, sighash).await?;

        signed_inputs.push(tx::SignedInput {
            signature: signature::EncodedSignature::from_sec1(&sec1_signature),
            pubkey,
            previous_output: outpoint.clone(),
            sequence: input.sequence,
        });
    }
    Ok(tx::SignedTransaction {
        inputs: signed_inputs,
        outputs: unsigned_tx.outputs,
        lock_time: unsigned_tx.lock_time,
    })
}

pub fn fake_sign(unsigned_tx: &tx::UnsignedTransaction) -> tx::SignedTransaction {
    tx::SignedTransaction {
        inputs: unsigned_tx
            .inputs
            .iter()
            .map(|unsigned_input| tx::SignedInput {
                previous_output: unsigned_input.previous_output.clone(),
                sequence: unsigned_input.sequence,
                signature: signature::EncodedSignature::fake(),
                pubkey: ByteBuf::from(vec![0u8; tx::PUBKEY_LEN]),
            })
            .collect(),
        outputs: unsigned_tx.outputs.clone(),
        lock_time: unsigned_tx.lock_time,
    }
}

#[derive(Debug, PartialEq)]
pub enum BuildTxError {
    /// The minter does not have enough UTXOs to make the transfer
    /// Try again later after pending transactions have settled.
    NotEnoughFunds,
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
/// * `dst_address` - The destination BTC address.
/// * `main_address` - The BTC address of minter's main account.
/// * `amount` - The amount to transfer to the `dst_pubkey`.
/// * `fee_per_vbyte` - The current 50th percentile of BTC fees, in millisatoshi/byte
///
/// # Success case properties
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
    dst_address: BitcoinAddress,
    main_address: BitcoinAddress,
    amount: Satoshi,
    fee_per_vbyte: u64,
) -> Result<(tx::UnsignedTransaction, Vec<Utxo>), BuildTxError> {
    const DUST_THRESHOLD: Satoshi = 300;
    /// Having a sequence number lower than (0xffffffff - 1) signals the use of replacement by fee.
    /// It allows us to increase the fee of a transaction already sent to the mempool.
    /// The rbf option is used in `resubmit_retrieve_btc`.
    /// https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
    const SEQUENCE_RBF_ENABLED: u32 = 0xfffffffd;

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
            address: dst_address.clone(),
        }]
    } else {
        let send_to_main = change.max(DUST_THRESHOLD + 1);

        vec![
            tx::TxOut {
                value: inputs_value - send_to_main,
                address: dst_address.clone(),
            },
            tx::TxOut {
                value: send_to_main,
                address: main_address,
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
                value: utxo.value,
                sequence: SEQUENCE_RBF_ENABLED,
            })
            .collect(),
        outputs,
        lock_time: 0,
    };

    let tx_len = fake_sign(&unsigned_tx).vsize();
    let fee = (tx_len as u64 * fee_per_vbyte) / 1000;

    if fee > amount {
        for utxo in input_utxos {
            minter_utxos.insert(utxo);
        }
        return Err(BuildTxError::AmountTooLow);
    }

    // NB. The receiver (always the first output) pays the fee.
    debug_assert_eq!(&unsigned_tx.outputs[0].address, &dst_address);
    unsigned_tx.outputs[0].value -= fee;

    Ok((unsigned_tx, input_utxos))
}
