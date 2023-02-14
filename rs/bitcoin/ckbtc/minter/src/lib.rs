use crate::address::BitcoinAddress;
use crate::logs::{P0, P1};
use candid::{CandidType, Deserialize};
use ic_btc_types::{MillisatoshiPerByte, Network, OutPoint, Satoshi, Utxo};
use ic_canister_log::log;
use ic_icrc1::Account;
use scopeguard::{guard, ScopeGuard};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub mod address;
pub mod dashboard;
pub mod guard;
pub mod lifecycle;
pub mod logs;
pub mod management;
pub mod metrics;
pub mod queries;
pub mod signature;
pub mod state;
pub mod storage;
pub mod tasks;
pub mod tx;
pub mod updates;

#[cfg(test)]
mod tests;

/// Time constants
const SEC_NANOS: u64 = 1_000_000_000;
const MIN_NANOS: u64 = 60 * SEC_NANOS;
/// The minimum number of pending request in the queue before we try to make
/// a batch transaction.
pub const MIN_PENDING_REQUESTS: usize = 20;
pub const MAX_REQUESTS_PER_BATCH: usize = 100;

/// The constants used to compute the minter's fee to cover its own cycle consumption.
/// The values are set to cover the cycle cost on a 28-node subnet.
pub const MINTER_FEE_PER_INPUT: u64 = 246;
pub const MINTER_FEE_PER_OUTPUT: u64 = 7;
pub const MINTER_FEE_CONSTANT: u64 = 52;

#[derive(CandidType, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ECDSAPublicKey {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

struct SignTxRequest {
    key_name: String,
    network: Network,
    ecdsa_public_key: ECDSAPublicKey,
    unsigned_tx: tx::UnsignedTransaction,
    change_output: state::ChangeOutput,
    outpoint_account: BTreeMap<OutPoint, Account>,
    /// The original requests that we keep around to place back to the queue
    /// if the signature fails.
    requests: Vec<state::RetrieveBtcRequest>,
    /// The list of UTXOs we use as transaction inputs.
    utxos: Vec<Utxo>,
}

/// Undoes changes we make to the ckBTC state when we construct a pending transaction.
/// We call this function if we fail to sign or send a Bitcoin transaction.
fn undo_sign_request(requests: Vec<state::RetrieveBtcRequest>, utxos: Vec<Utxo>) {
    state::mutate_state(|s| {
        for utxo in utxos {
            assert!(s.available_utxos.insert(utxo));
        }
        // Insert requests in reverse order so that they are still sorted.
        s.push_from_in_flight_to_pending_requests(requests);
    })
}

/// Updates the UTXOs for the main account of the minter to pick up change from
/// previous retrieve BTC requests.
async fn fetch_main_utxos(main_account: &Account, main_address: &BitcoinAddress) -> Vec<Utxo> {
    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    let utxos = match management::get_utxos(
        btc_network,
        &main_address.display(btc_network),
        min_confirmations,
    )
    .await
    {
        Ok(response) => response.utxos,
        Err(e) => {
            log!(
                P0,
                "[heartbeat]: failed to fetch UTXOs for the main address {}: {}",
                main_address.display(btc_network),
                e
            );
            return vec![];
        }
    };

    state::read_state(|s| match s.utxos_state_addresses.get(main_account) {
        Some(known_utxos) => utxos
            .into_iter()
            .filter(|u| !known_utxos.contains(u))
            .collect(),
        None => utxos,
    })
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
                log!(
                    P0,
                    "[heartbeat]: not enough data points ({}) to compute the fee",
                    fees.len()
                );
                None
            }
        }
        Err(err) => {
            log!(
                P0,
                "[heartbeat]: failed to get median fee per vbyte: {}",
                err
            );
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

    // We make requests if we have old requests in the queue or if have enough
    // requests to fill a batch.
    if !state::read_state(|s| s.can_form_a_batch(MIN_PENDING_REQUESTS, ic_cdk::api::time())) {
        return;
    }

    let main_account = Account {
        owner: ic_cdk::id().into(),
        subaccount: None,
    };

    updates::get_btc_address::init_ecdsa_public_key().await;

    let (main_address, ecdsa_public_key) = match state::read_state(|s| {
        s.ecdsa_public_key.clone().map(|key| {
            (
                address::account_to_bitcoin_address(&key, &main_account),
                key,
            )
        })
    }) {
        Some((address, key)) => (address, key),
        None => {
            log!(
                P0,
                "unreachable: have retrieve BTC requests but the ECDSA key is not initialized",
            );
            return;
        }
    };

    let fee_millisatoshi_per_vbyte = match estimate_fee_per_vbyte().await {
        Some(fee) => fee,
        None => return,
    };

    let maybe_sign_request = state::mutate_state(|s| {
        let batch = s.build_batch(MAX_REQUESTS_PER_BATCH);

        if batch.is_empty() {
            return None;
        }

        let outputs: Vec<_> = batch
            .iter()
            .map(|req| (req.address.clone(), req.amount))
            .collect();

        match build_unsigned_transaction(
            &mut s.available_utxos,
            outputs,
            main_address,
            fee_millisatoshi_per_vbyte,
        ) {
            Ok((unsigned_tx, change_output, utxos)) => {
                for req in batch.iter() {
                    s.push_in_flight_request(req.block_index, state::InFlightStatus::Signing);
                }

                Some(SignTxRequest {
                    key_name: s.ecdsa_key_name.clone(),
                    ecdsa_public_key,
                    change_output,
                    outpoint_account: filter_output_accounts(s, &unsigned_tx),
                    network: s.btc_network,
                    unsigned_tx,
                    requests: batch,
                    utxos,
                })
            }
            Err(BuildTxError::AmountTooLow) => {
                log!(P0,
                    "[heartbeat]: dropping requests for total BTC amount {} to addresses {} (too low to cover the fees)",
                    tx::DisplayAmount(batch.iter().map(|req| req.amount).sum::<u64>()),
                    batch.iter().map(|req| req.address.display(s.btc_network)).collect::<Vec<_>>().join(",")
                );

                // There is no point in retrying the request because the
                // amount is too low.
                for request in batch {
                    state::audit::remove_retrieve_btc_request(s, request);
                }
                None
            }
            Err(BuildTxError::ZeroOutput { address, amount }) => {
                log!(P0,
                    "[heartbeat]: dropping a request for BTC amount {} to {} (too low to cover the fees)",
                     tx::DisplayAmount(amount), address.display(s.btc_network)
                );

                let mut requests_to_put_back = vec![];
                for request in batch {
                    if request.address == address && request.amount == amount {
                        // Finalize the request that we cannot fulfill.
                        state::audit::remove_retrieve_btc_request(s, request);
                    } else {
                        // Keep the rest of the requests in the batch, we will
                        // try to build a new transaction on the next heartbeat.
                        requests_to_put_back.push(request);
                    }
                }

                s.push_from_in_flight_to_pending_requests(requests_to_put_back);

                None
            }
            Err(BuildTxError::NotEnoughFunds) => {
                log!(P0,
                    "[heartbeat]: not enough funds to unsigned transaction for requests at block indexes [{}]",
                    batch.iter().map(|req| req.block_index.to_string()).collect::<Vec<_>>().join(",")
                );

                s.push_from_in_flight_to_pending_requests(batch);
                None
            }
        }
    });

    if let Some(req) = maybe_sign_request {
        log!(
            P1,
            "[heartbeat]: signing a new transaction: {}",
            hex::encode(tx::encode_into(&req.unsigned_tx, Vec::new()))
        );

        // This guard ensures that we return pending requests and UTXOs back to
        // the state if the signing or sending a transaction fails or panics.
        let requests_guard = guard((req.requests, req.utxos), |(reqs, utxos)| {
            undo_sign_request(reqs, utxos);
        });

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
                    for retrieve_req in requests_guard.0.iter() {
                        s.push_in_flight_request(
                            retrieve_req.block_index,
                            state::InFlightStatus::Sending { txid },
                        );
                    }
                });

                log!(
                    P1,
                    "[heartbeat]: sending a signed transaction {}",
                    hex::encode(tx::encode_into(&signed_tx, Vec::new()))
                );
                match management::send_transaction(&signed_tx, req.network).await {
                    Ok(()) => {
                        log!(
                            P1,
                            "[heartbeat]: successfully sent transaction {}",
                            tx::DisplayTxid(&txid),
                        );

                        // Defuse the guard because we sent the transaction
                        // successfully.
                        let (requests, used_utxos) = ScopeGuard::into_inner(requests_guard);

                        state::mutate_state(|s| {
                            state::audit::sent_transaction(
                                s,
                                state::SubmittedBtcTransaction {
                                    requests,
                                    txid,
                                    used_utxos,
                                    change_output: Some(req.change_output),
                                    submitted_at: ic_cdk::api::time(),
                                },
                            );
                        });
                    }
                    Err(err) => {
                        log!(
                            P0,
                            "[heartbeat]: failed to send a bitcoin transaction: {}",
                            err
                        );
                    }
                }
            }
            Err(err) => {
                log!(P0, "[heartbeat]: failed to sign a BTC transaction: {}", err);
            }
        }
    }
}

fn finalization_time_estimate(min_confirmations: u32, network: Network) -> Duration {
    Duration::from_nanos(
        min_confirmations as u64
            * match network {
                Network::Mainnet => 10 * MIN_NANOS,
                Network::Testnet => MIN_NANOS,
                Network::Regtest => SEC_NANOS,
            },
    )
}

async fn finalize_requests() {
    if state::read_state(|s| s.submitted_transactions.is_empty()) {
        return;
    }

    updates::get_btc_address::init_ecdsa_public_key().await;

    let now = ic_cdk::api::time();

    let has_requests_to_finalize = state::read_state(|s| {
        let wait_time = finalization_time_estimate(s.min_confirmations, s.btc_network);
        s.submitted_transactions
            .iter()
            .any(|req| req.submitted_at + (wait_time.as_nanos() as u64) < now)
    });

    if !has_requests_to_finalize {
        return;
    }

    let ecdsa_public_key = match state::read_state(|s| s.ecdsa_public_key.clone()) {
        Some(key) => key,
        None => {
            log!(
                P0,
                "unreachable: have retrieve BTC requests but the ECDSA key is not initialized",
            );
            return;
        }
    };

    let main_account = Account {
        owner: ic_cdk::id().into(),
        subaccount: None,
    };

    let main_address = address::account_to_bitcoin_address(&ecdsa_public_key, &main_account);
    let new_utxos = fetch_main_utxos(&main_account, &main_address).await;

    // Transactions whose change outpoint is present in the newly fetched UTXOs
    // can be finalized.  Note that all new minter transactions must have a
    // change output because minter always charges a fee for converting tokens.
    let confirmed_transactions: Vec<_> = state::read_state(|s| {
        s.submitted_transactions
            .iter()
            .filter_map(|tx| {
                tx.change_output.as_ref().and_then(|out| {
                    new_utxos
                        .iter()
                        .any(|utxo| utxo.outpoint.vout == out.vout && utxo.outpoint.txid == tx.txid)
                        .then_some(tx.txid)
                })
            })
            .collect()
    });

    state::mutate_state(|s| {
        for txid in &confirmed_transactions {
            state::audit::confirm_transaction(s, txid);
        }
        state::audit::add_utxos(s, None, main_account, new_utxos);
    });
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

#[derive(Debug, PartialEq, Eq)]
pub enum BuildTxError {
    /// The minter does not have enough UTXOs to make the transfer
    /// Try again later after pending transactions have settled.
    NotEnoughFunds,
    /// The withdrawal amount is too low to pay the transfer fee.
    AmountTooLow,
    /// Withdrawal amount of at least one request is too low to cover its share
    /// of the fees.  Similar to `AmountTooLow`, but applies to a single
    /// request in a batch.
    ZeroOutput {
        address: BitcoinAddress,
        amount: u64,
    },
}

/// Builds a transaction that moves BTC to the specified destination accounts
/// using the UTXOs that the minter owns. The receivers pay the fee.
///
/// Sends the change back to the specified minter main address.
///
/// # Arguments
///
/// * `minter_utxos` - The set of all UTXOs minter owns
/// * `outputs` - The destination BTC addresses and respective amounts.
/// * `main_address` - The BTC address of the minter's main account do absorb the change.
/// * `fee_per_vbyte` - The current 50th percentile of BTC fees, in millisatoshi/byte
///
/// # Panics
///
/// This function panics if the `outputs` vector is empty as it indicates a bug
/// in the caller's code.
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
///  * The last output of the transaction is the minter's fee + the minter's change.
/// ```text
/// value(last_out) == minter_fee + minter_change
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
    outputs: Vec<(BitcoinAddress, Satoshi)>,
    main_address: BitcoinAddress,
    fee_per_vbyte: u64,
) -> Result<(tx::UnsignedTransaction, state::ChangeOutput, Vec<Utxo>), BuildTxError> {
    assert!(!outputs.is_empty());

    /// Having a sequence number lower than (0xffffffff - 1) signals the use of replacement by fee.
    /// It allows us to increase the fee of a transaction already sent to the mempool.
    /// The rbf option is used in `resubmit_retrieve_btc`.
    /// https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
    const SEQUENCE_RBF_ENABLED: u32 = 0xfffffffd;

    let amount = outputs.iter().map(|(_, amount)| amount).sum::<u64>();

    let input_utxos = greedy(amount, minter_utxos);

    if input_utxos.is_empty() {
        return Err(BuildTxError::NotEnoughFunds);
    }

    // This guard returns the selected UTXOs back to the available_utxos set if
    // we fail to build the transaction.
    let utxos_guard = guard(input_utxos, |utxos| {
        for utxo in utxos {
            minter_utxos.insert(utxo);
        }
    });

    let inputs_value = utxos_guard.iter().map(|u| u.value).sum::<u64>();

    debug_assert!(inputs_value >= amount);

    let minter_fee = MINTER_FEE_PER_INPUT * utxos_guard.len() as u64
        + MINTER_FEE_PER_OUTPUT * (outputs.len() + 1) as u64
        + MINTER_FEE_CONSTANT;

    let change = inputs_value - amount;
    let change_output = state::ChangeOutput {
        vout: outputs.len() as u32,
        value: change + minter_fee,
    };

    let tx_outputs: Vec<tx::TxOut> = outputs
        .iter()
        .map(|(address, value)| tx::TxOut {
            address: address.clone(),
            value: *value,
        })
        .chain(vec![tx::TxOut {
            address: main_address.clone(),
            value: change_output.value,
        }])
        .collect();

    debug_assert_eq!(
        tx_outputs.iter().map(|out| out.value).sum::<u64>() - minter_fee,
        inputs_value
    );

    let mut unsigned_tx = tx::UnsignedTransaction {
        inputs: utxos_guard
            .iter()
            .map(|utxo| tx::UnsignedInput {
                previous_output: utxo.outpoint.clone(),
                value: utxo.value,
                sequence: SEQUENCE_RBF_ENABLED,
            })
            .collect(),
        outputs: tx_outputs,
        lock_time: 0,
    };

    let tx_vsize = fake_sign(&unsigned_tx).vsize();
    let fee = (tx_vsize as u64 * fee_per_vbyte) / 1000;

    if fee + minter_fee > amount {
        return Err(BuildTxError::AmountTooLow);
    }

    let fee_shares = distribute(fee + minter_fee, outputs.len() as u64);

    for (output, fee_share) in unsigned_tx.outputs.iter_mut().zip(fee_shares.iter()) {
        if output.address != main_address {
            if output.value <= *fee_share {
                return Err(BuildTxError::ZeroOutput {
                    address: output.address.clone(),
                    amount: output.value,
                });
            }
            output.value = output.value.saturating_sub(*fee_share);
        }
    }

    debug_assert_eq!(
        inputs_value,
        fee + unsigned_tx.outputs.iter().map(|u| u.value).sum::<u64>()
    );

    Ok((
        unsigned_tx,
        change_output,
        ScopeGuard::into_inner(utxos_guard),
    ))
}

/// Distributes an amount across the specified number of shares as fairly as
/// possible.
///
/// For example, `distribute(5, 3) = [2, 2, 1]`.
fn distribute(amount: u64, n: u64) -> Vec<u64> {
    if n == 0 {
        return vec![];
    }

    let (avg, remainder) = (amount / n, amount % n);

    // Fill the shares with the average value.
    let mut shares = vec![avg; n as usize];
    // Distribute the remainder across the shares.
    for i in 0..remainder {
        shares[i as usize] += 1;
    }

    shares
}

pub fn timer() {
    use tasks::{pop_if_ready, schedule_after, TaskType};

    const INTERVAL_PROCESSING: Duration = Duration::from_secs(5);

    let task = match pop_if_ready() {
        Some(task) => task,
        None => return,
    };

    match task.task_type {
        TaskType::ProcessLogic => {
            ic_cdk::spawn(async {
                let _guard = match crate::guard::TimerLogicGuard::new() {
                    Some(guard) => guard,
                    None => return,
                };

                let _enqueue_followup_guard = guard((), |_| {
                    schedule_after(INTERVAL_PROCESSING, TaskType::ProcessLogic)
                });

                submit_pending_requests().await;
                finalize_requests().await;
            });
        }
    }
}
