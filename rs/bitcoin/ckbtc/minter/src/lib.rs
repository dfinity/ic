use crate::address::BitcoinAddress;
use crate::logs::{P0, P1};
use crate::management::CallError;
use crate::queries::WithdrawalFee;
use crate::updates::update_balance::UpdateBalanceError;
use async_trait::async_trait;
use candid::{CandidType, Deserialize, Principal};
use ic_btc_checker::CheckTransactionResponse;
use ic_btc_interface::{MillisatoshiPerByte, OutPoint, Page, Satoshi, Txid, Utxo};
use ic_canister_log::log;
use ic_cdk::api::management_canister::bitcoin;
use ic_management_canister_types_private::DerivationPath;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use scopeguard::{guard, ScopeGuard};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::cmp::max;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub mod address;
pub mod dashboard;
pub mod guard;
pub mod lifecycle;
pub mod logs;
pub mod management;
pub mod memo;
pub mod metrics;
pub mod queries;
pub mod signature;
pub mod state;
pub mod storage;
pub mod tasks;
pub mod tx;
pub mod updates;

#[cfg(test)]
pub mod test_fixtures;
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
pub const MINTER_FEE_PER_INPUT: u64 = 146;
pub const MINTER_FEE_PER_OUTPUT: u64 = 4;
pub const MINTER_FEE_CONSTANT: u64 = 26;
/// Dust limit for the minter's address.
/// The minter's address is of type P2WPKH which means it has a dust limit of 294 sats.
/// For additional safety, we round that value up.
pub const MINTER_ADDRESS_DUST_LIMIT: Satoshi = 300;

/// The minimum fee increment for transaction resubmission.
/// See https://en.bitcoin.it/wiki/Miner_fees#Relaying for more detail.
pub const MIN_RELAY_FEE_PER_VBYTE: MillisatoshiPerByte = 1_000;

/// The minimum time the minter should wait before replacing a stuck transaction.
pub const MIN_RESUBMISSION_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The maximum memo size of a transaction on the ckBTC ledger.
/// The ckBTC minter requires at least 69 bytes, we choose 80
/// to have some room for future modifications.
pub const CKBTC_LEDGER_MEMO_SIZE: u16 = 80;

/// The threshold for the number of UTXOs under management before
/// trying to match the number of outputs with the number of inputs
/// when building transactions.
pub const UTXOS_COUNT_THRESHOLD: usize = 1_000;

pub const IC_CANISTER_RUNTIME: IcCanisterRuntime = IcCanisterRuntime {};

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub enum Priority {
    P0,
    P1,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub priority: Priority,
    pub file: String,
    pub line: u32,
    pub message: String,
    pub counter: u64,
}

#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
pub struct Log {
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, CandidType, Deserialize, Serialize)]
pub struct MinterInfo {
    pub min_confirmations: u32,
    pub retrieve_btc_min_amount: u64,
    // Serialize to the old name to be backward compatible in Candid.
    #[serde(rename = "kyt_fee")]
    pub check_fee: u64,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct ECDSAPublicKey {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

pub type GetUtxosRequest = bitcoin::GetUtxosRequest;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct GetUtxosResponse {
    pub utxos: Vec<Utxo>,
    pub tip_height: u32,
    pub next_page: Option<Page>,
}

impl From<bitcoin::GetUtxosResponse> for GetUtxosResponse {
    fn from(response: bitcoin::GetUtxosResponse) -> Self {
        Self {
            utxos: response
                .utxos
                .into_iter()
                .map(|utxo| Utxo {
                    outpoint: OutPoint {
                        txid: Txid::try_from(utxo.outpoint.txid.as_slice())
                            .unwrap_or_else(|_| panic!("Unable to parse TXID")),
                        vout: utxo.outpoint.vout,
                    },
                    value: utxo.value,
                    height: utxo.height,
                })
                .collect(),

            tip_height: response.tip_height,
            next_page: response.next_page.map(Page::from),
        }
    }
}

// Note that both [ic_btc_interface::Network] and
// [ic_cdk::api::management_canister::bitcoin::BitcoinNetwork] from ic_cdk
// would serialize to lowercase names, but here we keep uppercase names for
// backward compatibility with the state of already deployed minter canister.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, CandidType, Deserialize, Serialize)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<Network> for bitcoin::BitcoinNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => bitcoin::BitcoinNetwork::Mainnet,
            Network::Testnet => bitcoin::BitcoinNetwork::Testnet,
            Network::Regtest => bitcoin::BitcoinNetwork::Regtest,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Regtest => write!(f, "regtest"),
        }
    }
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
async fn fetch_main_utxos<R: CanisterRuntime>(
    main_account: &Account,
    main_address: &BitcoinAddress,
    runtime: &R,
) -> Vec<Utxo> {
    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    let utxos = match management::get_utxos(
        btc_network,
        &main_address.display(btc_network),
        min_confirmations,
        management::CallSource::Minter,
        runtime,
    )
    .await
    {
        Ok(response) => response.utxos,
        Err(e) => {
            log!(
                P0,
                "[fetch_main_utxos]: failed to fetch UTXOs for the main address {}: {}",
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

/// Returns the minimum withdrawal amount based on the current median fee rate (in millisatoshi per byte).
/// The returned amount is in satoshi.
fn compute_min_withdrawal_amount(
    median_fee_rate_e3s: MillisatoshiPerByte,
    min_withdrawal_amount: u64,
    check_fee: u64,
) -> u64 {
    const PER_REQUEST_RBF_BOUND: u64 = 22_100;
    const PER_REQUEST_VSIZE_BOUND: u64 = 221;
    const PER_REQUEST_MINTER_FEE_BOUND: u64 = 305;

    let median_fee_rate = median_fee_rate_e3s / 1_000;
    ((PER_REQUEST_RBF_BOUND
        + PER_REQUEST_VSIZE_BOUND * median_fee_rate
        + PER_REQUEST_MINTER_FEE_BOUND
        + check_fee)
        / 50_000)
        * 50_000
        + min_withdrawal_amount
}

/// Returns an estimate for transaction fees in millisatoshi per vbyte. Returns
/// None if the Bitcoin canister is unavailable or does not have enough data for
/// an estimate yet.
pub async fn estimate_fee_per_vbyte() -> Option<MillisatoshiPerByte> {
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
                state::mutate_state(|s| {
                    s.last_fee_per_vbyte.clone_from(&fees);
                    s.fee_based_retrieve_btc_min_amount = compute_min_withdrawal_amount(
                        fees[50],
                        s.retrieve_btc_min_amount,
                        s.check_fee,
                    );
                });
                Some(fees[50])
            } else {
                log!(
                    P0,
                    "[estimate_fee_per_vbyte]: not enough data points ({}) to compute the fee",
                    fees.len()
                );
                None
            }
        }
        Err(err) => {
            log!(
                P0,
                "[estimate_fee_per_vbyte]: failed to get median fee per vbyte: {}",
                err
            );
            None
        }
    }
}

/// Constructs and sends out signed Bitcoin transactions for pending retrieve
/// requests.
pub async fn submit_pending_requests() {
    // We make requests if we have old requests in the queue or if have enough
    // requests to fill a batch.
    if !state::read_state(|s| s.can_form_a_batch(MIN_PENDING_REQUESTS, ic_cdk::api::time())) {
        return;
    }

    let main_account = Account {
        owner: ic_cdk::id(),
        subaccount: None,
    };

    let ecdsa_public_key = updates::get_btc_address::init_ecdsa_public_key().await;
    let main_address = address::account_to_bitcoin_address(&ecdsa_public_key, &main_account);

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
                    "[submit_pending_requests]: dropping requests for total BTC amount {} to addresses {} (too low to cover the fees)",
                    tx::DisplayAmount(batch.iter().map(|req| req.amount).sum::<u64>()),
                    batch.iter().map(|req| req.address.display(s.btc_network)).collect::<Vec<_>>().join(",")
                );

                // There is no point in retrying the request because the
                // amount is too low.
                for request in batch {
                    state::audit::remove_retrieve_btc_request(s, request, &IC_CANISTER_RUNTIME);
                }
                None
            }
            Err(BuildTxError::DustOutput { address, amount }) => {
                log!(P0,
                    "[submit_pending_requests]: dropping a request for BTC amount {} to {} (too low to cover the fees)",
                     tx::DisplayAmount(amount), address.display(s.btc_network)
                );

                let mut requests_to_put_back = vec![];
                for request in batch {
                    if request.address == address && request.amount == amount {
                        // Finalize the request that we cannot fulfill.
                        state::audit::remove_retrieve_btc_request(s, request, &IC_CANISTER_RUNTIME);
                    } else {
                        // Keep the rest of the requests in the batch, we will
                        // try to build a new transaction on the next iteration.
                        requests_to_put_back.push(request);
                    }
                }

                s.push_from_in_flight_to_pending_requests(requests_to_put_back);

                None
            }
            Err(BuildTxError::NotEnoughFunds) => {
                log!(P0,
                    "[submit_pending_requests]: not enough funds to unsigned transaction for requests at block indexes [{}]",
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
            "[submit_pending_requests]: signing a new transaction: {}",
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
                    P0,
                    "[submit_pending_requests]: sending a signed transaction {}",
                    hex::encode(tx::encode_into(&signed_tx, Vec::new()))
                );
                match management::send_transaction(&signed_tx, req.network).await {
                    Ok(()) => {
                        log!(
                            P1,
                            "[submit_pending_requests]: successfully sent transaction {}",
                            &txid,
                        );

                        // Defuse the guard because we sent the transaction
                        // successfully.
                        let (requests, used_utxos) = ScopeGuard::into_inner(requests_guard);

                        state::mutate_state(|s| {
                            s.last_transaction_submission_time_ns = Some(ic_cdk::api::time());
                            state::audit::sent_transaction(
                                s,
                                state::SubmittedBtcTransaction {
                                    requests,
                                    txid,
                                    used_utxos,
                                    change_output: Some(req.change_output),
                                    submitted_at: ic_cdk::api::time(),
                                    fee_per_vbyte: Some(fee_millisatoshi_per_vbyte),
                                },
                                &IC_CANISTER_RUNTIME,
                            );
                        });
                    }
                    Err(err) => {
                        log!(
                            P0,
                            "[submit_pending_requests]: failed to send a Bitcoin transaction: {}",
                            err
                        );
                    }
                }
            }
            Err(err) => {
                log!(
                    P0,
                    "[submit_pending_requests]: failed to sign a Bitcoin transaction: {}",
                    err
                );
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

/// Returns identifiers of finalized transactions from the list of `candidates` according to the
/// list of newly received UTXOs for the main minter account.
fn finalized_txids(candidates: &[state::SubmittedBtcTransaction], new_utxos: &[Utxo]) -> Vec<Txid> {
    candidates
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
}

pub async fn finalize_requests() {
    if state::read_state(|s| s.submitted_transactions.is_empty()) {
        panic!("no submitted txs");
        return;
    }

    let ecdsa_public_key = updates::get_btc_address::init_ecdsa_public_key().await;
    let now = ic_cdk::api::time();

    // The list of transactions that are likely to be finalized, indexed by the transaction id.
    let mut maybe_finalized_transactions: BTreeMap<Txid, state::SubmittedBtcTransaction> =
        state::read_state(|s| {
            let wait_time = finalization_time_estimate(s.min_confirmations, s.btc_network);
            s.submitted_transactions
                .iter()
                .filter(|&req| (req.submitted_at + (wait_time.as_nanos() as u64) < now))
                .map(|req| (req.txid, req.clone()))
                .collect()
        });

    if maybe_finalized_transactions.is_empty() {
        return;
    }

    let main_account = Account {
        owner: ic_cdk::id(),
        subaccount: None,
    };

    let main_address = address::account_to_bitcoin_address(&ecdsa_public_key, &main_account);
    let new_utxos = fetch_main_utxos(&main_account, &main_address, &IC_CANISTER_RUNTIME).await;

    // Transactions whose change outpoint is present in the newly fetched UTXOs
    // can be finalized. Note that all new minter transactions must have a
    // change output because minter always charges a fee for converting tokens.
    //Complexity |submitted_transactions| x |new_utxos|
    let confirmed_transactions: Vec<_> =
        state::read_state(|s| finalized_txids(&s.submitted_transactions, &new_utxos));

    // It's possible that some transactions we considered lost or rejected became finalized in the
    // meantime. If that happens, we should stop waiting for replacement transactions to finalize.
    //Complexity |stuck_transactions| x |new_utxos|
    let unstuck_transactions: Vec<_> =
        state::read_state(|s| finalized_txids(&s.stuck_transactions, &new_utxos));

    state::mutate_state(|s| {
        if !new_utxos.is_empty() {
            state::audit::add_utxos(s, None, main_account, new_utxos, &IC_CANISTER_RUNTIME);
        }
        for txid in &confirmed_transactions {
            state::audit::confirm_transaction(s, txid, &IC_CANISTER_RUNTIME);
            maybe_finalized_transactions.remove(txid);
        }
    });

    for txid in &unstuck_transactions {
        state::read_state(|s| {
            // linear in |replacement_txid|
            if let Some(replacement_txid) = s.find_last_replacement_tx(txid) {
                maybe_finalized_transactions.remove(replacement_txid);
            }
        });
    }

    state::mutate_state(|s| {
        for txid in unstuck_transactions {
            log!(
                P0,
                "[finalize_requests]: finalized transaction {} assumed to be stuck",
                &txid
            );
            state::audit::confirm_transaction(s, &txid, &IC_CANISTER_RUNTIME);
        }
    });

    // Do not replace transactions if less than MIN_RESUBMISSION_DELAY passed since their
    // submission. This strategy works around short-term fee spikes.
    maybe_finalized_transactions
        .retain(|_txid, tx| tx.submitted_at + MIN_RESUBMISSION_DELAY.as_nanos() as u64 <= now);

    if maybe_finalized_transactions.is_empty() {
        // There are no transactions eligible for replacement.
        return;
    }

    let btc_network = state::read_state(|s| s.btc_network);

    // There are transactions that should have been finalized by now. Let's check whether the
    // Bitcoin network knows about them or they got lost in the meantime. Note that the Bitcoin
    // canister doesn't have access to the mempool, we can detect only transactions with at least
    // one confirmation.
    let main_utxos_zero_confirmations = match management::get_utxos(
        btc_network,
        &main_address.display(btc_network),
        /*min_confirmations=*/ 0,
        management::CallSource::Minter,
        &IC_CANISTER_RUNTIME,
    )
    .await
    {
        Ok(response) => response.utxos,
        Err(e) => {
            log!(
                P0,
                "[finalize_requests]: failed to fetch UTXOs for the main address {}: {}",
                main_address.display(btc_network),
                e
            );
            return;
        }
    };

    for utxo in main_utxos_zero_confirmations {
        // This transaction got at least one confirmation, we don't need to replace it.
        maybe_finalized_transactions.remove(&utxo.outpoint.txid);
    }

    if maybe_finalized_transactions.is_empty() {
        // All transactions we assumed to be stuck have at least one confirmation.
        // We shall finalize these transaction later.
        return;
    }

    // Found transactions that appear to be stuck: they might be sitting in the mempool, got
    // evicted from the mempool, or never reached it due to a temporary issue in the Bitcoin
    // integration.
    //
    // Let's resubmit these transactions.
    log!(
        P0,
        "[finalize_requests]: found {} stuck transactions: {}",
        maybe_finalized_transactions.len(),
        maybe_finalized_transactions
            .keys()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );

    // We shall use the latest fee estimate for replacement transactions.
    let fee_per_vbyte = match estimate_fee_per_vbyte().await {
        Some(fee) => fee,
        None => return,
    };

    let key_name = state::read_state(|s| s.ecdsa_key_name.clone());

    for (old_txid, submitted_tx) in maybe_finalized_transactions {
        let mut utxos: BTreeSet<_> = submitted_tx.used_utxos.iter().cloned().collect();

        let tx_fee_per_vbyte = match submitted_tx.fee_per_vbyte {
            Some(prev_fee) => {
                // Ensure that the fee is at least min relay fee higher than the previous
                // transaction fee to comply with BIP-125 (https://en.bitcoin.it/wiki/BIP_0125).
                fee_per_vbyte.max(prev_fee + MIN_RELAY_FEE_PER_VBYTE)
            }
            None => fee_per_vbyte,
        };

        let outputs = submitted_tx
            .requests
            .iter()
            .map(|req| (req.address.clone(), req.amount))
            .collect();

        let (unsigned_tx, change_output, used_utxos) = match build_unsigned_transaction(
            &mut utxos,
            outputs,
            main_address.clone(),
            tx_fee_per_vbyte,
        ) {
            Ok(tx) => tx,
            // If it's impossible to build a new transaction, the fees probably became too high.
            // Let's ignore this transaction and wait for fees to go down.
            Err(err) => {
                log!(
                    P1,
                    "[finalize_requests]: failed to rebuild stuck transaction {}: {:?}",
                    &submitted_tx.txid,
                    err
                );
                continue;
            }
        };

        let outpoint_account = state::read_state(|s| filter_output_accounts(s, &unsigned_tx));

        assert!(
            utxos.is_empty(),
            "build_unsigned_transaction didn't use all inputs"
        );
        assert_eq!(used_utxos.len(), submitted_tx.used_utxos.len());

        let new_txid = unsigned_tx.txid();

        let maybe_signed_tx = sign_transaction(
            key_name.clone(),
            &ecdsa_public_key,
            &outpoint_account,
            unsigned_tx,
        )
        .await;

        let signed_tx = match maybe_signed_tx {
            Ok(tx) => tx,
            Err(err) => {
                log!(
                    P0,
                    "[finalize_requests]: failed to sign a BTC transaction: {}",
                    err
                );
                continue;
            }
        };

        match management::send_transaction(&signed_tx, btc_network).await {
            Ok(()) => {
                if old_txid == new_txid {
                    // DEFENSIVE: We should never take this branch because we increase fees for
                    // replacement transactions with each resubmission. However, since replacing a
                    // transaction with itself is not allowed, we still handle the transaction
                    // equality in case the fee computation rules change in the future.
                    log!(P0,
                        "[finalize_requests]: resent transaction {} with a new signature. TX bytes: {}",
                        &new_txid,
                        hex::encode(tx::encode_into(&signed_tx, Vec::new()))
                    );
                    continue;
                }
                log!(P0,
                    "[finalize_requests]: sent transaction {} to replace stuck transaction {}. TX bytes: {}",
                    &new_txid,
                    &old_txid,
                    hex::encode(tx::encode_into(&signed_tx, Vec::new()))
                );
                let new_tx = state::SubmittedBtcTransaction {
                    requests: submitted_tx.requests,
                    used_utxos,
                    txid: new_txid,
                    submitted_at: ic_cdk::api::time(),
                    change_output: Some(change_output),
                    fee_per_vbyte: Some(tx_fee_per_vbyte),
                };

                state::mutate_state(|s| {
                    state::audit::replace_transaction(s, old_txid, new_tx, &IC_CANISTER_RUNTIME);
                });
            }
            Err(err) => {
                log!(P0, "[finalize_requests]: failed to send transaction bytes {} to replace stuck transaction {}: {}",
                    hex::encode(tx::encode_into(&signed_tx, Vec::new())),
                    &old_txid,
                    err,
                );
                continue;
            }
        }
    }
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
                *state
                    .outpoint_account
                    .get(&input.previous_output)
                    .unwrap_or_else(|| {
                        panic!(
                            "bug: missing account for output point {:?}",
                            input.previous_output
                        )
                    }),
            )
        })
        .collect()
}

/// The algorithm greedily selects the smallest UTXO(s) with a value that is at least the given `target` in a first step.
///
/// If the minter manages more than [UTXOS_COUNT_THRESHOLD], it will then try to match the number of inputs with the
/// number of outputs + 1 (where the additional output corresponds to the change output).
///
/// If there are no UTXOs matching the criteria, returns an empty vector.
///
/// PROPERTY: sum(u.value for u in available_set) ≥ target ⇒ !solution.is_empty()
/// POSTCONDITION: !solution.is_empty() ⇒ sum(u.value for u in solution) ≥ target
/// POSTCONDITION:  solution.is_empty() ⇒ available_utxos did not change.
fn utxos_selection(
    target: u64,
    available_utxos: &mut BTreeSet<Utxo>,
    output_count: usize,
) -> Vec<Utxo> {
    let mut input_utxos = greedy(target, available_utxos);

    if input_utxos.is_empty() {
        return vec![];
    }

    if available_utxos.len() > UTXOS_COUNT_THRESHOLD {
        while input_utxos.len() < output_count + 1 {
            if let Some(min_utxo) = available_utxos.iter().min_by_key(|u| u.value) {
                input_utxos.push(min_utxo.clone());
                assert!(available_utxos.remove(&min_utxo.clone()));
            } else {
                break;
            }
        }
    }

    input_utxos
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
) -> Result<tx::SignedTransaction, CallError> {
    use crate::address::{derivation_path, derive_public_key};

    let mut signed_inputs = Vec::with_capacity(unsigned_tx.inputs.len());
    let sighasher = tx::TxSigHasher::new(&unsigned_tx);
    for input in &unsigned_tx.inputs {
        let outpoint = &input.previous_output;

        let account = output_account
            .get(outpoint)
            .unwrap_or_else(|| panic!("bug: no account for outpoint {:?}", outpoint));

        let path = derivation_path(account);
        let pubkey = ByteBuf::from(derive_public_key(ecdsa_public_key, account).public_key);
        let pkhash = tx::hash160(&pubkey);

        let sighash = sighasher.sighash(input, &pkhash);

        let sec1_signature = management::sign_with_ecdsa(
            key_name.clone(),
            DerivationPath::new(path),
            sighash,
            &IC_CANISTER_RUNTIME,
        )
        .await?;

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

#[derive(Eq, PartialEq, Debug)]
pub enum BuildTxError {
    /// The minter does not have enough UTXOs to make the transfer
    /// Try again later after pending transactions have settled.
    NotEnoughFunds,
    /// The withdrawal amount is too low to pay the transfer fee.
    AmountTooLow,
    /// Withdrawal amount of at least one request is too low to cover its share
    /// of the fees. Similar to `AmountTooLow`, but applies to a single
    /// request in a batch.
    DustOutput {
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

    let input_utxos = utxos_selection(amount, minter_utxos, outputs.len());

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

    let minter_fee = evaluate_minter_fee(utxos_guard.len() as u64, (outputs.len() + 1) as u64);

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
    // The default dustRelayFee is 3 sat/vB,
    // which translates to a dust threshold of 546 satoshi for P2PKH outputs.
    // The threshold for other types is lower,
    // so we simply use 546 satoshi as the minimum amount per output.
    const MIN_OUTPUT_AMOUNT: u64 = 546;

    for (output, fee_share) in unsigned_tx.outputs.iter_mut().zip(fee_shares.iter()) {
        if output.address != main_address {
            if output.value <= *fee_share + MIN_OUTPUT_AMOUNT {
                return Err(BuildTxError::DustOutput {
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

pub fn evaluate_minter_fee(num_inputs: u64, num_outputs: u64) -> Satoshi {
    max(
        MINTER_FEE_PER_INPUT * num_inputs
            + MINTER_FEE_PER_OUTPUT * num_outputs
            + MINTER_FEE_CONSTANT,
        MINTER_ADDRESS_DUST_LIMIT,
    )
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

pub fn timer<R: CanisterRuntime + 'static>(runtime: R) {
    use tasks::{pop_if_ready, run_task};

    if let Some(task) = pop_if_ready(&runtime) {
        ic_cdk::spawn(run_task(task, runtime));
    }
}

/// Computes an estimate for the size of transaction (in vbytes) with the given number of inputs and outputs.
pub fn tx_vsize_estimate(input_count: u64, output_count: u64) -> u64 {
    // See
    // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    // for the transaction structure and
    // https://bitcoin.stackexchange.com/questions/92587/calculate-transaction-fee-for-external-addresses-which-doesnt-belong-to-my-loca/92600#92600
    // for transaction size estimate.
    const INPUT_SIZE_VBYTES: u64 = 68;
    const OUTPUT_SIZE_VBYTES: u64 = 31;
    const TX_OVERHEAD_VBYTES: u64 = 11;

    input_count * INPUT_SIZE_VBYTES + output_count * OUTPUT_SIZE_VBYTES + TX_OVERHEAD_VBYTES
}

/// Computes an estimate for the retrieve_btc fee.
///
/// Arguments:
///   * `available_utxos` - the list of UTXOs available to the minter.
///   * `maybe_amount` - the withdrawal amount.
///   * `median_fee_millisatoshi_per_vbyte` - the median network fee, in millisatoshi per vbyte.
pub fn estimate_retrieve_btc_fee(
    available_utxos: &BTreeSet<Utxo>,
    maybe_amount: Option<u64>,
    median_fee_millisatoshi_per_vbyte: u64,
) -> WithdrawalFee {
    const DEFAULT_INPUT_COUNT: u64 = 2;
    // One output for the caller and one for the change.
    const DEFAULT_OUTPUT_COUNT: u64 = 2;
    let input_count = match maybe_amount {
        Some(amount) => {
            // We simulate the algorithm that selects UTXOs for the
            // specified amount. If the withdrawal rate is low, we
            // should get the exact number of inputs that the minter
            // will use.
            let mut utxos = available_utxos.clone();
            let selected_utxos =
                utxos_selection(amount, &mut utxos, DEFAULT_OUTPUT_COUNT as usize - 1);

            if !selected_utxos.is_empty() {
                selected_utxos.len() as u64
            } else {
                DEFAULT_INPUT_COUNT
            }
        }
        None => DEFAULT_INPUT_COUNT,
    };

    let vsize = tx_vsize_estimate(input_count, DEFAULT_OUTPUT_COUNT);
    let minter_fee = evaluate_minter_fee(input_count, DEFAULT_OUTPUT_COUNT);
    // We subtract one from the outputs because the minter's output
    // does not participate in fees distribution.
    let bitcoin_fee =
        vsize * median_fee_millisatoshi_per_vbyte / 1000 / (DEFAULT_OUTPUT_COUNT - 1).max(1);
    let minter_fee = minter_fee / (DEFAULT_OUTPUT_COUNT - 1).max(1);
    WithdrawalFee {
        minter_fee,
        bitcoin_fee,
    }
}

#[async_trait]
pub trait CanisterRuntime {
    /// Returns the caller of the current call.
    fn caller(&self) -> Principal;

    /// Returns the canister id
    fn id(&self) -> Principal;

    /// Gets current timestamp, in nanoseconds since the epoch (1970-01-01)
    fn time(&self) -> u64;

    /// Set a global timer to make the system schedule a call to the exported `canister_global_timer` Wasm method after the specified time.
    /// The time must be provided as nanoseconds since 1970-01-01.
    /// See the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#global-timer-1).
    fn global_timer_set(&self, timestamp: u64);

    /// Fetches all unspent transaction outputs (UTXOs) associated with the provided address in the specified Bitcoin network.
    async fn bitcoin_get_utxos(
        &self,
        request: GetUtxosRequest,
    ) -> Result<GetUtxosResponse, CallError>;

    async fn check_transaction(
        &self,
        btc_checker_principal: Principal,
        utxo: &Utxo,
        cycle_payment: u128,
    ) -> Result<CheckTransactionResponse, CallError>;

    async fn mint_ckbtc(
        &self,
        amount: u64,
        to: Account,
        memo: Memo,
    ) -> Result<u64, UpdateBalanceError>;

    async fn sign_with_ecdsa(
        &self,
        key_name: String,
        derivation_path: DerivationPath,
        message_hash: [u8; 32],
    ) -> Result<Vec<u8>, CallError>;
}

#[derive(Copy, Clone)]
pub struct IcCanisterRuntime {}

#[async_trait]
impl CanisterRuntime for IcCanisterRuntime {
    fn caller(&self) -> Principal {
        ic_cdk::caller()
    }

    fn id(&self) -> Principal {
        ic_cdk::id()
    }

    fn time(&self) -> u64 {
        ic_cdk::api::time()
    }

    fn global_timer_set(&self, timestamp: u64) {
        ic_cdk::api::set_global_timer(timestamp);
    }

    async fn bitcoin_get_utxos(
        &self,
        request: GetUtxosRequest,
    ) -> Result<GetUtxosResponse, CallError> {
        management::bitcoin_get_utxos(request).await
    }

    async fn check_transaction(
        &self,
        btc_checker_principal: Principal,
        utxo: &Utxo,
        cycle_payment: u128,
    ) -> Result<CheckTransactionResponse, CallError> {
        management::check_transaction(btc_checker_principal, utxo, cycle_payment).await
    }

    async fn mint_ckbtc(
        &self,
        amount: u64,
        to: Account,
        memo: Memo,
    ) -> Result<u64, UpdateBalanceError> {
        updates::update_balance::mint(amount, to, memo).await
    }

    async fn sign_with_ecdsa(
        &self,
        key_name: String,
        derivation_path: DerivationPath,
        message_hash: [u8; 32],
    ) -> Result<Vec<u8>, CallError> {
        use ic_cdk::api::management_canister::ecdsa::{
            EcdsaCurve, EcdsaKeyId, SignWithEcdsaArgument,
        };

        ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa(SignWithEcdsaArgument {
            message_hash: message_hash.to_vec(),
            derivation_path: derivation_path.into_inner(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name.clone(),
            },
        })
        .await
        .map(|(result,)| result.signature)
        .map_err(|err| CallError::from_cdk_error("sign_with_ecdsa", err))
    }
}

/// Time in nanoseconds since the epoch (1970-01-01).
#[derive(
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Debug,
    Default,
    Serialize,
    CandidType,
    serde::Deserialize,
)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn new(ns_since_epoch: u64) -> Self {
        Self(ns_since_epoch)
    }

    /// Number of nanoseconds since `UNIX EPOCH`.
    pub fn as_nanos_since_unix_epoch(self) -> u64 {
        self.0
    }

    pub fn checked_sub(self, rhs: Duration) -> Option<Timestamp> {
        if let Ok(rhs_nanos) = u64::try_from(rhs.as_nanos()) {
            Some(Timestamp(self.0.checked_sub(rhs_nanos)?))
        } else {
            None
        }
    }

    pub fn checked_duration_since(self, rhs: Timestamp) -> Option<Duration> {
        self.0.checked_sub(rhs.0).map(Duration::from_nanos)
    }

    pub fn checked_add(self, rhs: Duration) -> Option<Timestamp> {
        if let Ok(rhs_nanos) = u64::try_from(rhs.as_nanos()) {
            Some(Self(self.0.checked_add(rhs_nanos)?))
        } else {
            None
        }
    }

    pub fn saturating_add(self, rhs: Duration) -> Self {
        self.checked_add(rhs).unwrap_or(Timestamp(u64::MAX))
    }
}

impl From<u64> for Timestamp {
    fn from(timestamp: u64) -> Self {
        Self(timestamp)
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
struct Timestamped<Inner> {
    timestamp: Timestamp,
    inner: Option<Inner>,
}

impl<Inner> Timestamped<Inner> {
    fn new<T: Into<Timestamp>>(timestamp: T, inner: Inner) -> Self {
        Self {
            timestamp: timestamp.into(),
            inner: Some(inner),
        }
    }
}

/// A cache that expires older entries upon insertion.
///
/// More specifically, entries are inserted with a timestamp, and
/// then all existing entries with a timestamp less than `t - expiration` are removed before
/// the new entry is inserted.
///
/// Similarly, lookups will also take an additional timestamp as argument, and only entries
/// newer than that will be returned.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CacheWithExpiration<Key, Value> {
    expiration: Duration,
    keys: BTreeMap<Key, Timestamp>,
    values: BTreeMap<Timestamped<Key>, Value>,
}

impl<Key: Ord + Clone, Value: Clone> CacheWithExpiration<Key, Value> {
    pub fn new(expiration: Duration) -> Self {
        Self {
            expiration,
            keys: Default::default(),
            values: Default::default(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        let len = self.keys.len();
        assert_eq!(len, self.values.len());
        len
    }

    pub fn set_expiration(&mut self, expiration: Duration) {
        self.expiration = expiration;
    }

    pub fn prune<T: Into<Timestamp>>(&mut self, now: T) {
        let timestamp = now.into();
        if let Some(expire_cutoff) = timestamp.checked_sub(self.expiration) {
            let pivot = Timestamped {
                timestamp: expire_cutoff,
                inner: None,
            };
            let mut non_expired = self.values.split_off(&pivot);
            self.values.keys().for_each(|key| {
                self.keys.remove(key.inner.as_ref().unwrap());
            });
            std::mem::swap(&mut self.values, &mut non_expired);
            assert_eq!(self.keys.len(), self.values.len())
        }
    }

    fn insert_without_prune<T: Into<Timestamp>>(&mut self, key: Key, value: Value, now: T) {
        let timestamp = now.into();
        if let Some(old_timestamp) = self.keys.insert(key.clone(), timestamp) {
            self.values
                .remove(&Timestamped::new(old_timestamp, key.clone()));
        }
        self.values.insert(Timestamped::new(timestamp, key), value);
    }

    pub fn insert<T: Into<Timestamp>>(&mut self, key: Key, value: Value, now: T) {
        let timestamp = now.into();
        self.prune(timestamp);
        self.insert_without_prune(key, value, timestamp);
    }

    pub fn get<T: Into<Timestamp>>(&self, key: &Key, now: T) -> Option<&Value> {
        let now = now.into();
        let timestamp = *self.keys.get(key)?;
        if let Some(expire_cutoff) = now.checked_sub(self.expiration) {
            if timestamp < expire_cutoff {
                return None;
            }
        }
        self.values.get(&Timestamped {
            timestamp,
            inner: Some(key.clone()),
        })
    }
}

pub type GetUtxosCache = CacheWithExpiration<bitcoin::GetUtxosRequest, GetUtxosResponse>;
