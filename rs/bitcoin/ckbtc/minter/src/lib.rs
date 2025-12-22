use crate::address::BitcoinAddress;
use crate::logs::Priority;
use crate::management::CallError;
use crate::queries::WithdrawalFee;
use crate::reimbursement::{InvalidTransactionError, WithdrawalReimbursementReason};
use crate::updates::update_balance::UpdateBalanceError;
use async_trait::async_trait;
use candid::{CandidType, Deserialize, Principal};
use canlog::log;
use ic_cdk::bitcoin_canister;
use ic_cdk::management_canister::SignWithEcdsaArgs;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::Memo;
use scopeguard::{ScopeGuard, guard};
use serde::Serialize;
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::fees::{BitcoinFeeEstimator, FeeEstimator};
use crate::state::eventlog::{CkBtcEventLogger, EventLogger};
use crate::state::utxos::UtxoSet;
use crate::state::{CkBtcMinterState, mutate_state, read_state};
use crate::tx::TransactionVersion;
use crate::updates::get_btc_address;
use crate::updates::retrieve_btc::BtcAddressCheckStatus;
pub use ic_btc_checker::CheckTransactionResponse;
use ic_btc_checker::{CheckAddressArgs, CheckAddressResponse};
pub use ic_btc_interface::{MillisatoshiPerByte, OutPoint, Page, Satoshi, Txid, Utxo};

pub mod address;
pub mod dashboard;
pub mod fees;
pub mod guard;
pub mod lifecycle;
pub mod logs;
pub mod management;
pub mod memo;
pub mod metrics;
pub mod queries;
pub mod reimbursement;
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

/// The minimum number of pending request in the queue before we try to make
/// a batch transaction.
pub const MIN_PENDING_REQUESTS: usize = 20;
pub const MAX_REQUESTS_PER_BATCH: usize = 100;

/// The minimum time the minter should wait before replacing a stuck transaction.
pub const MIN_RESUBMISSION_DELAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum interval between UTXO consolidations.
pub const MIN_CONSOLIDATION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The maximum memo size of a transaction on the ckBTC ledger.
/// The ckBTC minter requires at least 69 bytes, we choose 80
/// to have some room for future modifications.
pub const CKBTC_LEDGER_MEMO_SIZE: u16 = 80;

/// The threshold for the number of UTXOs under management before
/// trying to match the number of outputs with the number of inputs
/// when building transactions.
pub const UTXOS_COUNT_THRESHOLD: usize = 1_000;

/// Fee collector subaccount
pub const FEE_COLLECTOR_SUBACCOUNT: Subaccount = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f,
    0xee,
];

pub const IC_CANISTER_RUNTIME: IcCanisterRuntime = IcCanisterRuntime {};

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

pub type GetUtxosRequest = bitcoin_canister::GetUtxosRequest;
pub type GetCurrentFeePercentilesRequest = bitcoin_canister::GetCurrentFeePercentilesRequest;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct GetUtxosResponse {
    pub utxos: Vec<Utxo>,
    pub tip_height: u32,
    pub next_page: Option<Page>,
}

impl From<bitcoin_canister::GetUtxosResponse> for GetUtxosResponse {
    fn from(response: bitcoin_canister::GetUtxosResponse) -> Self {
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

impl From<Network> for bitcoin_canister::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => bitcoin_canister::Network::Mainnet,
            Network::Testnet => bitcoin_canister::Network::Testnet,
            Network::Regtest => bitcoin_canister::Network::Regtest,
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
    requests: state::SubmittedWithdrawalRequests,
    utxos: Vec<Utxo>,
}

/// Undoes changes we make to the ckBTC state when we construct a pending transaction.
/// We call this function if we fail to sign or send a Bitcoin transaction.
fn undo_withdrawal_request(requests: state::SubmittedWithdrawalRequests, utxos: Vec<Utxo>) {
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
    main_address: &String,
    runtime: &R,
) -> Vec<Utxo> {
    let (btc_network, min_confirmations) =
        state::read_state(|s| (s.btc_network, s.min_confirmations));

    let utxos = match management::get_utxos(
        btc_network,
        main_address,
        min_confirmations,
        management::CallSource::Minter,
        runtime,
    )
    .await
    {
        Ok(response) => response.utxos,
        Err(e) => {
            log!(
                Priority::Info,
                "[fetch_main_utxos]: failed to fetch UTXOs for the main address {main_address}: {e}",
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

/// Returns an estimate for transaction fees in millisatoshi per vbyte. Returns
/// None if the Bitcoin canister is unavailable or does not have enough data for
/// an estimate yet.
pub async fn estimate_fee_per_vbyte<R: CanisterRuntime>(
    runtime: &R,
) -> Option<MillisatoshiPerByte> {
    let btc_network = state::read_state(|s| s.btc_network);
    match runtime
        .get_current_fee_percentiles(&bitcoin_canister::GetCurrentFeePercentilesRequest {
            network: btc_network.into(),
        })
        .await
    {
        Ok(fees) => {
            let fee_estimator = state::read_state(|s| runtime.fee_estimator(s));
            match fee_estimator.estimate_median_fee(&fees) {
                Some(median_fee) => {
                    let fee_based_retrieve_btc_min_amount =
                        fee_estimator.fee_based_minimum_withdrawal_amount(median_fee);
                    log!(
                        Priority::Debug,
                        "[estimate_fee_per_vbyte]: update median fee per vbyte to {median_fee} and fee-based minimum retrieve amount to {fee_based_retrieve_btc_min_amount} with {fees:?}"
                    );
                    mutate_state(|s| {
                        s.last_fee_per_vbyte = fees;
                        s.last_median_fee_per_vbyte = Some(median_fee);
                        s.fee_based_retrieve_btc_min_amount = fee_based_retrieve_btc_min_amount;
                    });
                    Some(median_fee)
                }
                None => None,
            }
        }
        Err(err) => {
            log!(
                Priority::Info,
                "[estimate_fee_per_vbyte]: failed to get median fee per vbyte: {}",
                err
            );
            None
        }
    }
}

fn reimburse_canceled_requests<R: CanisterRuntime>(
    state: &mut state::CkBtcMinterState,
    requests: BTreeSet<state::RetrieveBtcRequest>,
    reason: WithdrawalReimbursementReason,
    total_fee: u64,
    runtime: &R,
) {
    assert!(!requests.is_empty());
    let fees = distribute(total_fee, requests.len() as u64);
    // This assertion makes sure the fee is smaller than each request amount
    assert!(
        fees[0] <= state.retrieve_btc_min_amount,
        "BUG: fees {fees:?} for {} withdrawal requests are larger than `retrieve_btc_min_amount` {}",
        requests.len(),
        state.retrieve_btc_min_amount
    );
    for (request, fee) in requests.into_iter().zip(fees.into_iter()) {
        if let Some(account) = request.reimbursement_account {
            let amount = request.amount.saturating_sub(fee);
            if amount > 0 {
                state::audit::reimburse_withdrawal(
                    state,
                    request.block_index,
                    amount,
                    account,
                    reason.clone(),
                    runtime,
                );
            }
        } else {
            log!(
                Priority::Info,
                "[reimburse_canceled_requests]: account is not found for retrieve_btc request ({:?})",
                request
            );
        }
    }
}

pub fn confirm_transaction<R: CanisterRuntime>(
    state: &mut state::CkBtcMinterState,
    txid: &Txid,
    runtime: &R,
) {
    if let Some(state::WithdrawalCancellation {
        reason,
        requests,
        fee,
    }) = state::audit::confirm_transaction(state, txid, runtime)
    {
        reimburse_canceled_requests(state, requests, reason, fee, runtime)
    }
}

/// Constructs and sends out signed Bitcoin transactions for pending retrieve
/// requests.
async fn submit_pending_requests<R: CanisterRuntime>(runtime: &R) {
    // We make requests if we have old requests in the queue or if have enough
    // requests to fill a batch.
    if !state::read_state(|s| s.can_form_a_batch(MIN_PENDING_REQUESTS, runtime.time())) {
        return;
    }

    let ecdsa_public_key = updates::get_btc_address::init_ecdsa_public_key().await;
    let main_address = state::read_state(|s| runtime.derive_minter_address(s));

    let fee_millisatoshi_per_vbyte = match estimate_fee_per_vbyte(runtime).await {
        Some(fee) => fee,
        None => return,
    };
    let fee_estimator = read_state(|s| runtime.fee_estimator(s));
    let max_num_inputs_in_transaction = read_state(|s| s.max_num_inputs_in_transaction);

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
            &main_address,
            max_num_inputs_in_transaction,
            fee_millisatoshi_per_vbyte,
            runtime.transaction_version(),
            &fee_estimator,
        ) {
            Ok((unsigned_tx, change_output, total_fee, utxos)) => Some((
                SignTxRequest {
                    key_name: s.ecdsa_key_name.clone(),
                    ecdsa_public_key,
                    change_output,
                    network: s.btc_network,
                    unsigned_tx,
                    requests: state::SubmittedWithdrawalRequests::ToConfirm {
                        requests: batch.into_iter().collect(),
                    },
                    utxos,
                },
                total_fee,
            )),
            Err(BuildTxError::InvalidTransaction(err)) => {
                log!(
                    Priority::Info,
                    "[submit_pending_requests]: error in building transaction ({:?})",
                    err
                );
                let reason = reimbursement::WithdrawalReimbursementReason::InvalidTransaction(err);
                let reimbursement_fee = fee_estimator
                    .reimbursement_fee_for_pending_withdrawal_requests(batch.len() as u64);
                reimburse_canceled_requests(s, batch, reason, reimbursement_fee, runtime);
                None
            }
            Err(BuildTxError::AmountTooLow) => {
                log!(
                    Priority::Info,
                    "[submit_pending_requests]: dropping requests for total BTC amount {} to addresses {} (too low to cover the fees)",
                    tx::DisplayAmount(batch.iter().map(|req| req.amount).sum::<u64>()),
                    batch
                        .iter()
                        .map(|req| req.address.display(s.btc_network))
                        .collect::<Vec<_>>()
                        .join(",")
                );

                // There is no point in retrying the request because the
                // amount is too low.
                for request in batch {
                    state::audit::remove_retrieve_btc_request(
                        s,
                        request,
                        state::FinalizedStatus::AmountTooLow,
                        runtime,
                    );
                }
                None
            }
            Err(BuildTxError::DustOutput { address, amount }) => {
                log!(
                    Priority::Info,
                    "[submit_pending_requests]: dropping a request for BTC amount {} to {} (too low to cover the fees)",
                    tx::DisplayAmount(amount),
                    address.display(s.btc_network)
                );

                let mut requests_to_put_back = BTreeSet::new();
                for request in batch {
                    if request.address == address && request.amount == amount {
                        // Finalize the request that we cannot fulfill.
                        state::audit::remove_retrieve_btc_request(
                            s,
                            request,
                            state::FinalizedStatus::AmountTooLow,
                            runtime,
                        );
                    } else {
                        // Keep the rest of the requests in the batch, we will
                        // try to build a new transaction on the next iteration.
                        requests_to_put_back.insert(request);
                    }
                }

                s.push_from_in_flight_to_pending_requests(
                    state::SubmittedWithdrawalRequests::ToConfirm {
                        requests: requests_to_put_back,
                    },
                );

                None
            }
            Err(BuildTxError::NotEnoughFunds) => {
                log!(
                    Priority::Info,
                    "[submit_pending_requests]: not enough funds to unsigned transaction for requests at block indexes [{}]",
                    batch
                        .iter()
                        .map(|req| req.block_index.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );

                s.push_from_in_flight_to_pending_requests(
                    state::SubmittedWithdrawalRequests::ToConfirm {
                        requests: batch.into_iter().collect(),
                    },
                );
                None
            }
        }
    });
    if let Some((req, total_fee)) = maybe_sign_request {
        let _ = sign_and_submit_request(req, fee_millisatoshi_per_vbyte, total_fee, runtime).await;
    }
}

async fn sign_and_submit_request<R: CanisterRuntime>(
    req: SignTxRequest,
    fee_millisatoshi_per_vbyte: u64,
    total_fee: WithdrawalFee,
    runtime: &R,
) -> Result<Txid, CallError> {
    log!(
        Priority::Debug,
        "[submit_pending_requests]: signing a new transaction: {}",
        hex::encode(tx::encode_into(&req.unsigned_tx, Vec::new()))
    );

    state::mutate_state(|s| {
        for block_index in req.requests.iter_block_index() {
            s.push_in_flight_request(block_index, state::InFlightStatus::Signing);
        }
    });

    // This guard ensures that we return pending requests and UTXOs back to
    // the state if the signing or sending of a transaction fails or panics.
    let requests_guard = guard((req.requests, req.utxos), |(reqs, utxos)| {
        undo_withdrawal_request(reqs, utxos);
    });

    let signed_tx = sign_transaction(
        req.key_name,
        &req.ecdsa_public_key,
        |outpoint| state::read_state(|s| s.outpoint_account.get(outpoint).cloned()),
        req.unsigned_tx,
        runtime,
    )
    .await
    .inspect_err(|err| {
        log!(
            Priority::Info,
            "[sign_and_submit_request]: failed to sign a Bitcoin transaction: {}",
            err
        );
    })?;
    let txid = signed_tx.compute_txid();

    state::mutate_state(|s| {
        for block_index in requests_guard.0.iter_block_index() {
            s.push_in_flight_request(block_index, state::InFlightStatus::Sending { txid });
        }
    });

    log!(
        Priority::Info,
        "[sign_and_submit_request]: sending a signed transaction {}",
        hex::encode(tx::encode_into(&signed_tx, Vec::new()))
    );
    runtime
        .send_transaction(&signed_tx, req.network)
        .await
        .inspect_err(|err| {
            log!(
                Priority::Info,
                "[sign_and_submit_request]: failed to send a Bitcoin transaction: {}",
                err
            );
        })?;
    log!(
        Priority::Debug,
        "[sign_and_submit_request]: successfully sent transaction {}",
        &txid,
    );

    // Defuse the guard because we sent the transaction
    // successfully.
    let (requests, used_utxos) = ScopeGuard::into_inner(requests_guard);

    // Only fill signed_tx when it is a consolidation transaction.
    let signed_tx = match requests {
        state::SubmittedWithdrawalRequests::ToConsolidate { .. } => Some(signed_tx.serialize()),
        _ => None,
    };

    state::mutate_state(|s| {
        s.last_transaction_submission_time_ns = Some(runtime.time());
        state::audit::sent_transaction(
            s,
            state::SubmittedBtcTransaction {
                requests,
                txid,
                used_utxos,
                change_output: Some(req.change_output),
                submitted_at: runtime.time(),
                fee_per_vbyte: Some(fee_millisatoshi_per_vbyte),
                withdrawal_fee: Some(total_fee),
                signed_tx,
            },
            runtime,
        );
    });
    Ok(txid)
}

fn finalization_time_estimate<R: CanisterRuntime>(
    min_confirmations: u32,
    network: Network,
    runtime: &R,
) -> Duration {
    const ONE_SECOND: Duration = Duration::from_secs(1);

    let block_time = runtime.block_time(network);
    let estimated_block_time = match network {
        Network::Mainnet | Network::Testnet => block_time,
        // make things snappier for local testing
        Network::Regtest => block_time.min(ONE_SECOND),
    };
    min_confirmations * estimated_block_time
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

pub fn process_maybe_finalized_transactions<R: CanisterRuntime>(
    state: &mut state::CkBtcMinterState,
    maybe_finalized_transactions: &mut BTreeMap<Txid, state::SubmittedBtcTransaction>,
    new_utxos: Vec<Utxo>,
    main_account: Account,
    runtime: &R,
) {
    // Transactions whose change outpoint is present in the newly fetched UTXOs
    // can be finalized. Note that all new minter transactions must have a
    // change output because minter always charges a fee for converting tokens.
    let confirmed_transactions: Vec<_> = finalized_txids(&state.submitted_transactions, &new_utxos);

    // It's possible that some transactions we considered lost or rejected became finalized in the
    // meantime. If that happens, we should stop waiting for replacement transactions to finalize.
    let unstuck_transactions: Vec<_> = finalized_txids(&state.stuck_transactions, &new_utxos);

    if !new_utxos.is_empty() {
        state::audit::add_utxos(state, None, main_account, new_utxos, runtime);
    }
    for txid in &confirmed_transactions {
        confirm_transaction(state, txid, runtime);
        maybe_finalized_transactions.remove(txid);
    }

    for txid in &unstuck_transactions {
        if let Some(replacement_txid) = state.find_last_replacement_tx(txid) {
            maybe_finalized_transactions.remove(replacement_txid);
        }
    }

    for txid in unstuck_transactions {
        log!(
            Priority::Info,
            "[finalize_requests]: finalized transaction {} previously assumed to be stuck",
            &txid
        );
        confirm_transaction(state, &txid, runtime);
    }
}

async fn finalize_requests<R: CanisterRuntime>(runtime: &R) {
    if state::read_state(|s| s.submitted_transactions.is_empty()) {
        return;
    }

    let ecdsa_public_key = updates::get_btc_address::init_ecdsa_public_key().await;
    let now = runtime.time();

    // The list of transactions that are likely to be finalized, indexed by the transaction id.
    let mut maybe_finalized_transactions: BTreeMap<Txid, state::SubmittedBtcTransaction> =
        state::read_state(|s| {
            let wait_time = finalization_time_estimate(s.min_confirmations, s.btc_network, runtime);

            s.submitted_transactions
                .iter()
                .filter(|&req| req.submitted_at + (wait_time.as_nanos() as u64) < now)
                .map(|req| (req.txid, req.clone()))
                .collect()
        });

    if maybe_finalized_transactions.is_empty() {
        return;
    }

    let main_account = Account {
        owner: ic_cdk::api::canister_self(),
        subaccount: None,
    };

    let (main_address, main_address_str) = read_state(|s| {
        (
            runtime.derive_minter_address(s),
            runtime.derive_minter_address_str(s),
        )
    });
    let new_utxos = fetch_main_utxos(&main_account, &main_address_str, runtime).await;

    state::mutate_state(|state| {
        process_maybe_finalized_transactions(
            state,
            &mut maybe_finalized_transactions,
            new_utxos,
            main_account,
            runtime,
        )
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
        runtime,
    )
    .await
    {
        Ok(response) => response.utxos,
        Err(e) => {
            log!(
                Priority::Info,
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
        Priority::Info,
        "[finalize_requests]: found {} stuck transactions: {}",
        maybe_finalized_transactions.len(),
        maybe_finalized_transactions
            .keys()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );

    // We shall use the latest fee estimate for replacement transactions.
    let fee_per_vbyte = match estimate_fee_per_vbyte(runtime).await {
        Some(fee) => fee,
        None => return,
    };
    let key_name = state::read_state(|s| s.ecdsa_key_name.clone());
    let fee_estimator = state::read_state(|s| runtime.fee_estimator(s));
    resubmit_transactions(
        &key_name,
        fee_per_vbyte,
        main_address,
        ecdsa_public_key,
        btc_network,
        state::read_state(|s| s.retrieve_btc_min_amount),
        maybe_finalized_transactions,
        |outpoint| state::read_state(|s| s.outpoint_account.get(outpoint).cloned()),
        |old_txid, new_tx, reason| {
            state::mutate_state(|s| {
                state::audit::replace_transaction(s, old_txid, new_tx, reason, runtime);
            })
        },
        runtime,
        &fee_estimator,
    )
    .await
}

pub async fn resubmit_transactions<
    R: CanisterRuntime,
    F: Fn(&OutPoint) -> Option<Account>,
    G: Fn(Txid, state::SubmittedBtcTransaction, state::eventlog::ReplacedReason),
    Fee: FeeEstimator,
>(
    key_name: &str,
    fee_per_vbyte: u64,
    main_address: BitcoinAddress,
    ecdsa_public_key: ECDSAPublicKey,
    btc_network: Network,
    retrieve_btc_min_amount: u64,
    transactions: BTreeMap<Txid, state::SubmittedBtcTransaction>,
    lookup_outpoint_account: F,
    replace_transaction: G,
    runtime: &R,
    fee_estimator: &Fee,
) {
    for (old_txid, submitted_tx) in transactions {
        // ConsolidateUtxosRequest is directly re-sent if it already has signed_tx.
        if let Some((network, txid, signed_tx)) = read_state(|s| {
            s.current_consolidate_utxos_request
                .as_ref()
                .and_then(|req| {
                    s.get_submitted_transaction(req.block_index).and_then(|tx| {
                        if tx.txid == old_txid {
                            // For ConsolidatedUtxosRequest, signed_tx should always exist.
                            assert!(tx.signed_tx.is_some());
                            tx.signed_tx
                                .clone()
                                .map(|signed_tx| (s.btc_network, tx.txid, signed_tx))
                        } else {
                            None
                        }
                    })
                })
        }) {
            log!(
                Priority::Info,
                "[resubmit_transactions]: re-sending a signed consolidation transaction {}",
                txid,
            );
            match runtime.send_raw_transaction(signed_tx, network).await {
                Ok(_) => {
                    log!(
                        Priority::Debug,
                        "[resubmit_transactions]: successfully sent transaction {}",
                        txid,
                    );
                }
                Err(err) => {
                    log!(
                        Priority::Info,
                        "[resubmit_transactions]: failed to send transaction {} again: {}",
                        txid,
                        err
                    );
                }
            }
            continue;
        }
        let tx_fee_per_vbyte = match submitted_tx.fee_per_vbyte {
            Some(prev_fee) => {
                // Ensure that the fee is at least min relay fee higher than the previous
                // transaction fee to comply with BIP-125 (https://en.bitcoin.it/wiki/BIP_0125).
                fee_per_vbyte.max(prev_fee + Fee::MIN_RELAY_FEE_RATE_INCREASE)
            }
            None => fee_per_vbyte,
        };

        let outputs = match &submitted_tx.requests {
            state::SubmittedWithdrawalRequests::ToConfirm { requests } => requests
                .iter()
                .map(|req| (req.address.clone(), req.amount))
                .collect(),
            state::SubmittedWithdrawalRequests::ToCancel { .. } => {
                vec![(main_address.clone(), retrieve_btc_min_amount)]
            }
            state::SubmittedWithdrawalRequests::ToConsolidate { request } => {
                vec![(main_address.clone(), request.amount / 2)]
            }
        };

        let mut input_utxos = submitted_tx.used_utxos;
        let mut replaced_reason = state::eventlog::ReplacedReason::ToRetry;
        let mut new_tx_requests = submitted_tx.requests;
        let max_num_inputs_in_transaction = read_state(|s| s.max_num_inputs_in_transaction);
        let build_result = match build_unsigned_transaction_from_inputs(
            &input_utxos,
            outputs,
            &main_address,
            max_num_inputs_in_transaction,
            tx_fee_per_vbyte,
            runtime.transaction_version(),
            fee_estimator,
        ) {
            Err(BuildTxError::InvalidTransaction(err)) => {
                log!(
                    Priority::Info,
                    "[resubmit_transactions]: {:?}, transaction {} will be canceled",
                    err,
                    &submitted_tx.txid,
                );
                let mut inputs = UtxoSet::from_iter(input_utxos);
                // The following selection is guaranteed to select at least 1 UTXO because
                // the value of stuck transaction is no less than retrieve_btc_min_amount.
                input_utxos = utxos_selection(retrieve_btc_min_amount, &mut inputs, 0);
                // The requests field has to be cleared because the finalization of this
                // transaction is not meant to complete the corresponding RetrieveBtcRequests
                // but rather to cancel them.
                let requests = match new_tx_requests {
                    state::SubmittedWithdrawalRequests::ToConfirm { requests } => requests,
                    state::SubmittedWithdrawalRequests::ToCancel { .. } => {
                        unreachable!("cancellation tx never has too many inputs!")
                    }
                    state::SubmittedWithdrawalRequests::ToConsolidate { .. } => {
                        unreachable!("consolidation tx never has too many inputs!")
                    }
                };
                let reason = reimbursement::WithdrawalReimbursementReason::InvalidTransaction(err);
                replaced_reason = state::eventlog::ReplacedReason::ToCancel {
                    reason: reason.clone(),
                };
                new_tx_requests = state::SubmittedWithdrawalRequests::ToCancel { requests, reason };
                let outputs = vec![(main_address.clone(), retrieve_btc_min_amount)];
                build_unsigned_transaction_from_inputs(
                    &input_utxos,
                    outputs,
                    &main_address,
                    max_num_inputs_in_transaction,
                    fee_per_vbyte, // Use normal fee
                    runtime.transaction_version(),
                    fee_estimator,
                )
            }
            result => result,
        };
        let (unsigned_tx, change_output, total_fee) = match build_result {
            Ok(tx) => tx,
            // If it's impossible to build a new transaction, the fees probably became too high.
            // Let's ignore this transaction and wait for fees to go down.
            Err(err) => {
                log!(
                    Priority::Debug,
                    "[resubmit_transactions]: failed to rebuild stuck transaction {}: {:?}",
                    &submitted_tx.txid,
                    err
                );
                continue;
            }
        };

        let maybe_signed_tx = sign_transaction(
            key_name.to_string(),
            &ecdsa_public_key,
            &lookup_outpoint_account,
            unsigned_tx,
            runtime,
        )
        .await;

        let signed_tx = match maybe_signed_tx {
            Ok(tx) => tx,
            Err(err) => {
                log!(
                    Priority::Info,
                    "[resubmit_transactions]: failed to sign a BTC transaction: {}",
                    err
                );
                continue;
            }
        };
        let new_txid = signed_tx.compute_txid();

        match runtime.send_transaction(&signed_tx, btc_network).await {
            Ok(()) => {
                if old_txid == new_txid {
                    // DEFENSIVE: We should never take this branch because we increase fees for
                    // replacement transactions with each resubmission. However, since replacing a
                    // transaction with itself is not allowed, we still handle the transaction
                    // equality in case the fee computation rules change in the future.
                    log!(
                        Priority::Info,
                        "[finalize_requests]: resent transaction {} with a new signature. TX bytes: {}",
                        &new_txid,
                        hex::encode(tx::encode_into(&signed_tx, Vec::new()))
                    );
                    continue;
                }
                log!(
                    Priority::Info,
                    "[finalize_requests]: sent transaction {} to replace stuck transaction {}. TX bytes: {}",
                    &new_txid,
                    &old_txid,
                    hex::encode(tx::encode_into(&signed_tx, Vec::new()))
                );
                let new_tx = state::SubmittedBtcTransaction {
                    requests: new_tx_requests,
                    used_utxos: input_utxos,
                    txid: new_txid,
                    submitted_at: runtime.time(),
                    change_output: Some(change_output),
                    fee_per_vbyte: Some(tx_fee_per_vbyte),
                    withdrawal_fee: Some(total_fee),
                    // Do not fill signed_tx because this is not a consolidation transaction
                    signed_tx: None,
                };
                replace_transaction(old_txid, new_tx, replaced_reason);
            }
            Err(err) => {
                log!(
                    Priority::Info,
                    "[finalize_requests]: failed to send transaction bytes {} to replace stuck transaction {}: {}",
                    hex::encode(tx::encode_into(&signed_tx, Vec::new())),
                    &old_txid,
                    err,
                );
                continue;
            }
        }
    }
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
fn utxos_selection(target: u64, available_utxos: &mut UtxoSet, output_count: usize) -> Vec<Utxo> {
    #[cfg(feature = "canbench-rs")]
    let _scope = canbench_rs::bench_scope("utxos_selection");

    let mut input_utxos = greedy(target, available_utxos);

    if input_utxos.is_empty() {
        return vec![];
    }

    if available_utxos.len() > UTXOS_COUNT_THRESHOLD {
        while input_utxos.len() < output_count + 1 {
            if let Some(min_utxo) = available_utxos.pop_first() {
                input_utxos.push(min_utxo);
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
fn greedy(target: u64, available_utxos: &mut UtxoSet) -> Vec<Utxo> {
    #[cfg(feature = "canbench-rs")]
    let _scope = canbench_rs::bench_scope("greedy");

    let mut solution = vec![];
    let mut goal = target;
    while goal > 0 {
        let candidate_utxo = available_utxos
            .find_lower_bound(goal)
            .or_else(|| available_utxos.last())
            .cloned();
        match candidate_utxo {
            Some(utxo) => {
                let utxo = available_utxos.remove(&utxo).expect("BUG: missing UTXO");
                goal = goal.saturating_sub(utxo.value);
                solution.push(utxo);
            }
            None => {
                // Not enough available UTXOs to satisfy the request.
                for u in solution {
                    available_utxos.insert(u);
                }
                return vec![];
            }
        }
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
pub async fn sign_transaction<R: CanisterRuntime, F: Fn(&tx::OutPoint) -> Option<Account>>(
    key_name: String,
    ecdsa_public_key: &ECDSAPublicKey,
    lookup_outpoint_account: F,
    unsigned_tx: tx::UnsignedTransaction,
    runtime: &R,
) -> Result<tx::SignedTransaction, CallError> {
    use crate::address::derive_public_key_from_raw_path;

    let mut signed_inputs = Vec::with_capacity(unsigned_tx.inputs.len());
    let sighasher = tx::TxSigHasher::new(&unsigned_tx);
    for input in &unsigned_tx.inputs {
        let outpoint = &input.previous_output;

        let account = lookup_outpoint_account(outpoint)
            .unwrap_or_else(|| panic!("bug: no account for outpoint {outpoint:?}"));

        let derivation_path = runtime.derivation_path(&account);
        let pubkey = ByteBuf::from(
            derive_public_key_from_raw_path(ecdsa_public_key, derivation_path.clone()).public_key,
        );
        let pkhash = tx::hash160(&pubkey);

        let sighash = sighasher.sighash(input, &pkhash);

        let sec1_signature =
            management::sign_with_ecdsa(key_name.clone(), derivation_path, sighash, runtime)
                .await?;

        signed_inputs.push(tx::SignedInput {
            signature: signature::EncodedSignature::from_sec1(&sec1_signature),
            pubkey,
            previous_output: outpoint.clone(),
            sequence: input.sequence,
            uses_segwit: runtime.uses_segwit(),
        });
    }
    Ok(tx::SignedTransaction {
        version: unsigned_tx.version,
        inputs: signed_inputs,
        outputs: unsigned_tx.outputs,
        lock_time: unsigned_tx.lock_time,
    })
}

pub fn fake_sign(
    unsigned_tx: &tx::UnsignedTransaction,
    uses_segwit: bool,
) -> tx::SignedTransaction {
    tx::SignedTransaction {
        version: unsigned_tx.version,
        inputs: unsigned_tx
            .inputs
            .iter()
            .map(|unsigned_input| tx::SignedInput {
                previous_output: unsigned_input.previous_output.clone(),
                sequence: unsigned_input.sequence,
                signature: signature::EncodedSignature::fake(),
                pubkey: ByteBuf::from(vec![0u8; tx::PUBKEY_LEN]),
                uses_segwit,
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
    /// The transaction contains too many inputs.
    /// If such a transaction were signed, there is a risk that the resulting transaction
    /// will have a size over 100k vbytes and therefore be *non-standard*.
    InvalidTransaction(InvalidTransactionError),
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
pub fn build_unsigned_transaction<F: FeeEstimator>(
    available_utxos: &mut UtxoSet,
    outputs: Vec<(BitcoinAddress, Satoshi)>,
    main_address: &BitcoinAddress,
    max_num_inputs_in_transaction: usize,
    fee_per_vbyte: u64,
    tx_version: TransactionVersion,
    fee_estimator: &F,
) -> Result<
    (
        tx::UnsignedTransaction,
        state::ChangeOutput,
        WithdrawalFee,
        Vec<Utxo>,
    ),
    BuildTxError,
> {
    #[cfg(feature = "canbench-rs")]
    let _scope = canbench_rs::bench_scope("build_unsigned_transaction");

    assert!(!outputs.is_empty());
    let amount = outputs.iter().map(|(_, amount)| amount).sum::<u64>();
    let inputs = utxos_selection(amount, available_utxos, outputs.len());
    match build_unsigned_transaction_from_inputs(
        &inputs,
        outputs,
        main_address,
        max_num_inputs_in_transaction,
        fee_per_vbyte,
        tx_version,
        fee_estimator,
    ) {
        Ok((tx, change, total_fee)) => Ok((tx, change, total_fee, inputs)),
        Err(err) => {
            // Undo mutation to available_utxos in the error case
            for utxo in inputs {
                assert!(available_utxos.insert(utxo));
            }
            Err(err)
        }
    }
}

pub fn build_unsigned_transaction_from_inputs<F: FeeEstimator>(
    input_utxos: &[Utxo],
    outputs: Vec<(BitcoinAddress, Satoshi)>,
    main_address: &BitcoinAddress,
    max_num_inputs_in_transaction: usize,
    fee_per_vbyte: u64,
    tx_version: TransactionVersion,
    fee_estimator: &F,
) -> Result<(tx::UnsignedTransaction, state::ChangeOutput, WithdrawalFee), BuildTxError> {
    #[cfg(feature = "canbench-rs")]
    let _scope = canbench_rs::bench_scope("build_unsigned_transaction_from_inputs");

    assert!(!outputs.is_empty());

    /// Having a sequence number lower than (0xffffffff - 1) signals the use of replacement by fee.
    /// It allows us to increase the fee of a transaction already sent to the mempool.
    /// The rbf option is used in `resubmit_retrieve_btc`.
    /// https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki
    const SEQUENCE_RBF_ENABLED: u32 = 0xfffffffd;

    let amount = outputs.iter().map(|(_, amount)| amount).sum::<u64>();

    let num_inputs = input_utxos.len();
    if num_inputs == 0 {
        return Err(BuildTxError::NotEnoughFunds);
    }
    if num_inputs > max_num_inputs_in_transaction {
        return Err(BuildTxError::InvalidTransaction(
            InvalidTransactionError::TooManyInputs {
                max_num_inputs: max_num_inputs_in_transaction,
                num_inputs,
            },
        ));
    }

    let inputs_value = input_utxos.iter().map(|u| u.value).sum::<u64>();

    debug_assert!(inputs_value >= amount);

    let minter_fee =
        fee_estimator.evaluate_minter_fee(input_utxos.len() as u64, (outputs.len() + 1) as u64);

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
    let num_outputs = tx_outputs.len();

    debug_assert_eq!(
        tx_outputs.iter().map(|out| out.value).sum::<u64>() - minter_fee,
        inputs_value
    );

    let mut unsigned_tx = tx::UnsignedTransaction {
        version: tx_version,
        inputs: input_utxos
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

    let fee = fee_estimator.evaluate_transaction_fee(&unsigned_tx, fee_per_vbyte);

    if fee + minter_fee > amount {
        return Err(BuildTxError::AmountTooLow);
    }

    let fee_shares = distribute(fee + minter_fee, outputs.len() as u64);

    // The last output has to match the main_address.
    debug_assert!(matches!(unsigned_tx.outputs.iter().last(),
        Some(tx::TxOut { value: _, address }) if address == main_address));

    for (output, fee_share) in unsigned_tx
        .outputs
        .iter_mut()
        .zip(fee_shares.iter())
        .take(num_outputs - 1)
    {
        if output.value <= *fee_share + F::DUST_LIMIT {
            return Err(BuildTxError::DustOutput {
                address: output.address.clone(),
                amount: output.value,
            });
        }
        output.value = output.value.saturating_sub(*fee_share);
    }

    debug_assert_eq!(
        inputs_value,
        fee + unsigned_tx.outputs.iter().map(|u| u.value).sum::<u64>()
    );

    Ok((
        unsigned_tx,
        change_output,
        WithdrawalFee {
            bitcoin_fee: fee,
            minter_fee,
        },
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

pub fn timer<R: CanisterRuntime + 'static>(runtime: R) {
    use tasks::{pop_if_ready, run_task};

    if let Some(task) = pop_if_ready(&runtime) {
        // Remark: spawn_017_compat is not needed since there is no code after `spawn` in the timer.
        // See https://github.com/dfinity/cdk-rs/blob/0.18.3/ic-cdk/V18_GUIDE.md#futures-ordering-changes
        #[allow(clippy::disallowed_methods)]
        ic_cdk::futures::spawn(run_task(task, runtime));
    }
}

/// Computes an estimate for the retrieve_btc fee.
///
/// Arguments:
///   * `available_utxos` - the list of UTXOs available to the minter.
///   * `maybe_amount` - the withdrawal amount.
///   * `median_fee_millisatoshi_per_vbyte` - the median network fee, in millisatoshi per vbyte.
pub fn estimate_retrieve_btc_fee<F: FeeEstimator>(
    available_utxos: &mut UtxoSet,
    withdrawal_amount: u64,
    median_fee_millisatoshi_per_vbyte: u64,
    max_num_inputs_in_transaction: usize,
    tx_version: TransactionVersion,
    fee_estimator: &F,
) -> Result<WithdrawalFee, BuildTxError> {
    // Only the address type matters for the amount of vbytes, not the actual bytes in the address.
    let dummy_minter_address = BitcoinAddress::P2wpkhV0([u8::MAX; 20]);
    let dummy_recipient_address = BitcoinAddress::P2wpkhV0([42_u8; 20]);
    crate::queries::estimate_withdrawal_fee(
        available_utxos,
        withdrawal_amount,
        median_fee_millisatoshi_per_vbyte,
        dummy_minter_address,
        dummy_recipient_address,
        max_num_inputs_in_transaction,
        tx_version,
        fee_estimator,
    )
}

#[derive(Debug)]
pub enum ConsolidateUtxosError {
    TooSoon,
    TooFewAvailableUtxos,
    EstimateFeeNotAvailable,
    StillProcessing,
    BuildTx(BuildTxError),
    BurnCkbtc(updates::retrieve_btc::RetrieveBtcError, u64),
    SubmitRequest(CallError),
}

/// Consolidate UTXOs.
///
/// If there are more than 10,000 UTXOs, combine the smallest 1000 of them.
///
/// This function can be called any time to check if a consolidation is required, but
/// the consolidation process will only take place after a minimum interval since the last
/// consolidation submission.
///
/// A Consolidation transaction is like a special retrieve_btc transaction:
/// - Inputs are 1000 UTXOs with small values.
/// - Outputs (including change output) are addressed to the minter.
/// - Transaction fee (in ckBTC) is burned from the fee collector account.
///
/// Such a request is constructed differently but the signing and sending tasks
/// share the same logic as a retrieve_btc request.
pub async fn consolidate_utxos<R: CanisterRuntime>(
    runtime: &R,
) -> Result<Txid, ConsolidateUtxosError> {
    let utxo_consolidation_threshold = read_state(|s| s.utxo_consolidation_threshold);

    // Return early if number of available UTXOs is below consolidation threshold.
    if read_state(|s| s.available_utxos.len() < utxo_consolidation_threshold) {
        return Err(ConsolidateUtxosError::TooFewAvailableUtxos);
    }

    // Return early if MIN_CONSOLIDATION_INTERVAL is not met since last submission.
    let now = runtime.time();
    let last_submission = read_state(|s| s.last_consolidate_utxos_request_time_ns);
    if Timestamp::new(now).checked_duration_since(Timestamp::new(last_submission))
        < Some(MIN_CONSOLIDATION_INTERVAL)
    {
        return Err(ConsolidateUtxosError::TooSoon);
    }

    // Return early if there is still an on-going transaction.
    if read_state(|s| s.current_consolidate_utxos_request.is_some()) {
        return Err(ConsolidateUtxosError::StillProcessing);
    }

    let input_utxos = mutate_state(|s| {
        select_utxos_to_consolidate(&mut s.available_utxos, s.max_num_inputs_in_transaction)
    });
    let input_utxos_len = input_utxos.len();
    let restore_utxos = |utxos| {
        mutate_state(|s| {
            for utxo in utxos {
                s.available_utxos.insert(utxo);
            }
        })
    };

    let ecdsa_public_key = updates::get_btc_address::init_ecdsa_public_key().await;

    // TODO DEFI-2552: use 25% percentile
    let fee_millisatoshi_per_vbyte = estimate_fee_per_vbyte(runtime)
        .await
        .ok_or(ConsolidateUtxosError::EstimateFeeNotAvailable)?;

    // There will be two outputs: 1 normal output and 1 change output, each about
    // half of the total value of the input UTXOs. It could be made into just one
    // output, but two outputs make it easier to reuse the existing implementation
    // of build_unsigned_transaction_from_inputs.
    let total_amount = input_utxos.iter().map(|x| x.value).sum::<u64>();
    let output_amount = total_amount / 2;
    let main_address = read_state(|s| runtime.derive_minter_address(s));
    let fee_estimator = read_state(|s| runtime.fee_estimator(s));
    let max_num_inputs_in_transaction = read_state(|s| s.max_num_inputs_in_transaction);
    let (unsigned_tx, change_output, total_fee) = match build_unsigned_transaction_from_inputs(
        &input_utxos,
        vec![(main_address.clone(), output_amount)],
        &main_address,
        max_num_inputs_in_transaction,
        fee_millisatoshi_per_vbyte,
        runtime.transaction_version(),
        &fee_estimator,
    ) {
        Ok(result) => result,
        Err(err) => {
            log!(
                Priority::Info,
                "[consolidate_utxos]: failed to build conslidation transaction {:?}",
                err
            );
            restore_utxos(input_utxos);
            return Err(ConsolidateUtxosError::BuildTx(err));
        }
    };

    // In case of any error, revert state change by putting input_utxos back.
    let utxos_guard = guard(input_utxos, restore_utxos);

    // Burn transaction fee (bitcoin_fee) from fee collector's account.
    let burn_memo = memo::BurnMemo::Consolidate {
        value: total_amount,
        inputs: input_utxos_len as u64,
    };
    let block_index = updates::retrieve_btc::burn_ckbtcs_from_subaccount(
        FEE_COLLECTOR_SUBACCOUNT,
        total_fee.bitcoin_fee,
        crate::memo::encode(&burn_memo).into(),
    )
    .await
    .map_err(|err| {
        log!(
            Priority::Info,
            "[consolidate_utxos]: failed to burn ckbtc from fee account {:?}",
            err
        );
        ConsolidateUtxosError::BurnCkbtc(err, total_fee.bitcoin_fee)
    })?;

    let request = state::ConsolidateUtxosRequest {
        block_index,
        address: main_address,
        amount: total_amount,
        received_at: now,
    };
    mutate_state(|s| state::audit::create_consolidate_utxos_request(s, request.clone(), runtime));

    let utxos = ScopeGuard::into_inner(utxos_guard);
    let request = read_state(|s| SignTxRequest {
        key_name: s.ecdsa_key_name.clone(),
        ecdsa_public_key,
        change_output,
        network: s.btc_network,
        unsigned_tx,
        requests: state::SubmittedWithdrawalRequests::ToConsolidate { request },
        utxos,
    });

    sign_and_submit_request(request, fee_millisatoshi_per_vbyte, total_fee, runtime)
        .await
        .map_err(ConsolidateUtxosError::SubmitRequest)
}

// Return UTXOs for consolidation and remove them from available_utxos.
fn select_utxos_to_consolidate(available_utxos: &mut UtxoSet, num_inputs: usize) -> Vec<Utxo> {
    let mut utxos = Vec::with_capacity(num_inputs);
    while utxos.len() < num_inputs {
        if let Some(utxo) = available_utxos.pop_first() {
            utxos.push(utxo);
        } else {
            break;
        }
    }
    utxos
}

#[async_trait]
pub trait CanisterRuntime {
    /// Type used to estimate fees.
    type Estimator: FeeEstimator;

    /// Type used for events recording of state changes.
    type EventLogger: EventLogger;

    /// Returns the caller of the current call.
    fn caller(&self) -> Principal {
        ic_cdk::api::msg_caller()
    }

    /// Returns the canister id
    fn id(&self) -> Principal {
        ic_cdk::api::canister_self()
    }

    /// Gets current timestamp, in nanoseconds since the epoch (1970-01-01)
    fn time(&self) -> u64 {
        ic_cdk::api::time()
    }

    /// Set a global timer to make the system schedule a call to the exported `canister_global_timer` Wasm method after the specified time.
    /// The time must be provided as nanoseconds since 1970-01-01.
    /// See the [IC specification](https://internetcomputer.org/docs/current/references/ic-interface-spec#global-timer-1).
    fn global_timer_set(&self, timestamp: u64) {
        ic_cdk::api::global_timer_set(timestamp);
    }

    /// Validate the minter's state.
    fn validate_config(&self, state: &CkBtcMinterState) {
        state.validate_config()
    }

    /// How often is a block produced.
    fn block_time(&self, network: Network) -> Duration;

    fn parse_address(&self, address: &str, network: Network) -> Result<BitcoinAddress, String>;

    /// Returns the derivation path that should be used to sign a message from a
    /// specified account.
    fn derivation_path(&self, account: &Account) -> Vec<Vec<u8>>;

    /// Address controlled by the minter (via threshold ECDSA) for a given user.
    fn derive_user_address(&self, state: &CkBtcMinterState, account: &Account) -> String;

    /// Derive address controlled by the minter.
    fn derive_minter_address(&self, state: &CkBtcMinterState) -> BitcoinAddress;

    /// Derive address controlled by the minter.
    fn derive_minter_address_str(&self, state: &CkBtcMinterState) -> String;

    /// Returns the frequency at which fee percentiles are refreshed.
    fn refresh_fee_percentiles_frequency(&self) -> Duration;

    /// How to estimate fees.
    fn fee_estimator(&self, state: &CkBtcMinterState) -> Self::Estimator;

    /// How to record and replay events.
    fn event_logger(&self) -> Self::EventLogger;

    /// Whether segregated witness can be used (BIP-144).
    fn uses_segwit(&self) -> bool {
        true
    }

    /// Uses post BIP-68 transactions.
    fn transaction_version(&self) -> TransactionVersion {
        TransactionVersion::TWO
    }

    /// Retrieves the current transaction fee percentiles.
    async fn get_current_fee_percentiles(
        &self,
        request: &GetCurrentFeePercentilesRequest,
    ) -> Result<Vec<u64>, CallError>;

    /// Fetches all unspent transaction outputs (UTXOs) associated with the provided address in the specified network.
    async fn get_utxos(&self, request: &GetUtxosRequest) -> Result<GetUtxosResponse, CallError>;

    async fn check_transaction(
        &self,
        btc_checker_principal: Option<Principal>,
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
        derivation_path: Vec<Vec<u8>>,
        message_hash: [u8; 32],
    ) -> Result<Vec<u8>, CallError>;

    async fn send_transaction(
        &self,
        transaction: &tx::SignedTransaction,
        network: Network,
    ) -> Result<(), CallError>;

    async fn send_raw_transaction(
        &self,
        raw_transaction: Vec<u8>,
        network: Network,
    ) -> Result<(), CallError>;

    /// Check if the given address is blocked.
    async fn check_address(
        &self,
        btc_checker_principal: Option<Principal>,
        address: String,
    ) -> Result<BtcAddressCheckStatus, CallError>;
}

#[derive(Copy, Clone)]
pub struct IcCanisterRuntime {}

#[async_trait]
impl CanisterRuntime for IcCanisterRuntime {
    type Estimator = BitcoinFeeEstimator;
    type EventLogger = CkBtcEventLogger;

    fn refresh_fee_percentiles_frequency(&self) -> Duration {
        const ONE_HOUR: Duration = Duration::from_secs(3_600);
        ONE_HOUR
    }

    fn fee_estimator(&self, state: &CkBtcMinterState) -> BitcoinFeeEstimator {
        BitcoinFeeEstimator::from_state(state)
    }

    fn event_logger(&self) -> Self::EventLogger {
        CkBtcEventLogger
    }

    async fn get_current_fee_percentiles(
        &self,
        request: &GetCurrentFeePercentilesRequest,
    ) -> Result<Vec<u64>, CallError> {
        management::bitcoin_get_current_fee_percentiles(request).await
    }

    async fn get_utxos(&self, request: &GetUtxosRequest) -> Result<GetUtxosResponse, CallError> {
        management::bitcoin_get_utxos(request).await
    }

    async fn check_transaction(
        &self,
        btc_checker_principal: Option<Principal>,
        utxo: &Utxo,
        cycle_payment: u128,
    ) -> Result<CheckTransactionResponse, CallError> {
        let btc_checker_principal = btc_checker_principal
            .expect("BUG: upgrade procedure must ensure that the Bitcoin checker principal is set");
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
        derivation_path: Vec<Vec<u8>>,
        message_hash: [u8; 32],
    ) -> Result<Vec<u8>, CallError> {
        ic_cdk::management_canister::sign_with_ecdsa(&SignWithEcdsaArgs {
            message_hash: message_hash.to_vec(),
            derivation_path,
            key_id: ic_cdk::management_canister::EcdsaKeyId {
                curve: ic_cdk::management_canister::EcdsaCurve::Secp256k1,
                name: key_name.clone(),
            },
        })
        .await
        .map(|result| result.signature)
        .map_err(CallError::from_sign_error)
    }

    async fn send_transaction(
        &self,
        transaction: &tx::SignedTransaction,
        network: Network,
    ) -> Result<(), CallError> {
        management::send_transaction(transaction, network).await
    }

    async fn send_raw_transaction(
        &self,
        transaction: Vec<u8>,
        network: Network,
    ) -> Result<(), CallError> {
        bitcoin_canister::bitcoin_send_transaction(&bitcoin_canister::SendTransactionRequest {
            transaction,
            network: network.into(),
        })
        .await
        .map_err(|err| CallError::from_cdk_call_error("bitcoin_send_transaction", err))
    }

    fn block_time(&self, network: Network) -> Duration {
        match network {
            Network::Mainnet => {
                // https://github.com/bitcoin/bitcoin/blob/dfde31f2ec1f90976f3ba6b06f2b38a1307c01ab/src/kernel/chainparams.cpp#L102
                Duration::from_secs(600)
            }
            Network::Testnet => {
                // https://github.com/bitcoin/bitcoin/blob/dfde31f2ec1f90976f3ba6b06f2b38a1307c01ab/src/kernel/chainparams.cpp#L329
                Duration::from_secs(600)
            }
            Network::Regtest => {
                //https://github.com/bitcoin/bitcoin/blob/dfde31f2ec1f90976f3ba6b06f2b38a1307c01ab/src/kernel/chainparams.cpp#L558C9-L558C46
                Duration::from_secs(600)
            }
        }
    }

    fn parse_address(
        &self,
        address: &str,
        network: Network,
    ) -> Result<BitcoinAddress, std::string::String> {
        BitcoinAddress::parse(address, network).map_err(|e| e.to_string())
    }

    fn derivation_path(&self, account: &Account) -> Vec<Vec<u8>> {
        const SCHEMA_V1: u8 = 1;

        vec![
            vec![SCHEMA_V1],
            account.owner.as_slice().to_vec(),
            account.effective_subaccount().to_vec(),
        ]
    }

    fn derive_user_address(&self, state: &CkBtcMinterState, account: &Account) -> String {
        get_btc_address::account_to_p2wpkh_address_from_state(state, account)
    }

    fn derive_minter_address(&self, state: &CkBtcMinterState) -> BitcoinAddress {
        let main_account = Account {
            owner: ic_cdk::api::canister_self(),
            subaccount: None,
        };
        let ecdsa_public_key = state
            .ecdsa_public_key
            .as_ref()
            .expect("bug: the ECDSA public key must be initialized");
        address::account_to_bitcoin_address(ecdsa_public_key, &main_account)
    }

    fn derive_minter_address_str(&self, state: &CkBtcMinterState) -> String {
        self.derive_minter_address(state).display(state.btc_network)
    }

    async fn check_address(
        &self,
        btc_checker_principal: Option<Principal>,
        address: String,
    ) -> Result<BtcAddressCheckStatus, CallError> {
        let btc_checker_principal = btc_checker_principal
            .expect("BUG: upgrade procedure must ensure that the Bitcoin checker principal is set");

        ic_cdk::call::Call::bounded_wait(btc_checker_principal, "check_address")
            .with_arg(CheckAddressArgs {
                address: address.clone(),
            })
            .await
            .map_err(|e| CallError::from_cdk_call_error("check_address", e))?
            .candid()
            .map(|res: CheckAddressResponse| match res {
                CheckAddressResponse::Failed => {
                    log!(
                        Priority::Info,
                        "Discovered a tainted btc address {}",
                        address
                    );
                    BtcAddressCheckStatus::Tainted
                }
                CheckAddressResponse::Passed => BtcAddressCheckStatus::Clean,
            })
            .map_err(|e| CallError::from_cdk_call_error("check_address", e))
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
        if let Some(expire_cutoff) = now.checked_sub(self.expiration)
            && timestamp < expire_cutoff
        {
            return None;
        }
        self.values.get(&Timestamped {
            timestamp,
            inner: Some(key.clone()),
        })
    }
}

pub type GetUtxosCache = CacheWithExpiration<bitcoin_canister::GetUtxosRequest, GetUtxosResponse>;
