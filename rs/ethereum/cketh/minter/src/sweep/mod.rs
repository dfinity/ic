//! Sending transactions **from the minter's dedicated sweeper address** on the sweeper's own nonce
//! sequence, so a stuck sweep can never head-of-line-block a withdrawal on the main address'
//! pipeline.
//!
//! It drives the sweeper [`TransactionPipeline`] through the same
//! create → sign → send → resubmit → finalize state machine as user withdrawals
//! ([`crate::withdraw`]), reusing that module's sender-agnostic RPC helpers
//! (`latest_transaction_count`, `finalized_transaction_count`, `send_signed_transactions`,
//! `fetch_finalized_receipts`), but signing with the sweeper derivation path (`[3]`) and reading
//! the sweeper address' own transaction count.

#[cfg(test)]
mod tests;

use crate::attestation::{AttestationRequest, sign_attestation};
use crate::{
    deposit_address::{DepositAddressSchema, deposit_derivation_path, sweeper_derivation_path},
    guard::TimerGuard,
    logs::{DEBUG, INFO},
    numeric::{GasAmount, TransactionCount, TransactionNonce},
    runtime::CanisterRuntime,
    state::{
        State, TaskType,
        audit::{EventType, process_event},
        automatic_deposits::SweepTarget,
        mutate_state, read_state,
        transactions::{CreateSweepTransactionError, PipelineRequest},
    },
    time::TimeProvider,
    tx::{
        AuthorizationRequest, GasFeeEstimate, SignedAuthorization, lazy_refresh_gas_fee_estimate,
        sign_digest,
    },
    withdraw::{
        fetch_finalized_receipts, finalized_transaction_count, latest_transaction_count,
        send_signed_transactions,
    },
};
use futures::future::join_all;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::{BTreeMap, BTreeSet};

/// Gas limit of a sweep transaction. A fixed, conservative bound; a per-request estimate arrives
/// with the real delegate sweep call.
pub(crate) const SWEEP_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(100_000);

const SWEEP_REQUESTS_BATCH_SIZE: usize = 5;
const SWEEP_TRANSACTIONS_TO_SIGN_BATCH_SIZE: usize = 5;
const SWEEP_TRANSACTIONS_TO_SEND_BATCH_SIZE: usize = 5;
const MAX_DEPOSITS_PER_SWEEP: usize = 10;

/// Turns the deposits the balance scan queued into the sweep requests that
/// [`process_sweeper_transactions`] prices, signs, sends and finalizes.
pub async fn create_pending_sweeper_requests<R: CanisterRuntime>(runtime: &R) {
    let _guard = match TimerGuard::new(TaskType::SweeperEnqueue) {
        Ok(guard) => guard,
        Err(e) => {
            log!(
                DEBUG,
                "Failed retrieving timer guard to create pending sweeper requests: {e:?}",
            );
            return;
        }
    };

    let Some(sweeper_contract) = read_state(|s| s.sweeper_contract_address) else {
        log!(
            DEBUG,
            "[create_pending_sweeper_requests]: SKIPPING: no sweeper contract address is configured"
        );
        return;
    };

    let batch_per_token =
        read_state(|s| s.automatic_deposits.requests_batch(MAX_DEPOSITS_PER_SWEEP));
    if batch_per_token.is_empty() {
        return;
    }

    let Some(_gas_fee_estimate) = lazy_refresh_gas_fee_estimate(runtime).await else {
        log!(
            INFO,
            "[create_pending_sweeper_requests]: SKIPPING: failed retrieving gas fee estimate"
        );
        return;
    };

    for (_token, targets) in batch_per_token {
        let Some(attestation_requests) = read_state(|s| s.attestation_requests(&targets)) else {
            log!(
                DEBUG,
                "[create_pending_sweeper_requests]: SKIPPING: no deposit helper with subaccount is configured"
            );
            return;
        };
        sign_attestations_batch(attestation_requests, runtime).await;
        let _authorizations = sign_authorizations_batch(&targets, sweeper_contract, runtime).await;
    }
}

async fn sign_attestations_batch<R: CanisterRuntime>(
    requests: Vec<AttestationRequest>,
    runtime: &R,
) {
    let requests_to_sign: BTreeSet<_> = read_state(|s| {
        requests
            .into_iter()
            .filter(|request| s.automatic_deposits.attestation(request).is_none())
            .collect()
    });

    let signing_results = join_all(requests_to_sign.into_iter().map(|request| async move {
        (request.clone(), sign_attestation(&request, runtime).await)
    }))
    .await;

    let mut errors = Vec::new();
    for (request, signing_result) in signing_results {
        match signing_result {
            Ok(signature) => {
                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::AttestedDepositAddress { request, signature },
                        runtime,
                    )
                });
            }
            Err(e) => errors.push((request, e)),
        }
    }

    if !errors.is_empty() {
        log!(
            INFO,
            "[create_pending_sweeper_requests]: leaving out the deposits this sweep could not attest: {errors:?}"
        );
    }
}

/// One authorization per attested deposit address, keyed by the account it delegates.
///
/// Only attested addresses are signed: a deposit that could not be attested drops out of the sweep
/// anyway, so authorizing it would spend a signature on nothing. A tuple already recorded for the
/// address is reused rather than signed again — it names nonce 0, so it stays applicable for every
/// later sweep, see [`AuthorizationRequest`].
async fn sign_authorizations_batch<R: CanisterRuntime>(
    targets: &[SweepTarget],
    sweeper_contract: Address,
    runtime: &R,
) -> BTreeMap<Account, SignedAuthorization> {
    let chain_id = read_state(State::ethereum_network).chain_id();
    let (mut authorizations, to_sign): (BTreeMap<Account, SignedAuthorization>, Vec<_>) =
        read_state(|s| {
            let mut stored = BTreeMap::new();
            let mut to_sign = Vec::new();
            for request in targets
                .iter()
                .map(SweepTarget::account)
                .filter(|account| s.attestation(*account).is_some())
                .map(|account| {
                    AuthorizationRequest::new(
                        account,
                        chain_id,
                        sweeper_contract,
                        TransactionNonce::ZERO,
                    )
                })
            {
                match s.automatic_deposits.authorization(&request) {
                    Some(signature) => {
                        stored.insert(request.account(), request.signed_with(signature.clone()));
                    }
                    None => to_sign.push(request),
                }
            }
            (stored, to_sign)
        });

    let signing_results = join_all(to_sign.into_iter().map(|request| async move {
        let signature = sign_digest(
            &request.authorization().hash(),
            &deposit_derivation_path(DepositAddressSchema::CkErc20, &request.account()),
            runtime,
        )
        .await;
        (request, signature)
    }))
    .await;

    let mut errors = Vec::new();
    for (request, signing_result) in signing_results {
        match signing_result {
            Ok(signature) => {
                authorizations.insert(request.account(), request.signed_with(signature.clone()));
                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::AuthorizedDepositAddress { request, signature },
                        runtime,
                    )
                });
            }
            Err(e) => errors.push((request.account(), e)),
        }
    }

    if !errors.is_empty() {
        log!(
            INFO,
            "[create_pending_sweeper_requests]: leaving out the deposits this sweep could not authorize: {errors:?}"
        );
    }
    authorizations
}

pub async fn process_sweeper_transactions<R: CanisterRuntime>(runtime: R) {
    let _guard = match TimerGuard::new(TaskType::SweeperSend) {
        Ok(guard) => guard,
        Err(e) => {
            log!(
                DEBUG,
                "Failed retrieving timer guard to process sweeper transactions: {e:?}",
            );
            return;
        }
    };

    if read_state(|s| !s.automatic_deposits.has_pending_sweeps()) {
        return;
    }

    let Some(sender) = read_state(State::sweeper_address) else {
        log!(
            DEBUG,
            "[process_sweeper_transactions]: SKIPPING: the sweeper address is unknown (ECDSA public key not cached yet)"
        );
        return;
    };

    let gas_fee_estimate = match lazy_refresh_gas_fee_estimate(&runtime).await {
        Some(gas_fee_estimate) => gas_fee_estimate,
        None => {
            // The withdrawal task refreshes the same estimate under a shared guard and runs first
            // on an equal cadence, so losing that race is expected rather than exceptional. Retry
            // instead of waiting a whole interval: by then the refresh it was holding has cached an
            // estimate this task can reuse.
            log!(
                INFO,
                "[process_sweeper_transactions]: failed retrieving gas fee estimate, retrying",
            );
            schedule_retry(runtime);
            return;
        }
    };

    let latest_transaction_count = latest_transaction_count(sender).await;
    resubmit_transactions_batch(latest_transaction_count, &gas_fee_estimate, &runtime).await;
    create_transactions_batch(&gas_fee_estimate, &runtime);
    sign_transactions_batch(&runtime).await;
    send_transactions_batch(sender, latest_transaction_count).await;
    finalize_transactions_batch(sender, &runtime).await;

    if read_state(|s| s.automatic_deposits.has_pending_sweeps()) {
        schedule_retry(runtime);
    }
}

fn schedule_retry<R: CanisterRuntime>(runtime: R) {
    ic_cdk_timers::set_timer(
        crate::PROCESS_SWEEPER_TRANSACTIONS_RETRY_INTERVAL,
        async move { process_sweeper_transactions(runtime).await },
    );
}

async fn resubmit_transactions_batch<T: TimeProvider>(
    latest_transaction_count: Option<TransactionCount>,
    gas_fee_estimate: &GasFeeEstimate,
    time_provider: &T,
) {
    if read_state(|s| s.automatic_deposits.is_sent_sweep_tx_empty()) {
        return;
    }
    let Some(latest_transaction_count) = latest_transaction_count else {
        return;
    };
    let transactions_to_resubmit = read_state(|s| {
        s.automatic_deposits
            .create_resubmit_sweep_transactions(latest_transaction_count, gas_fee_estimate.clone())
    });
    for result in transactions_to_resubmit {
        match result {
            Ok((sweep_id, transaction)) => {
                log!(
                    INFO,
                    "[process_sweeper_transactions]: resubmitting sweep transaction {transaction:?}"
                );
                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::ReplacedSweeperTransaction {
                            sweep_id,
                            transaction,
                        },
                        time_provider,
                    )
                });
            }
            Err(e) => {
                log!(
                    INFO,
                    "[process_sweeper_transactions]: failed to resubmit sweep transaction: {e:?}"
                );
            }
        }
    }
}

fn create_transactions_batch<T: TimeProvider>(
    gas_fee_estimate: &GasFeeEstimate,
    time_provider: &T,
) {
    for request in read_state(|s| {
        s.automatic_deposits
            .sweep_requests_batch(SWEEP_REQUESTS_BATCH_SIZE)
    }) {
        let ethereum_network = read_state(State::ethereum_network);
        let nonce = read_state(|s| s.automatic_deposits.next_sweeper_transaction_nonce());
        let sweep_id = request.id;
        match request.create_transaction(
            nonce,
            gas_fee_estimate.clone(),
            SWEEP_TRANSACTION_GAS_LIMIT,
            ethereum_network,
        ) {
            Ok(transaction) => {
                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::CreatedSweeperTransaction {
                            sweep_id,
                            transaction,
                        },
                        time_provider,
                    );
                });
            }
            Err(CreateSweepTransactionError::InsufficientTransactionFee {
                allowed_max_transaction_fee,
                actual_max_transaction_fee,
                ..
            }) => {
                log!(
                    INFO,
                    "[process_sweeper_transactions]: Sweep {sweep_id:?} has prepaid gas {allowed_max_transaction_fee:?}, below the current transaction fee {actual_max_transaction_fee:?}. Sweep moved back to end of queue."
                );
                mutate_state(|s| s.automatic_deposits.reschedule_sweep_request(sweep_id));
            }
        }
    }
}

async fn sign_transactions_batch<R: CanisterRuntime>(runtime: &R) {
    let transactions_batch: Vec<_> = read_state(|s| {
        s.automatic_deposits
            .sweep_transactions_to_sign_batch(SWEEP_TRANSACTIONS_TO_SIGN_BATCH_SIZE)
    });
    let results = join_all(
        transactions_batch
            .into_iter()
            .map(|(sweep_id, tx)| async move {
                (
                    sweep_id,
                    crate::tx::sign(tx, sweeper_derivation_path(), runtime).await,
                )
            }),
    )
    .await;
    for (sweep_id, result) in results {
        match result {
            Ok(transaction) => mutate_state(|s| {
                process_event(
                    s,
                    EventType::SignedSweeperTransaction {
                        sweep_id,
                        transaction,
                    },
                    runtime,
                )
            }),
            Err(e) => log!(
                INFO,
                "[process_sweeper_transactions]: error signing sweep {sweep_id:?}: {e:?}"
            ),
        }
    }
}

async fn send_transactions_batch(
    sender: Address,
    latest_transaction_count: Option<TransactionCount>,
) {
    let Some(latest_transaction_count) = latest_transaction_count else {
        return;
    };
    let transactions_to_send: Vec<_> = read_state(|s| {
        s.automatic_deposits.sweep_transactions_to_send_batch(
            latest_transaction_count,
            SWEEP_TRANSACTIONS_TO_SEND_BATCH_SIZE,
        )
    });
    send_signed_transactions(sender, &transactions_to_send).await;
}

async fn finalize_transactions_batch<T: TimeProvider>(sender: Address, time_provider: &T) {
    if read_state(|s| s.automatic_deposits.is_sent_sweep_tx_empty()) {
        return;
    }
    match finalized_transaction_count(sender).await {
        Ok(finalized_tx_count) => {
            let txs_to_finalize = read_state(|s| {
                s.automatic_deposits
                    .sent_sweep_transactions_to_finalize(&finalized_tx_count)
            });
            if let Some(receipts) = fetch_finalized_receipts(txs_to_finalize).await {
                for (sweep_id, transaction_receipt) in receipts {
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::FinalizedSweeperTransaction {
                                sweep_id,
                                transaction_receipt: transaction_receipt.into(),
                            },
                            time_provider,
                        );
                    });
                }
            }
        }
        Err(e) => {
            log!(
                INFO,
                "[process_sweeper_transactions]: failed to get finalized transaction count: {e:?}"
            );
        }
    }
}
