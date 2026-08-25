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
//!
//! [`enqueue_batched_sweep`] is what feeds it: it takes the deposits the balance scan queued, signs
//! one delegation and one ownership attestation per address, and enqueues a single [`SweepRequest`]
//! whose call data sweeps them all through the deployed delegate.

use crate::{
    attestation::sign_attestation,
    deposit_address::{DepositAddressSchema, deposit_derivation_path, sweeper_derivation_path},
    guard::TimerGuard,
    logs::{DEBUG, INFO},
    numeric::{TransactionCount, TransactionNonce, Wei},
    state::{
        State, TaskType,
        audit::{EventType, process_event},
        mutate_state, read_state,
        transactions::{CreateSweepTransactionError, PipelineRequest, SweepRequest, SweptDeposit},
    },
    sweeper_contract::{SweepItem, encode_sweep_erc20_batch},
    tx::{Authorization, GasFeeEstimate, lazy_refresh_gas_fee_estimate},
    withdraw::{
        fetch_finalized_receipts, finalized_transaction_count, latest_transaction_count,
        send_signed_transactions,
    },
};
use futures::future::join_all;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use std::collections::BTreeSet;

/// Deposits swept in one transaction. Bounded by gas: each one adds an authorization, a delegated
/// call, an approval and a transfer.
const MAX_DEPOSITS_PER_SWEEP: usize = 20;

const SWEEP_REQUESTS_BATCH_SIZE: usize = 5;
const SWEEP_TRANSACTIONS_TO_SIGN_BATCH_SIZE: usize = 5;
const SWEEP_TRANSACTIONS_TO_SEND_BATCH_SIZE: usize = 5;

pub async fn process_sweeper_transactions() {
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

    if read_state(|s| !s.sweeper_transactions.has_pending_requests()) {
        return;
    }

    let Some(sender) = read_state(State::sweeper_address) else {
        log!(
            DEBUG,
            "[process_sweeper_transactions]: SKIPPING: the sweeper address is unknown (ECDSA public key not cached yet)"
        );
        return;
    };

    let gas_fee_estimate = match lazy_refresh_gas_fee_estimate().await {
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
            schedule_retry();
            return;
        }
    };

    let latest_transaction_count = latest_transaction_count(sender).await;
    resubmit_transactions_batch(latest_transaction_count, &gas_fee_estimate).await;
    create_transactions_batch(&gas_fee_estimate);
    sign_transactions_batch().await;
    send_transactions_batch(sender, latest_transaction_count).await;
    finalize_transactions_batch(sender).await;

    if read_state(|s| s.sweeper_transactions.has_pending_requests()) {
        schedule_retry();
    }
}

fn schedule_retry() {
    ic_cdk_timers::set_timer(crate::PROCESS_SWEEPER_TRANSACTIONS_RETRY_INTERVAL, async {
        process_sweeper_transactions().await
    });
}

async fn resubmit_transactions_batch(
    latest_transaction_count: Option<TransactionCount>,
    gas_fee_estimate: &GasFeeEstimate,
) {
    if read_state(|s| s.sweeper_transactions.is_sent_tx_empty()) {
        return;
    }
    let Some(latest_transaction_count) = latest_transaction_count else {
        return;
    };
    let transactions_to_resubmit = read_state(|s| {
        s.sweeper_transactions
            .create_resubmit_transactions(latest_transaction_count, gas_fee_estimate.clone())
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

fn create_transactions_batch(gas_fee_estimate: &GasFeeEstimate) {
    for request in read_state(|s| {
        s.sweeper_transactions
            .requests_batch(SWEEP_REQUESTS_BATCH_SIZE)
    }) {
        let ethereum_network = read_state(State::ethereum_network);
        let nonce = read_state(|s| s.sweeper_transactions.next_transaction_nonce());
        let sweep_id = request.id;
        match request.create_transaction(
            nonce,
            gas_fee_estimate.clone(),
            request.gas_limit(),
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
                mutate_state(|s| s.sweeper_transactions.reschedule_request(sweep_id));
            }
        }
    }
}

async fn sign_transactions_batch() {
    let transactions_batch: Vec<_> = read_state(|s| {
        s.sweeper_transactions
            .transactions_to_sign_batch(SWEEP_TRANSACTIONS_TO_SIGN_BATCH_SIZE)
    });
    let results = join_all(
        transactions_batch
            .into_iter()
            .map(|(sweep_id, tx)| async move {
                (
                    sweep_id,
                    crate::tx::sign(tx, sweeper_derivation_path()).await,
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
        s.sweeper_transactions.transactions_to_send_batch(
            latest_transaction_count,
            SWEEP_TRANSACTIONS_TO_SEND_BATCH_SIZE,
        )
    });
    send_signed_transactions(sender, &transactions_to_send).await;
}

async fn finalize_transactions_batch(sender: Address) {
    if read_state(|s| s.sweeper_transactions.is_sent_tx_empty()) {
        return;
    }
    match finalized_transaction_count(sender).await {
        Ok(finalized_tx_count) => {
            let txs_to_finalize = read_state(|s| {
                s.sweeper_transactions
                    .sent_transactions_to_finalize(&finalized_tx_count)
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

/// Enqueue a single sweep of everything the balance scan has queued, up to
/// [`MAX_DEPOSITS_PER_SWEEP`] deposits.
///
/// Each deposit contributes an ownership attestation, and each address that is not delegated yet
/// also contributes an EIP-7702 authorization — so the first sweep of an address rides a type-`0x04`
/// transaction and later ones a plain type-`0x02`. An authorization pins the address' nonce, which
/// is `0` for a deposit EOA: incoming ERC-20 transfers never touch it, and only one of its own
/// authorizations can advance it.
pub async fn enqueue_batched_sweep() {
    let _guard = match TimerGuard::new(TaskType::SweeperSend) {
        Ok(guard) => guard,
        Err(e) => {
            log!(
                DEBUG,
                "Failed retrieving timer guard to enqueue a batched sweep: {e:?}",
            );
            return;
        }
    };

    let Some(sweeper_contract) = read_state(|s| s.sweeper_contract_address) else {
        log!(
            DEBUG,
            "[enqueue_batched_sweep]: SKIPPING: no sweeper contract address is configured"
        );
        return;
    };
    let targets: Vec<_> = read_state(|s| {
        s.automatic_deposits
            .sweep_targets_iter()
            .take(MAX_DEPOSITS_PER_SWEEP)
            .collect()
    });
    if targets.is_empty() {
        return;
    }

    let chain_id = read_state(State::ethereum_network).chain_id();
    let mut items = Vec::with_capacity(targets.len());
    let mut deposits = Vec::with_capacity(targets.len());
    let mut authorizations = Vec::new();
    for target in targets {
        let account = target.account();
        let Some(request) = read_state(|s| s.attestation_request(account)) else {
            log!(
                DEBUG,
                "[enqueue_batched_sweep]: SKIPPING: no deposit helper with subaccount is configured"
            );
            return;
        };
        // An attestation is signed once per address and reused by every later sweep: it names the
        // account and the helper, neither of which this sweep changes.
        let attestation = match read_state(|s| s.attestation(account).cloned()) {
            Some(attestation) => attestation,
            None => match sign_attestation(&request).await {
                Ok(attestation) => {
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::AttestedDepositAddress {
                                request: request.clone(),
                                signature: attestation.clone(),
                            },
                        )
                    });
                    attestation
                }
                Err(e) => {
                    log!(
                        INFO,
                        "[enqueue_batched_sweep]: failed attesting {account:?}, skipping the whole sweep: {e}"
                    );
                    return;
                }
            },
        };
        let delegating = !read_state(|s| s.automatic_deposits.is_delegated(&target.address()));
        if delegating {
            let authorization = Authorization {
                chain_id,
                delegate: sweeper_contract,
                nonce: TransactionNonce::ZERO,
            };
            match authorization
                .sign(deposit_derivation_path(
                    DepositAddressSchema::CkErc20,
                    &account,
                ))
                .await
            {
                Ok(authorization) => authorizations.push(authorization),
                Err(e) => {
                    log!(
                        INFO,
                        "[enqueue_batched_sweep]: failed authorizing {account:?}, skipping the whole sweep: {e}"
                    );
                    return;
                }
            }
        }
        items.push(SweepItem {
            deposit: target.address(),
            account,
            attestation,
        });
        deposits.push(SweptDeposit {
            owner: account.owner,
            subaccount: account.subaccount,
            erc20_contract_address: target.token(),
            address: target.address(),
            delegating,
        });
    }

    let tokens: Vec<_> = deposits
        .iter()
        .map(|deposit| deposit.erc20_contract_address)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut request = SweepRequest {
        id: read_state(|s| s.next_sweep_id),
        destination: sweeper_contract,
        amount: Wei::ZERO,
        data: encode_sweep_erc20_batch(&items, &tokens),
        max_transaction_fee: Wei::ZERO,
        created_at: ic_cdk::api::time(),
        authorizations,
        deposits,
    };
    // What this sweep may spend on gas, and the ceiling its transaction is priced at. Taken from
    // the estimate now rather than left open: an unbounded allowance would price the transaction
    // above anything the sweeper address could pay, and the pipeline refuses to send a sweep whose
    // allowance the fee has outgrown, so it waits for a cheaper block instead.
    // TODO(DEFI-2933): gate this on the gas the sweeper address has actually been prepaid.
    let Some(gas_fee_estimate) = lazy_refresh_gas_fee_estimate().await else {
        log!(
            INFO,
            "[enqueue_batched_sweep]: SKIPPING: failed retrieving gas fee estimate"
        );
        return;
    };
    request.max_transaction_fee = gas_fee_estimate
        .to_price(request.gas_limit())
        .max_transaction_fee();
    log!(
        INFO,
        "[enqueue_batched_sweep]: sweeping {} deposits, {} of them delegating, via {sweeper_contract}",
        request.deposits.len(),
        request.authorizations.len()
    );
    mutate_state(|s| process_event(s, EventType::AcceptedSweepRequest(request)));
}
