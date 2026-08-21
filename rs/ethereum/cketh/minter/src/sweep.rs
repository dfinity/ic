//! Sending transactions **from the minter's dedicated sweeper address** on the sweeper's own nonce
//! sequence, so a stuck sweep can never head-of-line-block a withdrawal on the main address'
//! pipeline.
//!
//! This is the preparatory send-pipeline: it drives the sweeper [`TransactionPipeline`] through the same
//! create → sign → send → resubmit → finalize state machine as user withdrawals
//! ([`crate::withdraw`]), reusing that module's sender-agnostic RPC helpers
//! (`latest_transaction_count`, `finalized_transaction_count`, `send_signed_transactions`,
//! `fetch_finalized_receipts`), but signing with the sweeper derivation path (`[3]`) and reading
//! the sweeper address' own transaction count.
//!
//! Deliberately out of scope here (follow-ups): EIP-7702 (`0x04`) first-time delegation, building
//! the delegate sweep call data from the balance-sweep queue, and gating the pipeline on prepaid sweep
//! gas. Nothing enqueues a [`SweepRequest`] in production yet, so this task early-returns on an
//! empty pipeline.

use crate::{
    deposit_address::sweeper_derivation_path,
    guard::TimerGuard,
    logs::{DEBUG, INFO},
    numeric::{GasAmount, TransactionCount},
    state::{
        State, TaskType,
        audit::{EventType, process_event},
        mutate_state, read_state,
        transactions::PipelineRequest,
    },
    tx::{GasFeeEstimate, lazy_refresh_gas_fee_estimate},
    withdraw::{
        fetch_finalized_receipts, finalized_transaction_count, latest_transaction_count,
        send_signed_transactions,
    },
};
use futures::future::join_all;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use ic_management_canister_types_private::DerivationPath;

/// Gas limit of a sweep transaction. A fixed, conservative bound for the preparatory type-`0x02`
/// pipeline; a per-request estimate arrives with the real delegate sweep call.
pub(crate) const SWEEP_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(100_000);

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
            log!(
                INFO,
                "[process_sweeper_transactions]: failed retrieving gas fee estimate",
            );
            return;
        }
    };

    let latest_transaction_count = latest_transaction_count(sender).await;
    resubmit_transactions_batch(latest_transaction_count, &gas_fee_estimate).await;
    create_transactions_batch(&gas_fee_estimate);
    sign_transactions_batch().await;
    send_transactions_batch(latest_transaction_count).await;
    finalize_transactions_batch(sender).await;

    if read_state(|s| s.sweeper_transactions.has_pending_requests()) {
        ic_cdk_timers::set_timer(
            crate::PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL,
            async { process_sweeper_transactions().await },
        );
    }
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
        // `SweepRequest::Error` is `Infallible`: a sweep funds its own gas, so there is no
        // insufficient-fee case to handle here.
        let Ok(transaction) = request.create_transaction(
            nonce,
            gas_fee_estimate.clone(),
            SWEEP_TRANSACTION_GAS_LIMIT,
            ethereum_network,
        );
        mutate_state(|s| {
            process_event(
                s,
                EventType::CreatedSweeperTransaction {
                    sweep_id: request.id,
                    transaction,
                },
            );
        });
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
                    crate::tx::sign(tx, DerivationPath::new(sweeper_derivation_path())).await,
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
                "[process_sweeper_transactions]: error signing sweep {sweep_id}: {e:?}"
            ),
        }
    }
}

async fn send_transactions_batch(latest_transaction_count: Option<TransactionCount>) {
    let Some(latest_transaction_count) = latest_transaction_count else {
        return;
    };
    let transactions_to_send: Vec<_> = read_state(|s| {
        s.sweeper_transactions.transactions_to_send_batch(
            latest_transaction_count,
            SWEEP_TRANSACTIONS_TO_SEND_BATCH_SIZE,
        )
    });
    send_signed_transactions(&transactions_to_send).await;
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
