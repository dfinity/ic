use crate::eth_rpc::Hash;
use crate::{
    MAIN_DERIVATION_PATH,
    eth_logs::LedgerSubaccount,
    eth_rpc_client::{
        AnyOf, MIN_ATTACHED_CYCLES, MinByKey, MultiCallError, NoReduction, ToReducedWithStrategy,
        rpc_client,
    },
    guard::TimerGuard,
    logs::{DEBUG, INFO},
    numeric::{GasAmount, LedgerMintIndex, TransactionCount},
    runtime::CanisterRuntime,
    state::{
        State, TaskType,
        audit::{EventType, process_event},
        minter_address, mutate_state, read_state,
        transactions::{
            CreateTransactionError, PipelineRequest, Reimbursed, ReimbursementIndex,
            ReimbursementRequest, WithdrawalRequest,
        },
    },
    time::TimeProvider,
    tx::{GasFeeEstimate, SignableTransaction, Signed, lazy_refresh_gas_fee_estimate},
};
use candid::Nat;
use evm_rpc_types::{
    BlockTag, SendRawTransactionStatus, TransactionReceipt as EvmTransactionReceipt,
};
use futures::future::join_all;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg},
};
use num_traits::ToPrimitive;
use scopeguard::ScopeGuard;
use std::{
    collections::{BTreeMap, BTreeSet},
    iter::zip,
};

const WITHDRAWAL_REQUESTS_BATCH_SIZE: usize = 5;
const TRANSACTIONS_TO_SIGN_BATCH_SIZE: usize = 5;
const TRANSACTIONS_TO_SEND_BATCH_SIZE: usize = 5;

pub const CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(21_000);
pub const CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT: GasAmount = GasAmount::new(65_000);

pub async fn process_reimbursement<T: TimeProvider>(time_provider: &T) {
    let _guard = match TimerGuard::new(TaskType::Reimbursement) {
        Ok(guard) => guard,
        Err(e) => {
            log!(DEBUG, "Failed retrieving reimbursement guard: {e:?}",);
            return;
        }
    };

    let reimbursements: Vec<(ReimbursementIndex, ReimbursementRequest)> = read_state(|s| {
        s.withdrawal_transactions
            .reimbursement_requests_iter()
            .map(|(index, request)| (index.clone(), request.clone()))
            .collect()
    });
    if reimbursements.is_empty() {
        return;
    }

    let mut error_count = 0;

    for (index, reimbursement_request) in reimbursements {
        // Ensure that even if we were to panic in the callback, after having contacted the ledger to mint the tokens,
        // this reimbursement request will not be processed again.
        let prevent_double_minting_guard = scopeguard::guard(index.clone(), |index| {
            mutate_state(|s| {
                process_event(
                    s,
                    EventType::QuarantinedReimbursement { index },
                    time_provider,
                )
            });
        });
        let ledger_canister_id = match index {
            ReimbursementIndex::CkEth { .. } => read_state(|s| s.cketh_ledger_id),
            ReimbursementIndex::CkErc20 { ledger_id, .. } => ledger_id,
        };
        let client = ICRC1Client {
            runtime: CdkRuntime,
            ledger_canister_id,
        };
        let memo = Memo::from(reimbursement_request.clone());
        let args = TransferArg {
            from_subaccount: None,
            to: Account {
                owner: reimbursement_request.to,
                subaccount: reimbursement_request
                    .to_subaccount
                    .map(LedgerSubaccount::to_bytes),
            },
            fee: None,
            created_at_time: None,
            memo: Some(memo),
            amount: Nat::from(reimbursement_request.reimbursed_amount),
        };
        let block_index = match client.transfer(args).await {
            Ok(Ok(block_index)) => block_index
                .0
                .to_u64()
                .expect("block index should fit into u64"),
            Ok(Err(err)) => {
                log!(INFO, "[process_reimbursement] Failed to mint ckETH {err}");
                error_count += 1;
                // minting failed, defuse guard
                ScopeGuard::into_inner(prevent_double_minting_guard);
                continue;
            }
            Err(err) => {
                log!(
                    INFO,
                    "[process_reimbursement] Failed to send a message to the ledger ({ledger_canister_id}): {err:?}"
                );
                error_count += 1;
                // minting failed, defuse guard
                ScopeGuard::into_inner(prevent_double_minting_guard);
                continue;
            }
        };
        let reimbursed = Reimbursed {
            burn_in_block: reimbursement_request.ledger_burn_index,
            reimbursed_in_block: LedgerMintIndex::new(block_index),
            reimbursed_amount: reimbursement_request.reimbursed_amount,
            transaction_hash: reimbursement_request.transaction_hash,
        };
        let event = match index {
            ReimbursementIndex::CkEth {
                ledger_burn_index: _,
            } => EventType::ReimbursedEthWithdrawal(reimbursed),
            ReimbursementIndex::CkErc20 {
                cketh_ledger_burn_index,
                ledger_id,
                ckerc20_ledger_burn_index: _,
            } => EventType::ReimbursedErc20Withdrawal {
                cketh_ledger_burn_index,
                ckerc20_ledger_id: ledger_id,
                reimbursed,
            },
        };
        mutate_state(|s| process_event(s, event, time_provider));
        // minting succeeded, defuse guard
        ScopeGuard::into_inner(prevent_double_minting_guard);
    }
    if error_count > 0 {
        log!(
            INFO,
            "[process_reimbursement] Failed to reimburse {error_count} users, retrying later."
        );
    }
}

pub async fn process_retrieve_eth_requests<R: CanisterRuntime>(runtime: R) {
    let _guard = match TimerGuard::new(TaskType::RetrieveEth) {
        Ok(guard) => guard,
        Err(e) => {
            log!(
                DEBUG,
                "Failed retrieving timer guard to process ETH requests: {e:?}",
            );
            return;
        }
    };

    if read_state(|s| !s.withdrawal_transactions.has_pending_requests()) {
        return;
    }

    let gas_fee_estimate = match lazy_refresh_gas_fee_estimate(&runtime).await {
        Some(gas_fee_estimate) => gas_fee_estimate,
        None => {
            log!(
                INFO,
                "Failed retrieving gas fee estimate to process ETH requests",
            );
            return;
        }
    };

    let sender = minter_address(&runtime).await;
    let latest_transaction_count = latest_transaction_count(sender).await;
    resubmit_transactions_batch(latest_transaction_count, &gas_fee_estimate, &runtime).await;
    create_transactions_batch(gas_fee_estimate, &runtime);
    sign_transactions_batch(&runtime).await;
    send_transactions_batch(sender, latest_transaction_count).await;
    finalize_transactions_batch(sender, &runtime).await;

    if read_state(|s| s.withdrawal_transactions.has_pending_requests()) {
        ic_cdk_timers::set_timer(
            crate::PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL,
            async move { process_retrieve_eth_requests(runtime).await },
        );
    }
}

/// The latest (unconfirmed) transaction count of `sender` on chain, used to gate resubmission and
/// sending.
pub(crate) async fn latest_transaction_count(sender: Address) -> Option<TransactionCount> {
    match read_state(rpc_client)
        .get_transaction_count((sender.into_bytes(), BlockTag::Latest))
        .with_cycles(MIN_ATTACHED_CYCLES)
        .try_send()
        .await
        .map(|res| res.map(TransactionCount::from))
        .reduce_with_strategy(MinByKey::new(|count: &TransactionCount| *count))
    {
        Ok(transaction_count) => Some(transaction_count),
        Err(e) => {
            log!(
                INFO,
                "Failed to get the latest transaction count of {sender}: {e:?}"
            );
            None
        }
    }
}
async fn resubmit_transactions_batch<T: TimeProvider>(
    latest_transaction_count: Option<TransactionCount>,
    gas_fee_estimate: &GasFeeEstimate,
    time_provider: &T,
) {
    if read_state(|s| s.withdrawal_transactions.is_sent_tx_empty()) {
        return;
    }
    let latest_transaction_count = match latest_transaction_count {
        Some(latest_transaction_count) => latest_transaction_count,
        None => {
            return;
        }
    };
    let transactions_to_resubmit = read_state(|s| {
        s.withdrawal_transactions
            .create_resubmit_transactions(latest_transaction_count, gas_fee_estimate.clone())
    });
    for result in transactions_to_resubmit {
        match result {
            Ok((withdrawal_id, transaction)) => {
                log!(
                    INFO,
                    "[resubmit_transactions_batch]: transactions to resubmit {transaction:?}"
                );
                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::ReplacedTransaction {
                            withdrawal_id,
                            transaction,
                        },
                        time_provider,
                    )
                });
            }
            Err(e) => {
                log!(INFO, "Failed to resubmit transaction: {e:?}");
            }
        }
    }
}

fn create_transactions_batch<T: TimeProvider>(gas_fee_estimate: GasFeeEstimate, time_provider: &T) {
    for request in read_state(|s| {
        s.withdrawal_transactions
            .requests_batch(WITHDRAWAL_REQUESTS_BATCH_SIZE)
    }) {
        log!(DEBUG, "[create_transactions_batch]: processing {request:?}",);
        let ethereum_network = read_state(State::ethereum_network);
        let nonce = read_state(|s| s.withdrawal_transactions.next_transaction_nonce());
        let gas_limit = estimate_gas_limit(&request);
        match request.create_transaction(
            nonce,
            gas_fee_estimate.clone(),
            gas_limit,
            ethereum_network,
        ) {
            Ok(transaction) => {
                log!(
                    DEBUG,
                    "[create_transactions_batch]: created transaction {transaction:?}",
                );

                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::CreatedTransaction {
                            withdrawal_id: request.cketh_ledger_burn_index(),
                            transaction,
                        },
                        time_provider,
                    );
                });
            }
            Err(CreateTransactionError::InsufficientTransactionFee {
                cketh_ledger_burn_index: ledger_burn_index,
                allowed_max_transaction_fee: withdrawal_amount,
                actual_max_transaction_fee: max_transaction_fee,
            }) => {
                log!(
                    INFO,
                    "[create_transactions_batch]: Withdrawal request with burn index {ledger_burn_index} has insufficient amount {withdrawal_amount:?} to cover transaction fees: {max_transaction_fee:?}. Request moved back to end of queue."
                );
                mutate_state(|s| {
                    s.withdrawal_transactions
                        .reschedule_request(ledger_burn_index)
                });
            }
        };
    }
}

pub fn estimate_gas_limit(withdrawal_request: &WithdrawalRequest) -> GasAmount {
    match withdrawal_request {
        WithdrawalRequest::CkEth(_) | WithdrawalRequest::SweeperFunding(_) => {
            CKETH_WITHDRAWAL_TRANSACTION_GAS_LIMIT
        }
        WithdrawalRequest::CkErc20(_) => CKERC20_WITHDRAWAL_TRANSACTION_GAS_LIMIT,
    }
}

async fn sign_transactions_batch<R: CanisterRuntime>(runtime: &R) {
    let transactions_batch: Vec<_> = read_state(|s| {
        s.withdrawal_transactions
            .transactions_to_sign_batch(TRANSACTIONS_TO_SIGN_BATCH_SIZE)
    });
    log!(DEBUG, "Signing transactions {transactions_batch:?}");
    let results = join_all(
        transactions_batch
            .into_iter()
            .map(|(withdrawal_id, tx)| async move {
                (
                    withdrawal_id,
                    crate::tx::sign(tx, MAIN_DERIVATION_PATH, runtime).await,
                )
            }),
    )
    .await;
    let mut errors = Vec::new();
    for (withdrawal_id, result) in results {
        match result {
            Ok(transaction) => mutate_state(|s| {
                process_event(
                    s,
                    EventType::SignedTransaction {
                        withdrawal_id,
                        transaction,
                    },
                    runtime,
                )
            }),
            Err(e) => errors.push(e),
        }
    }
    if !errors.is_empty() {
        // At this point there might be a gap in transaction nonces between signed transactions, e.g.,
        // transactions 1,2,4,5 were signed, but 3 was not due to some unexpected error.
        // This means that transactions 4 and 5 are currently stuck until transaction 3 is signed.
        // However, we still proceed with transactions 4 and 5 since that way they might be mined faster
        // once transaction 3 is sent on the next iteration. Otherwise, we would need to re-sign transactions 4 and 5
        // and send them (together with transaction 3) on the next iteration.
        log!(INFO, "Errors encountered during signing: {errors:?}");
    }
}
async fn send_transactions_batch(
    sender: Address,
    latest_transaction_count: Option<TransactionCount>,
) {
    let latest_transaction_count = match latest_transaction_count {
        Some(latest_transaction_count) => latest_transaction_count,
        None => {
            return;
        }
    };
    let transactions_to_send: Vec<_> = read_state(|s| {
        s.withdrawal_transactions
            .transactions_to_send_batch(latest_transaction_count, TRANSACTIONS_TO_SEND_BATCH_SIZE)
    });
    send_signed_transactions(sender, &transactions_to_send).await;
}

/// Broadcast already-signed transactions via the EVM RPC canister. Sender- and
/// transaction-type-agnostic, so both the main-address withdrawal pipeline (type `0x02`) and the
/// sweeper-address pipeline (type `0x02` or `0x04`) reuse it.
pub(crate) async fn send_signed_transactions<T: SignableTransaction + std::fmt::Debug>(
    sender: Address,
    transactions_to_send: &[Signed<T>],
) {
    let rpc_client = read_state(rpc_client);
    let results = join_all(transactions_to_send.iter().map(async |tx| {
        rpc_client
            .send_raw_transaction(tx.raw_transaction_bytes())
            .with_cycles(MIN_ATTACHED_CYCLES)
            .try_send()
            .await
            .reduce_with_strategy(AnyOf)
    }))
    .await;

    for (signed_tx, result) in zip(transactions_to_send, results) {
        log!(
            DEBUG,
            "Sent transaction from {sender} {signed_tx:?}: {result:?}"
        );
        match result {
            Ok(SendRawTransactionStatus::Ok(_)) | Ok(SendRawTransactionStatus::NonceTooLow) => {
                // In case of resubmission we may hit the case of SendRawTransactionStatus::NonceTooLow
                // if the stuck transaction was mined in the meantime.
                // It will be cleaned-up once the transaction is finalized.
            }
            Ok(SendRawTransactionStatus::InsufficientFunds)
            | Ok(SendRawTransactionStatus::NonceTooHigh) => log!(
                INFO,
                "Failed to send transaction from {sender} {signed_tx:?}: {result:?}. Will retry later.",
            ),
            Err(e) => {
                log!(
                    INFO,
                    "Failed to send transaction from {sender} {signed_tx:?}: {e:?}. Will retry later."
                )
            }
        };
    }
}

async fn finalize_transactions_batch<T: TimeProvider>(sender: Address, time_provider: &T) {
    if read_state(|s| s.withdrawal_transactions.is_sent_tx_empty()) {
        return;
    }

    match finalized_transaction_count(sender).await {
        Ok(finalized_tx_count) => {
            let txs_to_finalize = read_state(|s| {
                s.withdrawal_transactions
                    .sent_transactions_to_finalize(&finalized_tx_count)
            });
            if let Some(receipts) = fetch_finalized_receipts(txs_to_finalize).await {
                for (withdrawal_id, transaction_receipt) in receipts {
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::FinalizedTransaction {
                                withdrawal_id,
                                transaction_receipt: transaction_receipt.into(),
                            },
                            time_provider,
                        );
                    });
                }
            }
        }

        Err(e) => {
            log!(INFO, "Failed to get finalized transaction count: {e:?}");
        }
    }
}

/// Fetch the finalized receipts for the given (transaction hash → pipeline id) map. Returns `None` when
/// the batch should be retried later (a receipt fetch failed, or the same hash came back with two
/// different receipts). On success the map is keyed by pipeline id, and its keys are asserted to be
/// exactly the ids expected to finalize. Sender/id-agnostic, so both pipelines reuse it.
pub(crate) async fn fetch_finalized_receipts<Id: Copy + Ord + std::fmt::Debug>(
    txs_to_finalize: BTreeMap<Hash, Id>,
) -> Option<BTreeMap<Id, EvmTransactionReceipt>> {
    let expected_finalized_ids: BTreeSet<Id> = txs_to_finalize.values().copied().collect();
    let rpc_client = read_state(rpc_client);
    let results = join_all(txs_to_finalize.keys().map(async |hash| {
        rpc_client
            .get_transaction_receipt(*hash)
            .with_cycles(MIN_ATTACHED_CYCLES)
            .try_send()
            .await
            .reduce_with_strategy(NoReduction)
    }))
    .await;
    let mut receipts: BTreeMap<Id, EvmTransactionReceipt> = BTreeMap::new();
    for ((hash, id), result) in zip(txs_to_finalize, results) {
        match result {
            Ok(Some(receipt)) => {
                log!(
                    DEBUG,
                    "Received transaction receipt {receipt:?} for transaction {hash} and id {id:?}"
                );
                match receipts.get(&id) {
                    // by construction we never query twice the same transaction hash, which is a field in TransactionReceipt.
                    Some(existing_receipt) => {
                        log!(
                            INFO,
                            "ERROR: received different receipts for transaction {hash} with id {id:?}: {existing_receipt:?} and {receipt:?}. Will retry later"
                        );
                        return None;
                    }
                    None => {
                        receipts.insert(id, receipt);
                    }
                }
            }
            Ok(None) => {
                log!(
                    DEBUG,
                    "Transaction {hash} for id {id:?} was not mined, it's probably a resubmitted transaction",
                )
            }
            Err(e) => {
                log!(
                    INFO,
                    "Failed to get transaction receipt for {hash} and id {id:?}: {e:?}. Will retry later",
                );
                return None;
            }
        }
    }
    let actual_finalized_ids: BTreeSet<Id> = receipts.keys().copied().collect();
    assert_eq!(
        expected_finalized_ids, actual_finalized_ids,
        "ERROR: unexpected transaction receipts for some ids"
    );
    Some(receipts)
}

pub(crate) async fn finalized_transaction_count(
    sender: Address,
) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
    read_state(rpc_client)
        .get_transaction_count((sender.into_bytes(), BlockTag::Finalized))
        .with_cycles(MIN_ATTACHED_CYCLES)
        .try_send()
        .await
        .map(|res| res.map(TransactionCount::from))
        .reduce_with_strategy(NoReduction)
}
