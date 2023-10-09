use crate::eth_rpc::JsonRpcResult;
use crate::eth_rpc::{
    BlockSpec, BlockTag, FeeHistory, FeeHistoryParams, Quantity, SendRawTransactionResult,
};
use crate::eth_rpc_client::requests::GetTransactionCountParams;
use crate::eth_rpc_client::responses::TransactionReceipt;
use crate::eth_rpc_client::EthRpcClient;
use crate::eth_rpc_client::MultiCallError;
use crate::guard::TimerGuard;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{LedgerBurnIndex, TransactionCount};
use crate::state::{mutate_state, read_state, State, TaskType};
use crate::transactions::{create_transaction, CreateTransactionError};
use crate::tx::{estimate_transaction_price, TransactionPrice};
use futures::future::join_all;
use ic_canister_log::log;
use std::collections::{BTreeMap, BTreeSet};
use std::iter::zip;

pub async fn eth_fee_history() -> FeeHistory {
    read_state(EthRpcClient::from_state)
        .eth_fee_history(FeeHistoryParams {
            block_count: Quantity::from(5_u8),
            highest_block: BlockSpec::Tag(BlockTag::Latest),
            reward_percentiles: vec![20],
        })
        .await
        .expect("HTTP call failed")
        .unwrap()
}

pub async fn latest_transaction_count() -> Result<TransactionCount, MultiCallError<TransactionCount>>
{
    read_state(EthRpcClient::from_state)
        .eth_get_transaction_count(GetTransactionCountParams {
            address: crate::state::minter_address().await,
            block: BlockSpec::Tag(BlockTag::Latest),
        })
        .await
        .reduce_with_min_by_key(|transaction_count| *transaction_count)
}

pub async fn finalized_transaction_count(
) -> Result<TransactionCount, MultiCallError<TransactionCount>> {
    read_state(EthRpcClient::from_state)
        .eth_get_transaction_count(GetTransactionCountParams {
            address: crate::state::minter_address().await,
            block: BlockSpec::Tag(BlockTag::Finalized),
        })
        .await
        .reduce_with_equality()
}

pub async fn finalize_transactions_batch() {
    if read_state(|s| s.eth_transactions.is_sent_tx_empty()) {
        return;
    }

    match finalized_transaction_count().await {
        Ok(finalized_tx_count) => {
            let txs_to_finalize = read_state(|s| {
                s.eth_transactions
                    .sent_transactions_to_finalize(&finalized_tx_count)
            });
            let expected_finalized_withdrawal_ids: BTreeSet<_> =
                txs_to_finalize.values().cloned().collect();
            let rpc_client = read_state(EthRpcClient::from_state);
            let results = join_all(
                txs_to_finalize
                    .keys()
                    .map(|hash| rpc_client.eth_get_transaction_receipt(*hash)),
            )
            .await;
            let mut receipts: BTreeMap<LedgerBurnIndex, TransactionReceipt> = BTreeMap::new();
            for ((hash, withdrawal_id), result) in zip(txs_to_finalize, results) {
                match result {
                    Ok(Some(receipt)) => {
                        log!(DEBUG, "Received transaction receipt {receipt:?} for transaction {hash} and withdrawal ID {withdrawal_id}");
                        match receipts.get(&withdrawal_id) {
                            // by construction we never query twice the same transaction hash, which is a field in TransactionReceipt.
                            Some(existing_receipt) => {
                                log!(INFO, "ERROR: received different receipts for transaction {hash} with withdrawal ID {withdrawal_id}: {existing_receipt:?} and {receipt:?}. Will retry later");
                                return;
                            }
                            None => {
                                receipts.insert(withdrawal_id, receipt);
                            }
                        }
                    }
                    Ok(None) => {
                        log!(
                            DEBUG,
                            "Transaction {hash} for withdrawal ID {withdrawal_id} was not mined, it's probably a resubmitted transaction",
                        )
                    }
                    Err(e) => {
                        log!(
                            INFO,
                            "Failed to get transaction receipt for {hash} and withdrawal ID {withdrawal_id}: {e:?}. Will retry later",
                        );
                        return;
                    }
                }
            }
            let actual_finalized_withdrawal_ids: BTreeSet<_> = receipts.keys().cloned().collect();
            assert_eq!(
                expected_finalized_withdrawal_ids, actual_finalized_withdrawal_ids,
                "ERROR: unexpected transaction receipts for some withdrawal IDs"
            );
            for (withdrawal_id, receipt) in receipts {
                mutate_state(|s| {
                    s.eth_transactions
                        .record_finalized_transaction(withdrawal_id, receipt)
                });
            }
        }

        Err(e) => {
            log!(INFO, "Failed to get finalized transaction count: {e:?}");
        }
    }
}

pub async fn send_transactions_batch() {
    let signed_transactions: Vec<_> = read_state(|s| {
        s.eth_transactions
            .signed_transactions_iter()
            .map(|(_nonce, _index, tx)| tx)
            .cloned()
            .collect()
    });

    let rpc_client = read_state(EthRpcClient::from_state);
    let results = join_all(
        signed_transactions
            .iter()
            .map(|tx| rpc_client.eth_send_raw_transaction(tx.raw_transaction_hex())),
    )
    .await;

    for (signed_tx, result) in zip(signed_transactions, results) {
        log!(DEBUG, "Sent transaction {signed_tx:?}: {result:?}");
        match result {
            Ok(JsonRpcResult::Result(tx_result)) if tx_result == SendRawTransactionResult::Ok => {
                 mutate_state(|s| {
                    s.eth_transactions
                        .record_sent_transaction(signed_tx)
                });
            }
            Ok(JsonRpcResult::Result(tx_result)) if tx_result == SendRawTransactionResult::NonceTooLow => {
                // In case of resubmission we may hit the case of SendRawTransactionResult::NonceTooLow
                // if the stuck transaction was mined in the meantime. In that case we
                // add the resubmitted transaction to sent_tx to keep a trace of it.
                // It will be cleaned-up once the transaction is finalized.
                mutate_state(|s| {
                    s.eth_transactions
                        .record_sent_transaction(signed_tx)
                });
            }
            Ok(JsonRpcResult::Result(tx_result)) => log!(INFO,
                "Failed to send transaction {signed_tx:?}: {tx_result:?}. Will retry later.",
            ),
            Ok(JsonRpcResult::Error { code, message }) => log!(INFO,
                "Failed to send transaction {signed_tx:?}: {message} (error code = {code}). Will retry later.",
            ),
            Err(e) => {
                log!(INFO, "Failed to send transaction {signed_tx:?}: {e:?}. Will retry later.")
            }
        };
    }
}

fn create_transactions_batch(transaction_price: TransactionPrice) {
    for request in read_state(|s| s.eth_transactions.withdrawal_requests_batch(5)) {
        log!(DEBUG, "[create_transactions_batch]: processing {request:?}",);
        let ethereum_network = read_state(State::ethereum_network);
        let nonce = read_state(|s| s.eth_transactions.next_transaction_nonce());
        match create_transaction(&request, nonce, transaction_price.clone(), ethereum_network) {
            Ok(tx) => {
                log!(
                    DEBUG,
                    "[create_transactions_batch]: created transaction {tx:?}",
                );

                mutate_state(|s| s.eth_transactions.record_created_transaction(request, tx));
            }
            Err(CreateTransactionError::InsufficientAmount {
                ledger_burn_index,
                withdrawal_amount,
                max_transaction_fee,
            }) => {
                log!(
                    INFO,
                    "[create_transactions_batch]: Withdrawal request with burn index {ledger_burn_index} has insufficient
                amount {withdrawal_amount:?} to cover transaction fees: {max_transaction_fee:?}.
                Request moved back to end of queue."
                );
                mutate_state(|s| s.eth_transactions.reschedule_withdrawal_request(request));
            }
        };
    }
}

pub async fn sign_transactions_batch() {
    let transactions_batch: Vec<_> = read_state(|s| {
        s.eth_transactions
            .created_transactions_iter()
            .map(|(_nonce, _ledger_burn_index, tx)| tx)
            .cloned()
            .collect()
    });
    log!(DEBUG, "Signing transactions {transactions_batch:?}");
    let results = join_all(transactions_batch.into_iter().map(|tx| tx.sign())).await;
    let mut errors = Vec::new();
    for result in results {
        match result {
            Ok(signed_tx) => {
                mutate_state(|s| s.eth_transactions.record_signed_transaction(signed_tx))
            }
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

pub async fn process_retrieve_eth_requests() {
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

    if read_state(|s| s.eth_transactions.nothing_to_process()) {
        return;
    }

    let transaction_price = estimate_transaction_price(&eth_fee_history().await);
    let max_transaction_fee = transaction_price.max_transaction_fee();
    log!(
        INFO,
        "[withdraw]: Estimated max transaction fee: {:?}",
        max_transaction_fee,
    );
    resubmit_transactions_batch(&transaction_price).await;
    create_transactions_batch(transaction_price);
    sign_transactions_batch().await;
    send_transactions_batch().await;
    finalize_transactions_batch().await;
}

pub async fn resubmit_transactions_batch(transaction_price: &TransactionPrice) {
    if read_state(|s| s.eth_transactions.is_sent_tx_empty()) {
        return;
    }
    match latest_transaction_count().await {
        Ok(latest_tx_count) => {
            let transactions_to_resubmit = read_state(|s| {
                s.eth_transactions
                    .create_resubmit_transactions(latest_tx_count, transaction_price.clone())
            });
            for tx in transactions_to_resubmit {
                match tx {
                    Ok(resubmit_tx) => {
                        log!(INFO, "[resubmit_transactions_batch]: transactions to resubmit {resubmit_tx:?}");
                        mutate_state(|s| {
                            s.eth_transactions.record_resubmit_transaction(resubmit_tx)
                        });
                    }
                    Err(e) => {
                        log!(INFO, "Failed to resubmit transaction: {e:?}");
                    }
                }
            }
        }
        Err(e) => {
            log!(INFO, "Failed to get latest transaction count: {e:?}");
        }
    }
}
