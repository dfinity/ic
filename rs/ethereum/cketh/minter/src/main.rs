use candid::{candid_method, Nat};
use futures::future::join_all;
use ic_canister_log::log;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_cketh_minter::address::{validate_address_as_destination, Address};
use ic_cketh_minter::endpoints::{
    Eip1559TransactionPrice, RetrieveEthRequest, RetrieveEthStatus, WithdrawalArg, WithdrawalError,
};
use ic_cketh_minter::eth_logs::{report_transaction_error, ReceivedEthEventError};
use ic_cketh_minter::eth_rpc::{FeeHistory, HttpOutcallResult};
use ic_cketh_minter::eth_rpc::{JsonRpcResult, SendRawTransactionResult};
use ic_cketh_minter::eth_rpc_client::EthRpcClient;
use ic_cketh_minter::guard::{retrieve_eth_guard, TimerGuard};
use ic_cketh_minter::lifecycle::MinterArg;
use ic_cketh_minter::logs::{DEBUG, INFO};
use ic_cketh_minter::numeric::{BlockNumber, LedgerBurnIndex, LedgerMintIndex, Wei};
use ic_cketh_minter::state::audit::{process_event, EventType};
use ic_cketh_minter::state::{
    lazy_call_ecdsa_public_key, mutate_state, read_state, State, TaskType, STATE,
};
use ic_cketh_minter::storage;
use ic_cketh_minter::transactions::{
    create_transaction, CreateTransactionError, EthWithdrawalRequest,
};
use ic_cketh_minter::tx::{
    estimate_transaction_price, ConfirmedEip1559Transaction, SignedEip1559TransactionRequest,
    TransactionPrice,
};
use ic_cketh_minter::{
    eth_logs, eth_rpc, MINT_RETRY_DELAY, PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL,
    SCRAPPING_ETH_LOGS_INTERVAL,
};
use ic_icrc1_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use std::cmp::{min, Ordering};
use std::iter::zip;
use std::str::FromStr;
use std::time::Duration;

mod dashboard;
pub const SEPOLIA_TEST_CHAIN_ID: u64 = 11155111;

#[init]
#[candid_method(init)]
fn init(arg: MinterArg) {
    match arg {
        MinterArg::InitArg(init_arg) => {
            log!(INFO, "[init]: initialized minter with arg: {:?}", init_arg);
            STATE.with(|cell| {
                storage::record_event(EventType::Init(init_arg.clone()));
                *cell.borrow_mut() =
                    Some(State::try_from(init_arg).expect("BUG: failed to initialize minter"))
            });
        }
        MinterArg::UpgradeArg(_) => {
            ic_cdk::trap("cannot init canister state with upgrade args");
        }
    }
    setup_timers();
}

fn setup_timers() {
    ic_cdk_timers::set_timer(Duration::from_secs(0), || {
        // Initialize the minter's public key to make the address known.
        ic_cdk::spawn(async {
            let _ = lazy_call_ecdsa_public_key().await;
        })
    });
    // Start scraping logs immediately after the install, then repeat with the interval.
    ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(scrap_eth_logs()));
    ic_cdk_timers::set_timer_interval(SCRAPPING_ETH_LOGS_INTERVAL, || {
        ic_cdk::spawn(scrap_eth_logs())
    });
    ic_cdk_timers::set_timer_interval(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, || {
        ic_cdk::spawn(process_retrieve_eth_requests())
    });
}

async fn scrap_eth_logs() {
    let _guard = match TimerGuard::new(TaskType::ScrapEthLogs) {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let contract_address = match read_state(|s| s.ethereum_contract_address) {
        Some(address) => address,
        None => {
            log!(
                DEBUG,
                "[scrap_eth_logs]: skipping scrapping ETH logs: no contract address"
            );
            return;
        }
    };
    let mut last_scraped_block_number = read_state(|s| s.last_scraped_block_number);
    let last_queried_block_number = update_last_observed_block_number().await;
    while last_scraped_block_number < last_queried_block_number {
        last_scraped_block_number = scrap_eth_logs_between(
            contract_address,
            last_scraped_block_number,
            last_queried_block_number,
        )
        .await;
    }
}

/// Scraps Ethereum logs between `from` and `min(from + 1024, to)` since certain RPC providers
/// require that the number of blocks queried is no greater than 1024.
/// Returns the last block number that was scraped (which is `min(from + 1024, to)`).
async fn scrap_eth_logs_between(
    contract_address: Address,
    from: BlockNumber,
    to: BlockNumber,
) -> BlockNumber {
    const MAX_BLOCK_SPREAD: u16 = 1024;
    match from.cmp(&to) {
        Ordering::Less => {
            let max_to = from
                .checked_add(BlockNumber::from(MAX_BLOCK_SPREAD))
                .unwrap_or(BlockNumber::MAX);
            let last_scraped_block_number = min(max_to, to);
            log!(
                DEBUG,
                "Scrapping ETH logs from block {:?} to block {:?}...",
                from,
                last_scraped_block_number
            );

            let (transaction_events, errors) = eth_logs::last_received_eth_events(
                contract_address,
                from,
                last_scraped_block_number,
            )
            .await;
            let has_new_events = !transaction_events.is_empty();
            for event in transaction_events {
                log!(
                    INFO,
                    "Received event {event:?}; will mint {} wei to {}",
                    event.value,
                    event.principal
                );
                mutate_state(|s| process_event(s, EventType::AcceptedDeposit(event)));
            }
            if has_new_events {
                ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(mint_cketh()));
            }
            for error in errors {
                if let ReceivedEthEventError::InvalidEventSource { source, error } = &error {
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::InvalidDeposit {
                                event_source: *source,
                                reason: error.to_string(),
                            },
                        )
                    });
                }
                report_transaction_error(error);
            }
            mutate_state(|s| s.last_scraped_block_number = last_scraped_block_number);
            last_scraped_block_number
        }
        Ordering::Equal => {
            log!(
                DEBUG,
                "[scrap_eth_logs] Skipping scrapping ETH logs: no new blocks",
            );
            to
        }
        Ordering::Greater => {
            ic_cdk::trap(&format!(
                "BUG: last scraped block number ({:?}) is greater than the last queried block number ({:?})",
                from, to
            ));
        }
    }
}

async fn update_last_observed_block_number() -> BlockNumber {
    use eth_rpc::{Block, BlockSpec};

    let finalized_block: Block = read_state(EthRpcClient::from_state)
        .eth_get_block_by_number(BlockSpec::Tag(read_state(State::ethereum_block_height)))
        .await
        .expect("HTTP call failed");
    let block_number = finalized_block.number;
    mutate_state(|s| s.last_observed_block_number = Some(block_number));
    block_number
}

async fn mint_cketh() {
    use icrc_ledger_types::icrc1::transfer::TransferArg;

    let _guard = match TimerGuard::new(TaskType::MintCkEth) {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let (ledger_canister_id, events) = read_state(|s| (s.ledger_id, s.events_to_mint.clone()));
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id,
    };

    let mut error_count = 0;

    for (event_source, event) in events {
        let block_index = match client
            .transfer(TransferArg {
                from_subaccount: None,
                to: event.principal.into(),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(event.value),
            })
            .await
        {
            Ok(Ok(block_index)) => block_index,
            Ok(Err(err)) => {
                log!(INFO, "Failed to mint ckETH: {event:?} {err}");
                error_count += 1;
                continue;
            }
            Err(err) => {
                log!(
                    INFO,
                    "Failed to send a message to the ledger ({ledger_canister_id}): {err:?}"
                );
                error_count += 1;
                continue;
            }
        };
        mutate_state(|s| {
            process_event(
                s,
                EventType::MintedCkEth {
                    event_source,
                    mint_block_index: LedgerMintIndex::new(block_index),
                },
            )
        });
        log!(
            INFO,
            "Minted {} ckWei to {} in block {block_index}",
            event.value,
            event.principal
        );
    }

    if error_count > 0 {
        log!(
            INFO,
            "Failed to mint {error_count} events, rescheduling the minting"
        );
        ic_cdk_timers::set_timer(MINT_RETRY_DELAY, || ic_cdk::spawn(mint_cketh()));
    }
}

async fn process_retrieve_eth_requests() {
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

    let transaction_price = estimate_transaction_price(&eth_fee_history().await);
    let max_transaction_fee = transaction_price.max_transaction_fee();
    log!(
        INFO,
        "[withdraw]: Estimated max transaction fee: {:?}",
        max_transaction_fee,
    );
    // TODO FI-933: for re-submission re-evaluate prices of all transactions whose nonce is at least
    // the value of eth_getTransactionCount at latest height. If needed resubmit transactions by
    // bumping price and insert transactions into created_tx. They will be picked up when calling
    // sign_and_send_transactions_batch in the same timer iteration.
    create_transactions_batch(transaction_price);
    sign_and_send_transactions_batch().await;
    finalize_transactions_batch().await;
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

async fn sign_and_send_transactions_batch() {
    let signed_transactions = sign_transactions_batch().await;
    let results = send_transactions_batch(&signed_transactions).await;
    for (signed_tx, result) in zip(signed_transactions, results) {
        log!(DEBUG, "Sent transaction {signed_tx:?}: {result:?}");
        match result {
            Ok(JsonRpcResult::Result(tx_result)) if tx_result == SendRawTransactionResult::Ok => {
                 mutate_state(|s| {
                    s.eth_transactions
                        .record_sent_transaction(signed_tx)
                });
            }
            // TODO FI-933: in case of resubmission we may hit the case of SendRawTransactionResult::NonceTooLow
            // if the stuck transaction was mined in the meantime. In that case we should probably
            // add the resubmitted transaction to sent_tx to keep a trace of it. It will be cleaned-up
            // once the transaction is finalized.
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

async fn sign_transactions_batch() -> Vec<SignedEip1559TransactionRequest> {
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
    let mut signed_transactions = Vec::with_capacity(results.len());
    for result in results {
        match result {
            Ok(signed_tx) => signed_transactions.push(signed_tx),
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
    log!(DEBUG, "Signed transactions {signed_transactions:?}");
    signed_transactions
}

async fn send_transactions_batch(
    signed_transactions: &[SignedEip1559TransactionRequest],
) -> Vec<HttpOutcallResult<JsonRpcResult<SendRawTransactionResult>>> {
    let rpc_client = read_state(EthRpcClient::from_state);
    join_all(
        signed_transactions
            .iter()
            .map(|tx| rpc_client.eth_send_raw_transaction(tx.raw_transaction_hex())),
    )
    .await
}

// TODO FI-942: currently finalized transaction just means that it was mined in some block.
// We should decide on whether a transaction was finalized by comparing the transaction nonce with
// eth_getTransactionCount at finalized block height and if finalized retrieve the transaction receipt
// to store with the transaction.
async fn finalize_transactions_batch() {
    let sent_transactions: Vec<_> = read_state(|s| {
        s.eth_transactions
            .sent_transactions_iter()
            .flat_map(|(_nonce, _index, txs)| txs)
            .cloned()
            .collect()
    });
    let rpc_client = read_state(EthRpcClient::from_state);
    let results = join_all(
        sent_transactions
            .iter()
            .map(|tx| rpc_client.eth_get_transaction_by_hash(tx.hash())),
    )
    .await;

    for (sent_tx, result) in zip(sent_transactions, results) {
        match result {
            Ok(Some(tx)) => {
                if let Some((block_hash, block_number, _transaction_index)) = tx.mined_in_block() {
                    let confirmed_tx =
                        ConfirmedEip1559Transaction::new(sent_tx, block_hash, block_number);
                    log!(INFO, "Confirmed transaction: {confirmed_tx:?}");
                    mutate_state(|s| {
                        s.eth_transactions
                            .record_finalized_transaction(confirmed_tx)
                    });
                } else {
                    log!(
                        DEBUG,
                        "Transaction {sent_tx:?} found but not confirmed yet. Will retry later.",
                    )
                }
            }
            Ok(None) => log!(
                DEBUG,
                "Transaction {sent_tx:?} not found. Will retry later.",
            ),
            Err(e) => log!(
                INFO,
                "Failed to get transaction by hash {sent_tx:?}: {e:?}. Will retry later.",
            ),
        };
    }
}

#[pre_upgrade]
fn pre_upgrade() {
    read_state(|s| {
        storage::encode_state(s);
        storage::record_event(EventType::SyncedToBlock {
            block_number: s.last_scraped_block_number,
        });
    });
}

#[update]
#[candid_method(update)]
async fn minter_address() -> String {
    let pubkey = lazy_call_ecdsa_public_key().await;
    Address::from_pubkey(&pubkey).to_string()
}

#[query]
#[candid_method(query)]
async fn smart_contract_address() -> String {
    read_state(|s| s.ethereum_contract_address)
        .map(|a| a.to_string())
        .unwrap_or("N/A".to_string())
}

/// Estimate price of EIP-1559 transaction based on the
/// `base_fee_per_gas` included in the last finalized block.
/// See https://www.blocknative.com/blog/eip-1559-fees
#[update]
#[candid_method(update)]
async fn eip_1559_transaction_price() -> Eip1559TransactionPrice {
    let transaction_price = estimate_transaction_price(&eth_fee_history().await);
    Eip1559TransactionPrice::from(transaction_price)
}

#[update]
#[candid_method(update)]
async fn withdraw_eth(
    WithdrawalArg { amount, recipient }: WithdrawalArg,
) -> Result<RetrieveEthRequest, WithdrawalError> {
    let caller = validate_caller_not_anonymous();
    let _guard = retrieve_eth_guard(caller).unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "Failed retrieving guard for principal {}: {:?}",
            caller, e
        ))
    });

    let amount = Wei::try_from(amount).expect("failed to convert Nat to u256");

    let minimum_withdrawal_amount = read_state(|s| s.minimum_withdrawal_amount);
    if amount < minimum_withdrawal_amount {
        return Err(WithdrawalError::AmountTooLow {
            min_withdrawal_amount: minimum_withdrawal_amount.into(),
        });
    }

    let destination = Address::from_str(&recipient)
        .and_then(|a| validate_address_as_destination(a).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| ic_cdk::trap(&format!("invalid recipient address: {:?}", e)));

    let ledger_canister_id = read_state(|s| s.ledger_id);
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id,
    };

    log!(INFO, "[withdraw]: burning {:?}", amount);
    match client
        .transfer_from(TransferFromArgs {
            spender_subaccount: None,
            from: caller.into(),
            to: ic_cdk::id().into(),
            amount: Nat::from(amount),
            fee: None,
            memo: None,
            created_at_time: None,
        })
        .await
    {
        Ok(Ok(block_index)) => {
            let ledger_burn_index = LedgerBurnIndex::new(block_index);
            let withdrawal_request = EthWithdrawalRequest {
                withdrawal_amount: amount,
                destination,
                ledger_burn_index,
            };

            log!(
                INFO,
                "[withdraw]: queuing withdrawal request {:?}",
                withdrawal_request,
            );

            mutate_state(|s| {
                s.eth_transactions
                    .record_withdrawal_request(withdrawal_request.clone())
            });
            Ok(RetrieveEthRequest::from(withdrawal_request))
        }
        Ok(Err(error)) => {
            log!(
                DEBUG,
                "[withdraw]: failed to transfer_from with error: {error:?}"
            );
            Err(WithdrawalError::from(error))
        }
        Err((error_code, message)) => {
            log!(
                DEBUG,
                "[withdraw]: failed to call ledger with error_code: {error_code} and message: {message}",
            );
            Err(WithdrawalError::TemporarilyUnavailable(
                "failed to call ledger with error_code: {error_code} and message: {message}"
                    .to_string(),
            ))
        }
    }
}

fn validate_caller_not_anonymous() -> candid::Principal {
    let principal = ic_cdk::caller();
    if principal == candid::Principal::anonymous() {
        panic!("anonymous principal is not allowed");
    }
    principal
}

async fn eth_fee_history() -> FeeHistory {
    use eth_rpc::{BlockSpec, BlockTag, FeeHistoryParams, Quantity};
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

#[update]
#[candid_method(update)]
async fn retrieve_eth_status(block_index: u64) -> RetrieveEthStatus {
    let ledger_burn_index = LedgerBurnIndex::new(block_index);
    read_state(|s| s.eth_transactions.transaction_status(&ledger_burn_index))
}

#[candid_method(update)]
#[update]
async fn get_canister_status() -> ic_cdk::api::management_canister::main::CanisterStatusResponse {
    ic_cdk::api::management_canister::main::canister_status(
        ic_cdk::api::management_canister::main::CanisterIdRecord {
            canister_id: ic_cdk::id(),
        },
    )
    .await
    .expect("failed to fetch canister status")
    .0
}

#[post_upgrade]
fn post_upgrade(minter_arg: Option<MinterArg>) {
    use ic_cketh_minter::lifecycle;
    match minter_arg {
        Some(MinterArg::InitArg(_)) => {
            ic_cdk::trap("cannot upgrade canister state with init args");
        }
        Some(MinterArg::UpgradeArg(upgrade_args)) => lifecycle::post_upgrade(Some(upgrade_args)),
        None => lifecycle::post_upgrade(None),
    }
    setup_timers();
}

#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    use ic_metrics_encoder::MetricsEncoder;

    if ic_cdk::api::data_certificate().is_none() {
        ic_cdk::trap("update call rejected");
    }

    if req.path() == "/metrics" {
        let mut writer = MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
            read_state(|s| {
                w.gauge_vec("cycle_balance", "Cycle balance of this canister.")?
                    .value(
                        &[("canister", "cketh-minter")],
                        ic_cdk::api::canister_balance128() as f64,
                    )?;

                w.encode_gauge(
                    "cketh_minter_last_observed_block",
                    s.last_observed_block_number
                        .map(|n| n.as_f64())
                        .unwrap_or(0.0),
                    "The last Ethereum block the ckETH minter observed.",
                )?;

                w.encode_gauge(
                    "cketh_minter_last_processed_block",
                    s.last_scraped_block_number.as_f64(),
                    "The last Ethereum block the ckETH minter checked for deposits.",
                )?;

                w.gauge_vec(
                    "cketh_minter_accepted_deposits",
                    "The number of deposits the ckETH minter processed, by status.",
                )?
                .value(&[("status", "accepted")], s.minted_events.len() as f64)?
                .value(&[("status", "rejected")], s.invalid_events.len() as f64)?;

                Ok(())
            })
        }

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                    .build()
            }
        }
    } else if req.path() == "/dashboard" {
        use askama::Template;
        let dashboard = read_state(dashboard::DashboardTemplate::from_state);
        HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard.render().unwrap())
            .build()
    } else if req.path() == "/logs" {
        use ic_cketh_minter::logs::{Log, Priority, Sort};
        use std::str::FromStr;

        let max_skip_timestamp = match req.raw_query_param("time") {
            Some(arg) => match u64::from_str(arg) {
                Ok(value) => value,
                Err(_) => {
                    return HttpResponseBuilder::bad_request()
                        .with_body_and_content_length("failed to parse the 'time' parameter")
                        .build()
                }
            },
            None => 0,
        };

        let mut log: Log = Default::default();

        match req.raw_query_param("priority") {
            Some(priority_str) => match Priority::from_str(priority_str) {
                Ok(priority) => match priority {
                    Priority::Info => log.push_logs(Priority::Info),
                    Priority::TraceHttp => log.push_logs(Priority::TraceHttp),
                    Priority::Debug => log.push_logs(Priority::Debug),
                },
                Err(_) => log.push_all(),
            },
            None => log.push_all(),
        }

        log.entries
            .retain(|entry| entry.timestamp >= max_skip_timestamp);

        fn ordering_from_query_params(sort: Option<&str>, max_skip_timestamp: u64) -> Sort {
            match sort {
                Some(ord_str) => match Sort::from_str(ord_str) {
                    Ok(order) => order,
                    Err(_) => {
                        if max_skip_timestamp == 0 {
                            Sort::Ascending
                        } else {
                            Sort::Descending
                        }
                    }
                },
                None => {
                    if max_skip_timestamp == 0 {
                        Sort::Ascending
                    } else {
                        Sort::Descending
                    }
                }
            }
        }

        log.sort_logs(ordering_from_query_params(
            req.raw_query_param("sort"),
            max_skip_timestamp,
        ));

        const MAX_BODY_SIZE: usize = 3_000_000;
        HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(log.serialize_logs(MAX_BODY_SIZE))
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

fn main() {}

/// Checks the real candid interface against the one declared in the did file
#[test]
fn check_candid_interface_compatibility() {
    fn source_to_str(source: &candid::utils::CandidSource) -> String {
        match source {
            candid::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid::utils::CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_equal(
        new_name: &str,
        new: candid::utils::CandidSource,
        old_name: &str,
        old: candid::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid::utils::service_equal(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{} is not compatible with {}!\n\n\
            {}:\n\
            {}\n\n\
            {}:\n\
            {}\n",
                    new_name, old_name, new_name, new_str, old_name, old_str
                );
                panic!("{:?}", e);
            }
        }
    }

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("cketh_minter.did");

    check_service_equal(
        "actual ledger candid interface",
        candid::utils::CandidSource::Text(&new_interface),
        "declared candid interface in cketh_minter.did file",
        candid::utils::CandidSource::File(old_interface.as_path()),
    );
}
