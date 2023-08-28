use candid::{candid_method, Nat};
use ic_canister_log::log;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::WithdrawalError;
use ic_cketh_minter::endpoints::{
    DebugState, Eip1559TransactionPrice, EthTransaction, MinterArg, RetrieveEthRequest,
    RetrieveEthStatus,
};
use ic_cketh_minter::eth_logs::report_transaction_error;
use ic_cketh_minter::eth_rpc::JsonRpcResult;
use ic_cketh_minter::eth_rpc::{into_nat, FeeHistory, Hash, SendRawTransactionResult};
use ic_cketh_minter::eth_rpc_client::EthRpcClient;
use ic_cketh_minter::guard::{mint_cketh_guard, retrieve_eth_guard, retrieve_eth_timer_guard};
use ic_cketh_minter::logs::{DEBUG, INFO};
use ic_cketh_minter::numeric::{LedgerBurnIndex, LedgerMintIndex, TransactionNonce, Wei};
use ic_cketh_minter::state::{mutate_state, read_state, State, STATE};
use ic_cketh_minter::transactions::PendingEthTransaction;
use ic_cketh_minter::tx::{estimate_transaction_price, AccessList, Eip1559TransactionRequest};
use ic_cketh_minter::{eth_logs, eth_rpc};
use ic_icrc1_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use std::cmp::{min, Ordering};
use std::str::FromStr;
use std::time::Duration;

const SCRAPPING_ETH_LOGS_INTERVAL: Duration = Duration::from_secs(3 * 60);
const PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL: Duration = Duration::from_secs(15);
const MINT_RETRY_DELAY: Duration = Duration::from_secs(3 * 60);

pub const SEPOLIA_TEST_CHAIN_ID: u64 = 11155111;
pub const MINIMUM_WITHDRAWAL_AMOUNT: Wei = Wei::new(10_000_000_000_000_000_128); // 0.01 ETH

#[init]
#[candid_method(init)]
fn init(arg: MinterArg) {
    match arg {
        MinterArg::InitArg(init_arg) => {
            log!(INFO, "[init]: initialized minter with arg: {:?}", init_arg);
            STATE.with(|cell| *cell.borrow_mut() = Some(State::from(init_arg)));
        }
        MinterArg::UpgradeArg => {
            ic_cdk::trap("cannot init canister state with upgrade args");
        }
    }
    setup_timers();
}

fn setup_timers() {
    ic_cdk_timers::set_timer_interval(SCRAPPING_ETH_LOGS_INTERVAL, || {
        ic_cdk::spawn(scrap_eth_logs())
    });
    ic_cdk_timers::set_timer_interval(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, || {
        ic_cdk::spawn(process_retrieve_eth_requests())
    });
}

async fn scrap_eth_logs() {
    use eth_rpc::Block;

    const MAX_BLOCK_SPREAD: u128 = 1024;

    let last_seen_block_number = read_state(|s| s.last_seen_block_number.clone());

    let finalized_block: Block = read_state(EthRpcClient::from_state)
        .eth_get_last_finalized_block()
        .await
        .expect("HTTP call failed");
    log!(
        DEBUG,
        "[scrap_eth_logs] last seen finalized block: {:?}, last finalized block: {:?}",
        last_seen_block_number,
        finalized_block
    );

    match last_seen_block_number.cmp(&finalized_block.number) {
        Ordering::Less => {
            let max_finalized_block_number = min(
                last_seen_block_number.clone() + MAX_BLOCK_SPREAD,
                finalized_block.number,
            );

            log!(
                DEBUG,
                "Scrapping ETH logs from block {:?} to block {:?}...",
                last_seen_block_number,
                max_finalized_block_number
            );

            let (transaction_events, errors) = eth_logs::last_received_eth_events(
                last_seen_block_number.clone(),
                max_finalized_block_number.clone(),
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
                mutate_state(|s| s.record_event_to_mint(event));
            }
            if has_new_events {
                ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(mint_cketh()));
            }
            for error in errors {
                mutate_state(|s| report_transaction_error(s, error));
            }
            mutate_state(|s| s.last_seen_block_number = max_finalized_block_number);
        }
        Ordering::Equal => {
            log!(
                DEBUG,
                "[scrap_eth_logs] Skipping scrapping ETH logs: no new blocks",
            );
        }
        Ordering::Greater => {
            ic_cdk::trap(&format!(
                "BUG: last seen block number ({:?}) is greater than the last finalized block number ({:?})",
                last_seen_block_number, finalized_block.number
            ));
        }
    }
}

async fn mint_cketh() {
    use icrc_ledger_types::icrc1::transfer::TransferArg;

    let _guard = match mint_cketh_guard() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let (ledger_canister_id, events) = read_state(|s| (s.ledger_id, s.events_to_mint.clone()));
    let client = ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id,
    };

    let mut error_count = 0;

    for event in events {
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
        mutate_state(|s| s.record_successful_mint(&event, LedgerMintIndex::new(block_index)));
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
    let _guard = match retrieve_eth_timer_guard() {
        Ok(guard) => guard,
        Err(e) => {
            log!(
                DEBUG,
                "Failed retrieving timer guard to process ETH requests: {e:?}",
            );
            return;
        }
    };
    sign_pending_eth_transactions().await;
    send_signed_eth_transactions().await;
}

async fn sign_pending_eth_transactions() {
    let tx_to_sign = read_state(|s| s.pending_retrieve_eth_requests.transactions_to_sign());
    log!(DEBUG, "{} transactions to sign", tx_to_sign.len());
    for tx in tx_to_sign {
        match tx.sign().await {
            Ok(signed_tx) => {
                mutate_state(|s| {
                    log!(DEBUG, "Queueing signed transaction: {signed_tx:?}");
                    s.pending_retrieve_eth_requests
                        .replace_with_signed_transaction(signed_tx)
                        .unwrap_or_else(|e| {
                            log!(
                                INFO,
                                "BUG: failed to replace transaction with signed one: {e}",
                            );
                        })
                });
            }
            Err(e) => {
                log!(INFO, "Failed to sign transaction: {e}");
            }
        }
    }
}

async fn send_signed_eth_transactions() {
    let tx_to_send = read_state(|s| s.pending_retrieve_eth_requests.transactions_to_send());
    log!(DEBUG, "{} transactions to send", tx_to_send.len());

    for tx in tx_to_send {
        let result = read_state(EthRpcClient::from_state)
            .eth_send_raw_transaction(tx.raw_transaction_hex())
            .await
            .expect("HTTP call failed");
        log!(DEBUG, "Sent transaction {tx:?}: {result:?}");
        match result {
            JsonRpcResult::Result(tx_result) if tx_result == SendRawTransactionResult::Ok => {
                mutate_state(|s| {
                    s.pending_retrieve_eth_requests
                        .replace_with_sent_transaction(tx)
                        .unwrap_or_else(|e| {
                            log!(
                                INFO,
                                "BUG: failed to replace transaction with sent one: {e:?}",
                            );
                        })
                })
            }
            JsonRpcResult::Result(tx_result) => {
                log!(
                    INFO,
                    "Failed to send transaction {tx:?}: {tx_result:?}. Will retry later.",
                );
            }
            JsonRpcResult::Error { code, message } => {
                log!(
                    INFO,
                    "Failed to send transaction {tx:?}: {message} (error code = {code}). Will retry later.",
                );
            }
        }
    }
}

#[pre_upgrade]
fn pre_upgrade() {
    read_state(|s| ciborium::ser::into_writer(s, StableWriter::default()))
        .expect("failed to encode ledger state");
}

#[update]
#[candid_method(update)]
async fn minter_address() -> String {
    use ic_cketh_minter::state::lazy_call_ecdsa_public_key;
    let pubkey = lazy_call_ecdsa_public_key().await;
    Address::from_pubkey(&pubkey).to_string()
}

type TransferResult = ic_cketh_minter::eth_rpc::JsonRpcResult<String>;
#[update]
#[candid_method(update)]
async fn test_transfer(value: u64, nonce: u64, to_string: String) -> TransferResult {
    let signed_transaction = Eip1559TransactionRequest {
        chain_id: SEPOLIA_TEST_CHAIN_ID,
        destination: Address::from_str(&to_string).unwrap(),
        nonce: TransactionNonce::from(nonce),
        gas_limit: 100000_u32.into(),
        max_fee_per_gas: Wei::new(1946965145_u128),
        amount: value.into(),
        data: vec![],
        access_list: AccessList::new(),
        max_priority_fee_per_gas: Wei::new(1946965145_u128),
    }
    .sign()
    .await
    .expect("signing failed");
    match read_state(EthRpcClient::from_state)
        .eth_send_raw_transaction(signed_transaction.raw_transaction_hex())
        .await
        .expect("HTTP call failed")
    {
        JsonRpcResult::Result(_) => JsonRpcResult::Result(signed_transaction.hash().to_string()),
        JsonRpcResult::Error { code, message } => JsonRpcResult::Error { code, message },
    }
}

/// Estimate price of EIP-1559 transaction based on the
/// `base_fee_per_gas` included in the last finalized block.
/// See https://www.blocknative.com/blog/eip-1559-fees
#[update]
#[candid_method(update)]
async fn eip_1559_transaction_price() -> Eip1559TransactionPrice {
    use eth_rpc::{BlockSpec, BlockTag, FeeHistoryParams, Quantity};

    let fee_history = read_state(EthRpcClient::from_state)
        .eth_fee_history(FeeHistoryParams {
            block_count: Quantity::from(5_u8),
            highest_block: BlockSpec::Tag(BlockTag::Finalized),
            reward_percentiles: vec![20],
        })
        .await
        .expect("HTTP call failed")
        .unwrap();

    debug_assert_eq!(fee_history.base_fee_per_gas.len(), 6);
    let base_fee_from_last_finalized_block = Nat::from(fee_history.base_fee_per_gas[4]);
    let base_fee_of_next_finalized_block = Nat::from(fee_history.base_fee_per_gas[5]);
    let price = estimate_transaction_price(&fee_history);

    Eip1559TransactionPrice {
        base_fee_from_last_finalized_block,
        base_fee_of_next_finalized_block,
        max_priority_fee_per_gas: price.max_priority_fee_per_gas.into(),
        max_fee_per_gas: price.max_fee_per_gas.into(),
        gas_limit: into_nat(price.gas_limit),
    }
}

#[update]
#[candid_method(update)]
async fn withdraw(amount: Nat, recipient: String) -> Result<RetrieveEthRequest, WithdrawalError> {
    let caller = validate_caller_not_anonymous();
    let _guard = retrieve_eth_guard(caller).unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "Failed retrieving guard for principal {}: {:?}",
            caller, e
        ))
    });

    let amount = Wei::try_from(amount).expect("failed to convert Nat to u256");

    if amount < MINIMUM_WITHDRAWAL_AMOUNT {
        return Err(WithdrawalError::AmountTooLow {
            min_withdrawal_amount: MINIMUM_WITHDRAWAL_AMOUNT.into(),
        });
    }

    let destination = Address::from_str(&recipient)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("failed to parse recipient address: {:?}", e)));

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

            log!(
                INFO,
                "[withdraw]: {} withdrawing {:?} wei to {:?}",
                caller,
                amount,
                destination
            );

            let transaction_price = estimate_transaction_price(&eth_fee_history().await);
            let max_transaction_fee = transaction_price.max_transaction_fee();
            log!(
                INFO,
                "[withdraw]: Estimated max transaction fee: {:?}",
                max_transaction_fee,
            );

            if max_transaction_fee >= amount {
                ic_cdk::trap(&format!(
                    "WARN: skipping transaction since fee {:?} is at least the amount {:?} to be withdrawn",
                    max_transaction_fee, amount
                ));
            }
            let tx_amount = amount.checked_sub(max_transaction_fee).expect(
                "BUG: should not happen due to previous check that amount > max_transaction_fee",
            );

            let (nonce, chain_id) =
                mutate_state(|s| (s.get_and_increment_nonce(), s.ethereum_network.chain_id()));
            let transaction = Eip1559TransactionRequest {
                chain_id,
                nonce,
                max_priority_fee_per_gas: transaction_price.max_priority_fee_per_gas,
                max_fee_per_gas: transaction_price.max_fee_per_gas,
                gas_limit: transaction_price.gas_limit,
                destination,
                amount: tx_amount,
                data: Vec::new(),
                access_list: AccessList::new(),
            };
            log!(
                INFO,
                "[withdraw]: queuing transaction: {:?} for signing",
                transaction,
            );
            mutate_state(|s| s.record_retrieve_eth_request(ledger_burn_index, transaction));

            Ok(RetrieveEthRequest {
                block_index: candid::Nat::from(block_index),
            })
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
            highest_block: BlockSpec::Tag(BlockTag::Finalized),
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
    let transaction = read_state(|s| {
        s.pending_retrieve_eth_requests
            .find_by_burn_index(ledger_burn_index)
    });
    match transaction {
        Some(PendingEthTransaction::NotSigned(_)) => RetrieveEthStatus::PendingSigning,
        Some(PendingEthTransaction::Signed(tx)) => RetrieveEthStatus::Signed(EthTransaction {
            transaction_hash: tx.hash().to_string(),
        }),
        Some(PendingEthTransaction::Sent(tx)) => RetrieveEthStatus::Sent(EthTransaction {
            transaction_hash: tx.hash().to_string(),
        }),
        None => RetrieveEthStatus::NotFound,
    }
}

#[post_upgrade]
fn post_upgrade(minter_arg: Option<MinterArg>) {
    match minter_arg {
        Some(MinterArg::InitArg(_)) => {
            ic_cdk::trap("cannot upgrade canister state with init args");
        }
        None | Some(MinterArg::UpgradeArg) => {
            let start = ic_cdk::api::instruction_counter();

            STATE.with(|cell| {
                *cell.borrow_mut() = Some(
                    ciborium::de::from_reader(StableReader::default())
                        .expect("failed to decode ledger state"),
                );
            });

            let end = ic_cdk::api::instruction_counter();

            log!(
                INFO,
                "[upgrade]: upgrade consumed {} instructions",
                start - end
            );
        }
    }
    setup_timers();
}

#[query]
#[candid_method(query)]
fn dump_state_for_debugging() -> DebugState {
    fn to_tx(hash: &Hash) -> EthTransaction {
        EthTransaction {
            transaction_hash: hash.to_string(),
        }
    }
    fn vec_debug<T: std::fmt::Debug>(v: &[T]) -> Vec<String> {
        v.iter().map(|x| format!("{:?}", x)).collect()
    }

    read_state(|s| DebugState {
        ecdsa_key_name: s.ecdsa_key_name.clone(),
        last_seen_block_number: Nat::from(s.last_seen_block_number.clone()),
        minted_transactions: s
            .minted_events
            .keys()
            .map(|source| to_tx(source.txhash()))
            .collect(),
        invalid_transactions: s
            .invalid_events
            .iter()
            .map(|source| to_tx(source.txhash()))
            .collect(),
        next_transaction_nonce: Nat::from(s.next_transaction_nonce),
        unapproved_retrieve_eth_requests: vec_debug(
            &s.pending_retrieve_eth_requests.transactions_to_sign(),
        ),
        signed_retrieve_eth_requests: vec_debug(
            &s.pending_retrieve_eth_requests.transactions_to_send(),
        ),
        sent_retrieve_eth_requests: vec_debug(&s.pending_retrieve_eth_requests.transactions_sent()),
    })
}

#[candid_method(query)]
#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    use ic_metrics_encoder::MetricsEncoder;

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
                    "cketh_minter_last_processed_block",
                    s.last_seen_block_number.as_f64(),
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
    } else if req.path() == "/logs" {
        use ic_cketh_minter::logs::{Log, Priority};
        use serde_json;
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

        let mut entries: Log = Default::default();

        match req.raw_query_param("priority") {
            Some(priority_str) => match Priority::from_str(priority_str) {
                Ok(priority) => match priority {
                    Priority::Info => entries.push_logs(Priority::Info),
                    Priority::TraceHttp => entries.push_logs(Priority::TraceHttp),
                    Priority::Debug => entries.push_logs(Priority::Debug),
                },
                Err(_) => entries.push_all(),
            },
            None => entries.push_all(),
        }

        entries
            .entries
            .retain(|entry| entry.timestamp >= max_skip_timestamp);
        HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
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

    fn check_service_compatible(
        new_name: &str,
        new: candid::utils::CandidSource,
        old_name: &str,
        old: candid::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid::utils::service_compatible(new, old) {
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

    check_service_compatible(
        "actual ledger candid interface",
        candid::utils::CandidSource::Text(&new_interface),
        "declared candid interface in cketh_minter.did file",
        candid::utils::CandidSource::File(old_interface.as_path()),
    );
}
