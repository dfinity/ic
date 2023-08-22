use candid::candid_method;
use ic_canister_log::log;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::{
    DebugState, DisplayLogsRequest, Eip1559TransactionPrice, Eip2930TransactionPrice,
    EthTransaction, MinterArg, ReceivedEthEvent, RetrieveEthRequest, RetrieveEthStatus,
};
use ic_cketh_minter::eth_logs::{mint_transaction, report_transaction_error};
use ic_cketh_minter::eth_rpc::JsonRpcResult;
use ic_cketh_minter::eth_rpc::{into_nat, FeeHistory, Hash, ResponseSizeEstimate};
use ic_cketh_minter::eth_rpc_client::EthereumChain;
use ic_cketh_minter::guard::{retrieve_eth_guard, retrieve_eth_timer_guard};
use ic_cketh_minter::logs::{DEBUG, INFO};
use ic_cketh_minter::numeric::{LedgerBurnIndex, TransactionNonce, Wei};
use ic_cketh_minter::state::mutate_state;
use ic_cketh_minter::state::read_state;
use ic_cketh_minter::state::State;
use ic_cketh_minter::state::STATE;
use ic_cketh_minter::transactions::PendingEthTransaction;
use ic_cketh_minter::tx::{estimate_transaction_price, AccessList, Eip1559TransactionRequest};
use ic_cketh_minter::{eth_logs, eth_rpc, RPC_CLIENT};
use std::cmp::{min, Ordering};
use std::str::FromStr;

const TRANSACTION_GAS_LIMIT: u32 = 21_000;
const SCRAPPING_ETH_LOGS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3 * 60);
const PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(15);

pub const SEPOLIA_TEST_CHAIN_ID: u64 = 11155111;

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

    let finalized_block: Block = RPC_CLIENT
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
            for event in transaction_events {
                mutate_state(|s| mint_transaction(&mut s.minted_transactions, event));
            }
            for error in errors {
                mutate_state(|s| report_transaction_error(&mut s.invalid_transactions, error));
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

async fn process_retrieve_eth_requests() {
    let _guard = match retrieve_eth_timer_guard() {
        Ok(guard) => guard,
        Err(e) => {
            ic_cdk::println!(
                "Failed retrieving timer guard to process ETH requests: {:?}",
                e
            );
            return;
        }
    };
    sign_pending_eth_transactions().await;
    send_signed_eth_transactions().await;
}

async fn sign_pending_eth_transactions() {
    let tx_to_sign = read_state(|s| s.pending_retrieve_eth_requests.transactions_to_sign());
    for tx in tx_to_sign {
        match tx.sign().await {
            Ok(signed_tx) => {
                mutate_state(|s| {
                    ic_cdk::println!("Queueing signed transaction: {:?}", signed_tx);
                    s.pending_retrieve_eth_requests
                        .replace_with_signed_transaction(signed_tx)
                        .unwrap_or_else(|e| {
                            ic_cdk::println!(
                                "BUG: failed to replace transaction with signed one: {:?}",
                                e
                            );
                        })
                });
            }
            Err(e) => {
                ic_cdk::println!("Failed to sign transaction: {:?}", e);
            }
        }
    }
}

async fn send_signed_eth_transactions() {
    let tx_to_send = read_state(|s| s.pending_retrieve_eth_requests.transactions_to_send());

    for tx in tx_to_send {
        let result = RPC_CLIENT
            .eth_send_raw_transaction(tx.raw_transaction_hex())
            .await
            .expect("HTTP call failed");
        ic_cdk::println!("Sent transaction: {:?}", result);
        match result {
            JsonRpcResult::Result(_) => mutate_state(|s| {
                s.pending_retrieve_eth_requests
                    .replace_with_sent_transaction(tx)
                    .unwrap_or_else(|e| {
                        ic_cdk::println!(
                            "BUG: failed to replace transaction with sent one: {:?}",
                            e
                        );
                    })
            }),
            JsonRpcResult::Error { code, message } => {
                ic_cdk::println!(
                    "Failed to send transaction {:?}: {} (error code = {:?}). Will retry later. ",
                    tx,
                    message,
                    code
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

#[update]
#[candid_method(update)]
async fn display_logs(req: DisplayLogsRequest) -> Vec<ReceivedEthEvent> {
    use candid::Nat;
    use eth_rpc::{Data, GetLogsParam, LogEntry};
    use ethabi::param_type::ParamType;

    let result: Vec<LogEntry> = eth_rpc::call(
        "https://rpc.sepolia.org",
        "eth_getLogs",
        vec![GetLogsParam {
            from_block: req.from.parse().expect("failed to parse 'from' block"),
            to_block: req.to.parse().expect("failed to parse 'to' block"),
            address: vec![req.address.parse().expect("failed to parse 'address'")],
            topics: vec![],
        }],
        ResponseSizeEstimate::new(1024),
    )
    .await
    .expect("HTTP call failed")
    .unwrap();
    result
        .into_iter()
        .map(|entry| {
            let Data(data) = entry.data;
            let args = ethabi::decode(
                &[ParamType::Address, ParamType::Uint(256), ParamType::String],
                &data,
            )
            .expect("failed to parse event payload");
            assert_eq!(args.len(), 3);
            ReceivedEthEvent {
                transaction_hash: entry.transaction_hash.expect("finalized block").to_string(),
                block_number: candid::Nat::from(entry.block_number.expect("finalized block")),
                log_index: into_nat(entry.log_index.expect("finalized block")),
                from_address: Address::new(args[0].clone().into_address().unwrap().0).to_string(),
                value: Nat::from(args[1].clone().into_uint().unwrap().as_u128()),
                principal: args[2].clone().into_string().unwrap().parse().unwrap(),
            }
        })
        .collect()
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
    match RPC_CLIENT
        .eth_send_raw_transaction(signed_transaction.raw_transaction_hex())
        .await
        .expect("HTTP call failed")
    {
        JsonRpcResult::Result(tx_hash) => JsonRpcResult::Result(tx_hash.to_string()),
        JsonRpcResult::Error { code, message } => JsonRpcResult::Error { code, message },
    }
}

/// Estimate price of EIP-1559 transaction based on the
/// `base_fee_per_gas` included in the last finalized block.
/// See https://www.blocknative.com/blog/eip-1559-fees
#[update]
#[candid_method(update)]
async fn eip_1559_transaction_price() -> Eip1559TransactionPrice {
    use candid::Nat;
    use eth_rpc::{BlockSpec, BlockTag, FeeHistoryParams, Quantity};

    let fee_history = RPC_CLIENT
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

/// Estimate price of EIP-2930 or legacy transactions based on the value returned by
/// `eth_gasPrice` JSON-RPC call.
#[update]
#[candid_method(update)]
async fn eip_2930_transaction_price() -> Eip2930TransactionPrice {
    use ic_cketh_minter::numeric::Wei;

    let gas_price: Wei = eth_rpc::call(
        "https://rpc.sepolia.org",
        "eth_gasPrice",
        (),
        ResponseSizeEstimate::new(100),
    )
    .await
    .expect("HTTP call failed")
    .unwrap();

    let gas_price = candid::Nat::from(gas_price);
    let gas_limit = candid::Nat::from(TRANSACTION_GAS_LIMIT);

    Eip2930TransactionPrice {
        gas_price,
        gas_limit,
    }
}

#[update]
#[candid_method(update)]
async fn withdraw(amount: u64, recipient: String) -> RetrieveEthRequest {
    let caller = validate_caller_not_anonymous();
    let _guard = retrieve_eth_guard(caller).unwrap_or_else(|e| {
        ic_cdk::trap(&format!(
            "Failed retrieving guard for principal {}: {:?}",
            caller, e
        ))
    });
    let amount = Wei::from(amount);
    let destination = Address::from_str(&recipient)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("failed to parse recipient address: {:?}", e)));
    //TODO FI-868: verify that the source account has enough funds on the ledger
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
    let tx_amount = amount
        .checked_sub(max_transaction_fee)
        .expect("BUG: should not happen due to previous check that amount > max_transaction_fee");

    //TODO FI-868: contact ledger to burn funds
    let ledger_burn_index = LedgerBurnIndex(0);
    log!(INFO, "[withdraw]: burning {:?}", amount);

    let nonce = mutate_state(|s| s.get_and_increment_nonce());
    let transaction = Eip1559TransactionRequest {
        //TODO FI-867: add chain id to InitArgs, read it from state and pass it as parameter of that function
        chain_id: EthereumChain::Sepolia.chain_id(),
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

    RetrieveEthRequest {
        block_index: candid::Nat::from(ledger_burn_index),
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
    RPC_CLIENT
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
    let ledger_burn_index = LedgerBurnIndex(block_index);
    let transaction = read_state(|s| {
        s.pending_retrieve_eth_requests
            .find_by_burn_index(ledger_burn_index)
    });
    match transaction {
        Some(PendingEthTransaction::NotSigned(_)) => RetrieveEthStatus::PendingSigning,
        Some(PendingEthTransaction::Signed(tx)) | Some(PendingEthTransaction::Sent(tx)) => {
            RetrieveEthStatus::Found(EthTransaction {
                transaction_hash: tx.hash().to_string(),
            })
        }
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
        last_seen_block_number: candid::Nat::from(s.last_seen_block_number.clone()),
        minted_transactions: s.minted_transactions.iter().map(to_tx).collect(),
        invalid_transactions: s.invalid_transactions.iter().map(to_tx).collect(),
        next_transaction_nonce: candid::Nat::from(s.next_transaction_nonce),
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
                .value(
                    &[("status", "accepted")],
                    s.minted_transactions.len() as f64,
                )?
                .value(
                    &[("status", "rejected")],
                    s.invalid_transactions.len() as f64,
                )?;

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
