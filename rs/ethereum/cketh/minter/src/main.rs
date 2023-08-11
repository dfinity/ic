use candid::candid_method;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::{
    DebugState, DisplayLogsRequest, Eip1559TransactionPrice, Eip2930TransactionPrice,
    EthTransaction, MinterArg, ReceivedEthEvent, RetrieveEthRequest, TransactionStatus,
};
use ic_cketh_minter::eth_logs::{mint_transaction, report_transaction_error};
use ic_cketh_minter::eth_rpc::{into_nat, FeeHistory, Hash, BLOCK_PI_RPC_PROVIDER_URL};
use ic_cketh_minter::eth_rpc::{JsonRpcResult, Transaction};
use ic_cketh_minter::numeric::{LedgerBurnIndex, TransactionNonce, Wei};
use ic_cketh_minter::state::mutate_state;
use ic_cketh_minter::state::read_state;
use ic_cketh_minter::state::State;
use ic_cketh_minter::state::STATE;
use ic_cketh_minter::tx::{estimate_transaction_price, Eip1559TransactionRequest};
use ic_cketh_minter::{eth_logs, eth_rpc};
use ic_crypto_ecdsa_secp256k1::PublicKey;
use std::cmp::{min, Ordering};
use std::str::FromStr;

const TRANSACTION_GAS_LIMIT: u32 = 21_000;
const SCRAPPING_ETH_LOGS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3 * 60);

pub const SEPOLIA_TEST_CHAIN_ID: u64 = 11155111;

#[init]
#[candid_method(init)]
fn init(arg: MinterArg) {
    match arg {
        MinterArg::InitArg(init_arg) => {
            STATE.with(|cell| *cell.borrow_mut() = Some(State::from(init_arg)));
        }
        MinterArg::UpgradeArg => {
            ic_cdk::trap("cannot init canister state with upgrade args");
        }
    }
    ic_cdk_timers::set_timer_interval(SCRAPPING_ETH_LOGS_INTERVAL, || {
        ic_cdk::spawn(scrap_eth_logs())
    });
}

async fn scrap_eth_logs() {
    use eth_rpc::{Block, BlockSpec, BlockTag};
    use ic_cketh_minter::eth_rpc::GetBlockByNumberParams;

    const MAX_BLOCK_SPREAD: u128 = 1024;

    let last_seen_block_number = read_state(|s| s.last_seen_block_number.clone());
    ic_cdk::println!(
        "Scraping ETH logs, last seen finalized block number: {:?}...",
        last_seen_block_number
    );

    let finalized_block: Block = eth_rpc::call(
        // contrary to other endpoints we do not use
        // rpc.sepolia.org for the PoC because its view on latest finalized block seems delayed
        // by a few **days**:
        // Last finalized block according to rpc.sepolia.org: 0x3c19ee (https://sepolia.etherscan.io/block/3938798)
        // Last finalized block according to blockpi: 0x3c6d08 (https://sepolia.etherscan.io/block/3960072)
        BLOCK_PI_RPC_PROVIDER_URL,
        "eth_getBlockByNumber",
        GetBlockByNumberParams {
            block: BlockSpec::Tag(BlockTag::Finalized),
            include_full_transactions: false,
        },
    )
    .await
    .expect("HTTP call failed")
    .unwrap();
    ic_cdk::println!("Last finalized block: {:?}", finalized_block);

    match last_seen_block_number.cmp(&finalized_block.number) {
        Ordering::Less => {
            let max_finalized_block_number = min(
                last_seen_block_number.clone() + MAX_BLOCK_SPREAD,
                finalized_block.number,
            );
            ic_cdk::println!(
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
            ic_cdk::println!(
                "Skipping scrapping ETH logs: no new blocks. Last seen block number: {:?}",
                last_seen_block_number
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

#[pre_upgrade]
fn pre_upgrade() {
    read_state(|s| ciborium::ser::into_writer(s, StableWriter::default()))
        .expect("failed to encode ledger state");
}

#[update]
#[candid_method(update)]
async fn minter_address() -> String {
    use ic_cdk::api::management_canister::ecdsa::{
        ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    };
    let key_name = read_state(|s| s.ecdsa_key_name.clone());
    let (response,) = ecdsa_public_key(EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: ic_cketh_minter::MAIN_DERIVATION_PATH
            .into_iter()
            .map(|x| x.to_vec())
            .collect(),
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    })
    .await
    .unwrap_or_else(|(error_code, message)| {
        ic_cdk::trap(&format!(
            "failed to get minter's public key: {} (error code = {:?})",
            message, error_code,
        ))
    });
    let pubkey = PublicKey::deserialize_sec1(&response.public_key).unwrap_or_else(|e| {
        ic_cdk::trap(&format!("failed to decode minter's public key: {:?}", e))
    });
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
    let tx_bytes = Eip1559TransactionRequest {
        chain_id: SEPOLIA_TEST_CHAIN_ID,
        destination: Address::from_str(&to_string).unwrap(),
        nonce: TransactionNonce::from(nonce),
        gas_limit: 100000_u32.into(),
        max_fee_per_gas: Wei::new(1946965145_u128),
        amount: value.into(),
        data: vec![],
        access_list: vec![],
        max_priority_fee_per_gas: Wei::new(1946965145_u128),
    }
    .sign()
    .await
    .expect("signing failed");
    let hex_string = format!("0x{}", hex::encode(&tx_bytes));
    let result: JsonRpcResult<String> = eth_rpc::call(
        "https://rpc.sepolia.org",
        "eth_sendRawTransaction",
        vec![hex_string],
    )
    .await
    .expect("HTTP call failed");
    result
}

#[update]
#[candid_method(update)]
async fn test_get_transaction_by_hash(transaction_hash: String) -> TransactionStatus {
    let transaction_hash = Hash::from_str(&transaction_hash)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("failed to parse transaction hash: {:?}", e)));
    let transaction: Option<Transaction> = eth_rpc::call(
        BLOCK_PI_RPC_PROVIDER_URL,
        "eth_getTransactionByHash",
        vec![transaction_hash],
    )
    .await
    .expect("HTTP call failed")
    .unwrap();
    match transaction {
        None => TransactionStatus::NotFound,
        Some(transaction) => {
            if transaction.is_confirmed() {
                TransactionStatus::Finalized
            } else {
                TransactionStatus::Pending
            }
        }
    }
}

/// Estimate price of EIP-1559 transaction based on the
/// `base_fee_per_gas` included in the last finalized block.
/// See https://www.blocknative.com/blog/eip-1559-fees
#[update]
#[candid_method(update)]
async fn eip_1559_transaction_price() -> Eip1559TransactionPrice {
    use candid::Nat;
    use eth_rpc::{BlockSpec, BlockTag, FeeHistory, FeeHistoryParams, Quantity};

    let fee_history: FeeHistory = eth_rpc::call(
        "https://rpc.sepolia.org",
        "eth_feeHistory",
        FeeHistoryParams {
            block_count: Quantity::from(5_u8),
            highest_block: BlockSpec::Tag(BlockTag::Finalized),
            reward_percentiles: vec![20],
        },
    )
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

    let gas_price: Wei = eth_rpc::call("https://rpc.sepolia.org", "eth_gasPrice", ())
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
    let amount = Wei::from(amount);
    let destination = Address::from_str(&recipient)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("failed to parse recipient address: {:?}", e)));
    //TODO FI-868: verify that the source account has enough funds on the ledger
    ic_cdk::println!(
        "Principal {} withdrawing {:?} to {:?}",
        caller,
        amount,
        destination
    );

    let transaction_price = estimate_transaction_price(&eth_fee_history().await);
    let max_transaction_fee = transaction_price.max_transaction_fee();
    ic_cdk::println!("Estimated max transaction fee: {:?}", max_transaction_fee);
    if max_transaction_fee >= amount {
        ic_cdk::trap(&format!(
            "WARN: skipping transaction since fee {:?} is at least the amount {:?} to be withdrawn",
            max_transaction_fee, amount
        ));
    }

    //TODO FI-868: contact ledger to burn funds
    let ledger_burn_index = LedgerBurnIndex(0);
    ic_cdk::println!(
        "Burning {:?}",
        amount
            .checked_sub(max_transaction_fee)
            .expect("cannot underflow due to previous check that max_transaction_fee >= amount")
    );

    let nonce = mutate_state(|s| s.increment_and_get_nonce());
    let transaction = Eip1559TransactionRequest::new_transfer(
        SEPOLIA_TEST_CHAIN_ID,
        nonce,
        transaction_price,
        destination,
        amount,
    );
    ic_cdk::println!("Queuing transaction: {:?} for signing", transaction,);
    mutate_state(|s| {
        s.pending_retrieve_eth_requests
            .insert(ledger_burn_index, transaction.clone())
            .unwrap_or_else(|e| {
                ic_cdk::trap(&format!(
                    "BUG: skipping transaction {:?} since it could not be queued for signing: {}",
                    transaction, e
                ))
            });
    });

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
    eth_rpc::call(
        "https://rpc.sepolia.org",
        "eth_feeHistory",
        FeeHistoryParams {
            block_count: Quantity::from(5_u8),
            highest_block: BlockSpec::Tag(BlockTag::Finalized),
            reward_percentiles: vec![20],
        },
    )
    .await
    .expect("HTTP call failed")
    .unwrap()
}

#[post_upgrade]
fn post_upgrade(minter_arg: Option<MinterArg>) {
    match minter_arg {
        Some(MinterArg::InitArg(_)) => {
            ic_cdk::trap("cannot upgrade canister state with init args");
        }
        None | Some(MinterArg::UpgradeArg) => {
            ic_cdk::println!("Upgrading...");
            STATE.with(|cell| {
                *cell.borrow_mut() = Some(
                    ciborium::de::from_reader(StableReader::default())
                        .expect("failed to decode ledger state"),
                );
            });
        }
    }
    ic_cdk_timers::set_timer_interval(SCRAPPING_ETH_LOGS_INTERVAL, || {
        ic_cdk::spawn(scrap_eth_logs())
    });
}

#[query]
#[candid_method(query)]
fn dump_state_for_debugging() -> DebugState {
    fn to_tx(hash: &Hash) -> EthTransaction {
        EthTransaction {
            transaction_hash: hash.to_string(),
        }
    }
    read_state(|s| DebugState {
        ecdsa_key_name: s.ecdsa_key_name.clone(),
        last_seen_block_number: candid::Nat::from(s.last_seen_block_number.clone()),
        minted_transactions: s.minted_transactions.iter().map(to_tx).collect(),
        invalid_transactions: s.invalid_transactions.iter().map(to_tx).collect(),
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
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

fn main() {}
