use candid::candid_method;
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::{
    DisplayLogsRequest, Eip1559TransactionPrice, Eip2930TransactionPrice, EthTransaction,
    MinterArg, ProcessedTransactions, ReceivedEthEvent, TransactionStatus,
};
use ic_cketh_minter::eth_logs::{mint_transaction, report_transaction_error};
use ic_cketh_minter::eth_rpc::{into_nat, GasPrice, Hash, BLOCK_PI_RPC_PROVIDER_URL};
use ic_cketh_minter::eth_rpc::{JsonRpcResult, Transaction};
use ic_cketh_minter::state::mutate_state;
use ic_cketh_minter::state::read_state;
use ic_cketh_minter::state::State;
use ic_cketh_minter::state::STATE;
use ic_cketh_minter::tx::TransactionRequest;
use ic_cketh_minter::{eth_logs, eth_rpc};
use ic_crypto_ecdsa_secp256k1::PublicKey;
use std::cmp::{min, Ordering};
use std::str::FromStr;

const TRANSACTION_GAS_LIMIT: u32 = 21_000;
const SCRAPPING_ETH_LOGS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

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

#[update]
#[candid_method(update)]
async fn minter_address() -> String {
    use ic_cdk::api::management_canister::ecdsa::{
        ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    };
    let key_name = read_state(|s| s.ecdsa_key_name.clone());
    let (response,) = ecdsa_public_key(EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: ic_cketh_minter::MAIN_DERIVATION_PATH,
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
    let tx_bytes = TransactionRequest {
        chain_id: SEPOLIA_TEST_CHAIN_ID,
        to: Address::from_str(&to_string).unwrap(),
        nonce: nonce.into(),
        gas_limit: 100000_u32.into(),
        max_fee_per_gas: 1946965145_u32.into(),
        value: value.into(),
        data: vec![],
        transaction_type: 2,
        access_list: vec![],
        max_priority_fee_per_gas: 1946965145_u32.into(),
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
    use eth_rpc::{BlockSpec, BlockTag, FeeHistory, FeeHistoryParams, Quantity};
    use ic_cketh_minter::eth_rpc::into_nat;

    // average value between the `minSuggestedMaxPriorityFeePerGas`
    // used by Metamask, see
    // https://github.com/MetaMask/core/blob/f5a4f52e17f407c6411e4ef9bd6685aab184b91d/packages/gas-fee-controller/src/fetchGasEstimatesViaEthFeeHistory/calculateGasFeeEstimatesForPriorityLevels.ts#L14
    const MIN_MAX_PRIORITY_FEE_PER_GAS: u64 = 1_500_000_000; //1.5 gwei

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
    let base_fee_from_last_finalized_block = into_nat(fee_history.base_fee_per_gas[4]);
    let base_fee_of_next_finalized_block = into_nat(fee_history.base_fee_per_gas[5]);
    let max_priority_fee_per_gas = {
        let mut rewards: Vec<Quantity> = fee_history.reward.into_iter().flatten().collect();
        let historic_max_priority_fee_per_gas = into_nat(
            *median(&mut rewards).expect("should be non-empty with rewards of the last 5 blocks"),
        );
        std::cmp::max(
            historic_max_priority_fee_per_gas,
            candid::Nat::from(MIN_MAX_PRIORITY_FEE_PER_GAS),
        )
    };
    let max_fee_per_gas =
        (2_u32 * base_fee_of_next_finalized_block.clone()) + max_priority_fee_per_gas.clone();
    let gas_limit = candid::Nat::from(TRANSACTION_GAS_LIMIT);

    Eip1559TransactionPrice {
        base_fee_from_last_finalized_block,
        base_fee_of_next_finalized_block,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
    }
}

fn median<T: Ord>(values: &mut [T]) -> Option<&T> {
    if values.is_empty() {
        return None;
    }
    let (_, item, _) = values.select_nth_unstable(values.len() / 2);
    Some(item)
}

/// Estimate price of EIP-2930 or legacy transactions based on the value returned by
/// `eth_gasPrice` JSON-RPC call.
#[update]
#[candid_method(update)]
async fn eip_2930_transaction_price() -> Eip2930TransactionPrice {
    use ic_cketh_minter::eth_rpc::into_nat;

    let gas_price: GasPrice = eth_rpc::call("https://rpc.sepolia.org", "eth_gasPrice", ())
        .await
        .expect("HTTP call failed")
        .unwrap();

    let gas_price = into_nat(gas_price.0);
    let gas_limit = candid::Nat::from(TRANSACTION_GAS_LIMIT);

    Eip2930TransactionPrice {
        gas_price,
        gas_limit,
    }
}

#[post_upgrade]
fn post_upgrade(minter_arg: Option<MinterArg>) {
    match minter_arg {
        Some(MinterArg::InitArg(_)) => {
            ic_cdk::trap("cannot upgrade canister state with init args");
        }
        None | Some(MinterArg::UpgradeArg) => {
            ic_cdk::println!("Upgrading...");
            STATE.with(|cell| *cell.borrow_mut() = Some(State::default()));
        }
    }
    ic_cdk_timers::set_timer_interval(SCRAPPING_ETH_LOGS_INTERVAL, || {
        ic_cdk::spawn(scrap_eth_logs())
    });
}

#[query]
#[candid_method(query)]
fn retrieve_processed_transactions() -> ProcessedTransactions {
    fn to_tx(hash: &Hash) -> EthTransaction {
        EthTransaction {
            transaction_hash: hash.to_string(),
        }
    }
    read_state(|s| ProcessedTransactions {
        minted: s.minted_transactions.iter().map(to_tx).collect(),
        invalid: s.invalid_transactions.iter().map(to_tx).collect(),
    })
}

fn main() {}
