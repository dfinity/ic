use candid::candid_method;
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::{
    DisplayLogsRequest, Eip1559TransactionPrice, Eip2930TransactionPrice, EthTransaction, InitArg,
    MinterArg, ProcessedTransactions, ReceivedEthEvent,
};
use ic_cketh_minter::eth_logs::{mint_transaction, report_transaction_error};
use ic_cketh_minter::eth_rpc::{into_nat, BlockNumber, GasPrice, Hash, BLOCK_PI_RPC_PROVIDER_URL};
use ic_cketh_minter::{eth_logs, eth_rpc};
use ic_crypto_ecdsa_secp256k1::PublicKey;
use std::cell::RefCell;
use std::cmp::{min, Ordering};
use std::collections::BTreeSet;

const TRANSACTION_GAS_LIMIT: u32 = 21_000;
const SCRAPPING_ETH_LOGS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

thread_local! {
    static STATE: RefCell<Option<State>> = RefCell::default();
}

pub struct State {
    ecdsa_key_name: String,
    last_seen_block_number: BlockNumber,
    minted_transactions: BTreeSet<Hash>,
    invalid_transactions: BTreeSet<Hash>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            ecdsa_key_name: "test_key_1".to_string(),
            // Note that the default block to start from for logs scrapping
            // depends on the chain we are using:
            // Ethereum and Sepolia have for example different block heights at a given time.
            // https://sepolia.etherscan.io/block/3938798
            last_seen_block_number: BlockNumber::new(3_956_206),
            minted_transactions: BTreeSet::new(),
            invalid_transactions: BTreeSet::new(),
        }
    }
}

impl From<InitArg> for State {
    fn from(InitArg { ecdsa_key_name }: InitArg) -> Self {
        Self {
            ecdsa_key_name,
            ..Self::default()
        }
    }
}

fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(s.borrow().as_ref().expect("BUG: state is not initialized")))
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| {
        f(s.borrow_mut()
            .as_mut()
            .expect("BUG: state is not initialized"))
    })
}

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
        derivation_path: vec![],
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

/// Estimate price of EIP-1559 transaction based on the
/// `base_fee_per_gas` included in the last finalized block.
/// See https://www.blocknative.com/blog/eip-1559-fees
#[update]
#[candid_method(update)]
async fn eip_1559_transaction_price() -> Eip1559TransactionPrice {
    use eth_rpc::{Block, BlockSpec, BlockTag};
    use ic_cketh_minter::eth_rpc::{into_nat, GetBlockByNumberParams};

    const MAX_PRIORITY_FEE_PER_GAS: u64 = 100_000_000; //0.1 gwei

    let finalized_block: Block = eth_rpc::call(
        "https://rpc.sepolia.org",
        "eth_getBlockByNumber",
        GetBlockByNumberParams {
            block: BlockSpec::Tag(BlockTag::Finalized),
            include_full_transactions: false,
        },
    )
    .await
    .expect("HTTP call failed")
    .unwrap();

    let base_fee_from_last_finalized_block = into_nat(finalized_block.base_fee_per_gas);
    let max_priority_fee_per_gas = candid::Nat::from(MAX_PRIORITY_FEE_PER_GAS);
    let max_fee_per_gas =
        (2_u32 * base_fee_from_last_finalized_block.clone()) + max_priority_fee_per_gas.clone();
    let gas_limit = candid::Nat::from(TRANSACTION_GAS_LIMIT);

    Eip1559TransactionPrice {
        base_fee_from_last_finalized_block,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
    }
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
