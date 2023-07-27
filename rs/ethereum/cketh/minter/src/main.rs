use candid::candid_method;
use ic_cdk_macros::{init, update};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::{
    DisplayLogsRequest, Eip1559TransactionPrice, Eip2930TransactionPrice, InitArg, MinterArg,
    ReceivedEthEvent,
};
use ic_cketh_minter::eth_rpc;
use ic_cketh_minter::eth_rpc::GasPrice;
use ic_crypto_ecdsa_secp256k1::PublicKey;
use std::cell::RefCell;

const TRANSACTION_GAS_LIMIT: u32 = 21_000;

thread_local! {
    static STATE: RefCell<Option<State>> = RefCell::default();
}

struct State {
    ecdsa_key_name: String,
}

impl From<InitArg> for State {
    fn from(InitArg { ecdsa_key_name }: InitArg) -> Self {
        Self { ecdsa_key_name }
    }
}

fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(s.borrow().as_ref().expect("BUG: state is not initialized")))
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

fn main() {}
