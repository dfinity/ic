use candid::candid_method;
use ic_cdk_macros::{init, update};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::{DisplayLogsRequest, InitArg, MinterArg, ReceivedEthEvent};
use ic_cketh_minter::eth_rpc;
use ic_crypto_ecdsa_secp256k1::PublicKey;
use std::cell::RefCell;

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

fn main() {}
