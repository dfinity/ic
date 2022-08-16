use candid::{Decode, Encode};
// use canister_test::PrincipalId;
// use canister_test::{PrincipalId, Project};
use ic_base_types::{CanisterId, PrincipalId};
use ic_btc_types::Network;
use ic_ckbtc_minter::{
    lifecycle::init::InitArgs as CkbtcMinterInitArgs,
    updates::get_btc_address::{GetBtcAddressArgs, GetBtcAddressResult},
};
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_load_wasm::load_wasm;

fn minter_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-ckbtc-minter",
        &[],
    )
}

fn install_minter(env: &StateMachine) -> CanisterId {
    let args = CkbtcMinterInitArgs {
        btc_network: Network::Regtest,
        /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
        /// a testing key for testnet and mainnet
        ecdsa_key_name: "dfx_test_key".parse().unwrap(),
    };
    env.install_canister(minter_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

#[test]
fn test_install_ckbtc_minter_canister() {
    let env = StateMachine::new();
    install_minter(&env);
}

fn _get_btc_address(
    env: &StateMachine,
    ckbtc_minter: CanisterId,
    sender: PrincipalId,
    arg: GetBtcAddressArgs,
) -> GetBtcAddressResult {
    let res = env
        .execute_ingress_as(
            sender,
            ckbtc_minter,
            "get_btc_address",
            Encode!(&arg).unwrap(),
        )
        .unwrap();
    match res {
        canister_test::WasmResult::Reply(r) => Decode!(&r, GetBtcAddressResult).unwrap(),
        canister_test::WasmResult::Reject(e) => panic!("{}", e),
    }
}

// TODO: enable this test when StateMachine has support for ecdsa_public_key
// #[test]
// fn get_btc_address_get_withdrawal_account() {
// let env = StateMachine::new();
// //env.install_wasm_in_mode(canister_id, mode, wasm, payload);
// let ckbtc_minter = install_ckbtc_minter(&env);
// let user = PrincipalId::new_user_test_id(42);
// println!("ckBTC Minter id: {}  user: {}", &ckbtc_minter, user);
// let GetBtcAddressResult { address } = get_btc_address(
//     &env,
//     ckbtc_minter,
//     user,
//     GetBtcAddressArgs { subaccount: None },
// );
// assert_eq!(address, "");
// }
