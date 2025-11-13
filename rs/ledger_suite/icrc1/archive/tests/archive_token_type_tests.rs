use candid::{Encode, Principal};
use ic_state_machine_tests::StateMachine;

fn archive_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_ARCHIVE_WASM_U64_PATH").unwrap()).unwrap()
}

fn archive_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_ARCHIVE_WASM_u256_PATH").unwrap()).unwrap()
}

fn archive_mainnet_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKBTC_IC_ICRC1_ARCHIVE_DEPLOYED_VERSION_WASM_PATH").unwrap())
        .unwrap()
}

fn archive_mainnet_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKETH_IC_ICRC1_ARCHIVE_DEPLOYED_VERSION_WASM_PATH").unwrap())
        .unwrap()
}

fn default_init_args() -> Vec<u8> {
    Encode!(&Principal::anonymous(), &0u64, &Some(10u64), &Some(10u64)).unwrap()
}

// TODO: When the PR that added this test is part of mainnet, we can uncomment the panic expectation.
#[test]
// #[should_panic(
//     expected = "Incompatible token type, the upgraded archive token type is U64, current wasm token type is U256"
// )]
fn test_mainnet_u64_to_master_u256() {
    let env = StateMachine::new();
    let archive_id = env
        .install_canister(archive_mainnet_u64_wasm(), default_init_args(), None)
        .unwrap();

    // Try to upgrade the archive from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&()).unwrap();
    env.upgrade_canister(archive_id, archive_u256_wasm(), upgrade_args)
        .expect("Unable to upgrade the archive canister");
}

#[test]
#[should_panic(
    expected = "Incompatible token type, the upgraded archive token type is U64, current wasm token type is U256"
)]
fn test_master_u64_to_master_u256() {
    let env = StateMachine::new();
    let archive_id = env
        .install_canister(archive_u64_wasm(), default_init_args(), None)
        .unwrap();

    // Try to upgrade the archive from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&()).unwrap();
    env.upgrade_canister(archive_id, archive_u256_wasm(), upgrade_args)
        .expect("Unable to upgrade the archive canister");
}

// TODO: When the PR that added this test is part of mainnet, we can uncomment the panic expectation.
#[test]
// #[should_panic(
//     expected = "Incompatible token type, the upgraded archive token type is U256, current wasm token type is U64"
// )]
fn test_mainnet_u256_to_master_u64() {
    let env = StateMachine::new();
    let archive_id = env
        .install_canister(archive_mainnet_u256_wasm(), default_init_args(), None)
        .unwrap();

    // Try to upgrade the archive from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&()).unwrap();
    env.upgrade_canister(archive_id, archive_u64_wasm(), upgrade_args)
        .expect("Unable to upgrade the archive canister");
}

#[test]
#[should_panic(
    expected = "Incompatible token type, the upgraded archive token type is U256, current wasm token type is U64"
)]
fn test_master_u256_to_master_u64() {
    let env = StateMachine::new();
    let archive_id = env
        .install_canister(archive_u256_wasm(), default_init_args(), None)
        .unwrap();

    // Try to upgrade the archive from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&()).unwrap();
    env.upgrade_canister(archive_id, archive_u64_wasm(), upgrade_args)
        .expect("Unable to upgrade the archive canister");
}

// TODO: The following 2 tests can be deleted when the PR that added them is part of mainnet - the intermediate
// upgrade will not be storing the `token_type` anymore - it will be stored in the initial install.

#[test]
#[should_panic(
    expected = "Incompatible token type, the upgraded archive token type is U64, current wasm token type is U256"
)]
fn test_mainnet_u64_to_master_u64_to_master_u256() {
    let env = StateMachine::new();
    let archive_id = env
        .install_canister(archive_mainnet_u64_wasm(), default_init_args(), None)
        .unwrap();

    // Upgrade the archive from an older u64 wasm to the current u64 wasm.
    // This will store the `token_type` in the archive config.
    // The intermediate upgrade is used to verify that the `token_type` was correctly
    // stored in the archive config - without it the last upgrade would succeed.
    let upgrade_args = Encode!(&()).unwrap();
    env.upgrade_canister(archive_id, archive_u64_wasm(), upgrade_args)
        .expect("Unable to upgrade the archive canister");

    // Try to upgrade the archive from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&()).unwrap();
    env.upgrade_canister(archive_id, archive_u256_wasm(), upgrade_args)
        .expect("Unable to upgrade the archive canister");
}

#[test]
#[should_panic(
    expected = "Incompatible token type, the upgraded archive token type is U256, current wasm token type is U64"
)]
fn test_mainnet_u256_to_master_u256_to_master_u64() {
    let env = StateMachine::new();
    let archive_id = env
        .install_canister(archive_mainnet_u256_wasm(), default_init_args(), None)
        .unwrap();

    // Upgrade the archive from an older u256 wasm to the current u256 wasm.
    // This will store the `token_type` in the archive config.
    // The intermediate upgrade is used to verify that the `token_type` was correctly
    // stored in the archive config - without it the last upgrade would succeed.
    let upgrade_args = Encode!(&()).unwrap();
    env.upgrade_canister(archive_id, archive_u256_wasm(), upgrade_args)
        .expect("Unable to upgrade the archive canister");

    // Try to upgrade the archive from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&()).unwrap();
    env.upgrade_canister(archive_id, archive_u64_wasm(), upgrade_args)
        .expect("Unable to upgrade the archive canister");
}
