use crate::common::{
    account, default_archive_options, install_ledger, wait_until_sync_is_completed,
};
use candid::{Encode, Principal};
use ic_agent::identity::Identity;
use ic_icrc1_index_ng::{IndexArg, InitArg as IndexInitArg};
use ic_icrc1_test_utils::minter_identity;
use ic_state_machine_tests::StateMachine;

mod common;

fn index_wasm(env_var: &str) -> Vec<u8> {
    let index_wasm_path = std::env::var(env_var).unwrap_or_else(|_| {
        panic!(
            "The Index wasm path must be set using the env variable {}",
            env_var
        )
    });
    std::fs::read(&index_wasm_path).unwrap_or_else(|e| {
        panic!(
            "failed to load index Wasm file from path {} (env var {}): {}",
            index_wasm_path, env_var, e
        )
    })
}

fn index_wasm_u64() -> Vec<u8> {
    index_wasm("IC_ICRC1_INDEX_WASM_U64_PATH")
}

fn index_wasm_u256() -> Vec<u8> {
    index_wasm("IC_ICRC1_INDEX_WASM_U256_PATH")
}

#[test]
#[should_panic(expected = "assertion `left == right` failed: u256 representation is 32-bytes long")]
fn should_fail_to_upgrade_index_ng_from_u64_to_u256_wasm() {
    index_install_and_upgrade_test(index_wasm_u64(), index_wasm_u256());
}

#[test]
#[should_panic(expected = "called `Result::unwrap()` on an `Err` value: TryFromSliceError(())")]
fn should_fail_to_upgrade_index_ng_from_u256_to_u64_wasm() {
    index_install_and_upgrade_test(index_wasm_u256(), index_wasm_u64());
}

fn index_install_and_upgrade_test(index_install_wasm: Vec<u8>, index_upgrade_wasm: Vec<u8>) {
    let initial_balances: Vec<_> = vec![(account(1, 0), 1_000_000_000_000)];
    let env = &StateMachine::new();
    let minter = minter_identity().sender().unwrap();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        default_archive_options(),
        None,
        minter,
    );
    let index_init_arg = IndexArg::Init(IndexInitArg {
        ledger_id: Principal::from(ledger_id),
        retrieve_blocks_from_ledger_interval_seconds: None,
    });
    let index_id = env
        .install_canister(index_install_wasm, Encode!(&index_init_arg).unwrap(), None)
        .unwrap();
    wait_until_sync_is_completed(env, index_id, ledger_id);

    let upgrade_args = Encode!(&None::<IndexArg>).unwrap();
    env.upgrade_canister(index_id, index_upgrade_wasm, upgrade_args.clone())
        .unwrap();
}
