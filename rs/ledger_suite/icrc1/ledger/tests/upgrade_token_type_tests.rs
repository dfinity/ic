use candid::{Encode, Nat};
use ic_base_types::PrincipalId;
use ic_icrc1_ledger::{InitArgs, LedgerArgument};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc1::account::Account;

fn ledger_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_LEDGER_WASM_U64_PATH").unwrap()).unwrap()
}

fn ledger_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_LEDGER_WASM_U256_PATH").unwrap()).unwrap()
}

fn ledger_mainnet_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKBTC_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap())
        .unwrap()
}

fn ledger_mainnet_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKETH_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap())
        .unwrap()
}

fn default_init_args(initial_balances: Vec<(Account, Nat)>) -> Vec<u8> {
    Encode!(&LedgerArgument::Init(InitArgs {
        minting_account: PrincipalId::new_user_test_id(0).0.into(),
        fee_collector_account: None,
        initial_balances,
        transfer_fee: 10_000u64.into(),
        token_name: "Test Token".to_string(),
        decimals: Some(8),
        token_symbol: "XTST".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: 10usize,
            num_blocks_to_archive: 5usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: Some(0),
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        index_principal: None,
    }))
    .unwrap()
}

// TODO: This test can be deleted when the PR that added it is part of mainnet.
#[test]
#[should_panic(expected = "assertion `left == right` failed: u256 representation is 32-bytes long")]
fn test_mainnet_u64_with_balance_to_master_u256() {
    let env = StateMachine::new();
    let ledger_id = env
        .install_canister(
            ledger_mainnet_u64_wasm(),
            default_init_args(vec![(
                PrincipalId::new_user_test_id(100).0.into(),
                Nat::from(1u64),
            )]),
            None,
        )
        .unwrap();

    // Try to upgrade the ledger from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_u256_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");
}

// TODO: When the PR that added this test is part of mainnet, we can uncomment the panic expectation.
#[test]
// #[should_panic(
//     expected = "Incompatible token type, the upgraded ledger token type is U64, current wasm token type is U256"
// )]
fn test_mainnet_u64_to_master_u256() {
    let env = StateMachine::new();
    let ledger_id = env
        .install_canister(ledger_mainnet_u64_wasm(), default_init_args(vec![]), None)
        .unwrap();

    // Try to upgrade the ledger from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_u256_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");
}

#[test]
#[should_panic(
    expected = "Incompatible token type, the upgraded ledger token type is U64, current wasm token type is U256"
)]
fn test_master_u64_to_master_u256() {
    let env = StateMachine::new();
    let ledger_id = env
        .install_canister(ledger_u64_wasm(), default_init_args(vec![]), None)
        .unwrap();

    // Try to upgrade the ledger from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_u256_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");
}

#[test]
#[should_panic(
    expected = "Failed to read the Ledger state from memory manager managed stable structures"
)]
fn test_mainnet_u256_to_master_u64() {
    let env = StateMachine::new();
    let ledger_id = env
        .install_canister(ledger_mainnet_u256_wasm(), default_init_args(vec![]), None)
        .unwrap();

    // Try to upgrade the ledger from using a u256 wasm to a u64 wasm
    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_u64_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");
}

#[test]
#[should_panic(
    expected = "Failed to read the Ledger state from memory manager managed stable structures"
)]
fn test_master_u256_to_master_u64() {
    let env = StateMachine::new();
    let ledger_id = env
        .install_canister(ledger_u256_wasm(), default_init_args(vec![]), None)
        .unwrap();

    // Try to upgrade the ledger from using a u256 wasm to a u64 wasm
    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_u64_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");
}
