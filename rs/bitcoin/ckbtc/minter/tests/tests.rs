use candid::Encode;
use ic_base_types::CanisterId;
use ic_btc_types::Network;
use ic_ckbtc_minter::lifecycle::init::InitArgs as CkbtcMinterInitArgs;
use ic_icrc1::Account;
use ic_icrc1_ledger::InitArgs as LedgerInitArgs;
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_load_wasm::load_wasm;
use ledger_canister::ArchiveOptions;
use std::path::PathBuf;

fn ledger_wasm() -> Vec<u8> {
    let path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rosetta-api")
        .join("icrc1")
        .join("ledger");
    load_wasm(path, "ic-icrc1-ledger", &[])
}

fn minter_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-ckbtc-minter",
        &[],
    )
}

fn install_ledger(env: &StateMachine) -> CanisterId {
    let args = LedgerInitArgs {
        minting_account: Account {
            owner: Default::default(),
            subaccount: None,
        },
        initial_balances: vec![],
        transfer_fee: 0,
        token_name: "Test Token".to_string(),
        token_symbol: "TST".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: 0,
            num_blocks_to_archive: 0,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: Default::default(),
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
    };
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn install_minter(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let args = CkbtcMinterInitArgs {
        btc_network: Network::Regtest,
        /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
        /// a testing key for testnet and mainnet
        ecdsa_key_name: "dfx_test_key".parse().unwrap(),
        retrieve_btc_min_fee: 0,
        retrieve_btc_min_amount: 0,
        ledger_id,
    };
    env.install_canister(minter_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

#[test]
fn test_install_ckbtc_minter_canister() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env);
    install_minter(&env, ledger_id);
}

#[test]
fn test_upgrade() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env);
    let minter_id = install_minter(&env, ledger_id);
    env.upgrade_canister(minter_id, minter_wasm(), Encode!().unwrap())
        .expect("Failed to upgrade the minter canister");
}
