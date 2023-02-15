use candid::{Decode, Encode, Principal};
use ic_base_types::CanisterId;
use ic_btc_types::Network;
use ic_ckbtc_minter::lifecycle::init::InitArgs as CkbtcMinterInitArgs;
use ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs;
use ic_ckbtc_minter::state::Mode;
use ic_ckbtc_minter::updates::retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError, RetrieveBtcOk};
use ic_ckbtc_minter::updates::update_balance::{
    UpdateBalanceArgs, UpdateBalanceError, UpdateBalanceResult,
};
use ic_icrc1::Account;
use ic_icrc1_ledger::{InitArgs as LedgerInitArgs, LedgerArgument};
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_load_wasm::load_wasm;
use icp_ledger::ArchiveOptions;
use std::path::PathBuf;
use std::str::FromStr;

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
    let args = LedgerArgument::Init(LedgerInitArgs {
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
    });
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn install_minter(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let args = CkbtcMinterInitArgs {
        btc_network: Network::Regtest,
        /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
        /// a testing key for testnet and mainnet
        ecdsa_key_name: "dfx_test_key".parse().unwrap(),
        retrieve_btc_min_amount: 0,
        ledger_id,
        max_time_in_queue_nanos: 0,
        min_confirmations: Some(1),
        mode: Mode::GeneralAvailability,
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
fn test_upgrade_read_only() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env);
    let minter_id = install_minter(&env, ledger_id);

    let authorized_principal =
        Principal::from_str("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
            .unwrap();

    // upgrade
    let upgrade_args = UpgradeArgs {
        retrieve_btc_min_amount: Some(100),
        min_confirmations: None,
        max_time_in_queue_nanos: Some(100),
        mode: Some(Mode::ReadOnly),
    };
    env.upgrade_canister(minter_id, minter_wasm(), Encode!(&upgrade_args).unwrap())
        .expect("Failed to upgrade the minter canister");

    // when the mode is ReadOnly then the minter should reject all update calls.

    // 1. update_balance
    let update_balance_args = UpdateBalanceArgs {
        owner: None,
        subaccount: None,
    };
    let res = env
        .execute_ingress_as(
            authorized_principal.into(),
            minter_id,
            "update_balance",
            Encode!(&update_balance_args).unwrap(),
        )
        .expect("Failed to call update_balance");
    let res = Decode!(&res.bytes(), Result<UpdateBalanceResult, UpdateBalanceError>).unwrap();
    assert!(
        matches!(res, Err(UpdateBalanceError::TemporarilyUnavailable(_))),
        "unexpected result: {:?}",
        res
    );

    // 2. retrieve_btc
    let retrieve_btc_args = RetrieveBtcArgs {
        amount: 10,
        address: "".into(),
    };
    let res = env
        .execute_ingress_as(
            authorized_principal.into(),
            minter_id,
            "retrieve_btc",
            Encode!(&retrieve_btc_args).unwrap(),
        )
        .expect("Failed to call retrieve_btc");
    let res = Decode!(&res.bytes(), Result<RetrieveBtcOk, RetrieveBtcError>).unwrap();
    assert!(
        matches!(res, Err(RetrieveBtcError::TemporarilyUnavailable(_))),
        "unexpected result: {:?}",
        res
    );
}

#[test]
fn test_upgrade_restricted() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env);
    let minter_id = install_minter(&env, ledger_id);

    let authorized_principal =
        Principal::from_str("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
            .unwrap();

    let unauthorized_principal =
        Principal::from_str("gjfkw-yiolw-ncij7-yzhg2-gq6ec-xi6jy-feyni-g26f4-x7afk-thx6z-6ae")
            .unwrap();

    // upgrade
    let upgrade_args = UpgradeArgs {
        retrieve_btc_min_amount: Some(100),
        min_confirmations: None,
        max_time_in_queue_nanos: Some(100),
        mode: Some(Mode::RestrictedTo(vec![authorized_principal])),
    };
    env.upgrade_canister(minter_id, minter_wasm(), Encode!(&upgrade_args).unwrap())
        .expect("Failed to upgrade the minter canister");

    // Check that the unauthorized user cannot modify the state.

    // 1. update_balance
    let update_balance_args = UpdateBalanceArgs {
        owner: None,
        subaccount: None,
    };
    let res = env
        .execute_ingress_as(
            unauthorized_principal.into(),
            minter_id,
            "update_balance",
            Encode!(&update_balance_args).unwrap(),
        )
        .expect("Failed to call update_balance");
    let res = Decode!(&res.bytes(), Result<UpdateBalanceResult, UpdateBalanceError>).unwrap();
    assert!(
        matches!(res, Err(UpdateBalanceError::TemporarilyUnavailable(_))),
        "unexpected result: {:?}",
        res
    );

    // 2. retrieve_btc
    let retrieve_btc_args = RetrieveBtcArgs {
        amount: 10,
        address: "".into(),
    };
    let res = env
        .execute_ingress_as(
            unauthorized_principal.into(),
            minter_id,
            "retrieve_btc",
            Encode!(&retrieve_btc_args).unwrap(),
        )
        .expect("Failed to call retrieve_btc");
    let res = Decode!(&res.bytes(), Result<RetrieveBtcOk, RetrieveBtcError>).unwrap();
    assert!(
        matches!(res, Err(RetrieveBtcError::TemporarilyUnavailable(_))),
        "unexpected result: {:?}",
        res
    );

    // Test restricted BTC deposits.
    let upgrade_args = UpgradeArgs {
        retrieve_btc_min_amount: Some(100),
        min_confirmations: None,
        max_time_in_queue_nanos: Some(100),
        mode: Some(Mode::DepositsRestrictedTo(vec![authorized_principal])),
    };
    env.upgrade_canister(minter_id, minter_wasm(), Encode!(&upgrade_args).unwrap())
        .expect("Failed to upgrade the minter canister");

    let update_balance_args = UpdateBalanceArgs {
        owner: None,
        subaccount: None,
    };

    let res = env
        .execute_ingress_as(
            unauthorized_principal.into(),
            minter_id,
            "update_balance",
            Encode!(&update_balance_args).unwrap(),
        )
        .expect("Failed to call update_balance");
    let res = Decode!(&res.bytes(), Result<UpdateBalanceResult, UpdateBalanceError>).unwrap();
    assert!(
        matches!(res, Err(UpdateBalanceError::TemporarilyUnavailable(_))),
        "unexpected result: {:?}",
        res
    );
}

#[test]
fn test_illegal_caller() {
    let env = StateMachine::new();
    let ledger_id = install_ledger(&env);
    let minter_id = install_minter(&env, ledger_id);

    let authorized_principal =
        Principal::from_str("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
            .unwrap();

    // update_balance with minter's principal as target
    let update_balance_args = UpdateBalanceArgs {
        owner: Some(Principal::from_str(&minter_id.get().to_string()).unwrap()),
        subaccount: None,
    };
    // This call should panick
    let res = env.execute_ingress_as(
        authorized_principal.into(),
        minter_id,
        "update_balance",
        Encode!(&update_balance_args).unwrap(),
    );
    assert!(res.is_err());
    // Anonynmous call should fail
    let res = env.execute_ingress(
        minter_id,
        "update_balance",
        Encode!(&update_balance_args).unwrap(),
    );
    assert!(res.is_err());
}
