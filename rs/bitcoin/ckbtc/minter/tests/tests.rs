use assert_matches::assert_matches;
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::{Address as BtcAddress, Network as BtcNetwork};
use candid::{CandidType, Decode, Encode, Nat, Principal};
use chrono::{DateTime, Utc};
use ic_base_types::{CanisterId, PrincipalId};
use ic_bitcoin_canister_mock::{OutPoint, PushUtxoToAddress, Utxo};
use ic_btc_checker::{
    BtcNetwork as CheckerBtcNetwork, CheckArg, CheckMode, InitArg as CheckerInitArg,
    UpgradeArg as CheckerUpgradeArg,
};
use ic_btc_interface::Txid;
use ic_ckbtc_minter::lifecycle::init::{InitArgs as CkbtcMinterInitArgs, MinterArg};
use ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs;
use ic_ckbtc_minter::queries::{EstimateFeeArg, RetrieveBtcStatusRequest, WithdrawalFee};
use ic_ckbtc_minter::state::eventlog::Event;
use ic_ckbtc_minter::state::{BtcRetrievalStatusV2, Mode, RetrieveBtcStatus, RetrieveBtcStatusV2};
use ic_ckbtc_minter::updates::get_btc_address::GetBtcAddressArgs;
use ic_ckbtc_minter::updates::retrieve_btc::{
    ErrorCode, RetrieveBtcArgs, RetrieveBtcError, RetrieveBtcOk, RetrieveBtcWithApprovalArgs,
    RetrieveBtcWithApprovalError,
};
use ic_ckbtc_minter::updates::update_balance::{
    PendingUtxo, UpdateBalanceArgs, UpdateBalanceError, UtxoStatus,
};
use ic_ckbtc_minter::{
    Log, MinterInfo, Network, CKBTC_LEDGER_MEMO_SIZE, MIN_RELAY_FEE_PER_VBYTE,
    MIN_RESUBMISSION_DELAY,
};
use ic_http_types::{HttpRequest, HttpResponse};
use ic_icrc1_ledger::{InitArgsBuilder as LedgerInitArgsBuilder, LedgerArgument};
use ic_metrics_assert::{CanisterHttpQuery, MetricsAssert};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, UserError, WasmResult};
use ic_test_utilities_load_wasm::load_wasm;
use ic_types::Cycles;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc3::transactions::{GetTransactionsRequest, GetTransactionsResponse};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

const CHECK_FEE: u64 = 2_000;
const TRANSFER_FEE: u64 = 10;
const MIN_CONFIRMATIONS: u32 = 12;
const MAX_TIME_IN_QUEUE: Duration = Duration::from_secs(10);
const WITHDRAWAL_ADDRESS: &str = "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c";
const SENDER_ID: PrincipalId = PrincipalId::new_user_test_id(1);

#[allow(deprecated)]
fn default_init_args() -> CkbtcMinterInitArgs {
    CkbtcMinterInitArgs {
        btc_network: Network::Regtest,
        ecdsa_key_name: "master_ecdsa_public_key".into(),
        retrieve_btc_min_amount: 2000,
        ledger_id: CanisterId::from(0),
        max_time_in_queue_nanos: MAX_TIME_IN_QUEUE.as_nanos() as u64,
        min_confirmations: Some(MIN_CONFIRMATIONS),
        mode: Mode::GeneralAvailability,
        check_fee: None,
        btc_checker_principal: Some(CanisterId::from(0)),
        kyt_principal: None,
        kyt_fee: None,
        get_utxos_cache_expiration_seconds: None,
    }
}

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

fn bitcoin_mock_wasm() -> Vec<u8> {
    load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("mock"),
        "ic-bitcoin-canister-mock",
        &[],
    )
}

fn btc_checker_wasm() -> Vec<u8> {
    load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("checker"),
        "ic-btc-checker",
        &[],
    )
}

fn install_ledger(env: &StateMachine) -> CanisterId {
    let args = LedgerArgument::Init(
        LedgerInitArgsBuilder::for_tests()
            .with_transfer_fee(0_u8)
            .build(),
    );
    env.install_canister(ledger_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn install_minter(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let args = CkbtcMinterInitArgs {
        ledger_id,
        ..default_init_args()
    };
    let minter_arg = MinterArg::Init(args);
    env.install_canister(minter_wasm(), Encode!(&minter_arg).unwrap(), None)
        .unwrap()
}

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("Expected a successful reply, got a reject: {}", reject)
        }
    }
}

fn input_utxos(tx: &bitcoin::Transaction) -> Vec<bitcoin::OutPoint> {
    tx.input.iter().map(|txin| txin.previous_output).collect()
}

fn assert_replacement_transaction(old: &bitcoin::Transaction, new: &bitcoin::Transaction) {
    assert_ne!(old.txid(), new.txid());
    assert_eq!(input_utxos(old), input_utxos(new));

    let new_out_value = new.output.iter().map(|out| out.value).sum::<u64>();
    let prev_out_value = old.output.iter().map(|out| out.value).sum::<u64>();
    let relay_cost = new.vsize() as u64 * MIN_RELAY_FEE_PER_VBYTE / 1000;

    assert!(
        new_out_value + relay_cost <= prev_out_value,
        "the transaction fees should have increased by at least {relay_cost}. prev out value: {prev_out_value}, new out value: {new_out_value}"
    );
}

fn vec_to_txid(vec: Vec<u8>) -> Txid {
    let bytes: [u8; 32] = vec.try_into().expect("Vector length must be exactly 32");
    bytes.into()
}

fn range_to_txid(range: std::ops::RangeInclusive<u8>) -> Txid {
    vec_to_txid(range.collect::<Vec<u8>>())
}

fn new_state_machine() -> StateMachine {
    StateMachineBuilder::new()
        .with_master_ecdsa_public_key()
        .build()
}

#[test]
fn test_install_ckbtc_minter_canister() {
    let env = new_state_machine();
    let ledger_id = install_ledger(&env);
    install_minter(&env, ledger_id);
}

#[test]
fn test_wrong_upgrade_parameter() {
    let env = new_state_machine();

    // wrong init args

    let args = MinterArg::Init(CkbtcMinterInitArgs {
        ecdsa_key_name: "".into(),
        ..default_init_args()
    });
    let args = Encode!(&args).unwrap();
    if env.install_canister(minter_wasm(), args, None).is_ok() {
        panic!("init expected to fail")
    }
    let args = MinterArg::Init(CkbtcMinterInitArgs {
        btc_checker_principal: None,
        ..default_init_args()
    });
    let args = Encode!(&args).unwrap();
    if env.install_canister(minter_wasm(), args, None).is_ok() {
        panic!("init expected to fail")
    }

    // install the minter

    let minter_id = install_minter(&env, CanisterId::from(0));

    // upgrade only with wrong parameters

    let upgrade_args = UpgradeArgs {
        retrieve_btc_min_amount: Some(100),
        max_time_in_queue_nanos: Some(100),
        mode: Some(Mode::ReadOnly),
        ..Default::default()
    };
    let minter_arg = MinterArg::Upgrade(Some(upgrade_args));
    if env
        .upgrade_canister(minter_id, minter_wasm(), Encode!(&minter_arg).unwrap())
        .is_ok()
    {
        panic!("upgrade expected to fail")
    }
}

#[test]
fn test_upgrade_read_only() {
    let env = new_state_machine();
    let ledger_id = install_ledger(&env);
    let minter_id = install_minter(&env, ledger_id);

    let authorized_principal =
        Principal::from_str("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
            .unwrap();

    // upgrade
    let upgrade_args = UpgradeArgs {
        mode: Some(Mode::ReadOnly),
        ..Default::default()
    };
    let minter_arg = MinterArg::Upgrade(Some(upgrade_args));
    env.upgrade_canister(minter_id, minter_wasm(), Encode!(&minter_arg).unwrap())
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
    let res = Decode!(&res.bytes(), Result<Vec<UtxoStatus>, UpdateBalanceError>).unwrap();
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
    let env = new_state_machine();
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
        mode: Some(Mode::RestrictedTo(vec![authorized_principal])),
        ..Default::default()
    };
    let minter_arg = MinterArg::Upgrade(Some(upgrade_args));
    env.upgrade_canister(minter_id, minter_wasm(), Encode!(&minter_arg).unwrap())
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
    let res = Decode!(&res.bytes(), Result<Vec<UtxoStatus>, UpdateBalanceError>).unwrap();
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
    let upgrade_args = UpgradeArgs::default();
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
    let res = Decode!(&res.bytes(), Result<Vec<UtxoStatus>, UpdateBalanceError>).unwrap();
    assert!(
        matches!(res, Err(UpdateBalanceError::TemporarilyUnavailable(_))),
        "unexpected result: {:?}",
        res
    );
}

#[test]
fn test_no_new_utxos() {
    let ckbtc = CkBtcSetup::new();

    ckbtc.set_tip_height(100);

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 99,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    let deposit_address = ckbtc.get_btc_address(user);

    ckbtc.push_utxo(deposit_address, utxo.clone());

    let update_balance_args = UpdateBalanceArgs {
        owner: None,
        subaccount: None,
    };
    let res = ckbtc
        .env
        .execute_ingress_as(
            PrincipalId::new_user_test_id(1),
            ckbtc.minter_id,
            "update_balance",
            Encode!(&update_balance_args).unwrap(),
        )
        .expect("Failed to call update_balance");
    let res = Decode!(&res.bytes(), Result<Vec<UtxoStatus>, UpdateBalanceError>).unwrap();
    assert_eq!(
        res,
        Err(UpdateBalanceError::NoNewUtxos {
            pending_utxos: Some(vec![PendingUtxo {
                outpoint: utxo.outpoint,
                value: utxo.value,
                confirmations: 2,
            }]),
            current_confirmations: Some(2),
            required_confirmations: 12,
            suspended_utxos: Some(vec![]),
        })
    );
    ckbtc
        .check_minter_metrics()
        .assert_contains_metric_matching(
            r#"ckbtc_minter_update_calls_latency_bucket\{num_new_utxos="0",le="(\d+|\+Inf)"\} 1 \d+"#,
        ) // exactly 1 match for an update call with no new UTXOs
        .assert_does_not_contain_metric_matching(
            r#"ckbtc_minter_update_calls_latency_bucket\{num_new_utxos="1".*"#,
        ); // no metrics for update call with new UTXOs
}

#[test]
fn update_balance_should_return_correct_confirmations() {
    let ckbtc = CkBtcSetup::new();
    let upgrade_args = UpgradeArgs {
        min_confirmations: Some(3),
        ..Default::default()
    };
    let minter_arg = MinterArg::Upgrade(Some(upgrade_args));
    ckbtc
        .env
        .upgrade_canister(
            ckbtc.minter_id,
            minter_wasm(),
            Encode!(&minter_arg).unwrap(),
        )
        .expect("Failed to upgrade the minter canister");

    ckbtc.set_tip_height(12);

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 10,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo);

    let update_balance_args = UpdateBalanceArgs {
        owner: None,
        subaccount: None,
    };

    let res = ckbtc
        .env
        .execute_ingress_as(
            PrincipalId::new_user_test_id(1),
            ckbtc.minter_id,
            "update_balance",
            Encode!(&update_balance_args).unwrap(),
        )
        .expect("Failed to call update_balance");
    let res = Decode!(&res.bytes(), Result<Vec<UtxoStatus>, UpdateBalanceError>).unwrap();
    assert_eq!(
        res,
        Err(UpdateBalanceError::NoNewUtxos {
            current_confirmations: None,
            required_confirmations: 3,
            pending_utxos: Some(vec![]),
            suspended_utxos: Some(vec![]),
        })
    );
    ckbtc
        .check_minter_metrics()
        .assert_contains_metric_matching(
            r#"ckbtc_minter_update_calls_latency_bucket\{num_new_utxos="0",le="(\d+|\+Inf)"\} 1 \d+"#,
        ) // exactly 1 match for an update call with no new UTXOs
        .assert_contains_metric_matching(
            r#"ckbtc_minter_update_calls_latency_bucket\{num_new_utxos="1",le="(\d+|\+Inf)"\} 1 \d+"#,
        ); // exactly 1 match for an update call with new UTXOs
}

#[test]
fn test_illegal_caller() {
    let env = new_state_machine();
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

pub fn get_btc_address(
    env: &StateMachine,
    sender: PrincipalId,
    minter_id: CanisterId,
    arg: &GetBtcAddressArgs,
) -> String {
    Decode!(
        &env.execute_ingress_as(sender, minter_id, "get_btc_address", Encode!(arg).unwrap())
            .expect("failed to get btc address")
            .bytes(),
        String
    )
    .expect("failed to decode String response")
}

#[test]
fn test_minter() {
    use bitcoin::Address;

    let env = new_state_machine();
    let args = MinterArg::Init(CkbtcMinterInitArgs {
        retrieve_btc_min_amount: 100_000,
        min_confirmations: Some(6_u32),
        check_fee: Some(1001),
        ..default_init_args()
    });
    let args = Encode!(&args).unwrap();
    let minter_id = env.install_canister(minter_wasm(), args, None).unwrap();

    let btc_address_1 = get_btc_address(
        &env,
        SENDER_ID,
        minter_id,
        &GetBtcAddressArgs {
            owner: None,
            subaccount: None,
        },
    );
    let address_1 = Address::from_str(&btc_address_1).expect("invalid Bitcoin address");
    let btc_address_2 = get_btc_address(
        &env,
        SENDER_ID,
        minter_id,
        &GetBtcAddressArgs {
            owner: None,
            subaccount: Some([1; 32]),
        },
    );
    let address_2 = Address::from_str(&btc_address_2).expect("invalid Bitcoin address");
    assert_ne!(address_1, address_2);
}

#[test]
fn get_btc_address_from_anonymous_caller_should_succeed() {
    let env = new_state_machine();
    let args = MinterArg::Init(default_init_args());
    let args = Encode!(&args).unwrap();
    let minter_id = env.install_canister(minter_wasm(), args, None).unwrap();

    let btc_address = get_btc_address(
        &env,
        PrincipalId::new_anonymous(),
        minter_id,
        &GetBtcAddressArgs {
            owner: Some(Principal::from(SENDER_ID)),
            subaccount: None,
        },
    );
    assert!(!btc_address.is_empty());
}

#[test]
#[should_panic(expected = "the owner must be non-anonymous")]
fn get_btc_address_with_anonymous_owner_should_panic() {
    let env = new_state_machine();
    let args = MinterArg::Init(default_init_args());
    let args = Encode!(&args).unwrap();
    let minter_id = env.install_canister(minter_wasm(), args, None).unwrap();

    get_btc_address(
        &env,
        SENDER_ID,
        minter_id,
        &GetBtcAddressArgs {
            owner: Some(Principal::anonymous()),
            subaccount: None,
        },
    );
}

#[test]
#[should_panic(expected = "the owner must be non-anonymous")]
fn get_btc_address_with_empty_owner_and_anonymous_caller_should_panic() {
    let env = new_state_machine();
    let args = MinterArg::Init(default_init_args());
    let args = Encode!(&args).unwrap();
    let minter_id = env.install_canister(minter_wasm(), args, None).unwrap();

    get_btc_address(
        &env,
        PrincipalId::new_anonymous(),
        minter_id,
        &GetBtcAddressArgs {
            owner: None,
            subaccount: None,
        },
    );
}

fn bitcoin_canister_id(btc_network: Network) -> CanisterId {
    CanisterId::try_from(
        PrincipalId::from_str(match btc_network {
            Network::Testnet | Network::Regtest => {
                ic_config::execution_environment::BITCOIN_TESTNET_CANISTER_ID
            }
            Network::Mainnet => ic_config::execution_environment::BITCOIN_MAINNET_CANISTER_ID,
        })
        .unwrap(),
    )
    .unwrap()
}

fn install_bitcoin_mock_canister(env: &StateMachine, btc_network: Network) {
    use ic_cdk::api::management_canister::bitcoin::BitcoinNetwork;
    let cid = bitcoin_canister_id(btc_network);
    env.create_canister_with_cycles(Some(cid.into()), Cycles::new(0), None);
    env.install_existing_canister(
        cid,
        bitcoin_mock_wasm(),
        Encode!(&BitcoinNetwork::from(btc_network)).unwrap(),
    )
    .unwrap();
}

struct CkBtcSetup {
    pub env: StateMachine,
    pub caller: PrincipalId,
    pub bitcoin_id: CanisterId,
    pub ledger_id: CanisterId,
    pub minter_id: CanisterId,
    pub btc_checker_id: CanisterId,
}

impl CkBtcSetup {
    pub fn new() -> Self {
        let retrieve_btc_min_amount = 100_000;
        Self::new_with(Network::Mainnet, retrieve_btc_min_amount)
    }

    pub fn new_with(btc_network: Network, retrieve_btc_min_amount: u64) -> Self {
        let bitcoin_id = bitcoin_canister_id(btc_network);
        let env = StateMachineBuilder::new()
            .with_master_ecdsa_public_key()
            .with_default_canister_range()
            .with_extra_canister_range(bitcoin_id..=bitcoin_id)
            .build();

        install_bitcoin_mock_canister(&env, btc_network);
        let ledger_id = env.create_canister(None);
        let minter_id =
            env.create_canister_with_cycles(None, Cycles::new(100_000_000_000_000), None);
        let btc_checker_id = env.create_canister(None);

        env.install_existing_canister(
            ledger_id,
            ledger_wasm(),
            Encode!(&LedgerArgument::Init(
                LedgerInitArgsBuilder::with_symbol_and_name("ckBTC", "ckBTC")
                    .with_minting_account(minter_id.get().0)
                    .with_transfer_fee(TRANSFER_FEE)
                    .with_max_memo_length(CKBTC_LEDGER_MEMO_SIZE)
                    .with_feature_flags(ic_icrc1_ledger::FeatureFlags { icrc2: true })
                    .build()
            ))
            .unwrap(),
        )
        .expect("failed to install the ledger");

        env.install_existing_canister(
            minter_id,
            minter_wasm(),
            Encode!(&MinterArg::Init(CkbtcMinterInitArgs {
                btc_network,
                retrieve_btc_min_amount,
                ledger_id,
                max_time_in_queue_nanos: 100,
                check_fee: Some(CHECK_FEE),
                btc_checker_principal: btc_checker_id.into(),
                ..default_init_args()
            }))
            .unwrap(),
        )
        .expect("failed to install the minter");

        let caller = PrincipalId::new_user_test_id(1);

        env.install_existing_canister(
            btc_checker_id,
            btc_checker_wasm(),
            Encode!(&CheckArg::InitArg(CheckerInitArg {
                btc_network: CheckerBtcNetwork::Mainnet,
                check_mode: CheckMode::AcceptAll,
                num_subnet_nodes: 1,
            }))
            .unwrap(),
        )
        .expect("failed to install the Bitcoin checker canister");

        env.execute_ingress(
            bitcoin_id,
            "set_fee_percentiles",
            Encode!(&(1..=100).map(|i| i * 100).collect::<Vec<u64>>()).unwrap(),
        )
        .expect("failed to set fee percentiles");

        Self {
            env,
            caller,
            bitcoin_id,
            ledger_id,
            minter_id,
            btc_checker_id,
        }
    }

    pub fn set_fee_percentiles(&self, fees: &Vec<u64>) {
        self.env
            .execute_ingress(
                self.bitcoin_id,
                "set_fee_percentiles",
                Encode!(fees).unwrap(),
            )
            .expect("failed to set fee percentiles");
    }

    pub fn set_tip_height(&self, tip_height: u32) {
        self.env
            .execute_ingress(
                self.bitcoin_id,
                "set_tip_height",
                Encode!(&tip_height).unwrap(),
            )
            .expect("failed to set fee tip height");
    }

    pub fn push_utxo(&self, address: String, utxo: Utxo) {
        assert_reply(
            self.env
                .execute_ingress(
                    self.bitcoin_id,
                    "push_utxo_to_address",
                    Encode!(&PushUtxoToAddress { address, utxo }).unwrap(),
                )
                .expect("failed to push a UTXO"),
        );
    }

    pub fn get_btc_address(&self, account: impl Into<Account>) -> String {
        let account = account.into();
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "get_btc_address",
                        Encode!(&GetBtcAddressArgs {
                            owner: Some(account.owner),
                            subaccount: account.subaccount,
                        })
                        .unwrap(),
                    )
                    .expect("failed to get btc address")
            ),
            String
        )
        .unwrap()
    }

    pub fn get_minter_info(&self) -> MinterInfo {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(self.minter_id, "get_minter_info", Encode!().unwrap(),)
                    .expect("failed to get minter info")
            ),
            MinterInfo
        )
        .unwrap()
    }

    pub fn replay_events(&self, events: &Vec<Event>) {
        self.env
            .execute_ingress(self.minter_id, "replay_events", Encode!(&events).unwrap())
            .expect("failed to replay_events");
    }

    pub fn finalize_requests_now(&self) {
        self.env
            .execute_ingress(self.minter_id, "finalize_requests_now", Encode!().unwrap())
            .expect("failed to finalize_requests_now");
    }

    pub fn get_logs(&self) -> Log {
        let request = HttpRequest {
            method: "".to_string(),
            url: "/logs".to_string(),
            headers: vec![],
            body: serde_bytes::ByteBuf::new(),
        };
        let response = Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "http_request", Encode!(&request).unwrap(),)
                    .expect("failed to get minter info")
            ),
            HttpResponse
        )
        .unwrap();
        serde_json::from_slice(&response.body).expect("failed to parse ckbtc minter log")
    }

    pub fn refresh_fee_percentiles(&self) {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "refresh_fee_percentiles",
                        Encode!().unwrap()
                    )
                    .expect("failed to refresh fee percentiles")
            ),
            Option<Nat>
        )
        .unwrap();
    }

    pub fn estimate_withdrawal_fee(&self, amount: Option<u64>) -> WithdrawalFee {
        self.refresh_fee_percentiles();
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.minter_id,
                        "estimate_withdrawal_fee",
                        Encode!(&EstimateFeeArg { amount }).unwrap()
                    )
                    .expect("failed to query minter fee estimate")
            ),
            WithdrawalFee
        )
        .unwrap()
    }

    pub fn deposit_utxo(&self, account: impl Into<Account>, utxo: Utxo) {
        let account = account.into();
        let deposit_address = self.get_btc_address(account);

        self.push_utxo(deposit_address, utxo.clone());

        let utxo_status = Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "update_balance",
                        Encode!(&UpdateBalanceArgs {
                            owner: Some(account.owner),
                            subaccount: account.subaccount,
                        })
                        .unwrap()
                    )
                    .expect("failed to update balance")
            ),
            Result<Vec<UtxoStatus>, UpdateBalanceError>
        )
        .unwrap();

        assert_eq!(
            utxo_status.unwrap(),
            vec![UtxoStatus::Minted {
                block_index: 0,
                minted_amount: utxo.value - CHECK_FEE,
                utxo,
            }]
        );
    }

    pub fn get_transactions(&self, arg: GetTransactionsRequest) -> GetTransactionsResponse {
        Decode!(
            &assert_reply(
                self.env
                    .query(self.ledger_id, "get_transactions", Encode!(&arg).unwrap())
                    .expect("failed to query get_transactions on the ledger")
            ),
            GetTransactionsResponse
        )
        .unwrap()
    }

    pub fn get_known_utxos(&self, account: impl Into<Account>) -> Vec<Utxo> {
        let account = account.into();
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.minter_id,
                        "get_known_utxos",
                        Encode!(&UpdateBalanceArgs {
                            owner: Some(account.owner),
                            subaccount: account.subaccount,
                        })
                        .unwrap()
                    )
                    .expect("failed to query balance on the ledger")
            ),
            Vec<Utxo>
        )
        .unwrap()
    }

    pub fn balance_of(&self, account: impl Into<Account>) -> Nat {
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.ledger_id,
                        "icrc1_balance_of",
                        Encode!(&account.into()).unwrap()
                    )
                    .expect("failed to query balance on the ledger")
            ),
            Nat
        )
        .unwrap()
    }

    pub fn withdrawal_account(&self, owner: PrincipalId) -> Account {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        owner,
                        self.minter_id,
                        "get_withdrawal_account",
                        Encode!().unwrap()
                    )
                    .expect("failed to get ckbtc withdrawal account")
            ),
            Account
        )
        .unwrap()
    }

    pub fn transfer(&self, from: impl Into<Account>, to: impl Into<Account>, amount: u64) -> Nat {
        let from = from.into();
        let to = to.into();
        Decode!(&assert_reply(self.env.execute_ingress_as(
            PrincipalId::from(from.owner),
            self.ledger_id,
            "icrc1_transfer",
            Encode!(&TransferArg {
                from_subaccount: from.subaccount,
                to,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(amount),
            }).unwrap()
            ).expect("failed to execute token transfer")),
            Result<Nat, TransferError>
        )
        .unwrap()
        .expect("token transfer failed")
    }

    pub fn approve_minter(
        &self,
        from: Principal,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> Nat {
        Decode!(&assert_reply(self.env.execute_ingress_as(
            PrincipalId::from(from),
            self.ledger_id,
            "icrc2_approve",
            Encode!(&ApproveArgs {
                from_subaccount,
                spender: Account {
                    owner: self.minter_id.into(),
                    subaccount: None
                },
                amount: Nat::from(amount),
                expected_allowance: None,
                expires_at: None,
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()
            ).expect("failed to execute token transfer")),
            Result<Nat, ApproveError>
        )
        .unwrap()
        .expect("approve failed")
    }

    pub fn retrieve_btc(
        &self,
        address: String,
        amount: u64,
    ) -> Result<RetrieveBtcOk, RetrieveBtcError> {
        Decode!(
            &assert_reply(
                self.env.execute_ingress_as(self.caller, self.minter_id, "retrieve_btc", Encode!(&RetrieveBtcArgs {
                    address,
                    amount,
                }).unwrap())
                .expect("failed to execute retrieve_btc request")
            ),
            Result<RetrieveBtcOk, RetrieveBtcError>
        ).unwrap()
    }

    pub fn retrieve_btc_with_approval(
        &self,
        address: String,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> Result<RetrieveBtcOk, RetrieveBtcWithApprovalError> {
        Decode!(
            &assert_reply(
                self.env.execute_ingress_as(self.caller, self.minter_id, "retrieve_btc_with_approval", Encode!(&RetrieveBtcWithApprovalArgs {
                    address,
                    amount,
                    from_subaccount
                }).unwrap())
                .expect("failed to execute retrieve_btc request")
            ),
            Result<RetrieveBtcOk, RetrieveBtcWithApprovalError>
        ).unwrap()
    }

    pub fn retrieve_btc_status(&self, block_index: u64) -> RetrieveBtcStatus {
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.minter_id,
                        "retrieve_btc_status",
                        Encode!(&RetrieveBtcStatusRequest { block_index }).unwrap()
                    )
                    .expect("failed to get ckbtc withdrawal account")
            ),
            RetrieveBtcStatus
        )
        .unwrap()
    }

    pub fn retrieve_btc_status_v2(&self, block_index: u64) -> RetrieveBtcStatusV2 {
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.minter_id,
                        "retrieve_btc_status_v2",
                        Encode!(&RetrieveBtcStatusRequest { block_index }).unwrap()
                    )
                    .expect("failed to retrieve_btc_status_v2")
            ),
            RetrieveBtcStatusV2
        )
        .unwrap()
    }

    pub fn retrieve_btc_status_v2_by_account(
        &self,
        maybe_account: Option<Account>,
    ) -> Vec<BtcRetrievalStatusV2> {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(
                        self.minter_id,
                        "retrieve_btc_status_v2_by_account",
                        Encode!(&maybe_account).unwrap()
                    )
                    .expect("failed to retrieve_btc_status_v2_by_account")
            ),
            Vec<BtcRetrievalStatusV2>
        )
        .unwrap()
    }

    pub fn tick_until<R>(
        &self,
        description: &str,
        max_ticks: u64,
        mut condition: impl FnMut(&CkBtcSetup) -> Option<R>,
    ) -> R {
        if let Some(result) = condition(self) {
            return result;
        }
        for _ in 0..max_ticks {
            self.env.tick();
            if let Some(result) = condition(self) {
                return result;
            }
        }
        self.print_minter_logs();
        self.print_minter_events();
        panic!(
            "did not reach condition '{}' in {} ticks",
            description, max_ticks
        )
    }

    /// Check that the given condition holds for the specified number of state machine ticks.
    pub fn assert_for_n_ticks(
        &self,
        description: &str,
        num_ticks: u64,
        mut condition: impl FnMut(&CkBtcSetup) -> bool,
    ) {
        for n in 0..num_ticks {
            self.env.tick();
            if !condition(self) {
                panic!(
                    "Condition '{}' does not hold after {} ticks",
                    description, n
                );
            }
        }
    }

    pub fn await_btc_transaction(&self, block_index: u64, max_ticks: usize) -> Txid {
        let mut last_status = None;
        for _ in 0..max_ticks {
            dbg!(self.get_logs());
            let status_v2 = self.retrieve_btc_status_v2(block_index);
            let status = self.retrieve_btc_status(block_index);
            assert_eq!(RetrieveBtcStatusV2::from(status.clone()), status_v2);
            match status {
                RetrieveBtcStatus::Submitted { txid } => {
                    return txid;
                }
                status => {
                    last_status = Some(status);
                    self.env.tick();
                }
            }
        }
        panic!(
            "the minter did not submit a transaction in {} ticks; last status {:?}",
            max_ticks, last_status
        )
    }

    pub fn print_minter_events(&self) {
        use ic_ckbtc_minter::state::eventlog::{Event, GetEventsArg};
        let events = Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.minter_id,
                        "get_events",
                        Encode!(&GetEventsArg {
                            start: 0,
                            length: 2000,
                        })
                        .unwrap()
                    )
                    .expect("failed to query minter events")
            ),
            Vec<Event>
        )
        .unwrap();
        println!("{:#?}", events);
    }

    pub fn print_minter_logs(&self) {
        let log = self.get_logs();
        for entry in log.entries {
            println!(
                "{} {}:{} {}",
                entry.timestamp, entry.file, entry.line, entry.message
            );
        }
    }

    pub fn await_finalization(&self, block_index: u64, max_ticks: usize) -> Txid {
        let mut last_status = None;
        for _ in 0..max_ticks {
            let status_v2 = self.retrieve_btc_status_v2(block_index);
            let status = self.retrieve_btc_status(block_index);
            assert_eq!(RetrieveBtcStatusV2::from(status.clone()), status_v2);
            match status {
                RetrieveBtcStatus::Confirmed { txid } => {
                    return txid;
                }
                status => {
                    last_status = Some(status);
                    self.env.tick();
                }
            }
        }
        panic!(
            "the minter did not finalize the transaction in {} ticks; last status: {:?}",
            max_ticks, last_status
        )
    }

    pub fn finalize_transaction(&self, tx: &bitcoin::Transaction) {
        let change_utxo = tx.output.last().unwrap();
        let change_address =
            BtcAddress::from_script(&change_utxo.script_pubkey, BtcNetwork::Bitcoin).unwrap();

        let main_address = self.get_btc_address(Principal::from(self.minter_id));
        assert_eq!(change_address.to_string(), main_address);

        self.env
            .advance_time(MIN_CONFIRMATIONS * Duration::from_secs(600) + Duration::from_secs(1));
        let txid_bytes: [u8; 32] = tx.txid().to_vec().try_into().unwrap();
        self.push_utxo(
            change_address.to_string(),
            Utxo {
                value: change_utxo.value,
                height: 0,
                outpoint: OutPoint {
                    txid: txid_bytes.into(),
                    vout: 1,
                },
            },
        );
    }

    pub fn mempool(&self) -> BTreeMap<Txid, bitcoin::Transaction> {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(self.bitcoin_id, "get_mempool", Encode!().unwrap())
                    .expect("failed to call get_mempool on the bitcoin mock")
            ),
            Vec<Vec<u8>>
        )
        .unwrap()
        .iter()
        .map(|tx_bytes| {
            let tx = bitcoin::Transaction::deserialize(tx_bytes)
                .expect("failed to parse a bitcoin transaction");

            (vec_to_txid(tx.txid().to_vec()), tx)
        })
        .collect()
    }

    pub fn minter_self_check(&self) {
        Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "self_check", Encode!().unwrap())
                    .expect("failed to query self_check")
            ),
            Result<(), String>
        )
        .unwrap()
        .expect("minter self-check failed")
    }

    pub fn check_minter_metrics(self) -> MetricsAssert<Self> {
        MetricsAssert::from_http_query(self)
    }
}

impl CanisterHttpQuery<UserError> for CkBtcSetup {
    fn http_query(&self, request: Vec<u8>) -> Result<Vec<u8>, UserError> {
        self.env
            .query(self.minter_id, "http_request", request)
            .map(assert_reply)
    }
}

#[test]
fn test_transaction_finalization() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo.clone());

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - CHECK_FEE));

    assert_eq!(ckbtc.get_known_utxos(user), vec![utxo]);

    // Step 2: request a withdrawal

    let withdrawal_amount = 50_000_000;
    let withdrawal_account = ckbtc.withdrawal_account(user.into());
    let fee_estimate = ckbtc.estimate_withdrawal_fee(Some(withdrawal_amount));
    dbg!(fee_estimate);
    let fee_estimate = ckbtc.estimate_withdrawal_fee(Some(withdrawal_amount));

    ckbtc.transfer(user, withdrawal_account, withdrawal_amount);

    let RetrieveBtcOk { block_index } = ckbtc
        .retrieve_btc(WITHDRAWAL_ADDRESS.to_string(), withdrawal_amount)
        .expect("retrieve_btc failed");

    ckbtc.env.advance_time(MAX_TIME_IN_QUEUE);

    // Step 3: wait for the transaction to be submitted

    let txid = ckbtc.await_btc_transaction(block_index, 10);
    let mempool = ckbtc.mempool();
    assert_eq!(
        mempool.len(),
        1,
        "ckbtc transaction did not appear in the mempool"
    );
    let tx = mempool
        .get(&txid)
        .expect("the mempool does not contain the withdrawal transaction");

    assert_eq!(2, tx.output.len());
    assert_eq!(
        tx.output[0].value,
        withdrawal_amount - fee_estimate.minter_fee - fee_estimate.bitcoin_fee
    );

    // Step 4: confirm the transaction

    ckbtc.finalize_transaction(tx);
    assert_eq!(ckbtc.await_finalization(block_index, 10), txid);

    assert_eq!(ckbtc.get_known_utxos(user), vec![]);
}

#[test]
fn test_min_retrieval_amount_default() {
    let ckbtc = CkBtcSetup::new();

    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 100_000);

    // The numbers used in this test have been re-computed using a python script using integers.
    ckbtc.set_fee_percentiles(&vec![0; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 100_000);

    ckbtc.set_fee_percentiles(&vec![116_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 150_000);

    ckbtc.set_fee_percentiles(&vec![342_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 150_000);

    ckbtc.set_fee_percentiles(&vec![343_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 200_000);
}

#[test]
fn test_min_retrieval_amount_custom() {
    let min_amount = 12_345;
    let ckbtc = CkBtcSetup::new_with(Network::Testnet, min_amount);

    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, min_amount);

    // The numbers used in this test have been re-computed using a python script using integers.
    ckbtc.set_fee_percentiles(&vec![0; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, min_amount);

    ckbtc.set_fee_percentiles(&vec![116_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 50_000 + min_amount);

    ckbtc.set_fee_percentiles(&vec![342_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 50_000 + min_amount);

    ckbtc.set_fee_percentiles(&vec![343_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 100_000 + min_amount);

    // When fee becomes 0 again, it goes back to the initial setting
    ckbtc.set_fee_percentiles(&vec![0; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, min_amount);

    // Test changing min_retrieve_fee when upgrade
    let min_amount = 123_456;
    let upgrade_args = UpgradeArgs {
        retrieve_btc_min_amount: Some(min_amount),
        ..Default::default()
    };
    let minter_arg = MinterArg::Upgrade(Some(upgrade_args));
    assert!(ckbtc
        .env
        .upgrade_canister(
            ckbtc.minter_id,
            minter_wasm(),
            Encode!(&minter_arg).unwrap()
        )
        .is_ok());
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, min_amount);
}

#[test]
fn test_stuck_transaction() {
    let ckbtc = CkBtcSetup::new();

    // init_ecdsa_public_key
    let user = Principal::from(ckbtc.caller);
    let withdrawal_account_before_event = ckbtc.withdrawal_account(user.into());
    assert_eq!(
        withdrawal_account_before_event.to_string(),
        "rrkah-fqaaa-aaaaa-aaaaq-cai-crp7eoq.16ed4ca467558d2f8b4191368b32517202925d24ae683f320e3fa17d41c1408e"
    );

    let events = Mainnet.deserialize();
    assert_eq!(events.total_event_count, 366_308);
    ckbtc.replay_events(&events.events);
    // ckbtc.minter_self_check(); //instruction limit

    //sanity check
    let status_3rd_stuck_tx = ckbtc.retrieve_btc_status_v2(2_626_488);
    assert_matches!(
        status_3rd_stuck_tx,
        RetrieveBtcStatusV2::Submitted{txid} if txid.to_string() == "422f3115c4f865536f92e94d22cb7b2795b0482e517f7c46561e2234cf03e603"
    );

    // state machine only works with "master_ecdsa_public_key"
    let upgrade_args = UpgradeArgs {
        ecdsa_key_name: Some("master_ecdsa_public_key".to_string()),
        ..Default::default()
    };
    let minter_arg = MinterArg::Upgrade(Some(upgrade_args));
    assert!(ckbtc
        .env
        .upgrade_canister(
            ckbtc.minter_id,
            minter_wasm(),
            Encode!(&minter_arg).unwrap()
        )
        .is_ok());

    // init_ecdsa_public_key
    let withdrawal_account = ckbtc.withdrawal_account(user.into());
    assert_eq!(withdrawal_account_before_event, withdrawal_account);

    ckbtc
        .env
        .set_time(SystemTime::UNIX_EPOCH + Duration::from_secs(1750879059));
    let datetime: DateTime<Utc> = ckbtc.env.time().into();
    assert_eq!(
        datetime.format("%d/%m/%Y %T").to_string(),
        "25/06/2025 19:17:39"
    );

    ckbtc.finalize_requests_now();
}

#[derive(Debug)]
struct Mainnet;

trait GetEventsFile {
    fn path_to_events_file(&self) -> PathBuf {
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push(format!("test_resources/{}", self.file_name()));
        path
    }

    fn file_name(&self) -> &str;

    fn deserialize(&self) -> GetEventsResult {
        use candid::Decode;
        use flate2::read::GzDecoder;
        use std::fs::File;
        use std::io::Read;

        let file = File::open(self.path_to_events_file()).unwrap();
        let mut gz = GzDecoder::new(file);
        let mut decompressed_buffer = Vec::new();
        gz.read_to_end(&mut decompressed_buffer)
            .expect("BUG: failed to decompress events");
        Decode!(&decompressed_buffer, GetEventsResult)
            .expect("Failed to decode events")
            .into()
    }
}

impl GetEventsFile for Mainnet {
    fn file_name(&self) -> &str {
        "mainnet_events.gz"
    }
}

#[derive(Clone, Debug, CandidType, serde::Deserialize)]
pub struct GetEventsResult {
    pub events: Vec<Event>,
    pub total_event_count: u64,
}

#[test]
fn test_transaction_resubmission_finalize_new() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo);

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - CHECK_FEE));

    // Step 2: request a withdrawal

    let withdrawal_amount = 50_000_000;
    let withdrawal_account = ckbtc.withdrawal_account(user.into());
    ckbtc.transfer(user, withdrawal_account, withdrawal_amount);

    let RetrieveBtcOk { block_index } = ckbtc
        .retrieve_btc(WITHDRAWAL_ADDRESS.to_string(), withdrawal_amount)
        .expect("retrieve_btc failed");

    ckbtc.env.advance_time(MAX_TIME_IN_QUEUE);

    // Step 3: wait for the transaction to be submitted

    let txid = ckbtc.await_btc_transaction(block_index, 10);
    let mempool = ckbtc.mempool();
    let tx = mempool
        .get(&txid)
        .expect("the mempool does not contain the original transaction");

    // Step 4: wait for the transaction resubmission

    ckbtc
        .env
        .advance_time(MIN_RESUBMISSION_DELAY - Duration::from_secs(1));

    ckbtc.assert_for_n_ticks("no resubmission before the delay", 5, |ckbtc| {
        ckbtc.mempool().len() == 1
    });

    // We need to wait at least 5 seconds before the next resubmission because it's the internal
    // timer interval.
    ckbtc.env.advance_time(Duration::from_secs(5));

    let mempool = ckbtc.tick_until("mempool has a replacement transaction", 10, |ckbtc| {
        let mempool = ckbtc.mempool();
        (mempool.len() > 1).then_some(mempool)
    });

    let new_txid = ckbtc.await_btc_transaction(block_index, 10);
    let new_tx = mempool
        .get(&new_txid)
        .expect("the pool does not contain the new transaction");

    assert_replacement_transaction(tx, new_tx);

    // Step 5: finalize the new transaction

    ckbtc.finalize_transaction(new_tx);
    assert_eq!(ckbtc.await_finalization(block_index, 10), new_txid);
    ckbtc.minter_self_check();
}

#[test]
fn test_transaction_resubmission_finalize_old() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo);

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - CHECK_FEE));

    // Step 2: request a withdrawal

    let withdrawal_amount = 50_000_000;
    let withdrawal_account = ckbtc.withdrawal_account(user.into());
    ckbtc.transfer(user, withdrawal_account, withdrawal_amount);

    let RetrieveBtcOk { block_index } = ckbtc
        .retrieve_btc(WITHDRAWAL_ADDRESS.to_string(), withdrawal_amount)
        .expect("retrieve_btc failed");

    ckbtc.env.advance_time(MAX_TIME_IN_QUEUE);

    // Step 3: wait for the transaction to be submitted

    let txid = ckbtc.await_btc_transaction(block_index, 10);
    let mempool = ckbtc.mempool();
    let tx = mempool
        .get(&txid)
        .expect("the mempool does not contain the original transaction");

    // Step 4: wait for the transaction resubmission

    ckbtc
        .env
        .advance_time(MIN_RESUBMISSION_DELAY + Duration::from_secs(1));

    let mempool = ckbtc.tick_until("mempool has a replacement transaction", 10, |ckbtc| {
        let mempool = ckbtc.mempool();
        (mempool.len() > 1).then_some(mempool)
    });

    let new_txid = ckbtc.await_btc_transaction(block_index, 10);

    let new_tx = mempool
        .get(&new_txid)
        .expect("the pool does not contain the new transaction");

    assert_replacement_transaction(tx, new_tx);

    // Step 5: finalize the old transaction

    ckbtc.finalize_transaction(tx);
    assert_eq!(ckbtc.await_finalization(block_index, 10), txid);
    ckbtc.minter_self_check();
}

#[test]
fn test_transaction_resubmission_finalize_middle() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo);

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - CHECK_FEE));

    // Step 2: request a withdrawal

    let withdrawal_amount = 50_000_000;
    let withdrawal_account = ckbtc.withdrawal_account(user.into());
    ckbtc.transfer(user, withdrawal_account, withdrawal_amount);

    let RetrieveBtcOk { block_index } = ckbtc
        .retrieve_btc(WITHDRAWAL_ADDRESS.to_string(), withdrawal_amount)
        .expect("retrieve_btc failed");

    ckbtc.env.advance_time(MAX_TIME_IN_QUEUE);

    // Step 3: wait for the transaction to be submitted

    let original_txid = ckbtc.await_btc_transaction(block_index, 10);
    let mempool = ckbtc.mempool();
    let original_tx = mempool
        .get(&original_txid)
        .expect("the mempool does not contain the original transaction");

    // Step 4: wait for the first transaction resubmission

    ckbtc
        .env
        .advance_time(MIN_RESUBMISSION_DELAY + Duration::from_secs(1));

    let mempool_2 = ckbtc.tick_until("mempool contains a replacement transaction", 10, |ckbtc| {
        let mempool = ckbtc.mempool();
        (mempool.len() > 1).then_some(mempool)
    });

    let second_txid = ckbtc.await_btc_transaction(block_index, 10);

    let second_tx = mempool_2
        .get(&second_txid)
        .expect("the pool does not contain the second transaction");

    assert_replacement_transaction(original_tx, second_tx);

    // Step 5: wait for the second transaction resubmission
    ckbtc
        .env
        .advance_time(MIN_RESUBMISSION_DELAY + Duration::from_secs(1));

    let mempool_3 = ckbtc.tick_until("mempool contains the third transaction", 10, |ckbtc| {
        let mempool = ckbtc.mempool();
        (mempool.len() > 2).then_some(mempool)
    });

    let third_txid = ckbtc.await_btc_transaction(block_index, 10);
    assert_ne!(third_txid, second_txid);
    assert_ne!(third_txid, original_txid);

    let third_tx = mempool_3
        .get(&third_txid)
        .expect("the pool does not contain the third transaction");

    assert_replacement_transaction(second_tx, third_tx);

    // Step 6: finalize the middle transaction

    ckbtc.finalize_transaction(second_tx);
    assert_eq!(ckbtc.await_finalization(block_index, 10), second_txid);
    ckbtc.minter_self_check();
}

#[test]
fn test_get_logs() {
    let ckbtc = CkBtcSetup::new();

    // Test that the endpoint does not trap.
    let _log = ckbtc.get_logs();
}

#[test]
fn test_taproot_transaction_finalization() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo);

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - CHECK_FEE));

    // Step 2: request a withdrawal

    let withdrawal_amount = 50_000_000;
    let withdrawal_account = ckbtc.withdrawal_account(user.into());
    ckbtc.transfer(user, withdrawal_account, withdrawal_amount);

    let RetrieveBtcOk { block_index } = ckbtc
        .retrieve_btc(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".to_string(),
            withdrawal_amount,
        )
        .expect("retrieve_btc failed");

    ckbtc.env.advance_time(MAX_TIME_IN_QUEUE);

    // Step 3: wait for the transaction to be submitted
    let txid = ckbtc.await_btc_transaction(block_index, 10);
    let mempool = ckbtc.mempool();
    assert_eq!(
        mempool.len(),
        1,
        "ckbtc transaction did not appear in the mempool"
    );
    let tx = mempool
        .get(&txid)
        .expect("the mempool does not contain the withdrawal transaction");

    assert_eq!(2, tx.output.len());

    // Step 4: confirm the transaction

    ckbtc.finalize_transaction(tx);
    assert_eq!(ckbtc.await_finalization(block_index, 10), txid);
}

#[test]
fn test_ledger_memo() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo);

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - CHECK_FEE));

    let get_transaction_request = GetTransactionsRequest {
        start: 0_u8.into(),
        length: 1_u8.into(),
    };
    let res = ckbtc.get_transactions(get_transaction_request);
    let memo = res.transactions[0].mint.clone().unwrap().memo.unwrap();

    use ic_ckbtc_minter::memo::MintMemo;
    let decoded_data = minicbor::decode::<MintMemo>(&memo.0).expect("failed to decode memo");
    assert_eq!(
        decoded_data,
        MintMemo::Convert {
            txid: Some(&(1..=32).collect::<Vec<u8>>()),
            vout: Some(1),
            kyt_fee: Some(CHECK_FEE),
        }
    );

    // Step 2: request a withdrawal

    let withdrawal_amount = 50_000_000;
    let withdrawal_account = ckbtc.withdrawal_account(user.into());
    ckbtc.transfer(user, withdrawal_account, withdrawal_amount);
    let btc_address = "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c".to_string();

    let RetrieveBtcOk { block_index } = ckbtc
        .retrieve_btc(btc_address.clone(), withdrawal_amount)
        .expect("retrieve_btc failed");

    let get_transaction_request = GetTransactionsRequest {
        start: block_index.into(),
        length: 1_u8.into(),
    };
    let res = ckbtc.get_transactions(get_transaction_request);
    let memo = res.transactions[0].burn.clone().unwrap().memo.unwrap();
    use ic_ckbtc_minter::memo::{BurnMemo, Status};

    let decoded_data = minicbor::decode::<BurnMemo>(&memo.0).expect("failed to decode memo");
    // `retrieve_btc` incurs no check fee
    assert_eq!(
        decoded_data,
        BurnMemo::Convert {
            address: Some(&btc_address),
            kyt_fee: None,
            status: Some(Status::Accepted),
        },
        "memo not found in burn"
    );
}

#[test]
fn test_filter_logs() {
    let ckbtc = CkBtcSetup::new();

    // Trigger an even to add some logs.

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo);

    let system_time = ckbtc.env.time();

    let nanos = system_time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos();

    let request = HttpRequest {
        method: "".to_string(),
        url: format!("/logs?time={}", nanos),
        headers: vec![],
        body: serde_bytes::ByteBuf::new(),
    };
    let response = Decode!(
        &assert_reply(
            ckbtc
                .env
                .query(ckbtc.minter_id, "http_request", Encode!(&request).unwrap(),)
                .expect("failed to get minter info")
        ),
        HttpResponse
    )
    .unwrap();
    let logs: Log =
        serde_json::from_slice(&response.body).expect("failed to parse ckbtc minter log");

    let request = HttpRequest {
        method: "".to_string(),
        url: format!("/logs?time={}", nanos + 30 * 1_000_000_000),
        headers: vec![],
        body: serde_bytes::ByteBuf::new(),
    };
    let response = Decode!(
        &assert_reply(
            ckbtc
                .env
                .query(ckbtc.minter_id, "http_request", Encode!(&request).unwrap(),)
                .expect("failed to get minter info")
        ),
        HttpResponse
    )
    .unwrap();
    let logs_filtered: Log =
        serde_json::from_slice(&response.body).expect("failed to parse ckbtc minter log");

    assert_ne!(logs.entries.len(), logs_filtered.entries.len());
}

#[test]
fn test_retrieve_btc_with_approval() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);

    ckbtc.deposit_utxo(user, utxo);
    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - CHECK_FEE));

    // Step 2: request a withdrawal

    let withdrawal_amount = 50_000_000;
    ckbtc.approve_minter(user, withdrawal_amount, None);
    let fee_estimate = ckbtc.estimate_withdrawal_fee(Some(withdrawal_amount));

    let RetrieveBtcOk { block_index } = ckbtc
        .retrieve_btc_with_approval(WITHDRAWAL_ADDRESS.to_string(), withdrawal_amount, None)
        .expect("retrieve_btc failed");

    let get_transaction_request = GetTransactionsRequest {
        start: block_index.into(),
        length: 1_u8.into(),
    };
    let res = ckbtc.get_transactions(get_transaction_request);
    let memo = res.transactions[0].burn.clone().unwrap().memo.unwrap();
    use ic_ckbtc_minter::memo::BurnMemo;

    let decoded_data = minicbor::decode::<BurnMemo>(&memo.0).expect("failed to decode memo");
    assert_eq!(
        decoded_data,
        BurnMemo::Convert {
            address: Some(WITHDRAWAL_ADDRESS),
            kyt_fee: None,
            status: None,
        },
        "memo not found in burn"
    );

    ckbtc.env.advance_time(MAX_TIME_IN_QUEUE);

    // Step 3: wait for the transaction to be submitted

    let txid = ckbtc.await_btc_transaction(block_index, 10);
    let mempool = ckbtc.mempool();
    assert_eq!(
        mempool.len(),
        1,
        "ckbtc transaction did not appear in the mempool"
    );
    let tx = mempool
        .get(&txid)
        .expect("the mempool does not contain the withdrawal transaction");

    assert_eq!(2, tx.output.len());
    assert_eq!(
        tx.output[0].value,
        withdrawal_amount - fee_estimate.minter_fee - fee_estimate.bitcoin_fee
    );

    // Step 4: confirm the transaction

    ckbtc.finalize_transaction(tx);
    assert_eq!(ckbtc.await_finalization(block_index, 10), txid);

    ckbtc
        .check_minter_metrics()
        .assert_contains_metric_matching(
            r#"ckbtc_minter_sign_with_ecdsa_latency_bucket\{result="success",le="(\d+|\+Inf)"\} 1 \d+"#,
        )
        .assert_does_not_contain_metric_matching(
            r#"ckbtc_minter_sign_with_ecdsa_latency_bucket\{result="failure",le="(\d+|\+Inf)"\} 1 \d+"#
        );
}

#[test]
fn test_retrieve_btc_with_approval_from_subaccount() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);
    let subaccount: Option<[u8; 32]> = Some([1; 32]);
    let user_account = Account {
        owner: user,
        subaccount,
    };

    ckbtc.deposit_utxo(user_account, utxo);
    assert_eq!(
        ckbtc.balance_of(user_account),
        Nat::from(deposit_value - CHECK_FEE)
    );

    // Step 2: request a withdrawal

    let withdrawal_amount = 50_000_000;
    ckbtc.approve_minter(user, withdrawal_amount, subaccount);
    let fee_estimate = ckbtc.estimate_withdrawal_fee(Some(withdrawal_amount));

    let RetrieveBtcOk { block_index } = ckbtc
        .retrieve_btc_with_approval(
            WITHDRAWAL_ADDRESS.to_string(),
            withdrawal_amount,
            subaccount,
        )
        .expect("retrieve_btc failed");

    let get_transaction_request = GetTransactionsRequest {
        start: block_index.into(),
        length: 1_u8.into(),
    };
    let res = ckbtc.get_transactions(get_transaction_request);
    let memo = res.transactions[0].burn.clone().unwrap().memo.unwrap();
    use ic_ckbtc_minter::memo::BurnMemo;

    let decoded_data = minicbor::decode::<BurnMemo>(&memo.0).expect("failed to decode memo");
    assert_eq!(
        decoded_data,
        BurnMemo::Convert {
            address: Some(WITHDRAWAL_ADDRESS),
            kyt_fee: None,
            status: None,
        },
        "memo not found in burn"
    );

    assert_eq!(
        ckbtc.retrieve_btc_status_v2_by_account(Some(user_account)),
        vec![BtcRetrievalStatusV2 {
            block_index,
            status_v2: Some(ckbtc.retrieve_btc_status_v2(block_index))
        }]
    );

    ckbtc.env.advance_time(MAX_TIME_IN_QUEUE);

    // Step 3: wait for the transaction to be submitted

    let txid = ckbtc.await_btc_transaction(block_index, 10);
    let mempool = ckbtc.mempool();
    assert_eq!(
        mempool.len(),
        1,
        "ckbtc transaction did not appear in the mempool"
    );
    let tx = mempool
        .get(&txid)
        .expect("the mempool does not contain the withdrawal transaction");

    assert_eq!(2, tx.output.len());
    assert_eq!(
        tx.output[0].value,
        withdrawal_amount - fee_estimate.minter_fee - fee_estimate.bitcoin_fee
    );

    // Step 4: confirm the transaction

    ckbtc.finalize_transaction(tx);
    assert_eq!(ckbtc.await_finalization(block_index, 10), txid);

    assert_eq!(
        ckbtc.retrieve_btc_status_v2_by_account(Some(user_account)),
        vec![BtcRetrievalStatusV2 {
            block_index,
            status_v2: Some(ckbtc.retrieve_btc_status_v2(block_index))
        }]
    );

    ckbtc
        .check_minter_metrics()
        .assert_contains_metric_matching(
            r#"ckbtc_minter_sign_with_ecdsa_latency_bucket\{result="success",le="(\d+|\+Inf)"\} 1 \d+"#,
        )
        .assert_does_not_contain_metric_matching(
            r#"ckbtc_minter_sign_with_ecdsa_latency_bucket\{result="failure",le="(\d+|\+Inf)"\} 1 \d+"#
        );
}

#[test]
fn test_retrieve_btc_with_approval_fail() {
    let ckbtc = CkBtcSetup::new();

    // Step 1: deposit ckBTC

    let deposit_value = 100_000_000;
    let utxo = Utxo {
        height: 0,
        outpoint: OutPoint {
            txid: range_to_txid(1..=32),
            vout: 1,
        },
        value: deposit_value,
    };

    let user = Principal::from(ckbtc.caller);
    let user_account = Account {
        owner: user,
        subaccount: Some([1; 32]),
    };

    ckbtc.deposit_utxo(user_account, utxo);
    assert_eq!(
        ckbtc.balance_of(user_account),
        Nat::from(deposit_value - CHECK_FEE)
    );

    // Step 2: request a withdrawal with ledger stopped

    let withdrawal_amount = 50_000_000;
    ckbtc.approve_minter(user, u64::MAX, Some([1; 32]));

    let stop_canister_result = ckbtc.env.stop_canister(ckbtc.ledger_id);
    assert_matches!(stop_canister_result, Ok(_));

    let retrieve_btc_result = ckbtc.retrieve_btc_with_approval(
        WITHDRAWAL_ADDRESS.to_string(),
        withdrawal_amount,
        Some([1; 32]),
    );
    assert_matches!(
        retrieve_btc_result,
        Err(RetrieveBtcWithApprovalError::TemporarilyUnavailable(_))
    );
    let start_canister_result = ckbtc.env.start_canister(ckbtc.ledger_id);
    assert_matches!(start_canister_result, Ok(_));

    let deposited_value = deposit_value - CHECK_FEE - TRANSFER_FEE;
    assert_eq!(ckbtc.balance_of(user_account), Nat::from(deposited_value));

    // Check that the correct error_code is returned if the check of the address fails

    ckbtc
        .env
        .upgrade_canister(
            ckbtc.btc_checker_id,
            btc_checker_wasm(),
            Encode!(&CheckArg::UpgradeArg(Some(CheckerUpgradeArg {
                check_mode: Some(CheckMode::RejectAll),
                ..CheckerUpgradeArg::default()
            })))
            .unwrap(),
        )
        .expect("failed to upgrade the Bitcoin checker canister");

    let retrieve_btc_result = ckbtc.retrieve_btc_with_approval(
        WITHDRAWAL_ADDRESS.to_string(),
        withdrawal_amount,
        Some([1; 32]),
    );
    assert_matches!(
        retrieve_btc_result,
        Err(RetrieveBtcWithApprovalError::GenericError { error_code, .. })
          if error_code == ErrorCode::TaintedAddress as u64
    );
    ckbtc.env.tick();
    assert_eq!(ckbtc.balance_of(user_account), Nat::from(deposited_value));

    // Check that the correct error_code is returned if the call to the Bitcoin checker canister fails

    let stop_canister_result = ckbtc.env.stop_canister(ckbtc.btc_checker_id);
    assert_matches!(stop_canister_result, Ok(_));

    let retrieve_btc_result = ckbtc.retrieve_btc_with_approval(
        WITHDRAWAL_ADDRESS.to_string(),
        withdrawal_amount,
        Some([1; 32]),
    );
    assert_matches!(
        retrieve_btc_result,
        Err(RetrieveBtcWithApprovalError::GenericError { error_code, .. })
          if error_code == ErrorCode::CheckCallFailed as u64
    );

    // Balance should be unchanged
    assert_eq!(ckbtc.balance_of(user_account), Nat::from(deposited_value));
    // No known reimbursement or pending status because the withdrawal is now rejected before burn.
    assert_eq!(
        ckbtc.retrieve_btc_status_v2_by_account(Some(user_account)),
        vec![]
    );
}
