use assert_matches::assert_matches;
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::{Address as BtcAddress, Network as BtcNetwork};
use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_bitcoin_canister_mock::{OutPoint, PushUtxoToAddress, Utxo};
use ic_btc_interface::{Network, Txid};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_ckbtc_kyt::{InitArg as KytInitArg, KytMode, LifecycleArg, SetApiKeyArg};
use ic_ckbtc_minter::lifecycle::init::{InitArgs as CkbtcMinterInitArgs, MinterArg};
use ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs;
use ic_ckbtc_minter::queries::{EstimateFeeArg, RetrieveBtcStatusRequest, WithdrawalFee};
use ic_ckbtc_minter::state::{
    BtcRetrievalStatusV2, Mode, ReimburseDepositTask, ReimbursedDeposit,
    ReimbursementReason::{CallFailed, TaintedDestination},
    RetrieveBtcStatus, RetrieveBtcStatusV2,
};
use ic_ckbtc_minter::updates::get_btc_address::GetBtcAddressArgs;
use ic_ckbtc_minter::updates::retrieve_btc::{
    RetrieveBtcArgs, RetrieveBtcError, RetrieveBtcOk, RetrieveBtcWithApprovalArgs,
    RetrieveBtcWithApprovalError,
};
use ic_ckbtc_minter::updates::update_balance::{
    PendingUtxo, UpdateBalanceArgs, UpdateBalanceError, UtxoStatus,
};
use ic_ckbtc_minter::{
    Log, MinterInfo, CKBTC_LEDGER_MEMO_SIZE, MIN_RELAY_FEE_PER_VBYTE, MIN_RESUBMISSION_DELAY,
};
use ic_icrc1_ledger::{InitArgsBuilder as LedgerInitArgsBuilder, LedgerArgument};
use ic_state_machine_tests::{Cycles, StateMachine, StateMachineBuilder, WasmResult};
use ic_test_utilities_load_wasm::load_wasm;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc3::transactions::{GetTransactionsRequest, GetTransactionsResponse};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

const KYT_FEE: u64 = 2_000;
const TRANSFER_FEE: u64 = 10;
const MIN_CONFIRMATIONS: u32 = 12;
const MAX_TIME_IN_QUEUE: Duration = Duration::from_secs(10);
const WITHDRAWAL_ADDRESS: &str = "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c";

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

fn kyt_wasm() -> Vec<u8> {
    load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("kyt"),
        "ic-ckbtc-kyt",
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
        btc_network: Network::Regtest.into(),
        // The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
        // a testing key for testnet and mainnet
        ecdsa_key_name: "dfx_test_key".parse().unwrap(),
        retrieve_btc_min_amount: 2000,
        ledger_id,
        max_time_in_queue_nanos: 0,
        min_confirmations: Some(1),
        mode: Mode::GeneralAvailability,
        kyt_fee: None,
        kyt_principal: Some(CanisterId::from(0)),
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
        btc_network: Network::Regtest.into(),
        ecdsa_key_name: "".into(),
        retrieve_btc_min_amount: 100_000,
        ledger_id: CanisterId::from_u64(0),
        max_time_in_queue_nanos: MAX_TIME_IN_QUEUE.as_nanos() as u64,
        min_confirmations: Some(6_u32),
        mode: Mode::GeneralAvailability,
        kyt_fee: Some(1001),
        kyt_principal: None,
    });
    let args = Encode!(&args).unwrap();
    if env.install_canister(minter_wasm(), args, None).is_ok() {
        panic!("init expected to fail")
    }
    let args = MinterArg::Init(CkbtcMinterInitArgs {
        btc_network: Network::Regtest.into(),
        ecdsa_key_name: "some_key".into(),
        retrieve_btc_min_amount: 100_000,
        ledger_id: CanisterId::from_u64(0),
        max_time_in_queue_nanos: MAX_TIME_IN_QUEUE.as_nanos() as u64,
        min_confirmations: Some(6_u32),
        mode: Mode::GeneralAvailability,
        kyt_fee: Some(1001),
        kyt_principal: None,
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
        min_confirmations: None,
        max_time_in_queue_nanos: Some(100),
        mode: Some(Mode::ReadOnly),
        kyt_principal: None,
        kyt_fee: None,
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
        retrieve_btc_min_amount: Some(2000),
        min_confirmations: None,
        max_time_in_queue_nanos: Some(100),
        mode: Some(Mode::ReadOnly),
        kyt_principal: Some(CanisterId::from(0)),
        kyt_fee: None,
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
        retrieve_btc_min_amount: Some(2000),
        min_confirmations: None,
        max_time_in_queue_nanos: Some(100),
        mode: Some(Mode::RestrictedTo(vec![authorized_principal])),
        kyt_fee: None,
        kyt_principal: Some(CanisterId::from(0)),
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
    let upgrade_args = UpgradeArgs {
        retrieve_btc_min_amount: Some(100),
        min_confirmations: None,
        max_time_in_queue_nanos: Some(100),
        mode: Some(Mode::DepositsRestrictedTo(vec![authorized_principal])),
        kyt_principal: Some(CanisterId::from(0)),
        kyt_fee: None,
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
        })
    );
}

#[test]
fn update_balance_should_return_correct_confirmations() {
    let ckbtc = CkBtcSetup::new();
    let upgrade_args = UpgradeArgs {
        retrieve_btc_min_amount: None,
        min_confirmations: Some(3),
        max_time_in_queue_nanos: None,
        mode: None,
        kyt_principal: None,
        kyt_fee: None,
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
            pending_utxos: Some(vec![])
        })
    );
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
    minter_id: CanisterId,
    arg: &GetBtcAddressArgs,
) -> String {
    Decode!(
        &env.execute_ingress_as(
            CanisterId::from_u64(100).into(),
            minter_id,
            "get_btc_address",
            Encode!(arg).unwrap()
        )
        .expect("failed to transfer funds")
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
        btc_network: Network::Regtest.into(),
        ecdsa_key_name: "master_ecdsa_public_key".into(),
        retrieve_btc_min_amount: 100_000,
        ledger_id: CanisterId::from_u64(0),
        max_time_in_queue_nanos: MAX_TIME_IN_QUEUE.as_nanos() as u64,
        min_confirmations: Some(6_u32),
        mode: Mode::GeneralAvailability,
        kyt_fee: Some(1001),
        kyt_principal: Some(CanisterId::from(0)),
    });
    let args = Encode!(&args).unwrap();
    let minter_id = env.install_canister(minter_wasm(), args, None).unwrap();

    let btc_address_1 = get_btc_address(
        &env,
        minter_id,
        &GetBtcAddressArgs {
            owner: None,
            subaccount: None,
        },
    );
    let address_1 = Address::from_str(&btc_address_1).expect("invalid bitcoin address");
    let btc_address_2 = get_btc_address(
        &env,
        minter_id,
        &GetBtcAddressArgs {
            owner: None,
            subaccount: Some([1; 32]),
        },
    );
    let address_2 = Address::from_str(&btc_address_2).expect("invalid bitcoin address");
    assert_ne!(address_1, address_2);
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
    let cid = bitcoin_canister_id(btc_network);
    env.create_canister_with_cycles(Some(cid.into()), Cycles::new(0), None);

    env.install_existing_canister(cid, bitcoin_mock_wasm(), Encode!(&btc_network).unwrap())
        .unwrap();
}

struct CkBtcSetup {
    pub env: StateMachine,
    pub caller: PrincipalId,
    pub kyt_provider: PrincipalId,
    pub bitcoin_id: CanisterId,
    pub ledger_id: CanisterId,
    pub minter_id: CanisterId,
    pub kyt_id: CanisterId,
}

impl CkBtcSetup {
    pub fn new() -> Self {
        Self::new_with(Network::Mainnet)
    }

    pub fn new_with(btc_network: Network) -> Self {
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
        let kyt_id = env.create_canister(None);

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

        let retrieve_btc_min_amount = match btc_network {
            Network::Testnet | Network::Regtest => 10_000,
            Network::Mainnet => 100_000,
        };

        env.install_existing_canister(
            minter_id,
            minter_wasm(),
            Encode!(&MinterArg::Init(CkbtcMinterInitArgs {
                btc_network: btc_network.into(),
                ecdsa_key_name: "master_ecdsa_public_key".to_string(),
                retrieve_btc_min_amount,
                ledger_id,
                max_time_in_queue_nanos: 100,
                min_confirmations: Some(MIN_CONFIRMATIONS),
                mode: Mode::GeneralAvailability,
                kyt_fee: Some(KYT_FEE),
                kyt_principal: kyt_id.into(),
            }))
            .unwrap(),
        )
        .expect("failed to install the minter");

        let caller = PrincipalId::new_user_test_id(1);
        let kyt_provider = PrincipalId::new_user_test_id(2);

        env.install_existing_canister(
            kyt_id,
            kyt_wasm(),
            Encode!(&LifecycleArg::InitArg(KytInitArg {
                minter_id: minter_id.into(),
                maintainers: vec![kyt_provider.into()],
                mode: KytMode::AcceptAll,
            }))
            .unwrap(),
        )
        .expect("failed to install the KYT canister");

        env.execute_ingress(
            bitcoin_id,
            "set_fee_percentiles",
            Encode!(&(1..=100).map(|i| i * 100).collect::<Vec<u64>>()).unwrap(),
        )
        .expect("failed to set fee percentiles");

        env.execute_ingress_as(
            kyt_provider,
            kyt_id,
            "set_api_key",
            Encode!(&SetApiKeyArg {
                api_key: "api key".to_string(),
            })
            .unwrap(),
        )
        .expect("failed to set api key");

        Self {
            env,
            kyt_provider,
            caller,
            bitcoin_id,
            ledger_id,
            minter_id,
            kyt_id,
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
                minted_amount: utxo.value - KYT_FEE,
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

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - KYT_FEE));

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
fn test_min_retrieval_amount_mainnet() {
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
fn test_min_retrieval_amount_testnet() {
    let ckbtc = CkBtcSetup::new_with(Network::Testnet);

    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 10_000);

    // The numbers used in this test have been re-computed using a python script using integers.
    ckbtc.set_fee_percentiles(&vec![0; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 10_000);

    ckbtc.set_fee_percentiles(&vec![116_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 60_000);

    ckbtc.set_fee_percentiles(&vec![342_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 60_000);

    ckbtc.set_fee_percentiles(&vec![343_000; 100]);
    ckbtc.refresh_fee_percentiles();
    let retrieve_btc_min_amount = ckbtc.get_minter_info().retrieve_btc_min_amount;
    assert_eq!(retrieve_btc_min_amount, 110_000);
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

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - KYT_FEE));

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

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - KYT_FEE));

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

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - KYT_FEE));

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

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - KYT_FEE));

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

    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - KYT_FEE));

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
            kyt_fee: Some(KYT_FEE),
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
    assert_eq!(
        decoded_data,
        BurnMemo::Convert {
            address: Some(&btc_address),
            kyt_fee: Some(KYT_FEE),
            status: Some(Status::Accepted),
        },
        "memo not found in burn"
    );

    ckbtc
        .env
        .execute_ingress(ckbtc.minter_id, "distribute_kyt_fee", Encode!().unwrap())
        .expect("failed to transfer funds");

    let get_transaction_request = GetTransactionsRequest {
        start: 3_u8.into(),
        length: 1_u8.into(),
    };
    let res = ckbtc.get_transactions(get_transaction_request);
    let memo = res.transactions[0].mint.clone().unwrap().memo.unwrap();
    assert_eq!(
        ckbtc.kyt_provider,
        res.transactions[0].mint.clone().unwrap().to.owner.into()
    );
    let decoded_data = minicbor::decode::<MintMemo>(&memo.0).expect("failed to decode memo");
    assert_eq!(decoded_data, MintMemo::Kyt);
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
    assert_eq!(ckbtc.balance_of(user), Nat::from(deposit_value - KYT_FEE));

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
            kyt_fee: Some(KYT_FEE),
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
        Nat::from(deposit_value - KYT_FEE)
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
            kyt_fee: Some(KYT_FEE),
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
        Nat::from(deposit_value - KYT_FEE)
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

    assert_eq!(
        ckbtc.balance_of(user_account),
        Nat::from(deposit_value - KYT_FEE - TRANSFER_FEE)
    );

    // Check that we reimburse ckBTC if the KYT check of the address fails

    ckbtc
        .env
        .upgrade_canister(
            ckbtc.kyt_id,
            kyt_wasm(),
            Encode!(&LifecycleArg::UpgradeArg(ic_ckbtc_kyt::UpgradeArg {
                minter_id: None,
                maintainers: None,
                mode: Some(KytMode::RejectAll),
            }))
            .unwrap(),
        )
        .expect("failed to upgrade the KYT canister");

    let retrieve_btc_result = ckbtc.retrieve_btc_with_approval(
        WITHDRAWAL_ADDRESS.to_string(),
        withdrawal_amount,
        Some([1; 32]),
    );
    assert_matches!(
        retrieve_btc_result,
        Err(RetrieveBtcWithApprovalError::GenericError { .. })
    );
    ckbtc.env.tick();
    assert_eq!(
        ckbtc.balance_of(user_account),
        Nat::from(deposit_value - 2 * KYT_FEE - TRANSFER_FEE)
    );

    ckbtc
        .env
        .execute_ingress(ckbtc.minter_id, "distribute_kyt_fee", Encode!().unwrap())
        .expect("failed to transfer funds");

    assert_eq!(
        ckbtc.balance_of(Principal::from(ckbtc.kyt_provider)),
        Nat::from(2 * KYT_FEE)
    );

    // Check that we reimburse ckBTC if the call to the KYT canister fails

    let stop_canister_result = ckbtc.env.stop_canister(ckbtc.kyt_id);
    assert_matches!(stop_canister_result, Ok(_));

    let retrieve_btc_result = ckbtc.retrieve_btc_with_approval(
        WITHDRAWAL_ADDRESS.to_string(),
        withdrawal_amount,
        Some([1; 32]),
    );
    assert_matches!(
        retrieve_btc_result,
        Err(RetrieveBtcWithApprovalError::GenericError { .. })
    );

    let reimbursed_tx_block_index_2 = BtcRetrievalStatusV2 {
        block_index: 2,
        status_v2: Some(RetrieveBtcStatusV2::Reimbursed(ReimbursedDeposit {
            account: user_account,
            amount: withdrawal_amount,
            reason: TaintedDestination {
                kyt_provider: ckbtc.kyt_provider.into(),
                kyt_fee: KYT_FEE,
            },
            mint_block_index: 3,
        })),
    };

    assert_eq!(
        ckbtc.retrieve_btc_status_v2_by_account(Some(user_account)),
        vec![
            reimbursed_tx_block_index_2.clone(),
            BtcRetrievalStatusV2 {
                block_index: 5,
                status_v2: Some(RetrieveBtcStatusV2::WillReimburse(ReimburseDepositTask {
                    account: user_account,
                    amount: withdrawal_amount,
                    reason: CallFailed
                }))
            }
        ]
    );

    ckbtc.env.tick();
    assert_eq!(
        ckbtc.balance_of(user_account),
        Nat::from(deposit_value - 2 * KYT_FEE - TRANSFER_FEE)
    );

    assert_eq!(
        ckbtc.retrieve_btc_status_v2_by_account(Some(user_account)),
        vec![
            reimbursed_tx_block_index_2,
            BtcRetrievalStatusV2 {
                block_index: 5,
                status_v2: Some(RetrieveBtcStatusV2::Reimbursed(ReimbursedDeposit {
                    account: user_account,
                    amount: withdrawal_amount,
                    reason: CallFailed,
                    mint_block_index: 6
                }))
            }
        ]
    );
}
