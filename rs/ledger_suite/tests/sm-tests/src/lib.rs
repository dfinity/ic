use crate::allowances::list_allowances;
use assert_matches::assert_matches;
use candid::{CandidType, Decode, Encode, Int, Nat, Principal};
use ic_agent::identity::{BasicIdentity, Identity};
use ic_base_types::CanisterId;
use ic_base_types::PrincipalId;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_error_types::UserError;
use ic_http_types::{HttpRequest, HttpResponse};
use ic_icrc1::blocks::encoded_block_to_generic_block;
use ic_icrc1::{Block, Operation, Transaction, hash::Hash};
use ic_icrc1_ledger::FeatureFlags;
use ic_icrc1_test_utils::{ArgWithCaller, LedgerEndpointArg, valid_transactions_strategy};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::TokensType;
use ic_ledger_hash_of::HashOf;
use ic_ledger_suite_in_memory_ledger::{
    AllowancesRecentlyPurged, InMemoryLedger, verify_ledger_state,
};
use ic_ledger_suite_state_machine_helpers::{
    AllowanceProvider, balance_of, fee, get_archive_blocks, get_archive_remaining_capacity,
    get_archive_transaction, get_archive_transactions, get_blocks, get_canister_info,
    get_transactions, icrc3_get_blocks, icrc21_consent_message, list_archives, metadata,
    minting_account, parse_metric, retrieve_metrics, send_approval, send_transfer,
    send_transfer_from, supported_block_types, supported_standards, total_supply, transfer,
    wait_ledger_ready,
};
use ic_ledger_suite_state_machine_tests_constants::{
    ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY, BLOB_META_VALUE, DECIMAL_PLACES, FEE, INT_META_KEY,
    INT_META_VALUE, NAT_META_KEY, NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY,
    TEXT_META_VALUE, TEXT_META_VALUE_2, TOKEN_NAME, TOKEN_SYMBOL,
};
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_management_canister_types_private::{self as ic00};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineConfig, WasmResult};
use ic_types::Cycles;
use ic_universal_canister::UNIVERSAL_CANISTER_WASM;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc::generic_value::Value as GenericValue;
use icrc_ledger_types::icrc1::account::{Account, DEFAULT_SUBACCOUNT, Subaccount};
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg, TransferError};
use icrc_ledger_types::icrc2::allowance::AllowanceArgs;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use icrc_ledger_types::icrc3;
use icrc_ledger_types::icrc3::archive::ArchiveInfo;
use icrc_ledger_types::icrc3::blocks::{GenericBlock as IcrcBlock, GetBlocksResult};
use icrc_ledger_types::icrc3::transactions::Transfer;
use icrc_ledger_types::icrc21::errors::ErrorInfo;
use icrc_ledger_types::icrc21::errors::Icrc21Error;
use icrc_ledger_types::icrc21::requests::ConsentMessageMetadata;
use icrc_ledger_types::icrc21::requests::{
    ConsentMessageRequest, ConsentMessageSpec, DisplayMessageType,
};
use icrc_ledger_types::icrc21::responses::{ConsentMessage, FieldsDisplay, Value as Icrc21Value};
use icrc_ledger_types::icrc103::get_allowances::{Allowances, GetAllowancesArgs};
use icrc_ledger_types::icrc106::errors::Icrc106Error;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use proptest::prelude::*;
use proptest::test_runner::{Config as TestRunnerConfig, TestCaseResult, TestRunner};
use serde_bytes::ByteBuf;
use std::sync::Arc;
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime},
};

mod allowances;
pub mod fee_collector;
pub mod icrc_106;
pub mod metrics;

pub const TX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

pub const MINTER: Account = Account {
    owner: PrincipalId::new(0, [0u8; 29]).0,
    subaccount: None,
};

#[derive(Clone, Eq, PartialEq, Debug, CandidType)]
pub struct InitArgs {
    pub minting_account: Account,
    pub fee_collector_account: Option<Account>,
    pub initial_balances: Vec<(Account, Nat)>,
    pub decimals: Option<u8>,
    pub transfer_fee: Nat,
    pub token_name: String,
    pub token_symbol: String,
    pub metadata: Vec<(String, Value)>,
    pub archive_options: ArchiveOptions,
    pub feature_flags: Option<FeatureFlags>,
    pub index_principal: Option<Principal>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType)]
pub enum ChangeFeeCollector {
    Unset,
    SetTo(Account),
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType)]
pub struct UpgradeArgs {
    pub metadata: Option<Vec<(String, Value)>>,
    pub token_name: Option<String>,
    pub token_symbol: Option<String>,
    pub transfer_fee: Option<Nat>,
    pub change_fee_collector: Option<ChangeFeeCollector>,
    pub feature_flags: Option<FeatureFlags>,
    pub change_archive_options: Option<ChangeArchiveOptions>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType)]
pub struct ChangeArchiveOptions {
    pub trigger_threshold: Option<usize>,
    pub num_blocks_to_archive: Option<usize>,
    pub node_max_memory_size_bytes: Option<u64>,
    pub max_message_size_bytes: Option<u64>,
    pub controller_id: Option<PrincipalId>,
    pub more_controller_ids: Option<Vec<PrincipalId>>,
    pub cycles_for_archive_creation: Option<u64>,
    pub max_transactions_per_response: Option<u64>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Debug, CandidType)]
pub enum LedgerArgument {
    Init(InitArgs),
    Upgrade(Option<UpgradeArgs>),
}

fn test_transfer_model<T>(
    accounts: Vec<Account>,
    mints: Vec<u64>,
    transfers: Vec<(usize, usize, u64)>,
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) -> TestCaseResult
where
    T: CandidType,
{
    let initial_balances: Vec<_> = mints
        .into_iter()
        .enumerate()
        .map(|(i, amount)| (accounts[i], amount))
        .collect();
    let mut balances: BalancesModel = initial_balances.iter().cloned().collect();

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, initial_balances);

    for (from_idx, to_idx, amount) in transfers.into_iter() {
        let from = accounts[from_idx];
        let to = accounts[to_idx];

        let ((from_balance, to_balance), maybe_error) =
            model_transfer(&mut balances, from, to, amount);

        let result = transfer(&env, canister_id, from, to, amount);

        prop_assert_eq!(result.is_err(), maybe_error.is_some());

        if let Err(err) = result {
            prop_assert_eq!(Some(err), maybe_error);
        }

        let actual_from_balance = balance_of(&env, canister_id, from);
        let actual_to_balance = balance_of(&env, canister_id, to);

        prop_assert_eq!(from_balance, actual_from_balance);
        prop_assert_eq!(to_balance, actual_to_balance);
    }
    Ok(())
}

type BalancesModel = HashMap<Account, u64>;

fn model_transfer(
    balances: &mut BalancesModel,
    from: Account,
    to: Account,
    amount: u64,
) -> ((u64, u64), Option<TransferError>) {
    let from_balance = balances.get(&from).cloned().unwrap_or_default();
    if from_balance < amount + FEE {
        let to_balance = balances.get(&to).cloned().unwrap_or_default();
        return (
            (from_balance, to_balance),
            Some(TransferError::InsufficientFunds {
                balance: Nat::from(from_balance),
            }),
        );
    }
    balances.insert(from, from_balance - amount - FEE);

    let to_balance = balances.get(&to).cloned().unwrap_or_default();
    balances.insert(to, to_balance + amount);

    let from_balance = balances.get(&from).cloned().unwrap_or_default();
    let to_balance = balances.get(&to).cloned().unwrap_or_default();

    ((from_balance, to_balance), None)
}

pub fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn get_phash(block: &IcrcBlock) -> Result<Option<Hash>, String> {
    match block {
        IcrcBlock::Map(map) => {
            for (k, v) in map.iter() {
                if k == "phash" {
                    return match v {
                        IcrcBlock::Blob(blob) => blob
                            .as_slice()
                            .try_into()
                            .map(Some)
                            .map_err(|_| "phash is not a hash".to_string()),
                        _ => Err("phash should be a blob".to_string()),
                    };
                }
            }
            Ok(None)
        }
        _ => Err("top level element should be a map".to_string()),
    }
}

fn arb_amount<Tokens: TokensType>() -> impl Strategy<Value = Tokens> {
    any::<u64>().prop_map(|n| Tokens::try_from(Nat::from(n)).unwrap())
}

fn arb_account() -> impl Strategy<Value = Account> {
    (
        proptest::collection::vec(any::<u8>(), 28),
        any::<Option<[u8; 32]>>(),
    )
        .prop_map(|(mut principal, subaccount)| {
            principal.push(0x00);
            Account {
                owner: Principal::try_from_slice(&principal[..]).unwrap(),
                subaccount,
            }
        })
}

fn arb_transfer<Tokens: TokensType>() -> impl Strategy<Value = Operation<Tokens>> {
    (
        arb_account(),
        arb_account(),
        arb_amount(),
        proptest::option::of(arb_amount()),
        proptest::option::of(arb_account()),
    )
        .prop_map(|(from, to, amount, fee, spender)| Operation::Transfer {
            from,
            to,
            amount,
            fee,
            spender,
        })
}

fn arb_approve<Tokens: TokensType>() -> impl Strategy<Value = Operation<Tokens>> {
    (
        arb_account(),
        arb_account(),
        arb_amount(),
        proptest::option::of(arb_amount()),
        proptest::option::of(arb_amount()),
        proptest::option::of(any::<u64>()),
    )
        .prop_map(
            |(from, spender, amount, fee, expected_allowance, expires_at)| Operation::Approve {
                from,
                spender,
                amount,
                fee,
                expected_allowance,
                expires_at,
            },
        )
}

fn arb_mint<Tokens: TokensType>() -> impl Strategy<Value = Operation<Tokens>> {
    (
        arb_account(),
        arb_amount(),
        proptest::option::of(arb_amount()),
    )
        .prop_map(|(to, amount, fee)| Operation::Mint { to, amount, fee })
}

fn arb_burn<Tokens: TokensType>() -> impl Strategy<Value = Operation<Tokens>> {
    (
        arb_account(),
        proptest::option::of(arb_account()),
        arb_amount(),
        proptest::option::of(arb_amount()),
    )
        .prop_map(|(from, spender, amount, fee)| Operation::Burn {
            from,
            spender,
            amount,
            fee,
        })
}

fn arb_operation<Tokens: TokensType>() -> impl Strategy<Value = Operation<Tokens>> {
    prop_oneof![arb_transfer(), arb_mint(), arb_burn(), arb_approve()]
}

fn arb_transaction<Tokens: TokensType>() -> impl Strategy<Value = Transaction<Tokens>> {
    (
        arb_operation(),
        any::<Option<u64>>(),
        any::<Option<[u8; 32]>>(),
    )
        .prop_map(|(operation, ts, memo)| Transaction {
            operation,
            created_at_time: ts,
            memo: memo.map(|m| Memo::from(m.to_vec())),
        })
}

fn arb_block<Tokens: TokensType>() -> impl Strategy<Value = Block<Tokens>> {
    (
        any::<Option<[u8; 32]>>(),
        arb_transaction(),
        proptest::option::of(arb_amount()),
        any::<u64>(),
        proptest::option::of(arb_account()),
        proptest::option::of(any::<u64>()),
    )
        .prop_map(
            |(parent_hash, transaction, effective_fee, ts, fee_col, fee_col_block)| Block {
                parent_hash: parent_hash.map(HashOf::new),
                transaction,
                effective_fee,
                timestamp: ts,
                fee_collector: fee_col,
                fee_collector_block_index: fee_col_block,
                btype: None,
            },
        )
}

fn init_args(initial_balances: Vec<(Account, u64)>) -> InitArgs {
    InitArgs {
        minting_account: MINTER,
        fee_collector_account: None,
        initial_balances: initial_balances
            .into_iter()
            .map(|(account, value)| (account, Nat::from(value)))
            .collect(),
        transfer_fee: FEE.into(),
        token_name: TOKEN_NAME.to_string(),
        token_symbol: TOKEN_SYMBOL.to_string(),
        decimals: Some(DECIMAL_PLACES),
        metadata: vec![
            Value::entry(NAT_META_KEY, NAT_META_VALUE),
            Value::entry(INT_META_KEY, INT_META_VALUE),
            Value::entry(TEXT_META_KEY, TEXT_META_VALUE),
            Value::entry(BLOB_META_KEY, BLOB_META_VALUE),
        ],
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: Some(0),
            max_transactions_per_response: None,
        },
        feature_flags: Some(FeatureFlags { icrc2: true }),
        index_principal: None,
    }
}

fn install_ledger<T>(
    env: &StateMachine,
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    initial_balances: Vec<(Account, u64)>,
) -> CanisterId
where
    T: CandidType,
{
    let args = encode_init_args(init_args(initial_balances));
    let args = Encode!(&args).unwrap();
    env.install_canister(ledger_wasm, args, None).unwrap()
}

// In order to implement FI-487 in steps we need to split the test
// //rs/ledger_suite/icrc1/ledger/tests/tests.rs#test_metadata in two:
//  1. the first part that setup ledger and environment and tests the
//     ICRC-1 metadata that both the ICP and the ICRC-1 Ledgers have
//  2. the second part that tests the metadata that only the ICRC-1 Ledger
//     has
// Once FI-487 is done and the ICP Ledger supports all the metadata
// endpoints this function will be merged back into test_metadata here.
pub fn setup<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    initial_balances: Vec<(Account, u64)>,
) -> (StateMachine, CanisterId)
where
    T: CandidType,
{
    let env = StateMachine::new();

    let canister_id = install_ledger(&env, ledger_wasm, encode_init_args, initial_balances);

    (env, canister_id)
}

pub fn test_ledger_http_request_decoding_quota<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm.clone(), encode_init_args, vec![]);

    test_http_request_decoding_quota(&env, canister_id);
}

pub fn test_balance_of<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm.clone(), encode_init_args, vec![]);
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    assert_eq!(0, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, p2.0));

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![
            (Account::from(p1.0), 10_000_000),
            (Account::from(p2.0), 5_000_000),
        ],
    );

    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1.0));
    assert_eq!(5_000_000u64, balance_of(&env, canister_id, p2.0));
}

pub fn test_metadata_icp_ledger<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    fn lookup<'a>(metadata: &'a BTreeMap<String, Value>, key: &str) -> &'a Value {
        metadata
            .get(key)
            .unwrap_or_else(|| panic!("no metadata key {key} in map {metadata:?}"))
    }

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    assert_eq!(
        TOKEN_SYMBOL,
        Decode!(
            &env.query(canister_id, "icrc1_symbol", Encode!().unwrap())
                .unwrap()
                .bytes(),
            String
        )
        .unwrap()
    );

    assert_eq!(
        8,
        Decode!(
            &env.query(canister_id, "icrc1_decimals", Encode!().unwrap())
                .unwrap()
                .bytes(),
            u8
        )
        .unwrap()
    );

    let metadata = metadata(&env, canister_id);
    assert_eq!(lookup(&metadata, "icrc1:name"), &Value::from(TOKEN_NAME));
    assert_eq!(
        lookup(&metadata, "icrc1:symbol"),
        &Value::from(TOKEN_SYMBOL)
    );
    assert_eq!(
        lookup(&metadata, "icrc1:decimals"),
        &Value::from(DECIMAL_PLACES as u64)
    );

    let mut standards = vec![];
    for standard in supported_standards(&env, canister_id) {
        standards.push(standard.name);
    }
    standards.sort();
    assert_eq!(standards, vec!["ICRC-1", "ICRC-2", "ICRC-21"]);
}
pub fn test_metadata<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    fn lookup<'a>(metadata: &'a BTreeMap<String, Value>, key: &str) -> &'a Value {
        metadata
            .get(key)
            .unwrap_or_else(|| panic!("no metadata key {key} in map {metadata:?}"))
    }

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    assert_eq!(
        TOKEN_SYMBOL,
        Decode!(
            &env.query(canister_id, "icrc1_symbol", Encode!().unwrap())
                .unwrap()
                .bytes(),
            String
        )
        .unwrap()
    );

    assert_eq!(
        DECIMAL_PLACES,
        Decode!(
            &env.query(canister_id, "icrc1_decimals", Encode!().unwrap())
                .unwrap()
                .bytes(),
            u8
        )
        .unwrap()
    );

    let metadata = metadata(&env, canister_id);
    assert_eq!(lookup(&metadata, "icrc1:name"), &Value::from(TOKEN_NAME));
    assert_eq!(
        lookup(&metadata, "icrc1:symbol"),
        &Value::from(TOKEN_SYMBOL)
    );
    assert_eq!(
        lookup(&metadata, "icrc1:decimals"),
        &Value::from(DECIMAL_PLACES as u64)
    );
    // Not all ICRC-1 implementations have the same metadata entries. Thus only certain basic fields are shared by all ICRC-1 implementations.
    assert_eq!(
        lookup(&metadata, NAT_META_KEY),
        &Value::from(NAT_META_VALUE)
    );
    assert_eq!(
        lookup(&metadata, INT_META_KEY),
        &Value::from(INT_META_VALUE)
    );
    assert_eq!(
        lookup(&metadata, TEXT_META_KEY),
        &Value::from(TEXT_META_VALUE)
    );
    assert_eq!(
        lookup(&metadata, BLOB_META_KEY),
        &Value::from(BLOB_META_VALUE)
    );
    let mut standards = vec![];
    for standard in supported_standards(&env, canister_id) {
        standards.push(standard.name);
    }
    standards.sort();
    assert_eq!(
        standards,
        vec![
            "ICRC-1", "ICRC-10", "ICRC-103", "ICRC-106", "ICRC-2", "ICRC-21", "ICRC-3"
        ]
    );
}

pub fn test_icrc3_supported_block_types<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);
    check_icrc3_supported_block_types(&env, canister_id, false);
}

pub fn check_icrc3_supported_block_types(
    env: &StateMachine,
    canister_id: CanisterId,
    supports_107: bool,
) {
    let mut block_types = vec![];
    for supported_block_type in supported_block_types(env, canister_id) {
        block_types.push(supported_block_type.block_type);
    }
    block_types.sort();
    let mut expected_block_types = vec!["1burn", "1mint", "1xfer", "2approve", "2xfer"];
    if supports_107 {
        expected_block_types.push("107feecol");
        expected_block_types.sort();
    }
    assert_eq!(block_types, expected_block_types);
}

pub fn test_total_supply<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![
            (Account::from(p1.0), 10_000_000),
            (Account::from(p2.0), 5_000_000),
        ],
    );
    assert_eq!(15_000_000, total_supply(&env, canister_id));
}

pub fn test_minting_account<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);
    assert_eq!(Some(MINTER), minting_account(&env, canister_id));
}

pub fn test_anonymous_transfers<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    const INITIAL_BALANCE: u64 = 10_000_000;
    const TRANSFER_AMOUNT: u64 = 1_000_000;
    let p1 = PrincipalId::new_user_test_id(1);
    let anon = PrincipalId::new_anonymous();
    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![
            (Account::from(p1.0), INITIAL_BALANCE),
            (Account::from(anon.0), INITIAL_BALANCE),
        ],
    );

    assert_eq!(INITIAL_BALANCE * 2, total_supply(&env, canister_id));
    assert_eq!(INITIAL_BALANCE, balance_of(&env, canister_id, p1.0));
    assert_eq!(INITIAL_BALANCE, balance_of(&env, canister_id, anon.0));

    // Transfer to the account of the anonymous principal
    println!("transferring to the account of the anonymous principal");
    transfer(&env, canister_id, p1.0, anon.0, TRANSFER_AMOUNT).expect("transfer failed");

    // Transfer from the account of the anonymous principal
    println!("transferring from the account of the anonymous principal");
    transfer(&env, canister_id, anon.0, p1.0, TRANSFER_AMOUNT).expect("transfer failed");

    assert_eq!(
        INITIAL_BALANCE * 2 - FEE * 2,
        total_supply(&env, canister_id)
    );
    assert_eq!(INITIAL_BALANCE - FEE, balance_of(&env, canister_id, p1.0));
    assert_eq!(INITIAL_BALANCE - FEE, balance_of(&env, canister_id, anon.0));
}

pub fn test_anonymous_approval<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    const INITIAL_BALANCE: u64 = 10_000_000;
    const APPROVE_AMOUNT: u64 = 1_000_000;
    let p1 = PrincipalId::new_user_test_id(1);
    let anon = PrincipalId::new_anonymous();
    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![
            (Account::from(anon.0), INITIAL_BALANCE),
            (Account::from(p1.0), INITIAL_BALANCE),
        ],
    );

    assert_eq!(INITIAL_BALANCE * 2, total_supply(&env, canister_id));
    assert_eq!(INITIAL_BALANCE, balance_of(&env, canister_id, p1.0));
    assert_eq!(INITIAL_BALANCE, balance_of(&env, canister_id, anon.0));

    // Approve transfers for p1 from the account of the anonymous principal
    let approve_args = ApproveArgs {
        from_subaccount: None,
        spender: p1.0.into(),
        amount: Nat::from(APPROVE_AMOUNT),
        fee: None,
        memo: None,
        expires_at: None,
        expected_allowance: None,
        created_at_time: None,
    };
    send_approval(&env, canister_id, anon.0, &approve_args).expect("approve failed");

    // Approve transfers for the anonymous principal from the account of p1
    let approve_args = ApproveArgs {
        from_subaccount: None,
        spender: anon.0.into(),
        amount: Nat::from(APPROVE_AMOUNT),
        fee: None,
        memo: None,
        expires_at: None,
        expected_allowance: None,
        created_at_time: None,
    };
    send_approval(&env, canister_id, p1.0, &approve_args).expect("approve failed");
}

pub fn test_single_transfer<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![
            (Account::from(p1.0), 10_000_000),
            (Account::from(p2.0), 5_000_000),
        ],
    );

    assert_eq!(15_000_000, total_supply(&env, canister_id));
    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1.0));
    assert_eq!(5_000_000u64, balance_of(&env, canister_id, p2.0));

    transfer(&env, canister_id, p1.0, p2.0, 1_000_000).expect("transfer failed");

    assert_eq!(15_000_000 - FEE, total_supply(&env, canister_id));
    assert_eq!(9_000_000u64 - FEE, balance_of(&env, canister_id, p1.0));
    assert_eq!(6_000_000u64, balance_of(&env, canister_id, p2.0));
}

pub fn test_tx_deduplication<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(p1.0), 10_000_000)],
    );
    // No created_at_time => no deduplication
    let block_id = transfer(&env, canister_id, p1.0, p2.0, 10_000).expect("transfer failed");
    assert!(transfer(&env, canister_id, p1.0, p2.0, 10_000).expect("transfer failed") > block_id);

    let now = system_time_to_nanos(env.time());

    let transfer_args = TransferArg {
        from_subaccount: None,
        to: p2.0.into(),
        fee: None,
        amount: Nat::from(1_000_000u32),
        created_at_time: Some(now),
        memo: None,
    };

    let block_idx =
        send_transfer(&env, canister_id, p1.0, &transfer_args).expect("transfer failed");

    assert_eq!(
        send_transfer(&env, canister_id, p1.0, &transfer_args),
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        })
    );

    // Same transaction, but with the fee set explicitly.
    // The Ledger should not deduplicate.
    let args = TransferArg {
        fee: Some(Nat::from(10_000u32)),
        ..transfer_args.clone()
    };
    let block_idx = send_transfer(&env, canister_id, p1.0, &args)
        .expect("transfer should not be deduplicated because the fee was set explicitly this time");

    // This time the transaction is a duplicate.
    assert_eq!(
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        }),
        send_transfer(&env, canister_id, p1.0, &args,)
    );

    env.advance_time(TX_WINDOW + Duration::from_secs(5 * 60));
    let now = system_time_to_nanos(env.time());

    assert_eq!(
        send_transfer(&env, canister_id, p1.0, &transfer_args,),
        Err(TransferError::TooOld),
    );

    // Same transaction, but `created_at_time` specified explicitly.
    // The ledger should not deduplicate this request.
    let block_idx = send_transfer(
        &env,
        canister_id,
        p1.0,
        &TransferArg {
            from_subaccount: None,
            to: p2.0.into(),
            fee: None,
            amount: Nat::from(1_000_000u32),
            created_at_time: Some(now),
            memo: None,
        },
    )
    .expect("transfer failed");

    // This time the transaction is a duplicate.
    assert_eq!(
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        }),
        send_transfer(
            &env,
            canister_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: p2.0.into(),
                fee: None,
                amount: Nat::from(1_000_000u32),
                created_at_time: Some(now),
                memo: None,
            }
        )
    );

    // from_subaccount set explicitly, don't decuplicate.
    send_transfer(
        &env,
        canister_id,
        p1.0,
        &TransferArg {
            from_subaccount: Some([0; 32]),
            to: p2.0.into(),
            fee: None,
            amount: Nat::from(1_000_000u32),
            created_at_time: Some(now),
            memo: None,
        },
    )
    .expect("transfer failed");

    // Same transaction, but with "default" `memo`.
    // The ledger should not deduplicate because we set a new field explicitly.
    let block_idx = send_transfer(
        &env,
        canister_id,
        p1.0,
        &TransferArg {
            from_subaccount: None,
            to: p2.0.into(),
            fee: None,
            amount: Nat::from(1_000_000u32),
            created_at_time: Some(now),
            memo: Some(Memo::default()),
        },
    )
    .expect("transfer failed");

    // This time the transaction is a duplicate.
    assert_eq!(
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        }),
        send_transfer(
            &env,
            canister_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: p2.0.into(),
                fee: None,
                amount: Nat::from(1_000_000u32),
                created_at_time: Some(now),
                memo: Some(Memo::default()),
            }
        )
    );

    let mut approve_args = default_approve_args(p2.0, 10_000_000);
    approve_args.created_at_time = Some(now);
    let block_idx = send_approval(&env, canister_id, p1.0, &approve_args).expect("approval failed");
    assert_eq!(
        Err(ApproveError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        }),
        send_approval(&env, canister_id, p1.0, &approve_args)
    );
    // from_subaccount set explicitly, don't deduplicate.
    approve_args.from_subaccount = Some([0; 32]);
    send_approval(&env, canister_id, p1.0, &approve_args).expect("approval failed");

    let mut transfer_from_args = default_transfer_from_args(p1.0, p2.0, 10_000);
    transfer_from_args.created_at_time = Some(now);

    let block_idx = send_transfer_from(&env, canister_id, p2.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(
        Err(TransferFromError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        }),
        send_transfer_from(&env, canister_id, p2.0, &transfer_from_args)
    );

    // spender_subaccount set explicitly, don't deduplicate.
    transfer_from_args.spender_subaccount = Some([0; 32]);
    send_transfer_from(&env, canister_id, p2.0, &transfer_from_args).expect("transfer_from failed");
}

pub fn test_mint_burn<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    assert_eq!(0, total_supply(&env, canister_id));
    assert_eq!(0, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, MINTER));

    transfer(&env, canister_id, MINTER, p1.0, 10_000_000).expect("mint failed");

    assert_eq!(10_000_000, total_supply(&env, canister_id));
    assert_eq!(10_000_000, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, MINTER));

    transfer(&env, canister_id, p1.0, MINTER, 1_000_000).expect("burn failed");

    assert_eq!(9_000_000, total_supply(&env, canister_id));
    assert_eq!(9_000_000, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, MINTER));

    // You have at least FEE, you can burn at least FEE.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE)
        }),
        transfer(&env, canister_id, p1.0, MINTER, FEE / 2),
    );

    transfer(&env, canister_id, p1.0, p2.0, FEE / 2).expect("transfer failed");

    assert_eq!(FEE / 2, balance_of(&env, canister_id, p2.0));

    // If you have less than FEE, you can burn only the whole amount.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE / 2)
        }),
        transfer(&env, canister_id, p2.0, MINTER, FEE / 4),
    );
    transfer(&env, canister_id, p2.0, MINTER, FEE / 2).expect("burn failed");

    assert_eq!(0, balance_of(&env, canister_id, p2.0));

    // You cannot burn zero tokens, no matter what your balance is.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE)
        }),
        transfer(&env, canister_id, p2.0, MINTER, 0),
    );
}

pub fn test_mint_burn_fee_rejected<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    assert_eq!(0, total_supply(&env, canister_id));
    assert_eq!(0, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, MINTER));

    const INITIAL_BALANCE: u64 = 10_000_000;
    const TX_AMOUNT: u64 = 1_000_000;

    let mint_error = send_transfer(
        &env,
        canister_id,
        MINTER.owner,
        &TransferArg {
            from_subaccount: None,
            to: p1.0.into(),
            fee: Some(FEE.into()),
            created_at_time: None,
            amount: Nat::from(INITIAL_BALANCE),
            memo: None,
        },
    )
    .unwrap_err();
    assert_eq!(
        mint_error,
        TransferError::BadFee {
            expected_fee: Nat::from(0u64)
        }
    );

    transfer(&env, canister_id, MINTER, p1.0, INITIAL_BALANCE).expect("mint failed");

    let mut expected_balance = INITIAL_BALANCE;

    assert_eq!(expected_balance, total_supply(&env, canister_id));
    assert_eq!(expected_balance, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, MINTER));

    let burn_error = send_transfer(
        &env,
        canister_id,
        p1.0,
        &TransferArg {
            from_subaccount: None,
            to: MINTER,
            fee: Some(FEE.into()),
            created_at_time: None,
            amount: Nat::from(TX_AMOUNT),
            memo: None,
        },
    )
    .unwrap_err();
    assert_eq!(
        burn_error,
        TransferError::BadFee {
            expected_fee: Nat::from(0u64)
        }
    );

    transfer(&env, canister_id, p1.0, MINTER, TX_AMOUNT).expect("burn failed");

    expected_balance -= TX_AMOUNT;

    assert_eq!(expected_balance, total_supply(&env, canister_id));
    assert_eq!(expected_balance, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, MINTER));

    let approve_args = default_approve_args(p2.0, u64::MAX);
    send_approval(&env, canister_id, p1.into(), &approve_args).expect("approval failed");

    expected_balance -= FEE;

    let mut transfer_from_args = TransferFromArgs {
        from: p1.0.into(),
        to: MINTER,
        fee: Some(FEE.into()),
        created_at_time: None,
        amount: Nat::from(TX_AMOUNT),
        memo: None,
        spender_subaccount: None,
    };
    let burn_from_error =
        send_transfer_from(&env, canister_id, p2.0, &transfer_from_args).unwrap_err();
    assert_eq!(
        burn_from_error,
        TransferFromError::BadFee {
            expected_fee: Nat::from(0u64)
        }
    );

    transfer_from_args.fee = None;
    send_transfer_from(&env, canister_id, p2.0, &transfer_from_args).expect("transfer from failed");

    expected_balance -= TX_AMOUNT;

    assert_eq!(expected_balance, total_supply(&env, canister_id));
    assert_eq!(expected_balance, balance_of(&env, canister_id, p1.0));
    assert_eq!(0, balance_of(&env, canister_id, MINTER));
}

pub fn test_account_canonicalization<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![
            (Account::from(p1.0), 10_000_000),
            (Account::from(p2.0), 5_000_000),
        ],
    );

    assert_eq!(
        10_000_000u64,
        balance_of(
            &env,
            canister_id,
            Account {
                owner: p1.0,
                subaccount: None
            }
        )
    );
    assert_eq!(
        10_000_000u64,
        balance_of(
            &env,
            canister_id,
            Account {
                owner: p1.0,
                subaccount: Some([0; 32])
            }
        )
    );

    transfer(
        &env,
        canister_id,
        p1.0,
        Account {
            owner: p2.0,
            subaccount: Some([0; 32]),
        },
        1_000_000,
    )
    .expect("transfer failed");

    assert_eq!(
        6_000_000u64,
        balance_of(
            &env,
            canister_id,
            Account {
                owner: p2.0,
                subaccount: None
            }
        )
    );
}

pub fn test_tx_time_bounds<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(p1.0), 10_000_000)],
    );

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let now = system_time_to_nanos(env.time());
    let tx_window = TX_WINDOW.as_nanos() as u64;

    assert_eq!(
        Err(TransferError::TooOld),
        send_transfer(
            &env,
            canister_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: p2.0.into(),
                fee: None,
                amount: Nat::from(1_000_000u32),
                created_at_time: Some(now - tx_window - 1),
                memo: None,
            }
        )
    );

    // advance time so that time does not grow implicitly when executing a round
    env.advance_time(Duration::from_secs(1));
    let now = system_time_to_nanos(env.time());

    assert_eq!(
        Err(TransferError::CreatedInFuture { ledger_time: now }),
        send_transfer(
            &env,
            canister_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: p2.0.into(),
                fee: None,
                amount: Nat::from(1_000_000u32),
                created_at_time: Some(now + Duration::from_secs(5 * 60).as_nanos() as u64),
                memo: None
            }
        )
    );

    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1.0));
    assert_eq!(0u64, balance_of(&env, canister_id, p2.0));
}

fn test_controllers<T>(
    expected_controllers: Vec<PrincipalId>,
    ledger_wasm: &[u8],
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    let (env, ledger_id) = setup(
        ledger_wasm.to_vec(),
        encode_init_args,
        vec![(Account::from(p1.0), 10_000_000)],
    );

    const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

    let ucan = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            Some(
                ic00::CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![p1])
                    .build(),
            ),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    for i in 0..ARCHIVE_TRIGGER_THRESHOLD {
        transfer(&env, ledger_id, p1.0, p2.0, 10_000 + i).expect("transfer failed");
    }

    let archive_info = list_archives(&env, ledger_id);
    assert_eq!(archive_info.len(), 1);

    let archives_info = get_canister_info(
        &env,
        ucan,
        CanisterId::unchecked_from_principal(archive_info[0].canister_id.into()),
    )
    .unwrap();

    assert_eq!(archives_info.controllers(), expected_controllers);
}

pub fn test_archive_controllers(ledger_wasm: Vec<u8>) {
    let p3 = PrincipalId::new_user_test_id(3);
    let p4 = PrincipalId::new_user_test_id(4);
    let p100 = PrincipalId::new_user_test_id(100);

    let expected_controllers = vec![p3, p4, p100];

    fn encode_init_args(args: InitArgs) -> LedgerArgument {
        LedgerArgument::Init(InitArgs {
            minting_account: MINTER,
            fee_collector_account: args.fee_collector_account,
            initial_balances: args.initial_balances,
            transfer_fee: FEE.into(),
            token_name: TOKEN_NAME.to_string(),
            decimals: Some(DECIMAL_PLACES),
            token_symbol: TOKEN_SYMBOL.to_string(),
            metadata: vec![],
            archive_options: ArchiveOptions {
                trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: PrincipalId::new_user_test_id(100),
                more_controller_ids: Some(vec![
                    PrincipalId::new_user_test_id(3),
                    PrincipalId::new_user_test_id(4),
                ]),
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            feature_flags: args.feature_flags,
            index_principal: None,
        })
    }

    test_controllers(expected_controllers, &ledger_wasm, encode_init_args);
}

pub fn test_archive_no_additional_controllers(ledger_wasm: Vec<u8>) {
    fn encode_init_args(args: InitArgs) -> LedgerArgument {
        LedgerArgument::Init(InitArgs {
            minting_account: MINTER,
            fee_collector_account: args.fee_collector_account,
            initial_balances: args.initial_balances,
            transfer_fee: FEE.into(),
            token_name: TOKEN_NAME.to_string(),
            decimals: Some(DECIMAL_PLACES),
            token_symbol: TOKEN_SYMBOL.to_string(),
            metadata: vec![],
            archive_options: ArchiveOptions {
                trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: PrincipalId::new_user_test_id(100),
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            feature_flags: args.feature_flags,
            index_principal: None,
        })
    }

    let p100 = PrincipalId::new_user_test_id(100);

    test_controllers(vec![p100], &ledger_wasm, encode_init_args);
}

pub fn test_archive_duplicate_controllers(ledger_wasm: Vec<u8>) {
    fn encode_init_args(args: InitArgs) -> LedgerArgument {
        LedgerArgument::Init(InitArgs {
            minting_account: MINTER,
            fee_collector_account: args.fee_collector_account,
            initial_balances: args.initial_balances,
            transfer_fee: FEE.into(),
            token_name: TOKEN_NAME.to_string(),
            decimals: Some(DECIMAL_PLACES),
            token_symbol: TOKEN_SYMBOL.to_string(),
            metadata: vec![],
            archive_options: ArchiveOptions {
                trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: PrincipalId::new_user_test_id(100),
                more_controller_ids: Some(vec![
                    PrincipalId::new_user_test_id(100),
                    PrincipalId::new_user_test_id(100),
                ]),
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            feature_flags: args.feature_flags,
            index_principal: None,
        })
    }
    let p100 = PrincipalId::new_user_test_id(100);

    test_controllers(vec![p100], &ledger_wasm, encode_init_args);
}

pub fn test_upgrade_archive_options<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let archive_controller = PrincipalId::new_user_test_id(100);

    let (env, ledger_id) = setup(
        ledger_wasm.clone(),
        encode_init_args,
        vec![(Account::from(p1.0), 10_000_000)],
    );

    for i in 0..ARCHIVE_TRIGGER_THRESHOLD {
        transfer(&env, ledger_id, p1.0, p2.0, 10_000 + i).expect("transfer failed");
    }

    let archive_info = list_archives(&env, ledger_id);
    let first_archive = ArchiveInfo {
        canister_id: "rrkah-fqaaa-aaaaa-aaaaq-cai".parse().unwrap(),
        block_range_start: 0_u8.into(),
        block_range_end: (NUM_BLOCKS_TO_ARCHIVE - 1).into(),
    };
    assert_eq!(archive_info, vec![first_archive.clone()]);
    assert_eq!(
        get_archive_remaining_capacity(&env, first_archive.canister_id),
        100
    );
    assert_eq!(
        env.canister_status_as(
            archive_controller,
            CanisterId::unchecked_from_principal(first_archive.canister_id.into())
        )
        .unwrap()
        .unwrap()
        .cycles(),
        0
    );

    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs {
        change_archive_options: Some(ChangeArchiveOptions {
            cycles_for_archive_creation: Some(100_000_000_000_000),
            ..Default::default()
        }),
        ..UpgradeArgs::default()
    }));
    env.upgrade_canister(ledger_id, ledger_wasm, Encode!(&upgrade_args).unwrap())
        .expect("failed to upgrade the archive canister");
    env.add_cycles(ledger_id, 200_000_000_000_000);

    for i in 0..NUM_BLOCKS_TO_ARCHIVE {
        transfer(&env, ledger_id, p1.0, p2.0, 10_000 + i).expect("transfer failed");
    }
    let archive_info = list_archives(&env, ledger_id);
    let second_archive = ArchiveInfo {
        canister_id: "ryjl3-tyaaa-aaaaa-aaaba-cai".parse().unwrap(),
        block_range_start: NUM_BLOCKS_TO_ARCHIVE.into(),
        block_range_end: (2 * NUM_BLOCKS_TO_ARCHIVE - 1).into(),
    };
    assert_eq!(
        archive_info,
        vec![first_archive.clone(), second_archive.clone()]
    );

    assert_eq!(
        env.canister_status_as(
            archive_controller,
            CanisterId::unchecked_from_principal(second_archive.canister_id.into())
        )
        .unwrap()
        .unwrap()
        .cycles(),
        100_000_000_000_000
    );
}

pub fn test_archiving<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    archive_wasm: Vec<u8>,
) where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(p1.0), 10_000_000)],
    );

    for i in 0..ARCHIVE_TRIGGER_THRESHOLD {
        transfer(&env, canister_id, p1.0, p2.0, 10_000 + i).expect("transfer failed");
    }

    let archive_info = list_archives(&env, canister_id);
    assert_eq!(archive_info.len(), 1);
    assert_eq!(archive_info[0].block_range_start, 0u8);
    assert_eq!(archive_info[0].block_range_end, NUM_BLOCKS_TO_ARCHIVE - 1);

    let archive_principal = archive_info[0].canister_id;

    let resp = get_transactions(&env, canister_id.get().0, 0, 1_000_000);
    assert_eq!(resp.first_index, Nat::from(NUM_BLOCKS_TO_ARCHIVE));
    assert_eq!(
        resp.transactions.len(),
        (ARCHIVE_TRIGGER_THRESHOLD - NUM_BLOCKS_TO_ARCHIVE + 1) as usize
    );
    assert_eq!(resp.archived_transactions.len(), 1);
    assert_eq!(resp.archived_transactions[0].start, Nat::from(0_u8));
    assert_eq!(
        resp.archived_transactions[0].length,
        Nat::from(NUM_BLOCKS_TO_ARCHIVE)
    );

    let archived_transactions =
        get_archive_transactions(&env, archive_principal, 0, NUM_BLOCKS_TO_ARCHIVE as usize)
            .transactions;

    for i in 1..NUM_BLOCKS_TO_ARCHIVE {
        let expected_tx = Transfer {
            from: Account {
                owner: p1.0,
                subaccount: None,
            },
            to: Account {
                owner: p2.0,
                subaccount: None,
            },
            amount: Nat::from(10_000 + i - 1),
            fee: Some(Nat::from(FEE)),
            memo: None,
            created_at_time: None,
            spender: None,
        };
        let tx = get_archive_transaction(&env, archive_principal, i).unwrap();
        assert_eq!(tx.transfer.as_ref(), Some(&expected_tx));
        let tx = archived_transactions[i as usize].clone();
        assert_eq!(tx.transfer.as_ref(), Some(&expected_tx));
    }

    // Check that requesting non-existing blocks does not crash the ledger.
    let missing_blocks_reply = get_transactions(&env, canister_id.get().0, 100, 5);
    assert_eq!(0, missing_blocks_reply.transactions.len());
    assert_eq!(0, missing_blocks_reply.archived_transactions.len());

    // Upgrade the archive and check that the data is still available.
    let archive_canister_id = CanisterId::unchecked_from_principal(archive_principal.into());

    env.upgrade_canister(archive_canister_id, archive_wasm, vec![])
        .expect("failed to upgrade the archive canister");

    for i in 1..NUM_BLOCKS_TO_ARCHIVE {
        let tx = get_archive_transaction(&env, archive_principal, i).unwrap();
        assert_eq!(
            tx.transfer,
            Some(Transfer {
                from: Account {
                    owner: p1.0,
                    subaccount: None
                },
                to: Account {
                    owner: p2.0,
                    subaccount: None
                },
                amount: Nat::from(10_000 + i - 1),
                fee: Some(Nat::from(FEE)),
                memo: None,
                created_at_time: None,
                spender: None,
            })
        );
    }

    // Check that we can append more blocks after the upgrade.
    for i in 0..(ARCHIVE_TRIGGER_THRESHOLD - NUM_BLOCKS_TO_ARCHIVE) {
        transfer(&env, canister_id, p1.0, p2.0, 20_000 + i).expect("transfer failed");
    }

    let archive_info = list_archives(&env, canister_id);
    assert_eq!(archive_info.len(), 1);
    assert_eq!(archive_info[0].block_range_start, 0u8);
    assert_eq!(
        archive_info[0].block_range_end,
        2 * NUM_BLOCKS_TO_ARCHIVE - 1
    );

    // Check that the archive handles requested ranges correctly.
    let archived_transactions =
        get_archive_transactions(&env, archive_principal, 0, 1_000_000).transactions;
    let n = 2 * NUM_BLOCKS_TO_ARCHIVE as usize;
    assert_eq!(archived_transactions.len(), n);

    for start in 0..n {
        for end in start..n {
            let tx = get_archive_transactions(&env, archive_principal, start as u64, end - start)
                .transactions;
            assert_eq!(archived_transactions[start..end], tx);
        }
    }
}

pub fn test_get_blocks<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(p1.0), 10_000_000)],
    );

    for i in 0..ARCHIVE_TRIGGER_THRESHOLD {
        transfer(&env, canister_id, p1.0, p2.0, 10_000 + i * 10_000).expect("transfer failed");
    }

    let resp = get_blocks(&env, canister_id.get().0, 0, 1_000_000);
    assert_eq!(resp.first_index, Nat::from(NUM_BLOCKS_TO_ARCHIVE));
    assert_eq!(
        resp.blocks.len(),
        (ARCHIVE_TRIGGER_THRESHOLD - NUM_BLOCKS_TO_ARCHIVE + 1) as usize
    );
    assert_eq!(resp.archived_blocks.len(), 1);
    assert_eq!(resp.archived_blocks[0].start, Nat::from(0_u8));
    assert_eq!(
        resp.archived_blocks[0].length,
        Nat::from(NUM_BLOCKS_TO_ARCHIVE)
    );
    assert!(resp.certificate.is_some());

    let archive_canister_id = list_archives(&env, canister_id)[0].canister_id;
    let archived_blocks =
        get_archive_blocks(&env, archive_canister_id, 0, NUM_BLOCKS_TO_ARCHIVE as usize).blocks;
    assert_eq!(archived_blocks.len(), NUM_BLOCKS_TO_ARCHIVE as usize);

    let mut prev_hash = None;

    // Check that the hash chain is correct.
    for block in archived_blocks.into_iter().chain(resp.blocks.into_iter()) {
        assert_eq!(
            prev_hash,
            get_phash(&block).expect("cannot get the hash of the previous block")
        );
        prev_hash = Some(block.hash());
    }

    // Check that requesting non-existing blocks does not crash the ledger.
    let missing_blocks_reply = get_blocks(&env, canister_id.get().0, 100, 5);
    assert_eq!(0, missing_blocks_reply.blocks.len());
    assert_eq!(0, missing_blocks_reply.archived_blocks.len());
}

// Generate random blocks and check that their CBOR encoding complies with the CDDL spec.
pub fn block_encoding_agrees_with_the_schema<Tokens: TokensType>() {
    use std::path::PathBuf;

    let block_cddl_path =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("block.cddl");
    let block_cddl =
        String::from_utf8(std::fs::read(block_cddl_path).expect("failed to read block.cddl file"))
            .unwrap();

    let mut runner = TestRunner::default();
    runner
        .run(&arb_block::<Tokens>(), |block| {
            let cbor_bytes = block.encode().into_vec();
            cddl::validate_cbor_from_slice(&block_cddl, &cbor_bytes, None).map_err(|e| {
                TestCaseError::fail(format!(
                    "Failed to validate CBOR: {} (inspect it on https://cbor.me), error: {}",
                    hex::encode(&cbor_bytes),
                    e
                ))
            })
        })
        .unwrap();
}

pub fn block_encoding_agreed_with_the_icrc3_schema<Tokens: TokensType>() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        ..Default::default()
    });
    runner
        .run(&arb_block::<Tokens>(), |block| {
            let encoded_block = block.encode();
            let generic_block = encoded_block_to_generic_block(&encoded_block);
            if let Err(errors) = icrc3::schema::validate(&generic_block) {
                panic!("generic_block: {generic_block:?}, errors:\n{errors}");
            }
            Ok(())
        })
        .unwrap();
}

// Check that different blocks produce different hashes.
pub fn transaction_hashes_are_unique<Tokens: TokensType>() {
    let mut runner = TestRunner::default();
    runner
        .run(
            &(arb_transaction::<Tokens>(), arb_transaction::<Tokens>()),
            |(lhs, rhs)| {
                use ic_ledger_canister_core::ledger::LedgerTransaction;

                prop_assume!(lhs != rhs);
                prop_assert_ne!(lhs.hash(), rhs.hash());

                Ok(())
            },
        )
        .unwrap();
}

pub fn block_hashes_are_unique<Tokens: TokensType>() {
    let mut runner = TestRunner::default();
    runner
        .run(&(arb_block::<Tokens>(), arb_block()), |(lhs, rhs)| {
            prop_assume!(lhs != rhs);

            let lhs_hash = Block::<Tokens>::block_hash(&lhs.encode());
            let rhs_hash = Block::<Tokens>::block_hash(&rhs.encode());

            prop_assert_ne!(lhs_hash, rhs_hash);
            Ok(())
        })
        .unwrap();
}

// Generate random blocks and check that the block hash is stable.
pub fn block_hashes_are_stable<Tokens: TokensType>() {
    let mut runner = TestRunner::default();
    runner
        .run(&arb_block::<Tokens>(), |block| {
            let encoded_block = block.encode();
            let hash1 = Block::<Tokens>::block_hash(&encoded_block);
            let decoded = Block::<Tokens>::decode(encoded_block).unwrap();
            let hash2 = Block::<Tokens>::block_hash(&decoded.encode());
            prop_assert_eq!(hash1, hash2);
            Ok(())
        })
        .unwrap();
}

pub fn check_transfer_model<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    use proptest::collection::vec as pvec;

    const NUM_ACCOUNTS: usize = 10;
    const MIN_TRANSACTIONS: usize = 5;
    const MAX_TRANSACTIONS: usize = 10;
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(5));
    runner
        .run(
            &(
                pvec(arb_account(), NUM_ACCOUNTS),
                pvec(0..10_000_000u64, NUM_ACCOUNTS),
                pvec(
                    (0..NUM_ACCOUNTS, 0..NUM_ACCOUNTS, 0..1_000_000_000u64),
                    MIN_TRANSACTIONS..MAX_TRANSACTIONS,
                ),
            ),
            |(accounts, mints, transfers)| {
                test_transfer_model(
                    accounts,
                    mints,
                    transfers,
                    ledger_wasm.clone(),
                    encode_init_args,
                )
            },
        )
        .unwrap();
}

pub fn test_upgrade<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm.clone(), encode_init_args, vec![]);

    let metadata_res = metadata(&env, canister_id);
    let metadata_value = metadata_res.get(TEXT_META_KEY).unwrap();
    assert_eq!(*metadata_value, Value::Text(TEXT_META_VALUE.to_string()));

    const OTHER_TOKEN_SYMBOL: &str = "NEWSYMBOL";
    const OTHER_TOKEN_NAME: &str = "NEWTKNNAME";
    const NEW_FEE: u64 = 1234;

    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs {
        metadata: Some(vec![(
            TEXT_META_KEY.into(),
            Value::Text(TEXT_META_VALUE_2.into()),
        )]),
        token_name: Some(OTHER_TOKEN_NAME.into()),
        token_symbol: Some(OTHER_TOKEN_SYMBOL.into()),
        transfer_fee: Some(NEW_FEE.into()),
        ..UpgradeArgs::default()
    }));

    env.upgrade_canister(canister_id, ledger_wasm, Encode!(&upgrade_args).unwrap())
        .expect("failed to upgrade the archive canister");

    let metadata_res_after_upgrade = metadata(&env, canister_id);
    assert_eq!(
        *metadata_res_after_upgrade.get(TEXT_META_KEY).unwrap(),
        Value::Text(TEXT_META_VALUE_2.to_string())
    );

    let token_symbol_after_upgrade: String = Decode!(
        &env.query(canister_id, "icrc1_symbol", Encode!().unwrap())
            .expect("failed to query symbol")
            .bytes(),
        String
    )
    .expect("failed to decode balance_of response");
    assert_eq!(token_symbol_after_upgrade, OTHER_TOKEN_SYMBOL);

    let token_name_after_upgrade: String = Decode!(
        &env.query(canister_id, "icrc1_name", Encode!().unwrap())
            .expect("failed to query name")
            .bytes(),
        String
    )
    .expect("failed to decode balance_of response");
    assert_eq!(token_name_after_upgrade, OTHER_TOKEN_NAME);

    let token_fee_after_upgrade = fee(&env, canister_id);
    assert_eq!(token_fee_after_upgrade, NEW_FEE);
}

pub fn test_memo_max_len<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from_account = Principal::from_slice(&[1u8; 29]).into();
    let (env, ledger_id) = setup(
        ledger_wasm.clone(),
        encode_init_args,
        vec![(from_account, 1_000_000_000)],
    );
    let to_account = Principal::from_slice(&[2u8; 29]).into();
    let transfer_with_memo = |memo: &[u8]| -> Result<WasmResult, UserError> {
        env.execute_ingress_as(
            PrincipalId(from_account.owner),
            ledger_id,
            "icrc1_transfer",
            Encode!(&TransferArg {
                from_subaccount: None,
                to: to_account,
                amount: Nat::from(1_u8),
                fee: None,
                created_at_time: None,
                memo: Some(Memo::from(memo.to_vec())),
            })
            .unwrap(),
        )
    };

    // We didn't set the max_memo_length in the init params of the ledger
    // so the memo will be accepted only if it's 32 bytes or less.
    for i in 0..=32 {
        assert!(transfer_with_memo(&vec![0u8; i]).is_ok(), "Memo size: {i}");
    }
    expect_memo_length_error(transfer_with_memo, &[0u8; 33]);

    // Change the memo to 64 bytes
    let args = ic_icrc1_ledger::LedgerArgument::Upgrade(Some(ic_icrc1_ledger::UpgradeArgs {
        max_memo_length: Some(64),
        ..ic_icrc1_ledger::UpgradeArgs::default()
    }));
    let args = Encode!(&args).unwrap();
    env.upgrade_canister(ledger_id, ledger_wasm.clone(), args)
        .unwrap();

    // Now the ledger should accept memos up to 64 bytes.
    for i in 0..=64 {
        assert!(transfer_with_memo(&vec![0u8; i]).is_ok(), "Memo size: {i}");
    }
    expect_memo_length_error(transfer_with_memo, &[0u8; 65]);

    expect_memo_length_error(transfer_with_memo, &[0u8; u16::MAX as usize + 1]);

    // Trying to shrink the memo should result in a failure.
    let args = ic_icrc1_ledger::LedgerArgument::Upgrade(Some(ic_icrc1_ledger::UpgradeArgs {
        max_memo_length: Some(63),
        ..ic_icrc1_ledger::UpgradeArgs::default()
    }));
    let args = Encode!(&args).unwrap();
    assert!(env.upgrade_canister(ledger_id, ledger_wasm, args).is_err());
}

fn expect_memo_length_error<T>(transfer_with_memo: T, memo: &[u8])
where
    T: FnOnce(&[u8]) -> Result<WasmResult, UserError>,
{
    match transfer_with_memo(memo) {
        Err(user_error) => assert_eq!(
            user_error.code(),
            ErrorCode::CanisterCalledTrap,
            "unexpected error: {user_error}"
        ),
        Ok(result) => panic!(
            "expected a reject for a {}-byte memo, got result {:?}",
            memo.len(),
            result
        ),
    }
}

/// Checks whether two values are equivalent with respect to numeric conversions.
fn equivalent_values(lhs: &GenericValue, rhs: &GenericValue) -> bool {
    match (lhs, rhs) {
        (GenericValue::Nat64(x), GenericValue::Nat64(y)) => x == y,
        (GenericValue::Nat(x), GenericValue::Nat(y)) => x == y,
        (GenericValue::Int(x), GenericValue::Int(y)) => x == y,
        (GenericValue::Blob(x), GenericValue::Blob(y)) => x == y,
        (GenericValue::Text(x), GenericValue::Text(y)) => x == y,
        (GenericValue::Array(xs), GenericValue::Array(ys)) => {
            xs.len() == ys.len()
                && xs
                    .iter()
                    .zip(ys.iter())
                    .all(|(x, y)| equivalent_values(x, y))
        }
        (GenericValue::Map(xs), GenericValue::Map(ys)) => {
            xs.len() == ys.len()
                && xs
                    .iter()
                    .zip(ys.iter())
                    .all(|((k1, x), (k2, y))| k1 == k2 && equivalent_values(x, y))
        }
        // Numeric conversions
        (GenericValue::Nat64(x), GenericValue::Int(y)) => &Int::from(*x) == y,
        (GenericValue::Int(x), GenericValue::Nat64(y)) => x == &Int::from(*y),
        (GenericValue::Nat64(x), GenericValue::Nat(y)) => &Nat::from(*x) == y,
        (GenericValue::Nat(x), GenericValue::Nat64(y)) => x == &Nat::from(*y),
        (GenericValue::Nat(x), GenericValue::Int(y)) => Some(&x.0) == y.0.to_biguint().as_ref(),
        (GenericValue::Int(x), GenericValue::Nat(y)) => x.0.to_biguint().as_ref() == Some(&y.0),
        _ => false,
    }
}

pub fn icrc1_test_block_transformation<T, Tokens>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
    Tokens: TokensType,
{
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);
    let p3 = PrincipalId::new_user_test_id(3);

    // Setup ledger as it is deployed on the mainnet.
    let (env, canister_id) = setup(
        ledger_wasm_mainnet,
        encode_init_args,
        vec![
            (Account::from(p1.0), 10_000_000),
            (Account::from(p2.0), 10_000_000),
            (Account::from(p3.0), 10_000_000),
        ],
    );

    transfer(&env, canister_id, p1.0, p2.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p1.0, p3.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p3.0, p2.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p2.0, p1.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p2.0, p3.0, 1_000_000).expect("transfer failed");
    transfer(&env, canister_id, p3.0, p1.0, 1_000_000).expect("transfer failed");

    // Fetch all blocks before the upgrade.
    let resp_pre_upgrade = get_blocks(&env, canister_id.get().0, 0, 1_000_000);

    // Now upgrade the ledger to the new canister wasm.
    env.upgrade_canister(
        canister_id,
        ledger_wasm_current,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    // Default archive threshold is 10 blocks so all blocks should be on the ledger directly
    // Fetch all blocks after the upgrade.
    let resp_post_upgrade = get_blocks(&env, canister_id.get().0, 0, 1_000_000);

    // Make sure the same number of blocks were fetched before and after the upgrade.
    assert_eq!(
        resp_pre_upgrade.blocks.len(),
        resp_post_upgrade.blocks.len()
    );

    // Go through all blocks and make sure the blocks fetched before the upgrade are the same as after the upgrade.
    for (block_pre_upgrade, block_post_upgrade) in resp_pre_upgrade
        .blocks
        .into_iter()
        .zip(resp_post_upgrade.blocks.into_iter())
    {
        assert!(
            equivalent_values(&block_pre_upgrade, &block_post_upgrade),
            "pre-upgrade block {block_pre_upgrade:?} is not equivalent to {block_post_upgrade:?}"
        );
        assert_eq!(
            Block::<Tokens>::try_from(block_pre_upgrade.clone()).unwrap(),
            Block::<Tokens>::try_from(block_post_upgrade.clone()).unwrap()
        );
        assert_eq!(
            Block::<Tokens>::try_from(block_pre_upgrade.clone())
                .unwrap()
                .encode(),
            Block::<Tokens>::try_from(block_post_upgrade.clone())
                .unwrap()
                .encode()
        );
        assert_eq!(
            Block::<Tokens>::block_hash(
                &Block::<Tokens>::try_from(block_pre_upgrade.clone())
                    .unwrap()
                    .encode()
            ),
            Block::<Tokens>::block_hash(
                &Block::<Tokens>::try_from(block_post_upgrade.clone())
                    .unwrap()
                    .encode()
            )
        );
        assert_eq!(
            Transaction::<Tokens>::try_from(block_pre_upgrade.clone()).unwrap(),
            Transaction::<Tokens>::try_from(block_post_upgrade.clone()).unwrap()
        );
    }
}

fn apply_arg_with_caller(
    env: &StateMachine,
    ledger_id: CanisterId,
    arg: &ArgWithCaller,
) -> BlockIndex {
    match &arg.arg {
        LedgerEndpointArg::ApproveArg(approve_arg) => {
            send_approval(env, ledger_id, arg.caller.sender().unwrap(), approve_arg)
                .expect("approval failed")
        }
        LedgerEndpointArg::TransferArg(transfer_arg) => {
            send_transfer(env, ledger_id, arg.caller.sender().unwrap(), transfer_arg)
                .expect("transfer failed")
        }
        LedgerEndpointArg::TransferFromArg(transfer_from_arg) => send_transfer_from(
            env,
            ledger_id,
            arg.caller.sender().unwrap(),
            transfer_from_arg,
        )
        .expect("transfer_from failed"),
    }
}

pub fn test_upgrade_serialization<Tokens>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current: Vec<u8>,
    init_args: Vec<u8>,
    upgrade_args: Vec<u8>,
    minter: Arc<BasicIdentity>,
    verify_blocks: bool,
    mainnet_on_prev_version: bool,
    test_stable_migration: bool,
) where
    Tokens: TokensType + Default + std::fmt::Display + From<u64>,
{
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    let now = SystemTime::now();
    let minter_principal: Principal = minter.sender().unwrap();
    const INITIAL_TX_BATCH_SIZE: usize = 100;
    const ADDITIONAL_TX_BATCH_SIZE: usize = 15;
    const TOTAL_TX_COUNT: usize = INITIAL_TX_BATCH_SIZE + 8 * ADDITIONAL_TX_BATCH_SIZE;
    runner
        .run(
            &(valid_transactions_strategy(minter, FEE, TOTAL_TX_COUNT, now).no_shrink(),),
            |(transactions,)| {
                let env = StateMachine::new();
                env.set_time(now);
                let ledger_id = env
                    .install_canister(ledger_wasm_mainnet.clone(), init_args.clone(), None)
                    .unwrap();

                let mut in_memory_ledger = InMemoryLedger::<Account, Tokens>::default();

                let mut tx_index = 0;
                let mut tx_index_target = INITIAL_TX_BATCH_SIZE;

                let mut add_tx_and_verify = || {
                    while tx_index < tx_index_target {
                        in_memory_ledger.apply_arg_with_caller(
                            &transactions[tx_index],
                            TimeStamp::from_nanos_since_unix_epoch(system_time_to_nanos(
                                env.time(),
                            )),
                            minter_principal,
                            Some(FEE.into()),
                        );
                        apply_arg_with_caller(&env, ledger_id, &transactions[tx_index]);
                        tx_index += 1;
                    }
                    tx_index_target += ADDITIONAL_TX_BATCH_SIZE;
                    in_memory_ledger.verify_balances_and_allowances(
                        &env,
                        ledger_id,
                        tx_index as u64,
                        AllowancesRecentlyPurged::Yes,
                    );
                };
                add_tx_and_verify();

                let mut test_upgrade = |ledger_wasm: Vec<u8>, expected_migration_steps: u64| {
                    env.upgrade_canister(ledger_id, ledger_wasm, upgrade_args.clone())
                        .unwrap();
                    wait_ledger_ready(&env, ledger_id, 10);
                    if test_stable_migration {
                        let stable_upgrade_migration_steps =
                            parse_metric(&env, ledger_id, "ledger_stable_upgrade_migration_steps");
                        assert_eq!(stable_upgrade_migration_steps, expected_migration_steps);
                    } else {
                        assert_eq!(0, expected_migration_steps);
                    }
                    add_tx_and_verify();
                };

                // Test if the old serialized approvals and balances are correctly deserialized
                let expected_steps = if mainnet_on_prev_version { 1 } else { 0 };
                test_upgrade(ledger_wasm_current.clone(), expected_steps);
                // Test the new wasm serialization
                test_upgrade(ledger_wasm_current.clone(), 0);
                // Test deserializing from memory manager
                test_upgrade(ledger_wasm_current.clone(), 0);
                // Downgrade to mainnet if possible.
                match env.upgrade_canister(
                    ledger_id,
                    ledger_wasm_mainnet.clone(),
                    Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
                ) {
                    Ok(_) => {
                        if mainnet_on_prev_version {
                            panic!("Upgrade from future ledger version should fail!")
                        }
                    }
                    Err(e) => {
                        if mainnet_on_prev_version {
                            assert!(
                                e.description()
                                    .contains("Trying to downgrade from incompatible version")
                            )
                        } else {
                            panic!("Upgrade to mainnet should succeed!")
                        }
                    }
                };
                if verify_blocks {
                    // This will also verify the ledger blocks.
                    // The current implementation of the InMemoryLedger cannot get blocks
                    // for the ICP ledger. This part of the test runs only for the ICRC1 ledger.
                    verify_ledger_state::<Tokens>(
                        &env,
                        ledger_id,
                        None,
                        AllowancesRecentlyPurged::Yes,
                    );
                }

                Ok(())
            },
        )
        .unwrap();
}

pub fn icrc1_test_multi_step_migration<T>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current_lowinstructionlimits: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    get_all_blocks: fn(&StateMachine, CanisterId) -> Vec<EncodedBlock>,
) where
    T: CandidType,
{
    let accounts = vec![
        Account::from(PrincipalId::new_user_test_id(1).0),
        Account {
            owner: PrincipalId::new_user_test_id(2).0,
            subaccount: Some([2; 32]),
        },
        Account::from(PrincipalId::new_user_test_id(3).0),
        Account {
            owner: PrincipalId::new_user_test_id(4).0,
            subaccount: Some([4; 32]),
        },
    ];
    let additional_accounts = vec![
        Account::from(PrincipalId::new_user_test_id(5).0),
        Account {
            owner: PrincipalId::new_user_test_id(6).0,
            subaccount: Some([6; 32]),
        },
    ];
    let mut initial_balances = vec![];
    let mut all_accounts = [accounts.clone(), additional_accounts.clone()].concat();
    for (index, account) in all_accounts.iter().enumerate() {
        initial_balances.push((*account, 10_000_000u64 + index as u64));
    }

    // Setup ledger as it is deployed on the mainnet.
    let (env, canister_id) = setup(ledger_wasm_mainnet, encode_init_args, initial_balances);

    const APPROVE_AMOUNT: u64 = 150_000;
    let expiration =
        system_time_to_nanos(env.time()) + Duration::from_secs(5000 * 3600).as_nanos() as u64;

    let mut expected_allowances = vec![];

    for i in 0..accounts.len() {
        for j in i + 1..accounts.len() {
            let mut approve_args = default_approve_args(accounts[j], APPROVE_AMOUNT);
            approve_args.from_subaccount = accounts[i].subaccount;
            send_approval(&env, canister_id, accounts[i].owner, &approve_args)
                .expect("approval failed");
            expected_allowances.push(Account::get_allowance(
                &env,
                canister_id,
                accounts[i],
                accounts[j],
            ));

            let mut approve_args = default_approve_args(accounts[i], APPROVE_AMOUNT);
            approve_args.expires_at = Some(expiration);
            approve_args.from_subaccount = accounts[j].subaccount;
            send_approval(&env, canister_id, accounts[j].owner, &approve_args)
                .expect("approval failed");
            expected_allowances.push(Account::get_allowance(
                &env,
                canister_id,
                accounts[j],
                accounts[i],
            ));
        }
    }
    for i in 7..7 + 30 {
        let to = Account::from(PrincipalId::new_user_test_id(i).0);
        transfer(&env, canister_id, accounts[0], to, 100).expect("failed to transfer funds");
        all_accounts.push(to);
    }
    let mut balances = BTreeMap::new();
    for account in &all_accounts {
        balances.insert(account, Nat::from(balance_of(&env, canister_id, *account)));
    }

    let test_upgrade = |ledger_wasm: Vec<u8>,
                        balances: BTreeMap<&Account, Nat>,
                        min_migration_steps: u64| {
        let blocks_before = get_all_blocks(&env, canister_id);

        env.upgrade_canister(
            canister_id,
            ledger_wasm,
            Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
        )
        .unwrap();

        wait_ledger_ready(&env, canister_id, 20);

        assert_eq!(blocks_before, get_all_blocks(&env, canister_id));

        let stable_upgrade_migration_steps =
            parse_metric(&env, canister_id, "ledger_stable_upgrade_migration_steps");
        assert!(stable_upgrade_migration_steps >= min_migration_steps);

        let mut allowances = vec![];
        for i in 0..accounts.len() {
            for j in i + 1..accounts.len() {
                let allowance = Account::get_allowance(&env, canister_id, accounts[i], accounts[j]);
                assert_eq!(allowance.allowance, Nat::from(APPROVE_AMOUNT));
                allowances.push(allowance);
                let allowance = Account::get_allowance(&env, canister_id, accounts[j], accounts[i]);
                assert_eq!(allowance.allowance, Nat::from(APPROVE_AMOUNT));
                allowances.push(allowance);
            }
        }
        assert_eq!(expected_allowances, allowances);

        for account in &all_accounts {
            assert_eq!(balance_of(&env, canister_id, *account), balances[account]);
        }
    };

    // Test if the old serialized approvals and balances are correctly deserialized
    test_upgrade(
        ledger_wasm_current_lowinstructionlimits.clone(),
        balances.clone(),
        2,
    );

    // Add some more approvals
    for a1 in &accounts {
        for a2 in &additional_accounts {
            let mut approve_args = default_approve_args(*a2, APPROVE_AMOUNT);
            approve_args.from_subaccount = a1.subaccount;
            send_approval(&env, canister_id, a1.owner, &approve_args).expect("approval failed");
            balances.insert(a1, balances[a1].clone() - approve_args.fee.unwrap());

            let mut approve_args = default_approve_args(*a1, APPROVE_AMOUNT);
            approve_args.expires_at = Some(expiration);
            approve_args.from_subaccount = a2.subaccount;
            send_approval(&env, canister_id, a2.owner, &approve_args).expect("approval failed");
            balances.insert(a2, balances[a2].clone() - approve_args.fee.unwrap());
        }
    }

    // Test the new wasm serialization
    test_upgrade(ledger_wasm_current_lowinstructionlimits, balances, 0);

    // See if the additional approvals are there
    for a1 in &accounts {
        for a2 in &additional_accounts {
            let allowance = Account::get_allowance(&env, canister_id, *a1, *a2);
            assert_eq!(allowance.allowance, Nat::from(APPROVE_AMOUNT));
            assert_eq!(allowance.expires_at, None);

            let allowance = Account::get_allowance(&env, canister_id, *a2, *a1);
            assert_eq!(allowance.allowance, Nat::from(APPROVE_AMOUNT));
            assert_eq!(allowance.expires_at, Some(expiration));
        }
    }
}

pub fn test_downgrade_from_incompatible_version<T>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_nextledgerversion: Vec<u8>,
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    downgrade_to_mainnet_possible: bool,
) where
    T: CandidType,
{
    // Setup ledger with mainnet version.
    let (env, canister_id) = setup(ledger_wasm_mainnet.clone(), encode_init_args, vec![]);

    // Upgrade to current version.
    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .expect("failed to upgrade to current version");

    // Upgrade to the same verison.
    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .expect("failed to upgrade to current version");

    // Downgrade to mainnet not possible.
    match env.upgrade_canister(
        canister_id,
        ledger_wasm_mainnet,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    ) {
        Ok(_) => {
            if !downgrade_to_mainnet_possible {
                panic!("Upgrade from future ledger version should fail!")
            }
        }
        Err(e) => {
            if downgrade_to_mainnet_possible {
                panic!("Downgrade to mainnet should be possible!")
            } else {
                assert!(
                    e.description()
                        .contains("Trying to downgrade from incompatible version")
                )
            }
        }
    };

    // Upgrade to the next version.
    env.upgrade_canister(
        canister_id,
        ledger_wasm_nextledgerversion.clone(),
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .expect("failed to upgrade to next version");

    // Downgrade to current not possible.
    match env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    ) {
        Ok(_) => {
            panic!("Downgrade from future ledger version should fail!")
        }
        Err(e) => {
            assert!(
                e.description()
                    .contains("Trying to downgrade from incompatible version")
            )
        }
    };

    // Upgrade to the same (future) version succeeds.
    env.upgrade_canister(
        canister_id,
        ledger_wasm_nextledgerversion,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .expect("failed to upgrade to next version");
}

pub fn icrc1_test_stable_migration_endpoints_disabled<T>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current_lowinstructionlimits: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    additional_endpoints: Vec<(&str, Vec<u8>)>,
) where
    T: CandidType,
{
    let account = Account::from(PrincipalId::new_user_test_id(1).0);
    let initial_balances = vec![(account, 100_000_000u64)];

    // Setup ledger as it is deployed on the mainnet.
    let (env, canister_id) = setup(ledger_wasm_mainnet, encode_init_args, initial_balances);

    const APPROVE_AMOUNT: u64 = 150_000;

    for i in 2..60 {
        let spender = Account::from(PrincipalId::new_user_test_id(i).0);
        let approve_args = default_approve_args(spender, APPROVE_AMOUNT);
        send_approval(&env, canister_id, account.owner, &approve_args).expect("approval failed");
    }

    for i in 2..60 {
        let to = Account::from(PrincipalId::new_user_test_id(i).0);
        transfer(&env, canister_id, account, to, 100).expect("failed to transfer funds");
    }

    env.upgrade_canister(
        canister_id,
        ledger_wasm_current_lowinstructionlimits,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    let transfer_args = TransferArg {
        from_subaccount: None,
        to: Account::from(PrincipalId::new_user_test_id(2).0),
        fee: None,
        created_at_time: None,
        amount: Nat::from(1u64),
        memo: None,
    };
    let approve_args = default_approve_args(
        Account::from(PrincipalId::new_user_test_id(200).0),
        APPROVE_AMOUNT,
    );
    let transfer_from_args = TransferFromArgs {
        spender_subaccount: None,
        from: account,
        to: Account::from(PrincipalId::new_user_test_id(2).0),
        amount: Nat::from(1u64),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let allowance_args = AllowanceArgs {
        account,
        spender: account,
    };

    let test_endpoint = |endpoint_name: &str, args: Vec<u8>, expect_error: bool| {
        println!("testing endpoint {endpoint_name}");
        let result = env.execute_ingress_as(account.owner.into(), canister_id, endpoint_name, args);
        if expect_error {
            result
                .unwrap_err()
                .assert_contains(ErrorCode::CanisterCalledTrap, "The Ledger is not ready");
        } else {
            assert!(result.is_ok());
        }
    };

    test_endpoint("icrc1_transfer", Encode!(&transfer_args).unwrap(), true);
    test_endpoint("icrc2_approve", Encode!(&approve_args).unwrap(), true);
    test_endpoint(
        "icrc2_transfer_from",
        Encode!(&transfer_from_args).unwrap(),
        true,
    );
    test_endpoint("icrc2_allowance", Encode!(&allowance_args).unwrap(), true);
    test_endpoint("icrc1_balance_of", Encode!(&account).unwrap(), true);
    test_endpoint("icrc1_total_supply", Encode!().unwrap(), true);
    for (endpoint_name, args) in additional_endpoints.clone() {
        test_endpoint(endpoint_name, args, true);
    }

    wait_ledger_ready(&env, canister_id, 50);

    test_endpoint("icrc1_transfer", Encode!(&transfer_args).unwrap(), false);
    test_endpoint("icrc2_approve", Encode!(&approve_args).unwrap(), false);
    test_endpoint(
        "icrc2_transfer_from",
        Encode!(&transfer_from_args).unwrap(),
        false,
    );
    test_endpoint("icrc2_allowance", Encode!(&allowance_args).unwrap(), false);
    test_endpoint("icrc1_balance_of", Encode!(&account).unwrap(), false);
    test_endpoint("icrc1_total_supply", Encode!().unwrap(), false);
    for (endpoint_name, args) in additional_endpoints {
        test_endpoint(endpoint_name, args, false);
    }
}

pub fn test_incomplete_migration<T>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current_lowinstructionlimits: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let account = Account::from(PrincipalId::new_user_test_id(1).0);
    let initial_balances = vec![(account, 100_000_000u64)];

    // Setup ledger as it is deployed on the mainnet.
    let (env, canister_id) = setup(
        ledger_wasm_mainnet.clone(),
        encode_init_args,
        initial_balances,
    );

    const APPROVE_AMOUNT: u64 = 150_000;
    const TRANSFER_AMOUNT: u64 = 100;

    const NUM_APPROVALS: u64 = 20;
    const NUM_TRANSFERS: u64 = 30;

    let send_approvals = || {
        for i in 2..2 + NUM_APPROVALS {
            let spender = Account::from(PrincipalId::new_user_test_id(i).0);
            let approve_args = default_approve_args(spender, APPROVE_AMOUNT);
            send_approval(&env, canister_id, account.owner, &approve_args)
                .expect("approval failed");
        }
    };

    send_approvals();

    for i in 2..2 + NUM_TRANSFERS {
        let to = Account::from(PrincipalId::new_user_test_id(i).0);
        transfer(&env, canister_id, account, to, TRANSFER_AMOUNT + FEE)
            .expect("failed to transfer funds");
    }

    let check_approvals = |non_zero_from: u64| {
        for i in 2..2 + NUM_APPROVALS {
            let allowance = Account::get_allowance(
                &env,
                canister_id,
                account,
                Account::from(PrincipalId::new_user_test_id(i).0),
            );
            let expected_allowance = if i < non_zero_from {
                Nat::from(0u64)
            } else {
                Nat::from(APPROVE_AMOUNT)
            };
            assert_eq!(allowance.allowance, expected_allowance);
        }
    };
    let check_balances = |non_zero_from: u64| {
        for i in 2..2 + NUM_TRANSFERS {
            let balance = balance_of(
                &env,
                canister_id,
                Account::from(PrincipalId::new_user_test_id(i).0),
            );
            let expected_balance = if i < non_zero_from {
                Nat::from(0u64)
            } else {
                Nat::from(TRANSFER_AMOUNT + FEE)
            };
            assert_eq!(balance, expected_balance);
        }
    };
    check_approvals(2);
    check_balances(2);

    env.upgrade_canister(
        canister_id,
        ledger_wasm_current_lowinstructionlimits.clone(),
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    let is_ledger_ready = Decode!(
        &env.query(canister_id, "is_ledger_ready", Encode!().unwrap())
            .expect("failed to call is_ledger_ready")
            .bytes(),
        bool
    )
    .expect("failed to decode is_ledger_ready response");
    assert!(!is_ledger_ready);

    // Downgrade to mainnet without waiting for the migration to complete.
    env.upgrade_canister(
        canister_id,
        ledger_wasm_mainnet,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    // All approvals should still be in UPGRADES_MEMORY and downgrade should succeed.
    check_approvals(2);

    for i in 2..5 {
        let spender = Account::from(PrincipalId::new_user_test_id(i).0);
        let approve_args = default_approve_args(spender, 0);
        send_approval(&env, canister_id, account.owner, &approve_args).expect("approval failed");
        transfer(&env, canister_id, spender, account, TRANSFER_AMOUNT)
            .expect("failed to transfer funds");
    }

    check_approvals(5);
    check_balances(5);

    env.upgrade_canister(
        canister_id,
        ledger_wasm_current_lowinstructionlimits,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();
    wait_ledger_ready(&env, canister_id, 20);

    check_approvals(5);
    check_balances(5);
}

pub fn test_incomplete_migration_to_current<T>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current_lowinstructionlimits: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let account = Account::from(PrincipalId::new_user_test_id(1).0);
    let initial_balances = vec![(account, 100_000_000u64)];

    // Setup ledger as it is deployed on the mainnet.
    let (env, canister_id) = setup(
        ledger_wasm_mainnet.clone(),
        encode_init_args,
        initial_balances,
    );

    const APPROVE_AMOUNT: u64 = 150_000;
    const TRANSFER_AMOUNT: u64 = 100;

    const NUM_APPROVALS: u64 = 20;
    const NUM_TRANSFERS: u64 = 30;

    let send_approvals = || {
        for i in 2..2 + NUM_APPROVALS {
            let spender = Account::from(PrincipalId::new_user_test_id(i).0);
            let approve_args = default_approve_args(spender, APPROVE_AMOUNT);
            send_approval(&env, canister_id, account.owner, &approve_args)
                .expect("approval failed");
        }
    };

    send_approvals();

    for i in 2..2 + NUM_TRANSFERS {
        let to = Account::from(PrincipalId::new_user_test_id(i).0);
        transfer(&env, canister_id, account, to, TRANSFER_AMOUNT + i)
            .expect("failed to transfer funds");
    }

    let check_approvals = || {
        for i in 2..2 + NUM_APPROVALS {
            let allowance = Account::get_allowance(
                &env,
                canister_id,
                account,
                Account::from(PrincipalId::new_user_test_id(i).0),
            );
            assert_eq!(allowance.allowance, Nat::from(APPROVE_AMOUNT));
        }
    };
    let check_balances = || {
        for i in 2..2 + NUM_TRANSFERS {
            let balance = balance_of(
                &env,
                canister_id,
                Account::from(PrincipalId::new_user_test_id(i).0),
            );
            assert_eq!(balance, Nat::from(TRANSFER_AMOUNT + i));
        }
    };

    check_approvals();
    check_balances();

    env.upgrade_canister(
        canister_id,
        ledger_wasm_current_lowinstructionlimits.clone(),
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    let is_ledger_ready = Decode!(
        &env.query(canister_id, "is_ledger_ready", Encode!().unwrap())
            .expect("failed to call is_ledger_ready")
            .bytes(),
        bool
    )
    .expect("failed to decode is_ledger_ready response");
    assert!(!is_ledger_ready);

    // Upgrade to current without completing the migration.
    env.upgrade_canister(
        canister_id,
        ledger_wasm_current_lowinstructionlimits,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    wait_ledger_ready(&env, canister_id, 20);
    check_approvals();
    check_balances();
}

pub fn test_migration_resumes_from_frozen<T>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current_lowinstructionlimits: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let account = Account::from(PrincipalId::new_user_test_id(1).0);
    let initial_balances = vec![(account, 100_000_000u64)];

    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config.clone(),
        HypervisorConfig::default(),
    ));

    let args = encode_init_args(init_args(initial_balances));
    let args = Encode!(&args).unwrap();
    let canister_id = env
        .install_canister_with_cycles(
            ledger_wasm_mainnet,
            args,
            None,
            Cycles::new(1_000_000_000_000),
        )
        .unwrap();

    const APPROVE_AMOUNT: u64 = 150_000;
    const TRANSFER_AMOUNT: u64 = 100;

    const NUM_APPROVALS: u64 = 40;
    const NUM_TRANSFERS: u64 = 40;

    let send_approvals = || {
        for i in 2..2 + NUM_APPROVALS {
            let spender = Account::from(PrincipalId::new_user_test_id(i).0);
            let approve_args = default_approve_args(spender, APPROVE_AMOUNT);
            send_approval(&env, canister_id, account.owner, &approve_args)
                .expect("approval failed");
        }
    };

    send_approvals();

    for i in 2..2 + NUM_TRANSFERS {
        let to = Account::from(PrincipalId::new_user_test_id(i).0);
        transfer(&env, canister_id, account, to, TRANSFER_AMOUNT + i)
            .expect("failed to transfer funds");
    }

    let check_approvals = || {
        for i in 2..2 + NUM_APPROVALS {
            let allowance = Account::get_allowance(
                &env,
                canister_id,
                account,
                Account::from(PrincipalId::new_user_test_id(i).0),
            );
            assert_eq!(allowance.allowance, Nat::from(APPROVE_AMOUNT));
        }
    };
    let check_balances = || {
        for i in 2..2 + NUM_TRANSFERS {
            let balance = balance_of(
                &env,
                canister_id,
                Account::from(PrincipalId::new_user_test_id(i).0),
            );
            assert_eq!(balance, Nat::from(TRANSFER_AMOUNT + i));
        }
    };

    check_approvals();
    check_balances();

    env.upgrade_canister(
        canister_id,
        ledger_wasm_current_lowinstructionlimits,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    let is_ledger_ready = || {
        Decode!(
            &env.query(canister_id, "is_ledger_ready", Encode!().unwrap())
                .expect("failed to call is_ledger_ready")
                .bytes(),
            bool
        )
        .expect("failed to decode is_ledger_ready response")
    };
    assert!(!is_ledger_ready());

    let freeze = |env: &StateMachine, canister_id: CanisterId| {
        let args = CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(1 << 62)
            .build();
        let result = env.update_settings(&canister_id, args);
        assert_matches!(result, Ok(_));
    };
    let unfreeze = |env: &StateMachine, canister_id: CanisterId| {
        let args = CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(0)
            .build();
        let result = env.update_settings(&canister_id, args);
        assert_matches!(result, Ok(_));
    };

    freeze(&env, canister_id);
    env.advance_time(Duration::from_secs(1000));
    // Make sure the timer was attempted to be scheduled.
    for _ in 0..10 {
        env.tick();
    }
    unfreeze(&env, canister_id);
    // even though 1000s passed, the ledger did not migrate when it was frozen
    assert!(!is_ledger_ready());
    wait_ledger_ready(&env, canister_id, 30);
    check_approvals();
    check_balances();
}

pub fn test_metrics_while_migrating<T>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current_lowinstructionlimits: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let account = Account::from(PrincipalId::new_user_test_id(1).0);
    let initial_balances = vec![(account, 100_000_000u64)];

    // Setup ledger as it is deployed on the mainnet.
    let (env, canister_id) = setup(
        ledger_wasm_mainnet.clone(),
        encode_init_args,
        initial_balances,
    );

    for i in 2..22 {
        let spender = Account::from(PrincipalId::new_user_test_id(i).0);
        let approve_args = default_approve_args(spender, 150_000);
        send_approval(&env, canister_id, account.owner, &approve_args).expect("approval failed");
    }

    for i in 2..31 {
        let to = Account::from(PrincipalId::new_user_test_id(i).0);
        transfer(&env, canister_id, account, to, 100).expect("failed to transfer funds");
    }

    env.upgrade_canister(
        canister_id,
        ledger_wasm_current_lowinstructionlimits,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    // The migration should not yet have completed - if this happens (e.g., due to a bump of some
    // dependency, leading to more blocks being migrated within the configured instruction limits),
    // consider adjusting the number of blocks stored in the ledger before starting the migration.
    let is_ledger_ready = Decode!(
        &env.query(canister_id, "is_ledger_ready", Encode!().unwrap())
            .expect("failed to call is_ledger_ready")
            .bytes(),
        bool
    )
    .expect("failed to decode is_ledger_ready response");
    assert!(!is_ledger_ready);

    let metrics = retrieve_metrics(&env, canister_id);
    assert!(
        metrics
            .iter()
            .any(|line| line.contains("ledger_transactions")),
        "Did not find ledger_transactions metric"
    );
    assert!(
        !metrics
            .iter()
            .any(|line| line.contains("ledger_num_approvals")),
        "ledger_num_approvals should not be in metrics"
    );

    wait_ledger_ready(&env, canister_id, 20);

    let metrics = retrieve_metrics(&env, canister_id);
    assert!(
        metrics
            .iter()
            .any(|line| line.contains("ledger_transactions")),
        "Did not find ledger_transactions metric"
    );
    assert!(
        metrics
            .iter()
            .any(|line| line.contains("ledger_num_approvals")),
        "Did not find ledger_num_approvals metric"
    );
}

pub fn test_upgrade_not_possible<T>(
    ledger_wasm_mainnet_v1: Vec<u8>,
    ledger_wasm_current: Vec<u8>,
    expected_errror_msg: &str,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    // Setup ledger with v1 state that does not use UPGRADES_MEMORY.
    let (env, canister_id) = setup(ledger_wasm_mainnet_v1, encode_init_args, vec![]);

    match env.upgrade_canister(
        canister_id,
        ledger_wasm_current,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    ) {
        Ok(_) => {
            panic!("Upgrade should fail!")
        }
        Err(e) => {
            assert!(e.description().contains(expected_errror_msg));
        }
    };
}

pub fn default_approve_args(spender: impl Into<Account>, amount: u64) -> ApproveArgs {
    ApproveArgs {
        from_subaccount: None,
        spender: spender.into(),
        amount: Nat::from(amount),
        expected_allowance: None,
        expires_at: None,
        fee: Some(Nat::from(FEE)),
        memo: None,
        created_at_time: None,
    }
}

pub fn default_transfer_from_args(
    from: impl Into<Account>,
    to: impl Into<Account>,
    amount: u64,
) -> TransferFromArgs {
    TransferFromArgs {
        spender_subaccount: None,
        from: from.into(),
        to: to.into(),
        amount: Nat::from(amount),
        fee: Some(Nat::from(FEE)),
        memo: None,
        created_at_time: None,
    }
}

pub fn test_approve_smoke<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let from_sub_1 = Account {
        owner: from.0,
        subaccount: Some([1; 32]),
    };

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000), (from_sub_1, 100_000)],
    );

    let mut approve_args = default_approve_args(spender.0, 150_000);

    // Standard approval.
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 2);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 90_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);

    // Approval for a subaccount.
    approve_args.from_subaccount = Some([1; 32]);
    approve_args.amount = Nat::from(1_000_000u32);
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 3);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    let allowance_sub_1 = Account::get_allowance(&env, canister_id, from_sub_1, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(allowance_sub_1.allowance.0.to_u64().unwrap(), 1_000_000);
    assert_eq!(allowance_sub_1.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 90_000);
    assert_eq!(balance_of(&env, canister_id, from_sub_1), 90_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_approve_expiration<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000)],
    );

    let mut approve_args = default_approve_args(spender.0, 150_000);

    // Approval with expiration in the past.
    approve_args.expires_at =
        Some(system_time_to_nanos(env.time()) - Duration::from_secs(5 * 3600).as_nanos() as u64);
    assert_eq!(
        send_approval(&env, canister_id, from.0, &approve_args),
        Err(ApproveError::Expired {
            ledger_time: system_time_to_nanos(env.time())
        })
    );
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 0);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 100_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);

    // Correct expiration.
    let expiration =
        system_time_to_nanos(env.time()) + Duration::from_secs(5 * 3600).as_nanos() as u64;
    approve_args.expires_at = Some(expiration);
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 1);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    assert_eq!(allowance.expires_at, Some(expiration));
    assert_eq!(balance_of(&env, canister_id, from.0), 90_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);

    // Decrease expiration.
    let new_expiration = expiration - Duration::from_secs(3600).as_nanos() as u64;
    approve_args.expires_at = Some(new_expiration);
    approve_args.amount = Nat::from(40_000u32);
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 2);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 40_000);
    assert_eq!(allowance.expires_at, Some(new_expiration));
    assert_eq!(balance_of(&env, canister_id, from.0), 80_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);

    // Increase expiration.
    let new_expiration = expiration + Duration::from_secs(3600).as_nanos() as u64;
    approve_args.expires_at = Some(new_expiration);
    approve_args.amount = Nat::from(300_000u32);
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 3);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 300_000);
    assert_eq!(allowance.expires_at, Some(new_expiration));
    assert_eq!(balance_of(&env, canister_id, from.0), 70_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_approve_self<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000)],
    );

    let mut approve_args = default_approve_args(spender.0, 150_000);

    // Self approval not allowed.
    approve_args.spender = from.0.into();
    let err = env
        .execute_ingress_as(
            from,
            canister_id,
            "icrc2_approve",
            Encode!(&approve_args).unwrap(),
        )
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterCalledTrap,
        "self approval is not allowed",
    );
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 0);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 100_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_approve_expected_allowance<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000)],
    );

    let mut approve_args = default_approve_args(spender.0, 150_000);

    send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");

    // Wrong expected_allowance.
    approve_args.expires_at = None;
    approve_args.amount = Nat::from(400_000u32);
    approve_args.expected_allowance = Some(Nat::from(100_000u32));
    assert_eq!(
        send_approval(&env, canister_id, from.0, &approve_args),
        Err(ApproveError::AllowanceChanged {
            current_allowance: Nat::from(150_000u32)
        })
    );
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 90_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);

    // Wrong expected_allowance - above u64::MAX
    approve_args.expires_at = None;
    approve_args.amount = Nat::from(400_000u32);
    approve_args.expected_allowance = Some(Nat::from(u128::MAX));
    assert_eq!(
        send_approval(&env, canister_id, from.0, &approve_args),
        Err(ApproveError::AllowanceChanged {
            current_allowance: Nat::from(150_000u32)
        })
    );
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 90_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);

    // Correct expected_allowance.
    approve_args.amount = Nat::from(400_000u32);
    approve_args.expected_allowance = Some(Nat::from(150_000u32));
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 2);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 400_000);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 80_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_approve_cant_pay_fee<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 5_000)],
    );

    let mut approve_args = default_approve_args(spender.0, 150_000);

    // Not enough funds to pay the fee.
    approve_args.expected_allowance = None;
    assert_eq!(
        send_approval(&env, canister_id, from.0, &approve_args),
        Err(ApproveError::InsufficientFunds {
            balance: Nat::from(5_000u32)
        })
    );
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 0);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 5_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_approve_cap<T, Tokens>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
    Tokens: TokensType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000)],
    );

    let mut approve_args = default_approve_args(spender.0, 150_000);

    approve_args.amount = Tokens::max_value().into() * 2u8;
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 1);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance, Tokens::max_value().into());
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 90_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_approve_pruning<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let from_sub_1 = Account {
        owner: from.0,
        subaccount: Some([1; 32]),
    };

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000), (from_sub_1, 100_000)],
    );

    let mut approve_args = default_approve_args(spender.0, 150_000);

    // Approval expiring 1 hour from now.
    let expiration =
        Some(system_time_to_nanos(env.time()) + Duration::from_secs(3600).as_nanos() as u64);
    approve_args.expires_at = expiration;
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 2);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    assert_eq!(allowance.expires_at, expiration);
    assert_eq!(balance_of(&env, canister_id, from.0), 90_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);

    // Test expired approval pruning, advance time 2 hours.
    env.advance_time(Duration::from_secs(2 * 3600));
    let expiration =
        Some(system_time_to_nanos(env.time()) + Duration::from_secs(3600).as_nanos() as u64);
    approve_args.from_subaccount = Some([1; 32]);
    approve_args.expires_at = expiration;
    approve_args.amount = Nat::from(100_000u32);
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 3);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    let allowance_sub_1 = Account::get_allowance(&env, canister_id, from_sub_1, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 0);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(allowance_sub_1.allowance.0.to_u64().unwrap(), 100_000);
    assert_eq!(allowance_sub_1.expires_at, expiration);
    assert_eq!(balance_of(&env, canister_id, from.0), 90_000);
    assert_eq!(balance_of(&env, canister_id, from_sub_1), 90_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_approve_from_minter<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    let minter = minting_account(&env, canister_id).unwrap();
    let spender = PrincipalId::new_user_test_id(1);
    let approve_args = default_approve_args(spender.0, 150_000);

    // Delegating mints is not allowed.
    let err = env
        .execute_ingress_as(
            minter.owner.into(),
            canister_id,
            "icrc2_approve",
            Encode!(&approve_args).unwrap(),
        )
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterCalledTrap,
        "the minting account cannot delegate mints",
    );
}

// The test focuses on testing whether given an (approver, spender) pair the correct
// sequence of allowances is returned.
pub fn test_allowance_listing_sequences<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    const NUM_PRINCIPALS: u64 = 3;
    const NUM_SUBACCOUNTS: u64 = 3;

    let mut initial_balances = vec![];
    let mut approvers = vec![];
    let mut spenders = vec![];

    for pid in 1..NUM_PRINCIPALS + 1 {
        for sub in 0..NUM_SUBACCOUNTS {
            let approver = Account {
                owner: Principal::from_slice(&[pid as u8; 2]),
                subaccount: Some([sub as u8; 32]),
            };
            approvers.push(approver);
            initial_balances.push((approver, 100_000));
            spenders.push(Account {
                owner: Principal::from_slice(&[pid as u8 + NUM_PRINCIPALS as u8; 2]),
                subaccount: Some([sub as u8; 32]),
            });
        }
    }

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, initial_balances);

    // Create approvals between all (approver, spender) pairs from `approvers` and `spenders`.
    // Additionally store all pairs in an array in sorted order in `approve_pairs`.
    // This allows us to check if the allowances returned by the `icrc103_get_allowances`
    // endpoint are correct - they will always form a contiguous subarray of `approve_pairs`.
    let mut approve_pairs = vec![];
    for approver in &approvers {
        for spender in &spenders {
            let approve_args = ApproveArgs {
                from_subaccount: approver.subaccount,
                spender: *spender,
                amount: Nat::from(10u64),
                expected_allowance: None,
                expires_at: None,
                fee: Some(Nat::from(FEE)),
                memo: None,
                created_at_time: None,
            };
            let _ = send_approval(&env, canister_id, approver.owner, &approve_args)
                .expect("approval failed");
            approve_pairs.push((approver, spender));
        }
    }
    assert!(approve_pairs.is_sorted());

    // Check if given allowances match the elements of `approve_pairs` starting at index `pair_index`.
    // Additionally check that the next element in `approve_pairs` has a different `from.owner`
    // and could not be part of the same response of `icrc103_get_allowances`.
    let check_allowances = |allowances: Allowances, pair_idx: usize, owner: Principal| {
        for i in 0..allowances.len() {
            let allowance = &allowances[i];
            let pair = approve_pairs[pair_idx + i];
            assert_eq!(allowance.from_account, *pair.0, "incorrect from account");
            assert_eq!(allowance.to_spender, *pair.1, "incorrect spender account");
        }
        let next_pair_idx = pair_idx + allowances.len();
        if next_pair_idx < approve_pairs.len() {
            assert_ne!(approve_pairs[next_pair_idx].0.owner, owner);
        }
    };

    // Create an Account that is lexicographically smaller than the given Account.
    // In the above Account generation scheme, the returned account will fall
    // between two approvers or spenders - we only modify the second byte of
    // the owner slice or the last byte of the subaccount slice.
    let prev_account = |account: &Account| {
        if account.subaccount.unwrap() == [0u8; 32] {
            let owner = account.owner.as_slice();
            let prev_owner = [owner[0], owner[1] - 1];
            Account {
                owner: Principal::from_slice(&prev_owner),
                subaccount: account.subaccount,
            }
        } else {
            let mut prev_subaccount = account.subaccount.unwrap();
            prev_subaccount[31] -= 1;
            Account {
                owner: account.owner,
                subaccount: Some(prev_subaccount),
            }
        }
    };

    let mut prev_from = None;
    for (idx, &(&from, &spender)) in approve_pairs.iter().enumerate() {
        let mut args = GetAllowancesArgs {
            from_account: Some(from),
            prev_spender: None,
            take: None,
        };

        if prev_from != Some(from) {
            prev_from = Some(from);

            // Listing without specifying the spender.
            let allowances = list_allowances(&env, canister_id, from.owner, args.clone())
                .expect("failed to list allowances");
            check_allowances(allowances, idx, from.owner);

            // List from a smaller `from_account`. If the smaller `from_account` has a different owner
            // the result list is empty - we don't have any approvals for that owner.
            // If the smaller `from_account` has a different subaccount, the result is the same
            // as listing for current `from_account` - the smaller subaccount does not match any account we generated.
            args.from_account = Some(prev_account(&from));
            let allowances = list_allowances(&env, canister_id, from.owner, args.clone())
                .expect("failed to list allowances");
            if args.from_account.unwrap().owner == from.owner {
                check_allowances(allowances, idx, from.owner);
            } else {
                assert_eq!(allowances.len(), 0);
            }
            args.from_account = Some(from);
        }

        // Listing with spender specified, the current `approve_pair` is skipped.
        args.prev_spender = Some(spender);
        let allowances = list_allowances(&env, canister_id, from.owner, args.clone())
            .expect("failed to list allowances");
        check_allowances(allowances, idx + 1, from.owner);

        // Listing with smaller spender, the current `approve_pair` is included.
        args.prev_spender = Some(prev_account(&spender));
        let allowances = list_allowances(&env, canister_id, from.owner, args)
            .expect("failed to list allowances");
        check_allowances(allowances, idx, from.owner);
    }
}

// The test focuses on testing if the returned allowances have the correct
// values for all fields (from, spender, amount, expiration).
pub fn test_allowance_listing_values<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let approver = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: None,
    };
    let approver_sub = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: Some([2u8; 32]),
    };
    let initial_balances = vec![(approver, 100_000), (approver_sub, 100_000)];
    let spender = Account {
        owner: PrincipalId::new_user_test_id(3).0,
        subaccount: None,
    };
    let spender_sub = Account {
        owner: PrincipalId::new_user_test_id(4).0,
        subaccount: Some([3u8; 32]),
    };

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, initial_balances);

    // Simplest possible approval.
    let approve_args = default_approve_args(spender, 1);
    let block_index =
        send_approval(&env, canister_id, approver.owner, &approve_args).expect("approval failed");
    assert_eq!(block_index, 2);

    let now = system_time_to_nanos(env.time());

    // Spender subaccount, expiration
    let expiration_far = Some(now + Duration::from_secs(3600).as_nanos() as u64);
    let mut approve_args = default_approve_args(spender_sub, 2);
    approve_args.expires_at = expiration_far;
    let block_index =
        send_approval(&env, canister_id, approver.owner, &approve_args).expect("approval failed");
    assert_eq!(block_index, 3);

    // From subaccount
    let mut approve_args = default_approve_args(spender, 3);
    approve_args.from_subaccount = approver_sub.subaccount;
    let block_index = send_approval(&env, canister_id, approver_sub.owner, &approve_args)
        .expect("approval failed");
    assert_eq!(block_index, 4);

    // From subaccount, spender subaccount, expiration
    let expiration_near = Some(now + Duration::from_secs(10).as_nanos() as u64);
    let mut approve_args = default_approve_args(spender_sub, 4);
    approve_args.from_subaccount = approver_sub.subaccount;
    approve_args.expires_at = expiration_near;
    let block_index = send_approval(&env, canister_id, approver_sub.owner, &approve_args)
        .expect("approval failed");
    assert_eq!(block_index, 5);

    let mut args = GetAllowancesArgs {
        from_account: Some(approver),
        prev_spender: None,
        take: None,
    };

    let allowances = list_allowances(&env, canister_id, approver.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 2);

    assert_eq!(allowances[0].from_account, approver);
    assert_eq!(allowances[0].to_spender, spender);
    assert_eq!(allowances[0].allowance, Nat::from(1u64));
    assert_eq!(allowances[0].expires_at, None);

    assert_eq!(allowances[1].from_account, approver);
    assert_eq!(allowances[1].to_spender, spender_sub);
    assert_eq!(allowances[1].allowance, Nat::from(2u64));
    assert_eq!(allowances[1].expires_at, expiration_far);

    args.take = Some(Nat::from(1u64));

    let allowances_take = list_allowances(&env, canister_id, approver.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances_take.len(), 1);
    assert_eq!(allowances_take[0], allowances[0]);

    let args = GetAllowancesArgs {
        from_account: Some(approver_sub),
        prev_spender: None,
        take: None,
    };

    // Here we additionally test listing approvals of another Principal.
    let allowances = list_allowances(&env, canister_id, approver.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 2);

    assert_eq!(allowances[0].from_account, approver_sub);
    assert_eq!(allowances[0].to_spender, spender);
    assert_eq!(allowances[0].allowance, Nat::from(3u64));
    assert_eq!(allowances[0].expires_at, None);

    assert_eq!(allowances[1].from_account, approver_sub);
    assert_eq!(allowances[1].to_spender, spender_sub);
    assert_eq!(allowances[1].allowance, Nat::from(4u64));
    assert_eq!(allowances[1].expires_at, expiration_near);

    env.advance_time(Duration::from_secs(10));

    let allowances_later = list_allowances(&env, canister_id, approver.owner, args)
        .expect("failed to list allowances");
    assert_eq!(allowances_later.len(), 1);
    assert_eq!(allowances_later[0], allowances[0]);
}

// Test whether specifying None/DEFAULT_SUBACCOUNT does not affect the results.
pub fn test_allowance_listing_subaccount<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let approver_none = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: None,
    };
    let approver_default = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: Some(*DEFAULT_SUBACCOUNT),
    };
    let initial_balances = vec![(approver_none, 100_000), (approver_default, 100_000)];
    let spender_none = Account {
        owner: PrincipalId::new_user_test_id(3).0,
        subaccount: None,
    };
    let spender_default = Account {
        owner: PrincipalId::new_user_test_id(3).0,
        subaccount: Some(*DEFAULT_SUBACCOUNT),
    };

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, initial_balances);

    let approve_args = default_approve_args(spender_none, 1);
    let block_index = send_approval(&env, canister_id, approver_none.owner, &approve_args)
        .expect("approval failed");
    assert_eq!(block_index, 2);

    let mut approve_args = default_approve_args(spender_default, 1);
    approve_args.from_subaccount = approver_default.subaccount;
    let block_index = send_approval(&env, canister_id, approver_default.owner, &approve_args)
        .expect("approval failed");
    assert_eq!(block_index, 3);

    // Should return the allowance, if we specify `from_account` as when creating approval
    let args = GetAllowancesArgs {
        from_account: Some(approver_none),
        prev_spender: None,
        take: None,
    };
    let allowances = list_allowances(&env, canister_id, approver_none.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 1);

    // Should return the allowance, if we specify `from_account` with explicit default subaccount.
    let mut approver_none_default = approver_none;
    approver_none_default.subaccount = Some(*DEFAULT_SUBACCOUNT);
    let args = GetAllowancesArgs {
        from_account: Some(approver_none_default),
        prev_spender: None,
        take: None,
    };
    let allowances = list_allowances(&env, canister_id, approver_none.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 1);

    // Should filter out the allowance if subaccount is none
    let args = GetAllowancesArgs {
        from_account: Some(approver_none),
        prev_spender: Some(spender_none),
        take: None,
    };
    let allowances = list_allowances(&env, canister_id, approver_none.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 0);

    // Should filter out the allowance if subaccount is default
    let args = GetAllowancesArgs {
        from_account: Some(approver_none),
        prev_spender: Some(spender_default),
        take: None,
    };
    let allowances = list_allowances(&env, canister_id, approver_none.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 0);

    // Should return the allowance, if we specify `from_account` as when creating approval
    let args = GetAllowancesArgs {
        from_account: Some(approver_default),
        prev_spender: None,
        take: None,
    };
    let allowances = list_allowances(&env, canister_id, approver_default.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 1);

    // Should return the allowance, if we specify `from_account` with none subaccount.
    let mut approver_default_none = approver_default;
    approver_default_none.subaccount = None;
    let args = GetAllowancesArgs {
        from_account: Some(approver_default_none),
        prev_spender: None,
        take: None,
    };
    let allowances = list_allowances(&env, canister_id, approver_default.owner, args)
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 1);
}

// The test focuses on testing various values for the `take` parameter.
pub fn test_allowance_listing_take<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    const MAX_RESULTS: usize = 500;
    const NUM_SPENDERS: usize = MAX_RESULTS + 1;

    let approver = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: None,
    };

    let mut spenders = vec![];
    for i in 2..NUM_SPENDERS + 2 {
        spenders.push(Account {
            owner: PrincipalId::new_user_test_id(i as u64).0,
            subaccount: None,
        });
    }
    assert_eq!(spenders.len(), NUM_SPENDERS);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(approver, 1_000_000_000)],
    );

    for spender in &spenders {
        let approve_args = ApproveArgs {
            from_subaccount: None,
            spender: *spender,
            amount: Nat::from(10u64),
            expected_allowance: None,
            expires_at: None,
            fee: Some(Nat::from(FEE)),
            memo: None,
            created_at_time: None,
        };
        let _ = send_approval(&env, canister_id, approver.owner, &approve_args)
            .expect("approval failed");
    }

    let mut args = GetAllowancesArgs {
        from_account: Some(approver),
        prev_spender: None,
        take: None,
    };

    let allowances = list_allowances(&env, canister_id, approver.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), MAX_RESULTS);

    args.take = Some(Nat::from(0u64));
    let allowances = list_allowances(&env, canister_id, approver.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 0);

    args.take = Some(Nat::from(5u64));
    let allowances = list_allowances(&env, canister_id, approver.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), 5);

    args.take = Some(Nat::from(u64::MAX));
    let allowances = list_allowances(&env, canister_id, approver.owner, args.clone())
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), MAX_RESULTS);

    args.take = Some(Nat::from(
        BigUint::parse_bytes(b"1000000000000000000000000000000000000000", 10).unwrap(),
    ));
    assert!(args.take.clone().unwrap().0.to_u64().is_none());
    let allowances = list_allowances(&env, canister_id, approver.owner, args)
        .expect("failed to list allowances");
    assert_eq!(allowances.len(), MAX_RESULTS);
}

pub fn expect_icrc2_disabled(
    env: &StateMachine,
    from: PrincipalId,
    canister_id: CanisterId,
    approve_args: &ApproveArgs,
    allowance_args: &AllowanceArgs,
    transfer_from_args: &TransferFromArgs,
) {
    let err = env
        .execute_ingress_as(
            from,
            canister_id,
            "icrc2_approve",
            Encode!(&approve_args).unwrap(),
        )
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterCalledTrap,
        "ICRC-2 features are not enabled on the ledger.",
    );
    let err = env
        .execute_ingress_as(
            from,
            canister_id,
            "icrc2_allowance",
            Encode!(&allowance_args).unwrap(),
        )
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterCalledTrap,
        "ICRC-2 features are not enabled on the ledger.",
    );
    let err = env
        .execute_ingress_as(
            from,
            canister_id,
            "icrc2_transfer_from",
            Encode!(&transfer_from_args).unwrap(),
        )
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterCalledTrap,
        "ICRC-2 features are not enabled on the ledger.",
    );
    let standards = supported_standards(env, canister_id);
    assert_eq!(standards.len(), 2);
    assert_eq!(standards[0].name, "ICRC-1");
}

pub fn test_feature_flags<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let env = StateMachine::new();

    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);
    let to = PrincipalId::new_user_test_id(3);

    let args = encode_init_args(InitArgs {
        feature_flags: None,
        ..init_args(vec![(Account::from(from.0), 100_000)])
    });
    let args = Encode!(&args).unwrap();
    let canister_id = env
        .install_canister(ledger_wasm.clone(), args, None)
        .unwrap();

    let approve_args = default_approve_args(spender.0, 150_000);
    let allowance_args = AllowanceArgs {
        account: from.0.into(),
        spender: spender.0.into(),
    };
    let transfer_from_args = default_transfer_from_args(from.0, to.0, 10_000);

    expect_icrc2_disabled(
        &env,
        from,
        canister_id,
        &approve_args,
        &allowance_args,
        &transfer_from_args,
    );

    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs {
        feature_flags: None,
        ..UpgradeArgs::default()
    }));

    env.upgrade_canister(
        canister_id,
        ledger_wasm.clone(),
        Encode!(&upgrade_args).unwrap(),
    )
    .expect("failed to upgrade the archive canister");

    expect_icrc2_disabled(
        &env,
        from,
        canister_id,
        &approve_args,
        &allowance_args,
        &transfer_from_args,
    );

    let upgrade_args = LedgerArgument::Upgrade(Some(UpgradeArgs {
        feature_flags: Some(FeatureFlags { icrc2: true }),
        ..UpgradeArgs::default()
    }));

    env.upgrade_canister(canister_id, ledger_wasm, Encode!(&upgrade_args).unwrap())
        .expect("failed to upgrade the archive canister");

    let mut standards = vec![];
    for standard in supported_standards(&env, canister_id) {
        standards.push(standard.name);
    }
    standards.sort();
    assert_eq!(standards, vec!["ICRC-1", "ICRC-2", "ICRC-21"]);

    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 1);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    let block_index = send_transfer_from(&env, canister_id, spender.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(block_index, 2);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 130_000);
    assert_eq!(balance_of(&env, canister_id, from.0), 70_000);
    assert_eq!(balance_of(&env, canister_id, to.0), 10_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_transfer_from_smoke<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);
    let to = PrincipalId::new_user_test_id(3);

    let from_sub_1 = Account {
        owner: from.0,
        subaccount: Some([1; 32]),
    };

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000), (from_sub_1, 100_000)],
    );

    let transfer_from_args = default_transfer_from_args(from.0, to.0, 30_000);
    assert_eq!(
        send_transfer_from(&env, canister_id, spender.0, &transfer_from_args),
        Err(TransferFromError::InsufficientAllowance {
            allowance: Nat::from(0_u8)
        })
    );

    let mut approve_args = default_approve_args(spender.0, 150_000);
    send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    approve_args.from_subaccount = Some([1; 32]);
    approve_args.amount = Nat::from(50_000u32);
    send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");

    let block_index = send_transfer_from(&env, canister_id, spender.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(block_index, 4);
    // `from` paid 2 fees (approval and transfer_from) and 30_000 was transferred.
    assert_eq!(balance_of(&env, canister_id, from.0), 50_000);
    // `from_sub_1` paid approval fee.
    assert_eq!(balance_of(&env, canister_id, from_sub_1), 90_000);
    assert_eq!(balance_of(&env, canister_id, to.0), 30_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 110_000);
    let allowance = Account::get_allowance(&env, canister_id, from_sub_1, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 50_000);

    let transfer_from_args = default_transfer_from_args(from_sub_1, to.0, 30_000);
    let block_index = send_transfer_from(&env, canister_id, spender.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(block_index, 5);
    assert_eq!(balance_of(&env, canister_id, from.0), 50_000);
    // `from_sub_1` paid 2 fees (approval and transfer_from) and 30_000 was transferred.
    assert_eq!(balance_of(&env, canister_id, from_sub_1), 50_000);
    assert_eq!(balance_of(&env, canister_id, to.0), 60_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
    let allowance = Account::get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 110_000);
    let allowance = Account::get_allowance(&env, canister_id, from_sub_1, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 10_000);

    let transfer_from_args = default_transfer_from_args(from.0, to.0, 60_000);
    assert_eq!(
        send_transfer_from(&env, canister_id, spender.0, &transfer_from_args),
        Err(TransferFromError::InsufficientFunds {
            balance: Nat::from(50_000u32)
        })
    );
    assert_eq!(balance_of(&env, canister_id, from.0), 50_000);
    assert_eq!(balance_of(&env, canister_id, from_sub_1), 50_000);
    assert_eq!(balance_of(&env, canister_id, to.0), 60_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);

    let transfer_from_args = default_transfer_from_args(from_sub_1, to.0, 10_000);
    assert_eq!(
        send_transfer_from(&env, canister_id, spender.0, &transfer_from_args),
        Err(TransferFromError::InsufficientAllowance {
            allowance: Nat::from(10_000u32)
        })
    );
    assert_eq!(balance_of(&env, canister_id, from.0), 50_000);
    assert_eq!(balance_of(&env, canister_id, from_sub_1), 50_000);
    assert_eq!(balance_of(&env, canister_id, to.0), 60_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_transfer_from_self<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let to = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000)],
    );

    let transfer_from_args = default_transfer_from_args(from.0, to.0, 30_000);
    let block_index = send_transfer_from(&env, canister_id, from.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(block_index, 1);
    assert_eq!(balance_of(&env, canister_id, from.0), 60_000);
    assert_eq!(balance_of(&env, canister_id, to.0), 30_000);
}

pub fn test_transfer_from_minter<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let spender = PrincipalId::new_user_test_id(2);
    let to = PrincipalId::new_user_test_id(3);

    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);

    let minter = minting_account(&env, canister_id).unwrap();

    let mut transfer_from_args = default_transfer_from_args(minter, to.0, 30_000);
    transfer_from_args.fee = None;

    let err = env
        .execute_ingress_as(
            spender,
            canister_id,
            "icrc2_transfer_from",
            Encode!(&transfer_from_args).unwrap(),
        )
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterCalledTrap,
        "the minter account cannot delegate mints",
    );
    assert_eq!(balance_of(&env, canister_id, to.0), 0);
}

pub fn test_transfer_from_burn<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let from = PrincipalId::new_user_test_id(1);
    let spender = PrincipalId::new_user_test_id(2);

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(from.0), 100_000)],
    );

    let minter = minting_account(&env, canister_id).unwrap();

    let mut transfer_from_args = default_transfer_from_args(from.0, minter, 30_000);
    transfer_from_args.fee = None;
    assert_eq!(
        send_transfer_from(&env, canister_id, spender.0, &transfer_from_args),
        Err(TransferFromError::InsufficientAllowance {
            allowance: Nat::from(0_u8)
        })
    );
    assert_eq!(balance_of(&env, canister_id, from.0), 100_000);

    let approve_args = default_approve_args(spender.0, 150_000);
    send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    let block_index = send_transfer_from(&env, canister_id, spender.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(block_index, 2);
    assert_eq!(balance_of(&env, canister_id, from.0), 60_000);
    assert_eq!(total_supply(&env, canister_id), 60_000);
}

pub fn test_icrc1_test_suite<T: candid::CandidType>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) {
    use anyhow::Context;
    use async_trait::async_trait;
    use candid::utils::{ArgumentDecoder, ArgumentEncoder, decode_args, encode_args};
    use futures::FutureExt;
    use icrc1_test_env::LedgerEnv;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Clone)]
    pub struct SMLedger {
        counter: Arc<AtomicU64>,
        sm: Arc<StateMachine>,
        sender: Principal,
        canister_id: Principal,
    }

    impl SMLedger {
        fn parse_ledger_response<Output>(
            &self,
            res: WasmResult,
            method: &str,
        ) -> anyhow::Result<Output>
        where
            Output: for<'a> ArgumentDecoder<'a>,
        {
            match res {
                WasmResult::Reply(bytes) => decode_args(&bytes).with_context(|| {
                    format!(
                        "Failed to decode method {} response into type {}, bytes: {}",
                        method,
                        std::any::type_name::<Output>(),
                        hex::encode(bytes)
                    )
                }),
                WasmResult::Reject(msg) => Err(anyhow::Error::msg(format!(
                    "Ledger {} rejected the {method} call: {}",
                    self.canister_id, msg
                ))),
            }
        }
    }

    #[async_trait(?Send)]
    impl LedgerEnv for SMLedger {
        fn fork(&self) -> Self {
            Self {
                counter: self.counter.clone(),
                sm: self.sm.clone(),
                sender: PrincipalId::new_user_test_id(self.counter.fetch_add(1, Ordering::Relaxed))
                    .0,
                canister_id: self.canister_id,
            }
        }

        fn principal(&self) -> Principal {
            self.sender
        }

        fn time(&self) -> std::time::SystemTime {
            self.sm.time()
        }

        async fn query<Input, Output>(&self, method: &str, input: Input) -> anyhow::Result<Output>
        where
            Input: ArgumentEncoder + std::fmt::Debug,
            Output: for<'a> ArgumentDecoder<'a>,
        {
            let debug_inputs = format!("{input:?}");
            let in_bytes = encode_args(input)
                .with_context(|| format!("Failed to encode arguments {debug_inputs}"))?;
            self.parse_ledger_response(
                self.sm
                    .query_as(
                        ic_base_types::PrincipalId(self.sender),
                        ic_base_types::CanisterId::try_from(ic_base_types::PrincipalId(
                            self.canister_id,
                        ))
                        .unwrap(),
                        method,
                        in_bytes,
                    )
                    .map_err(|err| anyhow::Error::msg(err.to_string()))
                    .with_context(|| {
                        format!(
                            "failed to execute query call {} on canister {}",
                            method, self.canister_id
                        )
                    })?,
                method,
            )
        }

        async fn update<Input, Output>(&self, method: &str, input: Input) -> anyhow::Result<Output>
        where
            Input: ArgumentEncoder + std::fmt::Debug,
            Output: for<'a> ArgumentDecoder<'a>,
        {
            let debug_inputs = format!("{input:?}");
            let in_bytes = encode_args(input)
                .with_context(|| format!("Failed to encode arguments {debug_inputs}"))?;
            self.parse_ledger_response(
                self.sm
                    .execute_ingress_as(
                        ic_base_types::PrincipalId(self.sender),
                        ic_base_types::CanisterId::try_from(ic_base_types::PrincipalId(
                            self.canister_id,
                        ))
                        .unwrap(),
                        method,
                        in_bytes,
                    )
                    .map_err(|err| anyhow::Error::msg(err.to_string()))
                    .with_context(|| {
                        format!(
                            "failed to execute update call {} on canister {}",
                            method, self.canister_id
                        )
                    })?,
                method,
            )
        }
    }

    let test_acc = PrincipalId::new_user_test_id(1);
    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![(Account::from(test_acc.0), 100_000_000)],
    );
    let ledger_env = SMLedger {
        counter: Arc::new(AtomicU64::new(10)),
        sm: env.into(),
        sender: test_acc.0,
        canister_id: canister_id.into(),
    };

    let tests = icrc1_test_suite::test_suite(ledger_env)
        .now_or_never()
        .unwrap();

    if !icrc1_test_suite::execute_tests(tests)
        .now_or_never()
        .unwrap()
    {
        panic!("The ICRC-1 test suite failed");
    }
}

pub fn convert_to_fields_args(args: &ConsentMessageRequest) -> ConsentMessageRequest {
    let mut fields_args = args.clone();
    fields_args.user_preferences.device_spec = Some(DisplayMessageType::FieldsDisplay);
    fields_args
}

pub fn modify_field(
    fields_message: &FieldsDisplay,
    field_name: String,
    new_value: Option<Icrc21Value>,
) -> FieldsDisplay {
    let mut result = FieldsDisplay {
        intent: fields_message.intent.clone(),
        ..Default::default()
    };
    for (f_name, f_value) in &fields_message.fields {
        if *f_name == field_name {
            if new_value.is_some() {
                result
                    .fields
                    .push((f_name.to_string(), new_value.clone().unwrap().clone()));
            }
        } else {
            result.fields.push((f_name.to_string(), f_value.clone()));
        }
    }
    result
}

fn test_icrc21_transfer_message(
    env: &StateMachine,
    canister_id: CanisterId,
    from_account: Account,
    receiver_account: Account,
) {
    let transfer_args = TransferArg {
        from_subaccount: from_account.subaccount,
        to: receiver_account,
        fee: None,
        amount: Nat::from(1_000_000u32),
        created_at_time: Some(system_time_to_nanos(env.time())),
        memo: Some(Memo::from(b"test_bytes".to_vec())),
    };

    // We check that the GenericDisplay message is created correctly.
    let mut args = ConsentMessageRequest {
        method: "icrc1_transfer".to_owned(),
        arg: Encode!(&transfer_args).unwrap(),
        user_preferences: ConsentMessageSpec {
            metadata: ConsentMessageMetadata {
                language: "en".to_string(),
                utc_offset_minutes: Some(60),
            },
            device_spec: Some(DisplayMessageType::GenericDisplay),
        },
    };

    let expected_transfer_message = "# Send Test Token

You are approving a transfer of funds from your account.

**From:**
`d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101`

**Amount:** `0.01 XTST`

**To:**
`6fyp7-3ibaa-aaaaa-aaaap-4ai-v57emui.202020202020202020202020202020202020202020202020202020202020202`

**Fees:** `0.0001 XTST`
Charged for processing the transfer.

**Memo:**
`test_bytes`";

    let expected_fields_message = FieldsDisplay {
        intent: "Send Test Token".to_string(),
        fields: vec![
            ("From".to_string(), Icrc21Value::Text{content: "d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101".to_string()}),
            ("Amount".to_string(),  Icrc21Value::TokenAmount {decimals: 8, amount: 1000000, symbol: "XTST".to_string()}), // "0.01 XTST".to_string()),
            ("To".to_string(), Icrc21Value::Text{content: "6fyp7-3ibaa-aaaaa-aaaap-4ai-v57emui.202020202020202020202020202020202020202020202020202020202020202".to_string()}),
            ("Fees".to_string(), Icrc21Value::TokenAmount {decimals: 8, amount: 10000, symbol: "XTST".to_string()}),
            ("Memo".to_string(), Icrc21Value::Text{content: "test_bytes".to_string()})],
    };

    let consent_info =
        icrc21_consent_message(env, canister_id, from_account.owner, args.clone()).unwrap();
    assert_eq!(consent_info.metadata.language, "en");
    assert!(matches!(
        consent_info.consent_message,
        ConsentMessage::GenericDisplayMessage { .. }
    ));
    let message = extract_icrc21_message_string(&consent_info.consent_message);
    assert_eq!(
        message, expected_transfer_message,
        "Expected: {expected_transfer_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    assert_eq!(
        fields_message, expected_fields_message,
        "Expected: {expected_fields_message:?}, got: {fields_message:?}"
    );

    // Make sure the accounts are formatted correctly.
    assert_eq!(
        from_account.to_string(),
        "d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101"
    );
    assert_eq!(
        receiver_account.to_string(),
        "6fyp7-3ibaa-aaaaa-aaaap-4ai-v57emui.202020202020202020202020202020202020202020202020202020202020202"
    );
    // If we do not set the Memo we expect it to not be included in the resulting message.
    args.arg = Encode!(&TransferArg {
        memo: None,
        ..transfer_args.clone()
    })
    .unwrap();
    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, from_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );
    let expected_message = expected_transfer_message.replace("\n\n**Memo:**\n`test_bytes`", "");
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message = modify_field(&expected_fields_message, "Memo".to_string(), None);
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );

    // If the memo is not a valid UTF string, it should be hex encoded.
    args.arg = Encode!(&TransferArg {
        memo: Some(vec![0, 159, 146, 150].into()),
        ..transfer_args.clone()
    })
    .unwrap();
    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, from_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );
    let expected_message =
        expected_transfer_message.replace("test_bytes", &hex::encode(vec![0, 159, 146, 150]));
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message = modify_field(
        &expected_fields_message,
        "Memo".to_string(),
        Some(Icrc21Value::Text {
            content: hex::encode(vec![0, 159, 146, 150]),
        }),
    );
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );

    // If the from account is anonymous, the message should not include the account information.
    args.arg = Encode!(&transfer_args.clone()).unwrap();
    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, Principal::anonymous(), args.clone())
            .unwrap()
            .consent_message,
    );
    let expected_message = expected_transfer_message.replace("\n\n**From:**\n`d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101`","" );
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        Principal::anonymous(),
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message = modify_field(&expected_fields_message, "From".to_string(), None);
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );
}

fn test_icrc21_approve_message(
    env: &StateMachine,
    canister_id: CanisterId,
    from_account: Account,
    spender_account: Account,
) {
    let message = &icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        ConsentMessageRequest {
            method: "INVALID_FUNCTION".to_owned(),
            arg: Encode!(&()).unwrap(),
            user_preferences: ConsentMessageSpec {
                metadata: ConsentMessageMetadata {
                    language: "en".to_string(),
                    utc_offset_minutes: None,
                },
                device_spec: Some(DisplayMessageType::GenericDisplay),
            },
        },
    )
    .unwrap_err();
    match message {
        Icrc21Error::UnsupportedCanisterCall(ErrorInfo { description }) => {
            assert!(description.contains("The function provided is not supported: INVALID_FUNCTION.\n Supported functions for ICRC-21 are: [\"icrc1_transfer\", \"icrc2_approve\", \"icrc2_transfer_from\", \"transfer\"].\n Error is: VariantNotFound"),"Unexpected Error message: {description}")
        }
        _ => panic!("Unexpected error: {message:?}"),
    }

    // Test the message for icrc2 approve
    let approve_args = ApproveArgs {
        spender: spender_account,
        amount: Nat::from(1_000_000u32),
        from_subaccount: from_account.subaccount,
        expires_at: Some(
            system_time_to_nanos(env.time()) + Duration::from_secs(3600).as_nanos() as u64,
        ),
        expected_allowance: Some(Nat::from(1_000_000u32)),
        created_at_time: Some(system_time_to_nanos(env.time())),
        fee: Some(Nat::from(FEE)),
        memo: Some(Memo::from(b"test_bytes".to_vec())),
    };
    assert_eq!(
        spender_account.to_string(),
        "djduj-3qcaa-aaaaa-aaaap-4ai-5r7aoqy.303030303030303030303030303030303030303030303030303030303030303"
    );
    let expected_approve_message = "# Approve spending

You are authorizing another address to withdraw funds from your account.

**From:**
`d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101`

**Approve to spender:**
`djduj-3qcaa-aaaaa-aaaap-4ai-5r7aoqy.303030303030303030303030303030303030303030303030303030303030303`

**Requested allowance:** `0.01 XTST`
This is the withdrawal limit that will apply upon approval.

**Existing allowance:** `0.01 XTST`
Until approval, this allowance remains in effect.

**Approval expiration:**
Thu, 06 May 2021 20:17:10 +0000

**Approval fees:** `0.0001 XTST`
Charged for processing the approval.

**Fees paid by:**
`d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101`

**Memo:**
`test_bytes`";

    let expected_fields_message = FieldsDisplay {
        intent: "Approve spending".to_string(),
        fields: vec![
            ("From".to_string(), Icrc21Value::Text{content: "d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101".to_string()}),
            ("Approve to spender".to_string(), Icrc21Value::Text{content: "djduj-3qcaa-aaaaa-aaaap-4ai-5r7aoqy.303030303030303030303030303030303030303030303030303030303030303".to_string()}),
            ("Requested allowance".to_string(), Icrc21Value::TokenAmount {decimals: 8, amount: 1000000, symbol: "XTST".to_string()}),
            ("Existing allowance".to_string(), Icrc21Value::TokenAmount {decimals: 8, amount: 1000000, symbol: "XTST".to_string()}),
            ("Approval expiration".to_string(), Icrc21Value::TimestampSeconds { amount: 1620332230 }),
            ("Approval fees".to_string(), Icrc21Value::TokenAmount {decimals: 8, amount: 10000, symbol: "XTST".to_string()}),
            ("Fees paid by".to_string(), Icrc21Value::Text{content: "d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101".to_string()}),
            ("Memo".to_string(), Icrc21Value::Text{content: "test_bytes".to_string()})]};

    let mut args = ConsentMessageRequest {
        method: "icrc2_approve".to_owned(),
        arg: Encode!(&approve_args).unwrap(),
        user_preferences: ConsentMessageSpec {
            metadata: ConsentMessageMetadata {
                language: "en".to_string(),
                utc_offset_minutes: None,
            },
            device_spec: Some(DisplayMessageType::GenericDisplay),
        },
    };
    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, from_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );
    assert_eq!(
        message, expected_approve_message,
        "Expected: {expected_approve_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    assert_eq!(
        fields_message, expected_fields_message,
        "Expected: {expected_fields_message:?}, got: {fields_message:?}"
    );

    args.arg = Encode!(&ApproveArgs {
        expected_allowance: None,
        ..approve_args.clone()
    })
    .unwrap();
    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, from_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );
    // When the expected allowance is not set, it should be skipped.
    let expected_message =
        expected_approve_message.replace("\n\n**Existing allowance:** `0.01 XTST`\nUntil approval, this allowance remains in effect.", "");
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message = modify_field(
        &expected_fields_message,
        "Existing allowance".to_string(),
        None,
    );
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );

    // Test approval without an expiration.
    args.arg = Encode!(&ApproveArgs {
        expires_at: None,
        ..approve_args.clone()
    })
    .unwrap();

    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, from_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );
    let expected_message = expected_approve_message.replace(
        "Thu, 06 May 2021 20:17:10 +0000",
        "This approval does not have an expiration.",
    );
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message = modify_field(
        &expected_fields_message,
        "Approval expiration".to_string(),
        Some(Icrc21Value::Text {
            content: "This approval does not have an expiration.".to_string(),
        }),
    );
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );

    // If the approver is anonymous, the message should not include the approver information.
    args.arg = Encode!(&approve_args.clone()).unwrap();
    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, Principal::anonymous(), args.clone())
            .unwrap()
            .consent_message,
    );
    let expected_message = expected_approve_message
        .replace("\n\n**Fees paid by:**\n`d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101`","" )
        .replace("\n\n**From:**\n`d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101`","");
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        Principal::anonymous(),
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message = modify_field(&expected_fields_message, "From".to_string(), None);
    let new_exp_fields_message =
        modify_field(&new_exp_fields_message, "Fees paid by".to_string(), None);
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );

    // If we set the offset to 1 hour the expiration date should be 1 hour ahead.
    args.user_preferences.metadata.utc_offset_minutes = Some(60);
    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, from_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );
    let expected_message = expected_approve_message.replace(
        "Thu, 06 May 2021 20:17:10 +0000",
        "Thu, 06 May 2021 21:17:10 +0100",
    );
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    assert_eq!(
        fields_message, expected_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );
    args.user_preferences.metadata.utc_offset_minutes = None;

    // If memo is not specified it should not be included.
    args.arg = Encode!(&ApproveArgs {
        memo: None,
        ..approve_args.clone()
    })
    .unwrap();

    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, from_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );

    let expected_message = expected_approve_message.replace("\n\n**Memo:**\n`test_bytes`", "");
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        from_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message = modify_field(&expected_fields_message, "Memo".to_string(), None);
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );
}

fn test_icrc21_transfer_from_message(
    env: &StateMachine,
    canister_id: CanisterId,
    from_account: Account,
    spender_account: Account,
    receiver_account: Account,
) {
    // Test the message for icrc2 transfer_from
    let transfer_from_args = TransferFromArgs {
        from: from_account,
        spender_subaccount: spender_account.subaccount,
        to: receiver_account,
        amount: Nat::from(1_000_000u32),
        fee: None,
        created_at_time: None,
        memo: Some(Memo::from(b"test_bytes".to_vec())),
    };

    let mut args = ConsentMessageRequest {
        method: "icrc2_transfer_from".to_owned(),
        arg: Encode!(&transfer_from_args).unwrap(),
        user_preferences: ConsentMessageSpec {
            metadata: ConsentMessageMetadata {
                language: "en".to_string(),
                utc_offset_minutes: None,
            },
            device_spec: Some(DisplayMessageType::GenericDisplay),
        },
    };

    let expected_transfer_from_message = "# Spend Test Token

You are approving a transfer of funds from a withdrawal account.

**From:**
`d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101`

**Amount:** `0.01 XTST`

**Spender:**
`djduj-3qcaa-aaaaa-aaaap-4ai-5r7aoqy.303030303030303030303030303030303030303030303030303030303030303`

**To:**
`6fyp7-3ibaa-aaaaa-aaaap-4ai-v57emui.202020202020202020202020202020202020202020202020202020202020202`

**Fees:** `0.0001 XTST`
Charged for processing the transfer.

**Memo:**
`test_bytes`";

    let expected_fields_message = FieldsDisplay {
        intent: "Spend Test Token".to_string(),
        fields: vec![
            ("From".to_string(), Icrc21Value::Text{content: "d2zjj-uyaaa-aaaaa-aaaap-4ai-qmfzyha.101010101010101010101010101010101010101010101010101010101010101".to_string()}),
            ("Amount".to_string(), Icrc21Value::TokenAmount {decimals: 8, amount: 1000000, symbol: "XTST".to_string()}),
            ("Spender".to_string(), Icrc21Value::Text{content: "djduj-3qcaa-aaaaa-aaaap-4ai-5r7aoqy.303030303030303030303030303030303030303030303030303030303030303".to_string()}),
            ("To".to_string(), Icrc21Value::Text{content: "6fyp7-3ibaa-aaaaa-aaaap-4ai-v57emui.202020202020202020202020202020202020202020202020202020202020202".to_string()}),
            ("Fees".to_string(), Icrc21Value::TokenAmount {decimals: 8, amount: 10000, symbol: "XTST".to_string()}),
            ("Memo".to_string(), Icrc21Value::Text{content: "test_bytes".to_string()})]};

    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, spender_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );
    assert_eq!(
        message, expected_transfer_from_message,
        "Expected: {expected_transfer_from_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        spender_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    assert_eq!(
        fields_message, expected_fields_message,
        "Expected: {expected_fields_message:?}, got: {fields_message:?}"
    );

    // If the spender is anonymous, the message should not include the spender account information.
    args.arg = Encode!(&transfer_from_args.clone()).unwrap();
    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, Principal::anonymous(), args.clone())
            .unwrap()
            .consent_message,
    );
    let expected_message = expected_transfer_from_message.replace(
        "\n\n**Spender:**\n`djduj-3qcaa-aaaaa-aaaap-4ai-5r7aoqy.303030303030303030303030303030303030303030303030303030303030303`",
        "",
    );
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        Principal::anonymous(),
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message =
        modify_field(&expected_fields_message, "Spender".to_string(), None);
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );

    // If memo is not specified it should not be included.
    args.arg = Encode!(&TransferFromArgs {
        memo: None,
        ..transfer_from_args.clone()
    })
    .unwrap();

    let message = extract_icrc21_message_string(
        &icrc21_consent_message(env, canister_id, spender_account.owner, args.clone())
            .unwrap()
            .consent_message,
    );

    let expected_message =
        expected_transfer_from_message.replace("\n\n**Memo:**\n`test_bytes`", "");
    assert_eq!(
        message, expected_message,
        "Expected: {expected_message}, got: {message}"
    );
    let fields_consent_info = icrc21_consent_message(
        env,
        canister_id,
        spender_account.owner,
        convert_to_fields_args(&args),
    )
    .unwrap();
    let fields_message = extract_icrc21_fields_message(&fields_consent_info.consent_message);
    let new_exp_fields_message = modify_field(&expected_fields_message, "Memo".to_string(), None);
    assert_eq!(
        fields_message, new_exp_fields_message,
        "Expected: {new_exp_fields_message:?}, got: {fields_message:?}"
    );
}

pub fn extract_icrc21_message_string(consent_message: &ConsentMessage) -> String {
    match consent_message {
        ConsentMessage::GenericDisplayMessage(message) => message.to_string(),
        ConsentMessage::FieldsDisplayMessage(_) => panic!("cannot convert to string"),
    }
}

pub fn extract_icrc21_fields_message(consent_message: &ConsentMessage) -> FieldsDisplay {
    match consent_message {
        ConsentMessage::GenericDisplayMessage(_) => panic!("should not be a string"),
        ConsentMessage::FieldsDisplayMessage(message) => message.clone(),
    }
}

pub fn test_icrc21_standard<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);
    let receiver_account = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: Some([2; 32]),
    };
    let from_account = Account {
        owner: PrincipalId::new_user_test_id(0).0,
        subaccount: Some([1; 32]),
    };
    let spender_account = Account {
        owner: PrincipalId::new_user_test_id(2).0,
        subaccount: Some([3; 32]),
    };

    test_icrc21_transfer_message(&env, canister_id, from_account, receiver_account);
    test_icrc21_approve_message(&env, canister_id, from_account, spender_account);
    test_icrc21_transfer_from_message(
        &env,
        canister_id,
        from_account,
        spender_account,
        receiver_account,
    );
}

pub fn test_icrc21_fee_error<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);
    let account = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: Some([2; 32]),
    };

    let transfer_args = TransferArg {
        from_subaccount: None,
        to: account,
        fee: Some(Nat::from(1u64)),
        amount: Nat::from(1_000_000u32),
        created_at_time: None,
        memo: None,
    };

    let mut args = ConsentMessageRequest {
        method: "icrc1_transfer".to_owned(),
        arg: Encode!(&transfer_args).unwrap(),
        user_preferences: ConsentMessageSpec {
            metadata: ConsentMessageMetadata {
                language: "en".to_string(),
                utc_offset_minutes: Some(60),
            },
            device_spec: Some(DisplayMessageType::GenericDisplay),
        },
    };

    let mut errors = vec![];
    let error = icrc21_consent_message(&env, canister_id, Principal::anonymous(), args.clone())
        .unwrap_err();
    errors.push(error);

    let approve_args = ApproveArgs {
        spender: account,
        amount: Nat::from(1_000_000u32),
        from_subaccount: None,
        expires_at: None,
        expected_allowance: None,
        created_at_time: None,
        fee: Some(Nat::from(1u64)),
        memo: None,
    };
    args.arg = Encode!(&approve_args).unwrap();
    args.method = "icrc2_approve".to_owned();
    let error = icrc21_consent_message(&env, canister_id, Principal::anonymous(), args.clone())
        .unwrap_err();
    errors.push(error);

    let transfer_from_args = TransferFromArgs {
        from: account,
        spender_subaccount: None,
        to: account,
        amount: Nat::from(1_000_000u32),
        fee: Some(Nat::from(1u64)),
        created_at_time: None,
        memo: None,
    };
    args.arg = Encode!(&transfer_from_args).unwrap();
    args.method = "icrc2_transfer_from".to_owned();
    let error = icrc21_consent_message(&env, canister_id, Principal::anonymous(), args.clone())
        .unwrap_err();
    errors.push(error);

    for error in errors {
        assert_eq!(
        error,
        Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description:
                "The fee specified in the arguments (1) is different than the ledger fee (10_000)"
                    .to_string()
        })
    )
    }
}

pub fn test_cycles_for_archive_creation_no_overwrite_of_none_in_upgrade<T>(
    ledger_wasm_pre_default_set: Vec<u8>,
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let account = Account::from(PrincipalId::new_user_test_id(1).0);
    let initial_balances = vec![(account, 100_000_000u64)];

    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config.clone(),
        HypervisorConfig::default(),
    ));

    // Initialization arguments with cycles_for_archive_creation set to None in archive_options.
    // The default in this older ledger version is 0.
    let args_with_null_cycles = InitArgs {
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        ..init_args(initial_balances)
    };

    let args = encode_init_args(args_with_null_cycles);
    let args = Encode!(&args).unwrap();
    let canister_id = env
        .install_canister_with_cycles(
            ledger_wasm_pre_default_set,
            args,
            None,
            Cycles::new(100_000_000_000_000),
        )
        .unwrap();

    const TRANSFER_AMOUNT: u64 = 100;

    let send_transfers = || {
        for i in 2..2 + ARCHIVE_TRIGGER_THRESHOLD {
            let to = Account::from(PrincipalId::new_user_test_id(i).0);
            transfer(&env, canister_id, account, to, TRANSFER_AMOUNT + i)
                .expect("failed to transfer funds");
        }
    };

    // Send enough transfers that should trigger an archive creation based on
    // ARCHIVE_TRIGGER_THRESHOLD.
    send_transfers();

    // Verify that no archive was spawned since the value used for cycles_for_archive_creation is 0.
    let archives = list_archives(&env, canister_id);
    assert!(archives.is_empty());

    // Upgrade the canister to the latest master version.
    env.upgrade_canister(
        canister_id,
        ledger_wasm,
        Encode!(&LedgerArgument::Upgrade(None)).unwrap(),
    )
    .unwrap();

    send_transfers();

    // Verify that no archive was spawned, since even though the default for
    // cycles_for_archive_creation is set to a non-zero value, it does not overwrite the initial
    // default that was set to 0 on ledger creation.
    let archives = list_archives(&env, canister_id);
    assert!(archives.is_empty());
}

pub fn test_cycles_for_archive_creation_default_spawns_archive<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let account = Account::from(PrincipalId::new_user_test_id(1).0);
    let initial_balances = vec![(account, 100_000_000u64)];

    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config.clone(),
        HypervisorConfig::default(),
    ));

    // Ledger initialization arguments with cycles_for_archive_creation set to None in archive_options.
    let args_with_null_cycles = InitArgs {
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE as usize,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId::new_user_test_id(100),
            more_controller_ids: None,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        ..init_args(initial_balances)
    };

    let args = encode_init_args(args_with_null_cycles);
    let args = Encode!(&args).unwrap();
    let canister_id = env
        .install_canister_with_cycles(ledger_wasm, args, None, Cycles::new(100_000_000_000_000))
        .unwrap();

    const TRANSFER_AMOUNT: u64 = 100;

    let send_transfers = || {
        for i in 2..2 + (ARCHIVE_TRIGGER_THRESHOLD * 2) {
            let to = Account::from(PrincipalId::new_user_test_id(i).0);
            transfer(&env, canister_id, account, to, TRANSFER_AMOUNT + i)
                .expect("failed to transfer funds");
        }
    };

    // Send enough transfers that should trigger an archive creation.
    send_transfers();

    // The non-zero default value for cycles_for_archive_creation was applied, so an archive should
    // have been successfully spawned.
    let archives = list_archives(&env, canister_id);
    assert_eq!(archives.len(), 1);
}

pub mod metadata {
    use super::*;

    const METADATA_DECIMALS: &str = "icrc1:decimals";
    const METADATA_NAME: &str = "icrc1:name";
    const METADATA_SYMBOL: &str = "icrc1:symbol";
    const METADATA_FEE: &str = "icrc1:fee";
    const METADATA_MAX_MEMO_LENGTH: &str = "icrc1:max_memo_length";
    const FORBIDDEN_METADATA: [&str; 5] = [
        METADATA_DECIMALS,
        METADATA_NAME,
        METADATA_SYMBOL,
        METADATA_FEE,
        METADATA_MAX_MEMO_LENGTH,
    ];

    pub fn test_setting_forbidden_metadata_works_in_v3_ledger<T>(
        ledger_wasm_v3: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
    ) where
        T: CandidType,
    {
        let env = StateMachine::new();

        let forbidden_metadata = vec![
            Value::entry(METADATA_DECIMALS, 8u64),
            Value::entry(METADATA_NAME, "BogusName"),
            Value::entry(METADATA_SYMBOL, "BN"),
            Value::entry(METADATA_FEE, Nat::from(10_000u64)),
            Value::entry(METADATA_MAX_MEMO_LENGTH, 8u64),
        ];

        let args = encode_init_args(InitArgs {
            metadata: forbidden_metadata.clone(),
            ..init_args(vec![])
        });
        let args = Encode!(&args).unwrap();
        let canister_id = env
            .install_canister(ledger_wasm_v3.clone(), args, None)
            .unwrap();

        let verify_duplicate_metadata = || {
            let metadata = Decode!(
                &env.query(canister_id, "icrc1_metadata", Encode!().unwrap())
                    .expect("failed to query metadata")
                    .bytes(),
                Vec<(String, Value)>
            )
            .expect("failed to decode metadata response");

            let mut key_counts = HashMap::new();

            for (k, _v) in metadata.iter() {
                key_counts
                    .entry(k.clone())
                    .and_modify(|counter| *counter += 1)
                    .or_insert(1);
            }

            // The forbidden metadata should be present twice - one instance from the init args, and
            // one dynamically set by the ledger based on its internal state.
            for forbidden_metadata in FORBIDDEN_METADATA.iter() {
                assert_eq!(key_counts.get(*forbidden_metadata), Some(&2));
            }
        };

        verify_duplicate_metadata();

        let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs {
            metadata: Some(forbidden_metadata),
            ..UpgradeArgs::default()
        }));
        env.upgrade_canister(
            canister_id,
            ledger_wasm_v3,
            Encode!(&ledger_upgrade_arg).unwrap(),
        )
        .unwrap();

        verify_duplicate_metadata();
    }

    pub fn test_setting_forbidden_metadata_not_possible<T>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
    ) where
        T: CandidType,
    {
        let env = StateMachine::new();

        // Verify that specifying any of the forbidden metadata in the init args is not possible.
        for forbidden_metadata in FORBIDDEN_METADATA.iter() {
            let args = encode_init_args(InitArgs {
                metadata: vec![Value::entry(*forbidden_metadata, 8u64)],
                ..init_args(vec![])
            });
            let args = Encode!(&args).unwrap();
            match env.install_canister(ledger_wasm.clone(), args, None) {
                Ok(_) => {
                    panic!("should not be able to install ledger with forbidden metadata")
                }
                Err(err) => {
                    err.assert_contains(
                        ErrorCode::CanisterCalledTrap,
                        "is reserved and cannot be set",
                    );
                }
            }
        }

        let args = encode_init_args(init_args(vec![]));
        let args = Encode!(&args).unwrap();
        let canister_id = env
            .install_canister(ledger_wasm.clone(), args, None)
            .expect("should successfully install ledger without forbidden metadata");

        // Verify that also upgrading does not accept the forbidden metadata
        for forbidden_metadata in FORBIDDEN_METADATA.iter() {
            let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs {
                metadata: Some(vec![Value::entry(*forbidden_metadata, 8u64)]),
                ..UpgradeArgs::default()
            }));
            match env.upgrade_canister(
                canister_id,
                ledger_wasm.clone(),
                Encode!(&ledger_upgrade_arg).unwrap(),
            ) {
                Ok(_) => {
                    panic!("should not be able to upgrade ledger with forbidden metadata")
                }
                Err(err) => {
                    err.assert_contains(
                        ErrorCode::CanisterCalledTrap,
                        "is reserved and cannot be set",
                    );
                }
            }
        }

        let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs::default()));
        env.upgrade_canister(
            canister_id,
            ledger_wasm.clone(),
            Encode!(&ledger_upgrade_arg).unwrap(),
        )
        .expect("should successfully upgrade the ledger");
    }
}

pub mod archiving {
    use super::*;
    use ic_ledger_canister_core::archive::DEFAULT_CYCLES_FOR_ARCHIVE_CREATION;
    use ic_ledger_canister_core::ledger::MAX_BLOCKS_TO_ARCHIVE;
    use ic_ledger_canister_core::range_utils;
    use ic_ledger_suite_state_machine_helpers::{get_logs, icrc3_get_blocks};
    use ic_state_machine_tests::StateMachineBuilder;
    use ic_types::ingress::{IngressState, IngressStatus};
    use ic_types::messages::MessageId;
    use icp_ledger::{GetEncodedBlocksResult, QueryEncodedBlocksResponse};
    use icrc_ledger_types::icrc1::transfer::NumTokens;
    use icrc_ledger_types::icrc3::blocks::BlockWithId;
    use std::cmp::Ordering;
    use std::fmt::Debug;
    use std::ops::Range;
    // ----- Tests -----

    /// Verify that archiving fails if the ledger does not have enough cycles to spawn the archive.
    pub fn test_archiving_fails_on_app_subnet_if_ledger_does_not_have_enough_cycles<T, B>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
        get_archives: fn(&StateMachine, CanisterId) -> Vec<Principal>,
        get_blocks_fn: fn(&StateMachine, CanisterId, u64, usize) -> GenericGetBlocksResponse<B>,
    ) where
        T: CandidType,
        B: Eq + Debug,
    {
        const NUM_BLOCKS_TO_ARCHIVE: usize = 1_000;
        const NUM_INITIAL_BALANCES: u64 = 70_000;
        const TRIGGER_THRESHOLD: usize = 2_000;
        let p1 = PrincipalId::new_user_test_id(1);
        let p2 = PrincipalId::new_user_test_id(2);
        let archive_controller = PrincipalId::new_user_test_id(1_000_000);
        let mut initial_balances = vec![];
        for i in 0..NUM_INITIAL_BALANCES {
            initial_balances.push((
                Account::from(PrincipalId::new_user_test_id(i).0),
                10_000_000,
            ));
        }

        let env = StateMachineBuilder::new()
            .with_subnet_type(SubnetType::Application)
            .build();
        let args = encode_init_args(InitArgs {
            archive_options: ArchiveOptions {
                trigger_threshold: TRIGGER_THRESHOLD,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: archive_controller,
                more_controller_ids: None,
                cycles_for_archive_creation: Some(
                    ic_ledger_canister_core::archive::DEFAULT_CYCLES_FOR_ARCHIVE_CREATION,
                ),
                max_transactions_per_response: None,
            },
            ..init_args(initial_balances)
        });
        let args = Encode!(&args).unwrap();
        let ledger_id = env
            .install_canister_with_cycles(
                ledger_wasm.clone(),
                args,
                None,
                Cycles::new((0.9 * DEFAULT_CYCLES_FOR_ARCHIVE_CREATION as f64) as u128),
            )
            .unwrap();

        // Assert no archives exist.
        assert!(get_archives(&env, ledger_id).is_empty());
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert_eq!(get_blocks_res.chain_length, NUM_INITIAL_BALANCES);
        // Verify that the ledger response contained no archive info.
        assert!(get_blocks_res.archived_ranges.is_empty());
        // Verify that the archiving failure metric is zero.
        assert_archiving_failure_metric(&env, ledger_id, 0u64);

        // Send a transfer that should trigger an attempt to spawn an archive.
        send_transfer(
            &env,
            ledger_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: p2.0.into(),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(10_000u64),
            },
        )
        .expect("transfer should succeed");

        // Assert no archives exist, as the spawning failed.
        assert!(get_archives(&env, ledger_id).is_empty());
        // Verify that no new block was created, since the transfer failed (the ledger panicked).
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert_eq!(get_blocks_res.chain_length, NUM_INITIAL_BALANCES + 1);
        // Verify that the ledger response contained no archive info.
        assert!(get_blocks_res.archived_ranges.is_empty());
        // Verify that the archiving failure metric was incremented.
        assert_archiving_failure_metric(&env, ledger_id, 1u64);
    }

    /// Verify that archiving succeeds on a system subnet even if the ledger does not have any cycles.
    pub fn test_archiving_succeeds_on_system_subnet_if_ledger_does_not_have_any_cycles<T, B>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
        get_archives: fn(&StateMachine, CanisterId) -> Vec<Principal>,
        get_blocks_fn: fn(&StateMachine, CanisterId, u64, usize) -> GenericGetBlocksResponse<B>,
    ) where
        T: CandidType,
        B: Eq + Debug,
    {
        const NUM_BLOCKS_TO_ARCHIVE: usize = 1_000;
        const NUM_INITIAL_BALANCES: u64 = 70_000;
        const TRIGGER_THRESHOLD: usize = 2_000;
        let p1 = PrincipalId::new_user_test_id(1);
        let p2 = PrincipalId::new_user_test_id(2);
        let archive_controller = PrincipalId::new_user_test_id(1_000_000);
        let mut initial_balances = vec![];
        for i in 0..NUM_INITIAL_BALANCES {
            initial_balances.push((
                Account::from(PrincipalId::new_user_test_id(i).0),
                10_000_000,
            ));
        }

        let env = StateMachine::new();
        let args = encode_init_args(InitArgs {
            archive_options: ArchiveOptions {
                trigger_threshold: TRIGGER_THRESHOLD,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: archive_controller,
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            ..init_args(initial_balances)
        });
        let args = Encode!(&args).unwrap();
        let ledger_id = env
            .install_canister(ledger_wasm.clone(), args, None)
            .unwrap();

        // Assert no archives exist.
        assert!(get_archives(&env, ledger_id).is_empty());
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert_eq!(get_blocks_res.chain_length, NUM_INITIAL_BALANCES);
        // Verify that the ledger response contained no archive info.
        assert!(get_blocks_res.archived_ranges.is_empty());
        // Verify that the archiving failure metric is zero.
        assert_archiving_failure_metric(&env, ledger_id, 0u64);

        // Send a transfer that should trigger an attempt to spawn an archive.
        send_transfer(
            &env,
            ledger_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: p2.0.into(),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(10_000u64),
            },
        )
        .expect("transfer should succeed");

        // Assert an archive was spawned.
        assert!(!get_archives(&env, ledger_id).is_empty());
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert_eq!(get_blocks_res.chain_length, NUM_INITIAL_BALANCES + 1);
        // Verify that the ledger response contained archive info.
        assert!(!get_blocks_res.archived_ranges.is_empty());
        // Verify that the archiving failure metric is zero.
        assert_archiving_failure_metric(&env, ledger_id, 0u64);
    }

    /// Verify that archiving is skipped but transactions succeed on an application subnet if
    /// `cycles_to_create_archive` is less than the cost of creating a canister.
    pub fn test_archiving_skipped_if_cycles_to_create_archive_less_than_cost<T, B>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
        get_archives: fn(&StateMachine, CanisterId) -> Vec<Principal>,
        get_blocks_fn: fn(&StateMachine, CanisterId, u64, usize) -> GenericGetBlocksResponse<B>,
    ) where
        T: CandidType,
        B: Eq + Debug,
    {
        const NUM_BLOCKS_TO_ARCHIVE: usize = 1_000;
        const NUM_INITIAL_BALANCES: u64 = 70_000;
        const TRIGGER_THRESHOLD: usize = 2_000;
        const EXPECTED_CREATE_CANISTER_ERROR: &str = "only 0 cycles were provided";
        let p1 = PrincipalId::new_user_test_id(1);
        let p2 = PrincipalId::new_user_test_id(2);
        let archive_controller = PrincipalId::new_user_test_id(1_000_000);
        let mut initial_balances = vec![];
        for i in 0..NUM_INITIAL_BALANCES {
            initial_balances.push((
                Account::from(PrincipalId::new_user_test_id(i).0),
                10_000_000,
            ));
        }

        let env = StateMachineBuilder::new()
            .with_subnet_type(SubnetType::Application)
            .build();
        let args = encode_init_args(InitArgs {
            archive_options: ArchiveOptions {
                trigger_threshold: TRIGGER_THRESHOLD,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: archive_controller,
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            ..init_args(initial_balances)
        });
        let args = Encode!(&args).unwrap();
        let ledger_id = env
            .install_canister_with_cycles(
                ledger_wasm.clone(),
                args,
                None,
                Cycles::new(
                    DEFAULT_CYCLES_FOR_ARCHIVE_CREATION
                        .checked_mul(100)
                        .unwrap() as u128,
                ),
            )
            .unwrap();

        // Assert no archives exist.
        assert!(get_archives(&env, ledger_id).is_empty());
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert_eq!(get_blocks_res.chain_length, NUM_INITIAL_BALANCES);
        // Verify that the ledger response contained no archive info.
        assert!(get_blocks_res.archived_ranges.is_empty());
        // Verify that the archiving failure metric is zero.
        assert_archiving_failure_metric(&env, ledger_id, 0u64);

        // Send a transfer that should trigger an attempt to spawn an archive.
        send_transfer(
            &env,
            ledger_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: p2.0.into(),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(10_000u64),
            },
        )
        .expect("transfer should succeed");

        // Assert no archive was spawned.
        assert!(get_archives(&env, ledger_id).is_empty());
        // Verify that a new block was created.
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert_eq!(get_blocks_res.chain_length, NUM_INITIAL_BALANCES + 1);
        // Verify that the ledger response contained no archive info.
        assert!(get_blocks_res.archived_ranges.is_empty());
        // Verify that the expected create_canister error was logged.
        let logs = parse_ledger_logs(&get_logs(&env, ledger_id));
        let mut create_canister_error_found = false;
        println!("Ledger log entries found: {}", logs.entries.len());
        for entry in &logs.entries {
            let log_message = &entry.message;
            println!("Ledger log message: {}", log_message);
            if log_message.contains(EXPECTED_CREATE_CANISTER_ERROR) {
                create_canister_error_found = true;
                break;
            }
        }
        assert!(
            create_canister_error_found,
            "No error log message containing '{}' was found in {} ledger logs",
            EXPECTED_CREATE_CANISTER_ERROR,
            logs.entries.len()
        );
        // Verify that the archiving failure metric was incremented.
        assert_archiving_failure_metric(&env, ledger_id, 1u64);
    }

    /// Verify that archiving succeeds if the ledger has enough cycles to spawn the archive.
    pub fn test_archiving_succeeds_if_ledger_has_enough_cycles_to_attach<T, B>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
        get_archives: fn(&StateMachine, CanisterId) -> Vec<Principal>,
        get_blocks_fn: fn(&StateMachine, CanisterId, u64, usize) -> GenericGetBlocksResponse<B>,
    ) where
        T: CandidType,
        B: Eq + Debug,
    {
        const NUM_BLOCKS_TO_ARCHIVE: usize = 1_000;
        const NUM_INITIAL_BALANCES: u64 = 70_000;
        const TRIGGER_THRESHOLD: usize = 2_000;
        let p1 = PrincipalId::new_user_test_id(1);
        let p2 = PrincipalId::new_user_test_id(2);
        let archive_controller = PrincipalId::new_user_test_id(1_000_000);
        let mut initial_balances = vec![];
        for i in 0..NUM_INITIAL_BALANCES {
            initial_balances.push((
                Account::from(PrincipalId::new_user_test_id(i).0),
                10_000_000,
            ));
        }

        let env = StateMachine::new();
        let args = encode_init_args(InitArgs {
            archive_options: ArchiveOptions {
                trigger_threshold: TRIGGER_THRESHOLD,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: archive_controller,
                more_controller_ids: None,
                cycles_for_archive_creation: Some(
                    ic_ledger_canister_core::archive::DEFAULT_CYCLES_FOR_ARCHIVE_CREATION,
                ),
                max_transactions_per_response: None,
            },
            ..init_args(initial_balances)
        });
        let args = Encode!(&args).unwrap();
        let ledger_id = env
            .install_canister(ledger_wasm.clone(), args, None)
            .unwrap();
        env.add_cycles(
            ledger_id,
            DEFAULT_CYCLES_FOR_ARCHIVE_CREATION.checked_mul(10).unwrap() as u128,
        );

        // Assert no archives exist.
        assert!(get_archives(&env, ledger_id).is_empty());
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert_eq!(get_blocks_res.chain_length, NUM_INITIAL_BALANCES);
        // Verify that the ledger response contained no archive info.
        assert!(get_blocks_res.archived_ranges.is_empty());
        // Verify that the archiving failure metric is zero.
        assert_archiving_failure_metric(&env, ledger_id, 0u64);

        // Send a transfer that should trigger spawning of an archive.
        send_transfer(
            &env,
            ledger_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: p2.0.into(),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(10_000u64),
            },
        )
        .expect("transfer should succeed");

        // Assert an archive was spawned.
        assert!(!get_archives(&env, ledger_id).is_empty());
        // Verify that a new block was created.
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert_eq!(get_blocks_res.chain_length, NUM_INITIAL_BALANCES + 1);
        // Verify that the ledger response contained an archive info.
        assert!(!get_blocks_res.archived_ranges.is_empty());
        // Verify that the archiving failure metric is still 0.
        assert_archiving_failure_metric(&env, ledger_id, 0u64);
    }

    /// Test that while archiving blocks in chunks, the ledger never reports a block to be present
    /// in more than one place (even though a block may actually be present e.g., in the ledger and
    /// an archive while the archiving is still ongoing).
    pub fn test_archiving_in_chunks_returns_disjoint_block_range_locations<T, B>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
        get_archives: fn(&StateMachine, CanisterId) -> Vec<Principal>,
        get_blocks_fn: fn(&StateMachine, CanisterId, u64, usize) -> GenericGetBlocksResponse<B>,
        archive_get_blocks_fn: fn(
            &StateMachine,
            CanisterId,
            u64,
            usize,
        ) -> GenericGetBlocksResponse<B>,
    ) where
        T: CandidType,
        B: Eq + Debug,
    {
        const NUM_BLOCKS_TO_ARCHIVE: usize = 100_000;
        const NUM_INITIAL_BALANCES: u64 = 70_000;
        const TRIGGER_THRESHOLD: usize = 2_000;
        let p1 = PrincipalId::new_user_test_id(1);
        let p2 = PrincipalId::new_user_test_id(2);
        let archive_controller = PrincipalId::new_user_test_id(1_000_000);
        let mut initial_balances = vec![];
        for i in 0..NUM_INITIAL_BALANCES {
            initial_balances.push((
                Account::from(PrincipalId::new_user_test_id(i).0),
                10_000_000,
            ));
        }

        // Install a ledger with a lot of initial balances
        let env = StateMachine::new();
        let args = encode_init_args(InitArgs {
            archive_options: ArchiveOptions {
                trigger_threshold: TRIGGER_THRESHOLD,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: archive_controller,
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            ..init_args(initial_balances)
        });
        let args = Encode!(&args).unwrap();
        let ledger_id = env
            .install_canister(ledger_wasm.clone(), args, None)
            .unwrap();

        // Assert no archives exist.
        assert!(get_archives(&env, ledger_id).is_empty());

        // Perform a transaction. This should spawn an archive, and archive `num_blocks_to_archive`,
        // but since there are so many blocks to archive, the archiving will be done in chunks.
        let transfer_message_id = env.send_ingress(
            p1,
            ledger_id,
            "icrc1_transfer",
            encode_transfer_args(p1.0, p2.0, 10_000),
        );
        let mut transfer_status = message_status(&env, &transfer_message_id).unwrap();
        assert!(transfer_status.is_none());

        // Keep listing the archives and calling env.tick() until the ledger reports that an
        // archive has been created.
        let mut archive_info = get_archives(&env, ledger_id);
        while archive_info.is_empty() {
            env.tick();
            archive_info = get_archives(&env, ledger_id);
        }
        // Verify that the ledger reports block `0` to be present only in the ledger
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert!(
            !ledger_reports_first_block_in_two_places(0, &get_blocks_res),
            "get_blocks_res: {get_blocks_res:?}"
        );
        // Verify that the ledger response contained no archive info.
        assert!(get_blocks_res.archived_ranges.is_empty());
        // Verify that the block was already archived. Since the archiving is done in chunks, the
        // archiving is not yet completed, so the ledger reports the block `0` to be present only
        // in the ledger, even though it is also present in the archive by now.
        let archive_id = archive_info
            .first()
            .expect("should return one archive info");
        let get_blocks_res = archive_get_blocks_fn(
            &env,
            CanisterId::unchecked_from_principal(PrincipalId::from(*archive_id)),
            0,
            1,
        );
        assert!(
            !get_blocks_res.blocks.is_empty(),
            "archive should contain at least one block"
        );

        // Tick until the transfer completes, meaning the archiving also completes.
        const MAX_TICKS: usize = 500;
        let mut ticks = 0;
        while transfer_status.is_none() {
            env.tick();
            ticks += 1;
            assert!(ticks < MAX_TICKS);
            transfer_status = message_status(&env, &transfer_message_id).unwrap();
        }
        let transfer_result = Decode!(
            &transfer_status.unwrap()
            .bytes(),
            Result<Nat, TransferError>
        )
        .expect("failed to decode transfer response")
        .map(|n| n.0.to_u64().unwrap())
        .expect("transfer should succeed");
        assert_eq!(transfer_result, NUM_INITIAL_BALANCES);

        // Verify that the ledger now does not return the first block, but reports that it is in
        // the first archive.
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert!(get_blocks_res.blocks.is_empty());
        let first_archive_info = get_blocks_res
            .archived_ranges
            .first()
            .expect("should return one archive info");
        assert!(
            first_archive_info.archived_range.contains(&0u64),
            "expected archived_range {:?} to contain block number 0",
            first_archive_info.archived_range
        );
    }

    /// Verify that archiving lots of blocks creates many archives of expected size.
    pub fn test_archiving_lots_of_blocks_after_enabling_archiving<T, B>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
        get_archives: fn(&StateMachine, CanisterId) -> Vec<Principal>,
        get_blocks_fn: fn(&StateMachine, CanisterId, u64, usize) -> GenericGetBlocksResponse<B>,
        archive_get_blocks_fn: fn(
            &StateMachine,
            CanisterId,
            u64,
            usize,
        ) -> GenericGetBlocksResponse<B>,
    ) where
        T: CandidType,
        B: Eq + Debug,
    {
        const NUM_BLOCKS_TO_ARCHIVE: usize = 1_000;
        const NUM_INITIAL_BALANCES: u64 = 70_000;
        const TRIGGER_THRESHOLD: usize = 2_000;
        // The limit of 100 blocks applies to the ICRC archive.
        const MAX_ARCHIVE_GET_BLOCKS_RESPONSE_SIZE: usize = 100;
        let p1 = PrincipalId::new_user_test_id(1);
        let p2 = PrincipalId::new_user_test_id(2);
        let archive_controller = PrincipalId::new_user_test_id(1_000_000);
        let mut initial_balances = vec![];
        for i in 0..NUM_INITIAL_BALANCES {
            initial_balances.push((
                Account::from(PrincipalId::new_user_test_id(i).0),
                10_000_000,
            ));
        }

        let env = StateMachine::new();
        let args = encode_init_args(InitArgs {
            archive_options: ArchiveOptions {
                trigger_threshold: TRIGGER_THRESHOLD,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: archive_controller,
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            ..init_args(initial_balances)
        });
        let args = Encode!(&args).unwrap();
        let ledger_id = env
            .install_canister(ledger_wasm.clone(), args, None)
            .unwrap();

        // Assert no archives exist.
        assert!(get_archives(&env, ledger_id).is_empty());

        // Perform enough transactions to spawn an archive and archive NUM_INITIAL_BALANCES.
        for i in 1..(NUM_INITIAL_BALANCES / NUM_BLOCKS_TO_ARCHIVE as u64) {
            // Perform a transaction. This should spawn an archive if one does not exist yet,
            // and archive `num_blocks_to_archive`, without chunking.
            let transfer_message_id = env.send_ingress(
                p1,
                ledger_id,
                "icrc1_transfer",
                encode_transfer_args(p1.0, p2.0, 10_000 + i),
            );
            // Verify that block `0` is only reported to exist in one place.
            let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
            assert!(!ledger_reports_first_block_in_two_places(
                0,
                &get_blocks_res
            ));

            // Tick until the transfer completes, meaning the archiving also completes.
            const MAX_TICKS: usize = 500;
            let mut ticks = 0;
            let mut transfer_status = message_status(&env, &transfer_message_id).unwrap();
            while transfer_status.is_none() {
                env.tick();
                ticks += 1;
                assert!(ticks < MAX_TICKS);
                transfer_status = message_status(&env, &transfer_message_id).unwrap();
                // Verify that block `0` is only reported to exist in one place.
                let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
                assert!(!ledger_reports_first_block_in_two_places(
                    0,
                    &get_blocks_res
                ));
            }
            let transfer_result = Decode!(
                &transfer_status.unwrap()
                .bytes(),
                Result<Nat, TransferError>
            )
            .expect("failed to decode transfer response")
            .map(|n| n.0.to_u64().unwrap())
            .expect("transfer should succeed");
            assert_eq!(transfer_result, NUM_INITIAL_BALANCES + i - 1);

            // An archive should exist
            assert!(!get_archives(&env, ledger_id).is_empty());
            // Try to get the first block from the ledger. This should return a pointer to the
            // archive, which we need for determining the callback method to call (for the ICP
            // ledger archive).
            let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
            let Some(archive_info) = get_blocks_res.archived_ranges.first() else {
                panic!("should return one archived blocks info");
            };
            let archive_blocks = archive_get_blocks_fn(
                &env,
                CanisterId::unchecked_from_principal(PrincipalId::from(archive_info.canister_id)),
                0,
                MAX_ARCHIVE_GET_BLOCKS_RESPONSE_SIZE,
            );
            assert_eq!(archive_blocks.first_block_index, 0);
            assert_eq!(
                archive_blocks.blocks.len(),
                MAX_ARCHIVE_GET_BLOCKS_RESPONSE_SIZE
            );
        }

        // Verity that trying to get block `0` from the ledger returns a pointer to the archive.
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, 1);
        assert!(get_blocks_res.blocks.is_empty());
        let archive_info = get_blocks_res
            .archived_ranges
            .first()
            .expect("should return one archived blocks info");
        assert_eq!(archive_info.archived_range.start, 0);
        assert_eq!(archive_info.archived_range.end, 1);
    }

    /// Verify that when archiving to multiple archives and requesting various block ranges, the
    /// correct ranges are returned.
    pub fn test_get_blocks_returns_multiple_archive_callbacks<T, B>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
        get_archive_count: fn(&StateMachine, CanisterId) -> Vec<Principal>,
        get_blocks_fn: fn(&StateMachine, CanisterId, u64, usize) -> GenericGetBlocksResponse<B>,
    ) where
        T: CandidType,
        B: Eq + Debug,
    {
        const MAX_RETRIES_WAITING_FOR_ARCHIVE_CREATION: usize = 100;
        const NUM_BLOCKS_TO_ARCHIVE: usize = 10;
        const NUM_INITIAL_BALANCES: usize = 20;
        const TRIGGER_THRESHOLD: usize = 20;
        const ARCHIVE_MAX_MEMORY_SIZE_BYTES: u64 = 330; // 3 blocks per archive
        const EXPECTED_NUM_BLOCKS_PER_ARCHIVE: usize = 3;
        const EXPECTED_NUM_ARCHIVES: usize = 4;
        const EXPECTED_NUM_BLOCKS_IN_LEDGER: usize =
            NUM_INITIAL_BALANCES + 1 - NUM_BLOCKS_TO_ARCHIVE;
        let p1 = PrincipalId::new_user_test_id(1);
        let p2 = PrincipalId::new_user_test_id(2);
        let archive_controller = PrincipalId::new_user_test_id(1_000_000);
        let mut initial_balances = vec![];
        for i in 0..NUM_INITIAL_BALANCES {
            initial_balances.push((
                Account::from(PrincipalId::new_user_test_id(i as u64).0),
                10_000_000,
            ));
        }

        let env = StateMachine::new();
        let args = encode_init_args(InitArgs {
            archive_options: ArchiveOptions {
                trigger_threshold: TRIGGER_THRESHOLD,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
                node_max_memory_size_bytes: Some(ARCHIVE_MAX_MEMORY_SIZE_BYTES),
                max_message_size_bytes: None,
                controller_id: archive_controller,
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            ..init_args(initial_balances)
        });
        let args = Encode!(&args).unwrap();
        let ledger_id = env
            .install_canister(ledger_wasm.clone(), args, None)
            .unwrap();

        // Assert no archives exist.
        assert!(get_archive_count(&env, ledger_id).is_empty());

        // Perform a transaction. This should spawn a bunch of archives.
        transfer(&env, ledger_id, p1.0, p2.0, 10_000).expect("failed to transfer funds");

        // Keep listing the archives and calling env.tick() until the ledger reports that an
        // archive has been created.
        let mut archive_count = get_archive_count(&env, ledger_id);
        let mut retries = 0;
        while archive_count.is_empty() {
            env.tick();
            archive_count = get_archive_count(&env, ledger_id);
            retries += 1;
            assert!(
                retries < MAX_RETRIES_WAITING_FOR_ARCHIVE_CREATION,
                "timed out waiting for archive creation"
            );
        }
        assert_eq!(
            archive_count.len(),
            EXPECTED_NUM_ARCHIVES,
            "expect {EXPECTED_NUM_ARCHIVES} archives"
        );

        // Request all the blocks and verify that they are included either in the ledger local
        // blocks, or in the archive callback request ranges.
        let get_blocks_res = get_blocks_fn(&env, ledger_id, 0, NUM_INITIAL_BALANCES + 1);
        assert_eq!(get_blocks_res.blocks.len(), EXPECTED_NUM_BLOCKS_IN_LEDGER);
        for (i, archive_info) in get_blocks_res.archived_ranges.iter().enumerate() {
            let archive_num_blocks = range_utils::range_len(&archive_info.archived_range);
            match (i + 1).cmp(&EXPECTED_NUM_ARCHIVES) {
                Ordering::Equal => {
                    // The last archive will only contain one block
                    assert_eq!(archive_num_blocks, 1);
                }
                _ => {
                    // Most archives will be full
                    assert_eq!(archive_num_blocks as usize, EXPECTED_NUM_BLOCKS_PER_ARCHIVE)
                }
            }
        }

        // Perform some more calls to get blocks and verify the response is correct.
        let mut runner = TestRunner::new(proptest::test_runner::Config::default());
        runner
            .run(
                &(
                    0..(NUM_INITIAL_BALANCES + 2) as u64,
                    0..(NUM_INITIAL_BALANCES + 2),
                )
                    .no_shrink(),
                |(start, len)| {
                    let get_blocks_res = get_blocks_fn(&env, ledger_id, start, len);
                    assert_query_encoded_blocks_response(start, len as u64, &get_blocks_res);
                    Ok(())
                },
            )
            .unwrap();
    }

    /// Test that when trying to archiving lots of blocks at once, the ledger respects the upper
    /// limit for `num_blocks_to_archive`.
    pub fn test_archiving_respects_num_blocks_to_archive_upper_limit<T, B>(
        ledger_wasm: Vec<u8>,
        encode_init_args: fn(InitArgs) -> T,
        num_initial_balances: u64,
        get_blocks_fn: fn(&StateMachine, CanisterId, u64, usize) -> GenericGetBlocksResponse<B>,
        get_archives: fn(&StateMachine, CanisterId) -> Vec<Principal>,
        archive_get_blocks_fn: fn(
            &StateMachine,
            CanisterId,
            u64,
            usize,
        ) -> GenericGetBlocksResponse<B>,
    ) where
        T: CandidType,
        B: Eq + Debug,
    {
        const NUM_BLOCKS_TO_ARCHIVE: usize = 800_000;
        const TRIGGER_THRESHOLD: usize = 2_000;
        let p1 = PrincipalId::new_user_test_id(1);
        let p2 = PrincipalId::new_user_test_id(2);
        let archive_controller = PrincipalId::new_user_test_id(1_000_000);
        let mut initial_balances = vec![];
        for i in 0..num_initial_balances {
            initial_balances.push((
                Account::from(PrincipalId::new_user_test_id(i).0),
                10_000_000,
            ));
        }

        // Install a ledger with a lot of initial balances
        let env = StateMachine::new();
        let args = encode_init_args(InitArgs {
            archive_options: ArchiveOptions {
                trigger_threshold: TRIGGER_THRESHOLD,
                num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: Some(2 * 1024 * 1024),
                controller_id: archive_controller,
                more_controller_ids: None,
                cycles_for_archive_creation: Some(0),
                max_transactions_per_response: None,
            },
            ..init_args(initial_balances)
        });
        let args = Encode!(&args).unwrap();
        let ledger_id = env
            .install_canister(ledger_wasm.clone(), args, None)
            .unwrap();

        let get_blocks_res = get_blocks_fn(&env, ledger_id, (MAX_BLOCKS_TO_ARCHIVE - 1) as u64, 1);
        let initial_chain_length = get_blocks_res.chain_length;
        let block_in_ledger = get_blocks_res
            .blocks
            .first()
            .expect("ledger should contain block");

        // Perform a transaction to trigger archiving.
        let transfer_block_id = send_transfer(
            &env,
            ledger_id,
            p1.0,
            &TransferArg {
                from_subaccount: None,
                to: Account::from(p2.0),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: NumTokens::from(12_345u64),
            },
        )
        .expect("transfer should succeed");

        assert_eq!(transfer_block_id, initial_chain_length);

        // The maximum number of blocks that will be returned from the ledger in a get_blocks/
        // icrc3_get_blocks response.
        const MAX_BLOCKS_PER_RESPONSE: usize = 100;
        const BLOCKS_EXPECTED_FROM_ARCHIVE: usize = 5;
        const BLOCKS_EXPECTED_FROM_LEDGER: usize =
            MAX_BLOCKS_PER_RESPONSE - BLOCKS_EXPECTED_FROM_ARCHIVE;

        // Try to retrieve up to MAX_BLOCKS_PER_RESPONSE from the ledger.
        let get_blocks_response = get_blocks_fn(
            &env,
            ledger_id,
            (MAX_BLOCKS_TO_ARCHIVE - BLOCKS_EXPECTED_FROM_ARCHIVE) as u64,
            MAX_BLOCKS_PER_RESPONSE,
        );
        // The ledger should contain blocks from index MAX_BLOCKS_TO_ARCHIVE onwards, so the above
        // request should return BLOCKS_EXPECTED_FROM_LEDGER blocks
        // from the ledger, and point to the archive for the rest.
        assert_eq!(
            get_blocks_response.blocks.len(),
            BLOCKS_EXPECTED_FROM_LEDGER
        );
        // The archive should contain exactly MAX_BLOCKS_TO_ARCHIVE blocks, and the archived range
        // should be (MAX_BLOCKS_TO_ARCHIVE - BLOCKS_EXPECTED_FROM_ARCHIVE)..MAX_BLOCKS_TO_ARCHIVE.
        let archive_info = get_blocks_response
            .archived_ranges
            .first()
            .expect("the archive should have some blocks");
        let expected_archive_range = range_utils::make_range(
            (MAX_BLOCKS_TO_ARCHIVE - BLOCKS_EXPECTED_FROM_ARCHIVE) as u64,
            BLOCKS_EXPECTED_FROM_ARCHIVE,
        );
        assert_eq!(expected_archive_range, archive_info.archived_range);
        // Block (MAX_BLOCKS_TO_ARCHIVE-1) should be in the archive.
        let archive_ids = get_archives(&env, ledger_id);
        let archive_blocks_res = archive_get_blocks_fn(
            &env,
            CanisterId::unchecked_from_principal(PrincipalId::from(
                *archive_ids.first().expect("should have one archive"),
            )),
            (MAX_BLOCKS_TO_ARCHIVE - 1) as u64,
            1,
        );
        let block_in_archive = archive_blocks_res
            .blocks
            .first()
            .expect("archive should contain block");
        assert_eq!(block_in_ledger, block_in_archive);
        assert_eq!(archive_blocks_res.blocks.len(), 1);
    }

    // ----- Helper structures -----

    #[derive(Debug)]
    pub struct GenericArchiveInfo {
        pub canister_id: Principal,
        pub method_name: String,
        pub archived_range: Range<u64>,
    }

    #[derive(Debug)]
    pub struct GenericGetBlocksResponse<B> {
        pub chain_length: u64,
        pub blocks: Vec<B>,
        pub first_block_index: u64,
        pub archived_ranges: Vec<GenericArchiveInfo>,
    }

    impl From<QueryEncodedBlocksResponse> for GenericGetBlocksResponse<EncodedBlock> {
        fn from(value: QueryEncodedBlocksResponse) -> Self {
            let mut archived_ranges = vec![];
            for archived_blocks in value.archived_blocks {
                let start = archived_blocks.start;
                let length = archived_blocks.length;
                archived_ranges.push(GenericArchiveInfo {
                    canister_id: archived_blocks.callback.canister_id,
                    method_name: archived_blocks.callback.method,
                    archived_range: Range {
                        start,
                        end: start + length,
                    },
                });
            }
            GenericGetBlocksResponse {
                chain_length: value.chain_length,
                blocks: value.blocks,
                first_block_index: value.first_block_index,
                archived_ranges,
            }
        }
    }

    impl From<GetBlocksResult> for GenericGetBlocksResponse<BlockWithId> {
        fn from(value: GetBlocksResult) -> Self {
            let mut archived_ranges = vec![];
            for archived_range in &value.archived_blocks {
                let start = archived_range
                    .args
                    .first()
                    .unwrap()
                    .clone()
                    .start
                    .0
                    .to_u64()
                    .unwrap();
                let length = archived_range
                    .args
                    .first()
                    .unwrap()
                    .length
                    .0
                    .to_u64()
                    .unwrap();
                archived_ranges.push(GenericArchiveInfo {
                    canister_id: archived_range.callback.canister_id,
                    method_name: archived_range.callback.method.clone(),
                    archived_range: Range {
                        start,
                        end: start + length,
                    },
                });
            }
            let first_block_index = match value.blocks.first() {
                Some(block) => block.id.0.to_u64().unwrap(),
                None => 0,
            };
            GenericGetBlocksResponse {
                chain_length: value.log_length.0.to_u64().unwrap(),
                blocks: value.blocks,
                first_block_index,
                archived_ranges,
            }
        }
    }

    impl From<GetEncodedBlocksResult> for GenericGetBlocksResponse<EncodedBlock> {
        fn from(value: GetEncodedBlocksResult) -> Self {
            match value {
                Ok(blocks) => GenericGetBlocksResponse {
                    chain_length: 0,
                    blocks,
                    first_block_index: 0,
                    archived_ranges: vec![],
                },
                Err(err) => {
                    panic!("error calling get_encoded_blocks on ICP archive: {err:?}");
                }
            }
        }
    }

    // ----- Helper functions -----

    pub fn icp_archives(env: &StateMachine, ledger_id: CanisterId) -> Vec<Principal> {
        Decode!(
            &env.query(ledger_id, "archives", Encode!().unwrap())
                .expect("failed to query archives")
                .bytes(),
            icp_ledger::Archives
        )
        .expect("failed to decode archives response")
        .archives
        .into_iter()
        .map(|archive| archive.canister_id.get().0)
        .collect()
    }

    pub fn icrc_archives(env: &StateMachine, ledger_id: CanisterId) -> Vec<Principal> {
        list_archives(env, ledger_id)
            .into_iter()
            .map(|archive| archive.canister_id)
            .collect()
    }

    /// Function to call the `get_encoded_blocks` endpoint of the ICP archive.
    pub fn get_encoded_blocks(
        env: &StateMachine,
        canister_id: CanisterId,
        start: u64,
        length: usize,
    ) -> GenericGetBlocksResponse<EncodedBlock> {
        let get_blocks_args = icp_ledger::GetBlocksArgs {
            start,
            length: length as u64,
        };
        let res = Decode!(
            &env.query(
                canister_id,
                "get_encoded_blocks",
                Encode!(&get_blocks_args).unwrap()
            )
            .expect("failed to query encoded blocks")
            .bytes(),
            GetEncodedBlocksResult
        )
        .expect("failed to decode query_encoded_blocks response");
        GenericGetBlocksResponse::from(res)
    }

    /// Function to call the `query_encoded_blocks` endpoint of the ICP ledger.
    pub fn query_encoded_blocks(
        env: &StateMachine,
        canister_id: CanisterId,
        start: u64,
        length: usize,
    ) -> GenericGetBlocksResponse<EncodedBlock> {
        let get_blocks_args = icp_ledger::GetBlocksArgs {
            start,
            length: length as u64,
        };
        let res = Decode!(
            &env.query(
                canister_id,
                "query_encoded_blocks",
                Encode!(&get_blocks_args).unwrap()
            )
            .expect("failed to query encoded blocks")
            .bytes(),
            QueryEncodedBlocksResponse
        )
        .expect("failed to decode query_encoded_blocks response");
        GenericGetBlocksResponse::from(res)
    }

    /// Function to query the `icrc3_get_blocks` endpoint of the ICRC ledger.
    pub fn query_icrc3_get_blocks(
        env: &StateMachine,
        canister_id: CanisterId,
        start: u64,
        length: usize,
    ) -> GenericGetBlocksResponse<BlockWithId> {
        let icrc3_get_blocks_result = icrc3_get_blocks(env, canister_id, start, length);
        GenericGetBlocksResponse::from(icrc3_get_blocks_result)
    }

    // ----- Private utility functions -----

    #[track_caller]
    fn assert_archiving_failure_metric(
        env: &StateMachine,
        ledger_id: CanisterId,
        expected_value: u64,
    ) {
        let archiving_failure_metric = parse_metric(env, ledger_id, "ledger_archiving_failures");
        assert_eq!(
            archiving_failure_metric, expected_value,
            "expected archiving failure metric to be {expected_value}, got {archiving_failure_metric}"
        );
    }

    fn assert_query_encoded_blocks_response<B>(
        req_start: u64,
        req_len: u64,
        get_blocks_response: &GenericGetBlocksResponse<B>,
    ) where
        B: Eq + Debug,
    {
        // Compute the effective range, i.e., based on the query, which blocks should the ledger
        // be expected to return (either itself, or as archive callbacks).
        let effective_range = range_utils::intersect(
            &range_utils::make_range(req_start, req_len as usize),
            &Range {
                start: 0,
                end: get_blocks_response.chain_length,
            },
        )
        .unwrap_or(Range { start: 0, end: 0 });
        let mut total_blocks_returned = get_blocks_response.blocks.len() as u64;
        let ledger_range = match get_blocks_response.blocks.is_empty() {
            true => {
                // Empty range
                Range {
                    start: req_start,
                    end: req_start,
                }
            }
            false => {
                let start = get_blocks_response.first_block_index;
                let length = get_blocks_response.blocks.len();
                range_utils::make_range(start, length)
            }
        };
        let archived_ranges = &get_blocks_response.archived_ranges;
        for archive_info in archived_ranges {
            total_blocks_returned += range_utils::range_len(&archive_info.archived_range);
        }
        // Make sure the archived ranges are ordered
        let mut previous_start = None;
        for archive_info in archived_ranges {
            if let Some(previous_start) = previous_start {
                assert!(
                    archive_info.archived_range.start > previous_start,
                    "expected the archived ranges to be ordered"
                );
            }
            previous_start = Some(archive_info.archived_range.start);
        }
        // Make sure each requested block that exists in the (ledger+archives) is returned.
        for block_id in effective_range.start..effective_range.end {
            assert!(
                ledger_range.contains(&block_id)
                    || archived_ranges
                        .iter()
                        .any(|archive_info| archive_info.archived_range.contains(&block_id))
            );
        }
        assert_eq!(
            range_utils::range_len(&effective_range),
            total_blocks_returned
        )
    }

    fn encode_transfer_args(
        from: impl Into<Account>,
        to: impl Into<Account>,
        amount: u64,
    ) -> Vec<u8> {
        let from = from.into();
        Encode!(&TransferArg {
            from_subaccount: from.subaccount,
            to: to.into(),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(amount),
        })
        .unwrap()
    }

    // Verify that the ledger reports that the first block is present in both the ledger and the
    // first and only archive. This function assumes that the `icrc3_get_blocks_result` is the
    // result of a query of length 1.
    fn ledger_reports_first_block_in_two_places<B>(
        block_id: u64,
        icrc3_get_blocks_result: &GenericGetBlocksResponse<B>,
    ) -> bool
    where
        B: Eq + Debug,
    {
        // Verify that the first block was returned from the ledger
        match icrc3_get_blocks_result.blocks.len() {
            0 => return false,
            _ => {
                if block_id != icrc3_get_blocks_result.first_block_index {
                    return false;
                }
            }
        }
        let Some(first_archived_range) = icrc3_get_blocks_result.archived_ranges.first() else {
            return false;
        };
        first_archived_range.archived_range.start == block_id
            && range_utils::range_len(&first_archived_range.archived_range) == 1
    }

    fn message_status(
        env: &StateMachine,
        message_id: &MessageId,
    ) -> Result<Option<WasmResult>, UserError> {
        match env.ingress_status(message_id) {
            IngressStatus::Known {
                state: IngressState::Completed(result),
                ..
            } => Ok(Some(result)),
            IngressStatus::Known {
                state: IngressState::Processing,
                ..
            } => Ok(None),
            IngressStatus::Known {
                state: IngressState::Failed(error),
                ..
            } => Err(error),
            s => {
                panic!("Unexpected ingress status: {s:?}");
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct LogEntry {
        pub timestamp: u64,
        pub file: String,
        pub line: u32,
        pub message: String,
    }

    #[derive(Clone, Debug, Default)]
    pub struct Log {
        pub entries: Vec<LogEntry>,
    }

    /// Parse ledger logs into a Log struct.
    /// Example log line:
    /// 1620328630000000031 rs/ledger_suite/common/ledger_canister_core/src/ledger.rs:456 [ledger] archiving 1000 blocks
    pub fn parse_ledger_logs(logs: &[u8]) -> Log {
        let logs_as_single_string = String::from_utf8_lossy(logs).to_string();
        let mut entries = vec![];
        for line in logs_as_single_string.lines() {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            assert_eq!(parts.len(), 3, "log line has insufficient parts: {}", line);
            let timestamp = parts[0].parse::<u64>().unwrap_or(0);
            let file_and_line_parts: Vec<&str> = parts[1].split(':').collect();
            let file = file_and_line_parts[0].to_string();
            let line_num = file_and_line_parts[1].parse::<u32>().unwrap_or(0);
            let message = parts[2].to_string();
            entries.push(LogEntry {
                timestamp,
                file,
                line: line_num,
                message,
            });
        }
        Log { entries }
    }
}

pub fn test_setting_fee_collector_to_minting_account<T>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
{
    let env = StateMachine::new();

    let args = encode_init_args(InitArgs {
        fee_collector_account: Some(MINTER),
        ..init_args(vec![])
    });
    let args = Encode!(&args).unwrap();
    match env.install_canister(ledger_wasm.clone(), args, None) {
        Ok(_) => {
            panic!(
                "should not install ledger with minting account and fee collector set to the same account"
            )
        }
        Err(err) => {
            err.assert_contains(
                ErrorCode::CanisterCalledTrap,
                "The fee collector account cannot be the same as the minting account",
            );
        }
    }

    let args = encode_init_args(InitArgs {
        fee_collector_account: Some(Account::from(PrincipalId::new_user_test_id(1).0)),
        ..init_args(vec![])
    });
    let args = Encode!(&args).unwrap();
    env.install_canister(ledger_wasm, args, None)
        .expect("should successfully install ledger");
}

pub fn test_icrc3_blocks_compatibility_with_production_ledger<T>(
    production_ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
    icrc3_test_ledger_wasm: Vec<u8>,
) where
    T: CandidType,
{
    use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy};
    use icrc_ledger_types::icrc::generic_value::ICRC3Value;
    use icrc_ledger_types::icrc3::blocks::{BlockWithId, GetBlocksRequest};

    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    let now = SystemTime::now();
    let minter = Arc::new(minter_identity());
    let minter_principal = minter.sender().unwrap();

    runner
        .run(
            &(valid_transactions_strategy(minter, FEE, 20, now).no_shrink(),),
            |(transactions,)| {
                let env = StateMachine::new();
                env.set_time(now);

                let production_ledger_id = env
                    .install_canister(
                        production_ledger_wasm.clone(),
                        Encode!(&encode_init_args(InitArgs {
                            minting_account: Account::from(minter_principal),
                            ..init_args(vec![])
                        }))
                        .unwrap(),
                        None,
                    )
                    .unwrap();

                // Apply the generated valid transactions to the production ledger
                for transaction in &transactions {
                    apply_arg_with_caller(&env, production_ledger_id, transaction);
                }

                // Retrieve all blocks from the production ledger using icrc3_get_blocks
                let production_blocks_response =
                    icrc3_get_blocks(&env, production_ledger_id, 0, u64::MAX as usize);
                let production_blocks: Vec<ICRC3Value> = production_blocks_response
                    .blocks
                    .into_iter()
                    .map(|block_with_id: BlockWithId| block_with_id.block)
                    .collect();

                // Install the ICRC-3 test ledger
                let test_ledger_id = env
                    .install_canister(icrc3_test_ledger_wasm.clone(), vec![], None)
                    .unwrap();

                // Add all production ledger blocks to the ICRC-3 test ledger
                for block in &production_blocks {
                    let add_block_result = Decode!(
                        &env.execute_ingress(
                            test_ledger_id,
                            "add_block",
                            Encode!(block).unwrap(),
                        )
                        .expect("failed to add block")
                        .bytes(),
                        Result<Nat, String>
                    )
                    .expect("failed to decode add_block response");

                    prop_assert!(
                        add_block_result.is_ok(),
                        "Failed to add block: {:?}",
                        add_block_result
                    );
                }

                // Retrieve all blocks from the ICRC-3 test ledger
                let test_blocks_response = Decode!(
                    &env.query(
                        test_ledger_id,
                        "icrc3_get_blocks",
                        Encode!(&vec![GetBlocksRequest {
                            start: Nat::from(0u64),
                            length: Nat::from(production_blocks.len() as u64),
                        }])
                        .unwrap(),
                    )
                    .expect("failed to get blocks from test ledger")
                    .bytes(),
                    GetBlocksResult
                )
                .expect("failed to decode icrc3_get_blocks response");

                let test_blocks: Vec<ICRC3Value> = test_blocks_response
                    .blocks
                    .into_iter()
                    .map(|block_with_id: BlockWithId| block_with_id.block)
                    .collect();

                // Verify that the blocks are identical
                prop_assert_eq!(
                    production_blocks.len(),
                    test_blocks.len(),
                    "Number of blocks should match"
                );

                for (i, (production_block, test_block)) in
                    production_blocks.iter().zip(test_blocks.iter()).enumerate()
                {
                    prop_assert_eq!(
                        production_block,
                        test_block,
                        "Block {} should be identical",
                        i
                    );
                }

                Ok(())
            },
        )
        .unwrap();
}

/// Tests that `http_request` endpoint of a given canister rejects overly large HTTP requests
/// (exceeding the candid decoding quota of 10,000, corresponding to roughly 10 KB of decoded data).
pub fn test_http_request_decoding_quota(env: &StateMachine, canister_id: CanisterId) {
    // The anonymous end-user sends a small HTTP request. This should succeed.
    let http_request = HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: vec![],
        body: ByteBuf::from(vec![42; 1_000]),
    };
    let http_request_bytes = Encode!(&http_request).unwrap();
    let response = match env
        .execute_ingress(canister_id, "http_request", http_request_bytes)
        .unwrap()
    {
        WasmResult::Reply(bytes) => Decode!(&bytes, HttpResponse).unwrap(),
        WasmResult::Reject(reason) => panic!("Unexpected reject: {}", reason),
    };
    assert_eq!(response.status_code, 200);

    // The anonymous end-user sends a large HTTP request. This should be rejected.
    let mut large_http_request = http_request;
    large_http_request.body = ByteBuf::from(vec![42; 1_000_000]);
    let large_http_request_bytes = Encode!(&large_http_request).unwrap();
    let err = env
        .execute_ingress(canister_id, "http_request", large_http_request_bytes)
        .unwrap_err();
    assert!(
        err.description().contains("Deserialization Failed")
            || err
                .description()
                .contains("Decoding cost exceeds the limit")
    );
}
