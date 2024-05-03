use candid::{CandidType, Decode, Encode, Int, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_error_types::UserError;
use ic_icrc1::blocks::encoded_block_to_generic_block;
use ic_icrc1::{endpoints::StandardRecord, hash::Hash, Block, Operation, Transaction};
use ic_icrc1_ledger::FeatureFlags;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::{BlockIndex, BlockType};
use ic_ledger_hash_of::HashOf;
use ic_management_canister_types::{
    self as ic00, CanisterInfoRequest, CanisterInfoResponse, Method, Payload,
};
use ic_state_machine_tests::{CanisterId, ErrorCode, StateMachine, WasmResult};
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc::generic_value::Value as GenericValue;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg, TransferError};
use icrc_ledger_types::icrc2::allowance::{Allowance, AllowanceArgs};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use icrc_ledger_types::icrc3;
use icrc_ledger_types::icrc3::archive::ArchiveInfo;
use icrc_ledger_types::icrc3::blocks::BlockRange;
use icrc_ledger_types::icrc3::blocks::GenericBlock as IcrcBlock;
use icrc_ledger_types::icrc3::blocks::GetBlocksResponse;
use icrc_ledger_types::icrc3::transactions::GetTransactionsRequest;
use icrc_ledger_types::icrc3::transactions::GetTransactionsResponse;
use icrc_ledger_types::icrc3::transactions::Transaction as Tx;
use icrc_ledger_types::icrc3::transactions::TransactionRange;
use icrc_ledger_types::icrc3::transactions::Transfer;
use num_traits::ToPrimitive;
use proptest::prelude::*;
use proptest::test_runner::{Config as TestRunnerConfig, TestCaseResult, TestRunner};
use std::{
    cmp,
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime},
};
pub const FEE: u64 = 10_000;
pub const DECIMAL_PLACES: u8 = 8;
pub const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
pub const NUM_BLOCKS_TO_ARCHIVE: u64 = 5;
pub const TX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

pub const MINTER: Account = Account {
    owner: PrincipalId::new(0, [0u8; 29]).0,
    subaccount: None,
};

// Metadata-related constants
pub const TOKEN_NAME: &str = "Test Token";
pub const TOKEN_SYMBOL: &str = "XTST";
pub const TEXT_META_KEY: &str = "test:image";
pub const TEXT_META_VALUE: &str = "grumpy_cat.png";
pub const TEXT_META_VALUE_2: &str = "dog.png";
pub const BLOB_META_KEY: &str = "test:blob";
pub const BLOB_META_VALUE: &[u8] = b"\xca\xfe\xba\xbe";
pub const NAT_META_KEY: &str = "test:nat";
pub const NAT_META_VALUE: u128 = u128::MAX;
pub const INT_META_KEY: &str = "test:int";
pub const INT_META_VALUE: i128 = i128::MIN;

#[cfg(not(feature = "u256-tokens"))]
type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
type Tokens = ic_icrc1_tokens_u256::U256;

#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
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
    pub maximum_number_of_accounts: Option<u64>,
    pub accounts_overflow_trim_quantity: Option<u64>,
}

#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub enum ChangeFeeCollector {
    Unset,
    SetTo(Account),
}

#[derive(CandidType, Clone, Debug, Default, PartialEq, Eq)]
pub struct UpgradeArgs {
    pub metadata: Option<Vec<(String, Value)>>,
    pub token_name: Option<String>,
    pub token_symbol: Option<String>,
    pub transfer_fee: Option<Nat>,
    pub change_fee_collector: Option<ChangeFeeCollector>,
    pub feature_flags: Option<FeatureFlags>,
    pub maximum_number_of_accounts: Option<u64>,
    pub accounts_overflow_trim_quantity: Option<u64>,
    pub change_archive_options: Option<ChangeArchiveOptions>,
}

#[derive(CandidType, Clone, Debug, Default, PartialEq, Eq)]
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
#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
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

fn send_transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: Principal,
    arg: &TransferArg,
) -> Result<BlockIndex, TransferError> {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(from),
            ledger,
            "icrc1_transfer",
            Encode!(arg)
            .unwrap()
        )
        .expect("failed to transfer funds")
        .bytes(),
        Result<Nat, TransferError>
    )
    .expect("failed to decode transfer response")
    .map(|n| n.0.to_u64().unwrap())
}

pub fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

pub fn transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: impl Into<Account>,
    to: impl Into<Account>,
    amount: u64,
) -> Result<BlockIndex, TransferError> {
    let from = from.into();
    send_transfer(
        env,
        ledger,
        from.owner,
        &TransferArg {
            from_subaccount: from.subaccount,
            to: to.into(),
            fee: None,
            created_at_time: None,
            amount: Nat::from(amount),
            memo: None,
        },
    )
}

fn list_archives(env: &StateMachine, ledger: CanisterId) -> Vec<ArchiveInfo> {
    Decode!(
        &env.query(ledger, "archives", Encode!().unwrap())
            .expect("failed to query archives")
            .bytes(),
        Vec<ArchiveInfo>
    )
    .expect("failed to decode archives response")
}

fn get_archive_remaining_capacity(env: &StateMachine, archive: Principal) -> u64 {
    let canister_id = CanisterId::unchecked_from_principal(archive.into());
    Decode!(
        &env.query(canister_id, "remaining_capacity", Encode!().unwrap())
            .expect("failed to get archive remaining capacity")
            .bytes(),
        u64
    )
    .expect("failed to decode remaining_capacity response")
}

fn get_archive_transaction(env: &StateMachine, archive: Principal, block_index: u64) -> Option<Tx> {
    let canister_id = CanisterId::unchecked_from_principal(archive.into());
    Decode!(
        &env.query(
            canister_id,
            "get_transaction",
            Encode!(&block_index).unwrap()
        )
        .expect("failed to get transaction")
        .bytes(),
        Option<Tx>
    )
    .expect("failed to decode get_transaction response")
}

fn get_transactions_as<Response: CandidType + for<'a> candid::Deserialize<'a>>(
    env: &StateMachine,
    canister: Principal,
    start: u64,
    length: usize,
    method_name: String,
) -> Response {
    let canister_id = CanisterId::unchecked_from_principal(canister.into());
    Decode!(
        &env.query(
            canister_id,
            method_name,
            Encode!(&GetTransactionsRequest {
                start: Nat::from(start),
                length: Nat::from(length)
            })
            .unwrap()
        )
        .expect("failed to query ledger transactions")
        .bytes(),
        Response
    )
    .expect("failed to decode get_transactions response")
}

fn get_archive_transactions(
    env: &StateMachine,
    archive: Principal,
    start: u64,
    length: usize,
) -> TransactionRange {
    get_transactions_as(env, archive, start, length, "get_transactions".to_string())
}

fn universal_canister_payload(
    receiver: &PrincipalId,
    method: &str,
    payload: Vec<u8>,
    cycles: Cycles,
) -> Vec<u8> {
    wasm()
        .call_with_cycles(
            receiver,
            method,
            call_args()
                .other_side(payload)
                .on_reject(wasm().reject_message().reject()),
            cycles,
        )
        .build()
}

fn get_canister_info(
    env: &StateMachine,
    ucan: CanisterId,
    canister_id: CanisterId,
) -> Result<CanisterInfoResponse, String> {
    let info_request_payload = universal_canister_payload(
        &PrincipalId::default(),
        &Method::CanisterInfo.to_string(),
        CanisterInfoRequest::new(canister_id, None).encode(),
        Cycles::new(0),
    );
    let wasm_result = env
        .execute_ingress(ucan, "update", info_request_payload)
        .unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => Ok(CanisterInfoResponse::decode(&bytes[..])
            .expect("failed to decode canister_info response")),
        WasmResult::Reject(reason) => Err(reason),
    }
}

fn get_transactions(
    env: &StateMachine,
    archive: Principal,
    start: u64,
    length: usize,
) -> GetTransactionsResponse {
    get_transactions_as(env, archive, start, length, "get_transactions".to_string())
}

fn get_blocks(
    env: &StateMachine,
    archive: Principal,
    start: u64,
    length: usize,
) -> GetBlocksResponse {
    get_transactions_as(env, archive, start, length, "get_blocks".to_string())
}

fn get_archive_blocks(
    env: &StateMachine,
    archive: Principal,
    start: u64,
    length: usize,
) -> BlockRange {
    get_transactions_as(env, archive, start, length, "get_blocks".to_string())
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

pub fn total_supply(env: &StateMachine, ledger: CanisterId) -> u64 {
    Decode!(
        &env.query(ledger, "icrc1_total_supply", Encode!().unwrap())
            .expect("failed to query total supply")
            .bytes(),
        Nat
    )
    .expect("failed to decode totalSupply response")
    .0
    .to_u64()
    .unwrap()
}

pub fn supported_standards(env: &StateMachine, ledger: CanisterId) -> Vec<StandardRecord> {
    Decode!(
        &env.query(ledger, "icrc1_supported_standards", Encode!().unwrap())
            .expect("failed to query supported standards")
            .bytes(),
        Vec<StandardRecord>
    )
    .expect("failed to decode icrc1_supported_standards response")
}

pub fn minting_account(env: &StateMachine, ledger: CanisterId) -> Option<Account> {
    Decode!(
        &env.query(ledger, "icrc1_minting_account", Encode!().unwrap())
            .expect("failed to query minting account icrc1")
            .bytes(),
        Option<Account>
    )
    .expect("failed to decode icrc1_minting_account response")
}

pub fn balance_of(env: &StateMachine, ledger: CanisterId, acc: impl Into<Account>) -> u64 {
    Decode!(
        &env.query(ledger, "icrc1_balance_of", Encode!(&acc.into()).unwrap())
            .expect("failed to query balance")
            .bytes(),
        Nat
    )
    .expect("failed to decode balance_of response")
    .0
    .to_u64()
    .unwrap()
}

pub fn metadata(env: &StateMachine, ledger: CanisterId) -> BTreeMap<String, Value> {
    Decode!(
        &env.query(ledger, "icrc1_metadata", Encode!().unwrap())
            .expect("failed to query metadata")
            .bytes(),
        Vec<(String, Value)>
    )
    .expect("failed to decode metadata response")
    .into_iter()
    .collect()
}

pub fn send_approval(
    env: &StateMachine,
    ledger: CanisterId,
    from: Principal,
    arg: &ApproveArgs,
) -> Result<BlockIndex, ApproveError> {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(from),
            ledger,
            "icrc2_approve",
            Encode!(arg)
            .unwrap()
        )
        .expect("failed to apply approval")
        .bytes(),
        Result<Nat, ApproveError>
    )
    .expect("failed to decode approve response")
    .map(|n| n.0.to_u64().unwrap())
}

pub fn send_transfer_from(
    env: &StateMachine,
    ledger: CanisterId,
    from: Principal,
    arg: &TransferFromArgs,
) -> Result<BlockIndex, TransferFromError> {
    Decode!(
        &env.execute_ingress_as(
            PrincipalId(from),
            ledger,
            "icrc2_transfer_from",
            Encode!(arg)
            .unwrap()
        )
        .expect("failed to apply approval")
        .bytes(),
        Result<Nat, TransferFromError>
    )
    .expect("failed to decode transfer_from response")
    .map(|n| n.0.to_u64().unwrap())
}

pub fn get_allowance(
    env: &StateMachine,
    ledger: CanisterId,
    account: impl Into<Account>,
    spender: impl Into<Account>,
) -> Allowance {
    let arg = AllowanceArgs {
        account: account.into(),
        spender: spender.into(),
    };
    Decode!(
        &env.query(ledger, "icrc2_allowance", Encode!(&arg).unwrap())
            .expect("failed to guery the allowance")
            .bytes(),
        Allowance
    )
    .expect("failed to decode allowance response")
}

fn arb_amount() -> impl Strategy<Value = Tokens> {
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

fn arb_transfer() -> impl Strategy<Value = Operation<Tokens>> {
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

fn arb_approve() -> impl Strategy<Value = Operation<Tokens>> {
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

fn arb_mint() -> impl Strategy<Value = Operation<Tokens>> {
    (arb_account(), arb_amount()).prop_map(|(to, amount)| Operation::Mint { to, amount })
}

fn arb_burn() -> impl Strategy<Value = Operation<Tokens>> {
    (
        arb_account(),
        proptest::option::of(arb_account()),
        arb_amount(),
    )
        .prop_map(|(from, spender, amount)| Operation::Burn {
            from,
            spender,
            amount,
        })
}

fn arb_operation() -> impl Strategy<Value = Operation<Tokens>> {
    prop_oneof![arb_transfer(), arb_mint(), arb_burn(), arb_approve()]
}

fn arb_transaction() -> impl Strategy<Value = Transaction<Tokens>> {
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

fn arb_block() -> impl Strategy<Value = Block<Tokens>> {
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
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        feature_flags: Some(FeatureFlags { icrc2: true }),
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
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
// //rs/rosetta-api/icrc1/ledger/tests/tests.rs#test_metadata in two:
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
            .unwrap_or_else(|| panic!("no metadata key {} in map {:?}", key, metadata))
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
    assert_eq!(standards, vec!["ICRC-1", "ICRC-2"]);
}
pub fn test_metadata<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    fn lookup<'a>(metadata: &'a BTreeMap<String, Value>, key: &str) -> &'a Value {
        metadata
            .get(key)
            .unwrap_or_else(|| panic!("no metadata key {} in map {:?}", key, metadata))
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
    assert_eq!(standards, vec!["ICRC-1", "ICRC-2", "ICRC-3"]);
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

    let now = system_time_to_nanos(env.time_of_next_round());
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

    let now = system_time_to_nanos(env.time_of_next_round());

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

    env.run_until_completion(/*max_ticks=*/ 10);

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
                cycles_for_archive_creation: None,
                max_transactions_per_response: None,
            },
            feature_flags: args.feature_flags,
            maximum_number_of_accounts: args.maximum_number_of_accounts,
            accounts_overflow_trim_quantity: args.accounts_overflow_trim_quantity,
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
                cycles_for_archive_creation: None,
                max_transactions_per_response: None,
            },
            feature_flags: args.feature_flags,
            maximum_number_of_accounts: args.maximum_number_of_accounts,
            accounts_overflow_trim_quantity: args.accounts_overflow_trim_quantity,
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
                cycles_for_archive_creation: None,
                max_transactions_per_response: None,
            },
            feature_flags: args.feature_flags,
            maximum_number_of_accounts: args.maximum_number_of_accounts,
            accounts_overflow_trim_quantity: args.accounts_overflow_trim_quantity,
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
    env.run_until_completion(/*max_ticks=*/ 10);

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
    env.run_until_completion(/*max_ticks=*/ 10);
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

    env.run_until_completion(/*max_ticks=*/ 10);

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

    env.run_until_completion(/*max_ticks=*/ 10);

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
pub fn block_encoding_agrees_with_the_schema() {
    use std::path::PathBuf;

    let block_cddl_path =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("block.cddl");
    let block_cddl =
        String::from_utf8(std::fs::read(block_cddl_path).expect("failed to read block.cddl file"))
            .unwrap();

    let mut runner = TestRunner::default();
    runner
        .run(&arb_block(), |block| {
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

pub fn block_encoding_agreed_with_the_icrc3_schema() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        ..Default::default()
    });
    runner
        .run(&arb_block(), |block| {
            let encoded_block = block.encode();
            let generic_block = encoded_block_to_generic_block(&encoded_block);
            if let Err(errors) = icrc3::schema::validate(&generic_block) {
                panic!("generic_block: {:?}, errors:\n{}", generic_block, errors);
            }
            Ok(())
        })
        .unwrap();
}

// Check that different blocks produce different hashes.
pub fn transaction_hashes_are_unique() {
    let mut runner = TestRunner::default();
    runner
        .run(&(arb_transaction(), arb_transaction()), |(lhs, rhs)| {
            use ic_ledger_canister_core::ledger::LedgerTransaction;

            prop_assume!(lhs != rhs);
            prop_assert_ne!(lhs.hash(), rhs.hash());

            Ok(())
        })
        .unwrap();
}

pub fn block_hashes_are_unique() {
    let mut runner = TestRunner::default();
    runner
        .run(&(arb_block(), arb_block()), |(lhs, rhs)| {
            prop_assume!(lhs != rhs);

            let lhs_hash = Block::<Tokens>::block_hash(&lhs.encode());
            let rhs_hash = Block::<Tokens>::block_hash(&rhs.encode());

            prop_assert_ne!(lhs_hash, rhs_hash);
            Ok(())
        })
        .unwrap();
}

// Generate random blocks and check that the block hash is stable.
pub fn block_hashes_are_stable() {
    let mut runner = TestRunner::default();
    runner
        .run(&arb_block(), |block| {
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

    let token_fee_after_upgrade: u64 = Decode!(
        &env.query(canister_id, "icrc1_fee", Encode!().unwrap())
            .expect("failed to query fee")
            .bytes(),
        Nat
    )
    .expect("failed to decode balance_of response")
    .0
    .to_u64()
    .unwrap();
    assert_eq!(token_fee_after_upgrade, NEW_FEE);
}

pub fn test_fee_collector<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let env = StateMachine::new();
    // By default the fee collector is not set.
    let ledger_id = install_ledger(&env, ledger_wasm.clone(), encode_init_args, vec![]);
    // Only 1 test case because we modify the ledger within the test.
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    runner
        .run(
            &(
                arb_account(),
                arb_account(),
                arb_account(),
                1..10_000_000u64,
            )
                .prop_filter("The three accounts must be different", |(a1, a2, a3, _)| {
                    a1 != a2 && a2 != a3 && a1 != a3
                }),
            |(account_from, account_to, fee_collector, amount)| {
                // Test 1: with no fee collector the fee should be burned.

                // Mint some tokens for a user.
                transfer(&env, ledger_id, MINTER, account_from, 3 * (amount + FEE))
                    .expect("Unable to mint tokens");

                // Record the previous total_supply and make the transfer.
                let total_supply_before = total_supply(&env, ledger_id);
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform transfer");

                // If the fee was burned then the total_supply after the
                // transfer should be the one before plus the (burned) FEE.
                assert_eq!(
                    total_supply_before,
                    total_supply(&env, ledger_id) + FEE,
                    "Total supply should have been decreased of the (burned) fee {}",
                    FEE
                );

                // Test 2: upgrade the ledger to have a fee collector.
                //         The fee should be collected by the fee collector.

                // Set the fee collector.
                let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs {
                    change_fee_collector: Some(ChangeFeeCollector::SetTo(fee_collector)),
                    ..UpgradeArgs::default()
                }));
                env.upgrade_canister(
                    ledger_id,
                    ledger_wasm.clone(),
                    Encode!(&ledger_upgrade_arg).unwrap(),
                )
                .unwrap();

                // Record the previous total_supply and make the transfer.
                let total_supply_before = total_supply(&env, ledger_id);
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform transfer");

                // If the fee was burned then the total_supply after the
                // transfer should be the one before (nothing burned).
                assert_eq!(
                    total_supply_before,
                    total_supply(&env, ledger_id),
                    "Total supply shouldn't have changed"
                );

                // The fee collector must have collected the fee.
                assert_eq!(
                    FEE,
                    balance_of(&env, ledger_id, fee_collector),
                    "The fee_collector should have collected the fee"
                );

                // Test 3: upgrade the ledger to not have a fee collector.
                //         The fee should once again be burned.

                // Unset the fee collector.
                let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs {
                    change_fee_collector: Some(ChangeFeeCollector::Unset),
                    ..UpgradeArgs::default()
                }));
                env.upgrade_canister(
                    ledger_id,
                    ledger_wasm.clone(),
                    Encode!(&ledger_upgrade_arg).unwrap(),
                )
                .unwrap();

                // Record the previous total_supply and make the transfer.
                let total_supply_before = total_supply(&env, ledger_id);
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform transfer");

                // If the fee was burned then the total_supply after the
                // transfer should be the one before plus the (burned) FEE.
                assert_eq!(
                    total_supply_before,
                    total_supply(&env, ledger_id) + FEE,
                    "Total supply should have been decreased of the (burned) fee {}",
                    FEE
                );

                // The fee collector must have collected no fee this time.
                assert_eq!(
                    FEE,
                    balance_of(&env, ledger_id, fee_collector),
                    "The fee_collector should have collected the fee"
                );

                Ok(())
            },
        )
        .unwrap();
}

pub fn test_fee_collector_blocks<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    fn value_as_u64(value: icrc_ledger_types::icrc::generic_value::Value) -> u64 {
        use icrc_ledger_types::icrc::generic_value::Value;
        match value {
            Value::Nat64(n) => n,
            Value::Nat(n) => n.0.to_u64().expect("block index should fit into u64"),
            Value::Int(int) => int.0.to_u64().expect("block index should fit into u64"),
            value => panic!("Expected a numeric value but found {:?}", value),
        }
    }

    fn value_as_account(value: icrc_ledger_types::icrc::generic_value::Value) -> Account {
        use icrc_ledger_types::icrc::generic_value::Value;

        match value {
            Value::Array(array) => match &array[..] {
                [Value::Blob(principal_bytes)] => Account {
                    owner: Principal::try_from(principal_bytes.as_ref())
                        .expect("failed to parse account owner"),
                    subaccount: None,
                },
                [Value::Blob(principal_bytes), Value::Blob(subaccount_bytes)] => Account {
                    owner: Principal::try_from(principal_bytes.as_ref())
                        .expect("failed to parse account owner"),
                    subaccount: Some(
                        Subaccount::try_from(subaccount_bytes.as_ref())
                            .expect("failed to parse subaccount"),
                    ),
                },
                _ => panic!("Unexpected account representation: {:?}", array),
            },
            value => panic!("Expected Value::Array but found {:?}", value),
        }
    }

    fn fee_collector_from_block(
        block: icrc_ledger_types::icrc::generic_value::Value,
    ) -> (Option<Account>, Option<u64>) {
        match block {
            icrc_ledger_types::icrc::generic_value::Value::Map(block_map) => {
                let fee_collector = block_map
                    .get("fee_col")
                    .map(|fee_collector| value_as_account(fee_collector.clone()));
                let fee_collector_block_index = block_map
                    .get("fee_col_block")
                    .map(|value| value_as_u64(value.clone()));
                (fee_collector, fee_collector_block_index)
            }
            _ => panic!("A block should be a map!"),
        }
    }

    let env = StateMachine::new();
    // Only 1 test case because we modify the ledger within the test.
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    runner
        .run(
            &(
                arb_account(),
                arb_account(),
                arb_account(),
                1..10_000_000u64,
            )
                .prop_filter("The three accounts must be different", |(a1, a2, a3, _)| {
                    a1 != a2 && a2 != a3 && a1 != a3
                }),
            |(account_from, account_to, fee_collector_account, amount)| {
                let args = encode_init_args(InitArgs {
                    fee_collector_account: Some(fee_collector_account),
                    initial_balances: vec![(account_from, Nat::from((amount + FEE) * 6))],
                    ..init_args(vec![])
                });
                let args = Encode!(&args).unwrap();
                let ledger_id = env
                    .install_canister(ledger_wasm.clone(), args, None)
                    .unwrap();

                // The block at index 0 is the minting operation for account_from and
                // has the fee collector set.
                // Make 2 more transfers that should point to the first block index.
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");

                let blocks = get_blocks(&env, ledger_id.get().0, 0, 4).blocks;

                // The first block must have the fee collector explicitly defined.
                assert_eq!(
                    fee_collector_from_block(blocks.first().unwrap().clone()),
                    (Some(fee_collector_account), None)
                );
                // The other two blocks must have a pointer to the first block.
                assert_eq!(
                    fee_collector_from_block(blocks.get(1).unwrap().clone()),
                    (None, Some(0))
                );
                assert_eq!(
                    fee_collector_from_block(blocks.get(2).unwrap().clone()),
                    (None, Some(0))
                );

                // Change the fee collector to a new one. The next block must have
                // the fee collector set while the ones that follow will point
                // to that one.
                let ledger_upgrade_arg = LedgerArgument::Upgrade(Some(UpgradeArgs {
                    change_fee_collector: Some(ChangeFeeCollector::SetTo(account_from)),
                    ..UpgradeArgs::default()
                }));
                env.upgrade_canister(
                    ledger_id,
                    ledger_wasm.clone(),
                    Encode!(&ledger_upgrade_arg).unwrap(),
                )
                .unwrap();

                let block_id = transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");
                transfer(&env, ledger_id, account_from, account_to, amount)
                    .expect("Unable to perform the transfer");
                let blocks = get_blocks(&env, ledger_id.get().0, block_id, 3).blocks;
                assert_eq!(
                    fee_collector_from_block(blocks.first().unwrap().clone()),
                    (Some(account_from), None)
                );
                assert_eq!(
                    fee_collector_from_block(blocks.get(1).unwrap().clone()),
                    (None, Some(block_id))
                );
                assert_eq!(
                    fee_collector_from_block(blocks.get(2).unwrap().clone()),
                    (None, Some(block_id))
                );

                Ok(())
            },
        )
        .unwrap()
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
        assert!(
            transfer_with_memo(&vec![0u8; i]).is_ok(),
            "Memo size: {}",
            i
        );
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
        assert!(
            transfer_with_memo(&vec![0u8; i]).is_ok(),
            "Memo size: {}",
            i
        );
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
            "unexpected error: {}",
            user_error
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

pub fn icrc1_test_block_transformation<T>(
    ledger_wasm_mainnet: Vec<u8>,
    ledger_wasm_current: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) where
    T: CandidType,
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    let allowance_sub_1 = get_allowance(&env, canister_id, from_sub_1, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(err.description().ends_with("self approval is not allowed"));
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 0);
    assert_eq!(allowance.expires_at, None);
    assert_eq!(balance_of(&env, canister_id, from.0), 5_000);
    assert_eq!(balance_of(&env, canister_id, spender.0), 0);
}

pub fn test_approve_cap<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
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

    approve_args.amount = Nat::from(Tokens::MAX) * 2u8;
    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 1);
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance, Nat::from(Tokens::MAX));
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    let allowance_sub_1 = get_allowance(&env, canister_id, from_sub_1, spender.0);
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
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(err
        .description()
        .ends_with("the minting account cannot delegate mints"));
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
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(
        err.description()
            .ends_with("ICRC-2 features are not enabled on the ledger."),
        "Expected ICRC-2 disabled error, got: {}",
        err.description()
    );
    let err = env
        .execute_ingress_as(
            from,
            canister_id,
            "icrc2_allowance",
            Encode!(&allowance_args).unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(
        err.description()
            .ends_with("ICRC-2 features are not enabled on the ledger."),
        "Expected ICRC-2 disabled error, got: {}",
        err.description()
    );
    let err = env
        .execute_ingress_as(
            from,
            canister_id,
            "icrc2_transfer_from",
            Encode!(&transfer_from_args).unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(
        err.description()
            .ends_with("ICRC-2 features are not enabled on the ledger."),
        "Expected ICRC-2 disabled error, got: {}",
        err.description()
    );
    let standards = supported_standards(env, canister_id);
    assert_eq!(standards.len(), 1);
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
    assert_eq!(standards, vec!["ICRC-1", "ICRC-2"]);

    let block_index =
        send_approval(&env, canister_id, from.0, &approve_args).expect("approval failed");
    assert_eq!(block_index, 1);
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 150_000);
    let block_index = send_transfer_from(&env, canister_id, spender.0, &transfer_from_args)
        .expect("transfer_from failed");
    assert_eq!(block_index, 2);
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 110_000);
    let allowance = get_allowance(&env, canister_id, from_sub_1, spender.0);
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
    let allowance = get_allowance(&env, canister_id, from.0, spender.0);
    assert_eq!(allowance.allowance.0.to_u64().unwrap(), 110_000);
    let allowance = get_allowance(&env, canister_id, from_sub_1, spender.0);
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
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(err
        .description()
        .ends_with("the minter account cannot delegate mints"));
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

pub fn test_balances_overflow<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let env = StateMachine::new();

    let args = encode_init_args(InitArgs {
        maximum_number_of_accounts: Some(8),
        accounts_overflow_trim_quantity: Some(2),
        ..init_args(vec![])
    });
    let args = Encode!(&args).unwrap();
    let canister_id = env.install_canister(ledger_wasm, args, None).unwrap();

    let minter = minting_account(&env, canister_id).unwrap();

    let mut credited = 0;
    for i in 0..11 {
        transfer(
            &env,
            canister_id,
            minter,
            PrincipalId::new_user_test_id(i).0,
            i,
        )
        .expect("failed to mint tokens");
        credited += i;
    }
    assert_eq!(
        balance_of(&env, canister_id, PrincipalId::new_user_test_id(1).0),
        0
    );
    assert_eq!(
        balance_of(&env, canister_id, PrincipalId::new_user_test_id(2).0),
        0
    );
    for i in 3..11 {
        assert_eq!(
            balance_of(&env, canister_id, PrincipalId::new_user_test_id(i).0),
            i
        );
    }
    assert_eq!(total_supply(&env, canister_id), credited - 1 - 2);
}

pub fn test_approval_trimming<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let env = StateMachine::new();

    let args = encode_init_args(InitArgs {
        feature_flags: Some(FeatureFlags { icrc2: true }),
        maximum_number_of_accounts: Some(9),
        accounts_overflow_trim_quantity: Some(2),
        ..init_args(vec![])
    });
    let args = Encode!(&args).unwrap();
    let canister_id = env.install_canister(ledger_wasm, args, None).unwrap();

    let minter = minting_account(&env, canister_id).unwrap();

    for i in 0..4 {
        transfer(
            &env,
            canister_id,
            minter,
            PrincipalId::new_user_test_id(i).0,
            1_000_000,
        )
        .expect("failed to mint tokens");
    }

    let num_approvals = 3;
    for i in 0..num_approvals {
        let mut approve_args = default_approve_args(PrincipalId::new_user_test_id(i).0, 10_000);
        if i < 2 {
            approve_args.expires_at = Some(
                system_time_to_nanos(env.time())
                    + Duration::from_secs((i + 1) * 3600).as_nanos() as u64,
            );
        }
        send_approval(
            &env,
            canister_id,
            PrincipalId::new_user_test_id(3).0,
            &approve_args,
        )
        .expect("approval failed");
    }

    for i in 0..4 {
        assert_ne!(
            balance_of(&env, canister_id, PrincipalId::new_user_test_id(i).0),
            0
        );
    }

    fn total_allowance(env: &StateMachine, canister_id: CanisterId, num_approvals: u64) -> Nat {
        let mut allowance = Nat::from(0_u8);
        for i in 0..num_approvals {
            allowance += get_allowance(
                env,
                canister_id,
                PrincipalId::new_user_test_id(3).0,
                PrincipalId::new_user_test_id(i).0,
            )
            .allowance;
        }
        allowance
    }

    assert_eq!(
        total_allowance(&env, canister_id, num_approvals),
        Nat::from(30_000u32)
    );

    let mut new_accounts = 0;
    for i in 4..11 {
        transfer(
            &env,
            canister_id,
            minter,
            PrincipalId::new_user_test_id(i).0,
            1_000_000,
        )
        .expect("failed to mint tokens");
        new_accounts += 1;

        let remaining_approvals = cmp::max(num_approvals as i64 - (new_accounts + 1) / 2, 0) as u64;
        assert_eq!(
            total_allowance(&env, canister_id, num_approvals),
            Nat::from(10_000 * remaining_approvals)
        );
    }
}

pub fn test_icrc1_test_suite<T: candid::CandidType>(
    ledger_wasm: Vec<u8>,
    encode_init_args: fn(InitArgs) -> T,
) {
    use anyhow::Context;
    use async_trait::async_trait;
    use candid::utils::{decode_args, encode_args, ArgumentDecoder, ArgumentEncoder};
    use futures::FutureExt;
    use icrc1_test_env::LedgerEnv;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

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
            let debug_inputs = format!("{:?}", input);
            let in_bytes = encode_args(input)
                .with_context(|| format!("Failed to encode arguments {}", debug_inputs))?;
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
            let debug_inputs = format!("{:?}", input);
            let in_bytes = encode_args(input)
                .with_context(|| format!("Failed to encode arguments {}", debug_inputs))?;
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
