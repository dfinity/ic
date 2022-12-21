use candid::{CandidType, Decode, Encode, Nat};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{StandardRecord, TransferArg, TransferError, Value},
    Account, Memo,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::BlockIndex;
use ic_state_machine_tests::{CanisterId, StateMachine};
use num_traits::ToPrimitive;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
pub const FEE: u64 = 10_000;
pub const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
pub const NUM_BLOCKS_TO_ARCHIVE: u64 = 5;
pub const TX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

pub const MINTER: Account = Account {
    owner: PrincipalId::new(0, [0u8; 29]),
    subaccount: None,
};

// Metadata-related constants
pub const TOKEN_NAME: &str = "Test Token";
pub const TOKEN_SYMBOL: &str = "XTST";
pub const TEXT_META_KEY: &str = "test:image";
pub const TEXT_META_VALUE: &str = "grumpy_cat.png";
pub const BLOB_META_KEY: &str = "test:blob";
pub const BLOB_META_VALUE: &[u8] = b"\xca\xfe\xba\xbe";
pub const NAT_META_KEY: &str = "test:nat";
pub const NAT_META_VALUE: u128 = u128::MAX;
pub const INT_META_KEY: &str = "test:int";
pub const INT_META_VALUE: i128 = i128::MIN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitArgs {
    pub minting_account: Account,
    pub initial_balances: Vec<(Account, u64)>,
    pub transfer_fee: u64,
    pub token_name: String,
    pub token_symbol: String,
    pub metadata: Vec<(String, Value)>,
    pub archive_options: ArchiveOptions,
}

fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn send_transfer(
    env: &StateMachine,
    ledger: CanisterId,
    from: PrincipalId,
    arg: &TransferArg,
) -> Result<BlockIndex, TransferError> {
    Decode!(
        &env.execute_ingress_as(
            from,
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

fn transfer(
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

fn init_args(initial_balances: Vec<(Account, u64)>) -> InitArgs {
    InitArgs {
        minting_account: MINTER.clone(),
        initial_balances,
        transfer_fee: FEE,
        token_name: TOKEN_NAME.to_string(),
        token_symbol: TOKEN_SYMBOL.to_string(),
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
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
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
//  1. the first part that setup ledger and environemnt and tests the
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

    assert_eq!(0, balance_of(&env, canister_id, p1));
    assert_eq!(0, balance_of(&env, canister_id, p2));

    let (env, canister_id) = setup(
        ledger_wasm,
        encode_init_args,
        vec![
            (Account::from(p1), 10_000_000),
            (Account::from(p2), 5_000_000),
        ],
    );

    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1));
    assert_eq!(5_000_000u64, balance_of(&env, canister_id, p2));
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
    assert_eq!(lookup(&metadata, "icrc1:decimals"), &Value::from(8u64));
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
    assert_eq!(lookup(&metadata, "icrc1:decimals"), &Value::from(8u64));
    //Not all ICRC-1 impelmentations have the same metadata entries. Thus only certain basic fields are shared by all ICRC-1 implementaions
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
    let standards = supported_standards(&env, canister_id);
    assert_eq!(
        standards,
        vec![StandardRecord {
            name: "ICRC-1".to_string(),
            url: "https://github.com/dfinity/ICRC-1".to_string(),
        }]
    );
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
            (Account::from(p1), 10_000_000),
            (Account::from(p2), 5_000_000),
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
            (Account::from(p1), 10_000_000),
            (Account::from(p2), 5_000_000),
        ],
    );

    assert_eq!(15_000_000, total_supply(&env, canister_id));
    assert_eq!(10_000_000u64, balance_of(&env, canister_id, p1));
    assert_eq!(5_000_000u64, balance_of(&env, canister_id, p2));

    transfer(&env, canister_id, p1, p2, 1_000_000).expect("transfer failed");

    assert_eq!(15_000_000 - FEE, total_supply(&env, canister_id));
    assert_eq!(9_000_000u64 - FEE, balance_of(&env, canister_id, p1));
    assert_eq!(6_000_000u64, balance_of(&env, canister_id, p2));
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
        vec![(Account::from(p1), 10_000_000)],
    );
    // No created_at_time => no deduplication
    let block_id = transfer(&env, canister_id, p1, p2, 10_000).expect("transfer failed");
    assert!(transfer(&env, canister_id, p1, p2, 10_000).expect("transfer failed") > block_id);

    let now = system_time_to_nanos(env.time());

    let transfer_args = TransferArg {
        from_subaccount: None,
        to: p2.into(),
        fee: None,
        amount: Nat::from(1_000_000),
        created_at_time: Some(now),
        memo: None,
    };

    let block_idx = send_transfer(&env, canister_id, p1, &transfer_args).expect("transfer failed");

    assert_eq!(
        send_transfer(&env, canister_id, p1, &transfer_args),
        Err(TransferError::Duplicate {
            duplicate_of: Nat::from(block_idx)
        })
    );

    env.advance_time(TX_WINDOW + Duration::from_secs(5 * 60));
    let now = system_time_to_nanos(env.time());

    assert_eq!(
        send_transfer(&env, canister_id, p1, &transfer_args,),
        Err(TransferError::TooOld),
    );

    // Same transaction, but `created_at_time` specified explicitly.
    // The ledger should not deduplicate this request.
    let block_idx = send_transfer(
        &env,
        canister_id,
        p1,
        &TransferArg {
            from_subaccount: None,
            to: p2.into(),
            fee: None,
            amount: Nat::from(1_000_000),
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
            p1,
            &TransferArg {
                from_subaccount: None,
                to: p2.into(),
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now),
                memo: None,
            }
        )
    );

    // Same transaction, but with "default" `memo`.
    // The ledger should not deduplicate because we set a new field explicitly.
    let block_idx = send_transfer(
        &env,
        canister_id,
        p1,
        &TransferArg {
            from_subaccount: None,
            to: p2.into(),
            fee: None,
            amount: Nat::from(1_000_000),
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
            p1,
            &TransferArg {
                from_subaccount: None,
                to: p2.into(),
                fee: None,
                amount: Nat::from(1_000_000),
                created_at_time: Some(now),
                memo: Some(Memo::default()),
            }
        )
    );
}

pub fn test_mint_burn<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
    let (env, canister_id) = setup(ledger_wasm, encode_init_args, vec![]);
    let p1 = PrincipalId::new_user_test_id(1);
    let p2 = PrincipalId::new_user_test_id(2);

    assert_eq!(0, total_supply(&env, canister_id));
    assert_eq!(0, balance_of(&env, canister_id, p1));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    transfer(&env, canister_id, MINTER.clone(), p1, 10_000_000).expect("mint failed");

    assert_eq!(10_000_000, total_supply(&env, canister_id));
    assert_eq!(10_000_000, balance_of(&env, canister_id, p1));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    transfer(&env, canister_id, p1, MINTER.clone(), 1_000_000).expect("burn failed");

    assert_eq!(9_000_000, total_supply(&env, canister_id));
    assert_eq!(9_000_000, balance_of(&env, canister_id, p1));
    assert_eq!(0, balance_of(&env, canister_id, MINTER.clone()));

    // You have at least FEE, you can burn at least FEE
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE)
        }),
        transfer(&env, canister_id, p1, MINTER.clone(), FEE / 2),
    );

    transfer(&env, canister_id, p1, p2, FEE / 2).expect("transfer failed");

    assert_eq!(FEE / 2, balance_of(&env, canister_id, p2));

    // If you have less than FEE, you can burn only the whole amount.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE / 2)
        }),
        transfer(&env, canister_id, p2, MINTER.clone(), FEE / 4),
    );
    transfer(&env, canister_id, p2, MINTER.clone(), FEE / 2).expect("burn failed");

    assert_eq!(0, balance_of(&env, canister_id, p2));

    // You cannot burn zero tokens, no matter what your balance is.
    assert_eq!(
        Err(TransferError::BadBurn {
            min_burn_amount: Nat::from(FEE)
        }),
        transfer(&env, canister_id, p2, MINTER.clone(), 0),
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
            (Account::from(p1), 10_000_000),
            (Account::from(p2), 5_000_000),
        ],
    );

    assert_eq!(
        10_000_000u64,
        balance_of(
            &env,
            canister_id,
            Account {
                owner: p1,
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
                owner: p1,
                subaccount: Some([0; 32])
            }
        )
    );

    transfer(
        &env,
        canister_id,
        p1,
        Account {
            owner: p2,
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
                owner: p2,
                subaccount: None
            }
        )
    );
}
