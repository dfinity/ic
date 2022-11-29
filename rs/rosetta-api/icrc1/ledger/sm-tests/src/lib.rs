use candid::{CandidType, Decode, Encode, Nat};
use ic_base_types::PrincipalId;
use ic_icrc1::{
    endpoints::{StandardRecord, Value},
    Account,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_state_machine_tests::{CanisterId, StateMachine};
use num_traits::ToPrimitive;
use std::time::Duration;

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

#[derive(Clone, Debug, PartialEq)]
pub struct InitArgs {
    pub minting_account: Account,
    pub initial_balances: Vec<(Account, u64)>,
    pub transfer_fee: u64,
    pub token_name: String,
    pub token_symbol: String,
    pub metadata: Vec<(String, Value)>,
    pub archive_options: ArchiveOptions,
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

pub fn test_metadata<T>(ledger_wasm: Vec<u8>, encode_init_args: fn(InitArgs) -> T)
where
    T: CandidType,
{
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
        TOKEN_NAME,
        Decode!(
            &env.query(canister_id, "icrc1_name", Encode!().unwrap())
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
