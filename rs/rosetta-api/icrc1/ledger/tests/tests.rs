use candid::{Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger::{InitArgs, LedgerArgument};
use ic_icrc1_ledger_sm_tests::{
    ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY, BLOB_META_VALUE, FEE, INT_META_KEY, INT_META_VALUE,
    MINTER, NAT_META_KEY, NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY, TEXT_META_VALUE,
    TOKEN_NAME, TOKEN_SYMBOL,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::BlockIndex;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use num_traits::ToPrimitive;
use std::path::PathBuf;

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icrc1-ledger",
        &[],
    )
}

fn archive_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("archive"),
        "ic-icrc1-archive",
        &[],
    )
}

fn encode_init_args(args: ic_icrc1_ledger_sm_tests::InitArgs) -> LedgerArgument {
    LedgerArgument::Init(InitArgs {
        minting_account: MINTER,
        fee_collector_account: args.fee_collector_account,
        initial_balances: args.initial_balances,
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
        max_memo_length: None,
        feature_flags: args.feature_flags,
    })
}

#[test]
fn test_metadata() {
    ic_icrc1_ledger_sm_tests::test_metadata(ledger_wasm(), encode_init_args)
}

#[test]
fn test_upgrade() {
    ic_icrc1_ledger_sm_tests::test_upgrade(ledger_wasm(), encode_init_args)
}

#[test]
fn test_tx_deduplication() {
    ic_icrc1_ledger_sm_tests::test_tx_deduplication(ledger_wasm(), encode_init_args);
}

#[test]
fn test_mint_burn() {
    ic_icrc1_ledger_sm_tests::test_mint_burn(ledger_wasm(), encode_init_args);
}
#[test]
fn test_single_transfer() {
    ic_icrc1_ledger_sm_tests::test_single_transfer(ledger_wasm(), encode_init_args);
}

#[test]
fn test_account_canonicalization() {
    ic_icrc1_ledger_sm_tests::test_account_canonicalization(ledger_wasm(), encode_init_args);
}

#[test]
fn test_memo_validation() {
    ic_icrc1_ledger_sm_tests::test_account_canonicalization(ledger_wasm(), encode_init_args);
}

#[test]
fn test_tx_time_bounds() {
    ic_icrc1_ledger_sm_tests::test_tx_time_bounds(ledger_wasm(), encode_init_args);
}

#[test]
fn test_archiving() {
    ic_icrc1_ledger_sm_tests::test_archiving(ledger_wasm(), encode_init_args, archive_wasm());
}

#[test]
fn test_get_blocks() {
    ic_icrc1_ledger_sm_tests::test_get_blocks(ledger_wasm(), encode_init_args);
}

// Generate random blocks and check that their CBOR encoding complies with the CDDL spec.
#[test]
fn block_encoding_agrees_with_the_schema() {
    ic_icrc1_ledger_sm_tests::block_encoding_agrees_with_the_schema();
}

// Check that different blocks produce different hashes.
#[test]
fn transaction_hashes_are_unique() {
    ic_icrc1_ledger_sm_tests::transaction_hashes_are_unique();
}

// Check that different blocks produce different hashes.
#[test]
fn block_hashes_are_unique() {
    ic_icrc1_ledger_sm_tests::block_hashes_are_unique();
}

// Generate random blocks and check that the block hash is stable.
#[test]
fn block_hashes_are_stable() {
    ic_icrc1_ledger_sm_tests::block_hashes_are_stable();
}

#[test]
fn check_transfer_model() {
    ic_icrc1_ledger_sm_tests::check_transfer_model(ledger_wasm(), encode_init_args);
}

#[test]
fn check_fee_collector() {
    ic_icrc1_ledger_sm_tests::test_fee_collector(ledger_wasm(), encode_init_args);
}

#[test]
fn check_fee_collector_blocks() {
    ic_icrc1_ledger_sm_tests::test_fee_collector_blocks(ledger_wasm(), encode_init_args);
}

#[test]
fn check_memo_max_len() {
    ic_icrc1_ledger_sm_tests::test_memo_max_len(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_smoke() {
    ic_icrc1_ledger_sm_tests::test_approve_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expiration() {
    ic_icrc1_ledger_sm_tests::test_approve_expiration(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_self() {
    ic_icrc1_ledger_sm_tests::test_approve_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expected_allowance() {
    ic_icrc1_ledger_sm_tests::test_approve_expected_allowance(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_cant_pay_fee() {
    ic_icrc1_ledger_sm_tests::test_approve_cant_pay_fee(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_cap() {
    ic_icrc1_ledger_sm_tests::test_approve_cap(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_pruning() {
    ic_icrc1_ledger_sm_tests::test_approve_pruning(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_max_expiration() {
    ic_icrc1_ledger_sm_tests::test_approve_max_expiration(ledger_wasm(), encode_init_args);
}

#[test]
fn test_feature_flags() {
    ic_icrc1_ledger_sm_tests::test_feature_flags(ledger_wasm(), encode_init_args);
}

#[test]
fn test_block_transformation() {
    ic_icrc1_ledger_sm_tests::icrc1_test_block_transformation(
        std::fs::read(std::env::var("IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap())
            .unwrap(),
        ledger_wasm(),
        encode_init_args,
    );
}

// Validate upgrade of the Ledger from previous versions

fn account(n: u64) -> Account {
    Account {
        owner: PrincipalId::new_user_test_id(n).0,
        subaccount: None,
    }
}

fn transfer(
    env: &StateMachine,
    ledger_id: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> BlockIndex {
    let args = Encode!(&TransferArg {
        from_subaccount: None,
        to,
        amount: amount.into(),
        fee: None,
        created_at_time: None,
        memo: None
    })
    .unwrap();
    let res = env
        .execute_ingress_as(from.owner.into(), ledger_id, "icrc1_transfer", args)
        .expect("Unable to perform icrc1_transfer")
        .bytes();
    Decode!(&res, Result<Nat, TransferError>)
        .unwrap()
        .expect("Unable to decode icrc1_transfer error")
        .0
        .to_u64()
        .unwrap()
}

fn balance_of(env: &StateMachine, ledger_id: CanisterId, account: Account) -> u64 {
    let args = Encode!(&account).unwrap();
    let res = env
        .query(ledger_id, "icrc1_balance_of", args)
        .expect("Unable to perform icrc1_balance_of")
        .bytes();
    Decode!(&res, Nat).unwrap().0.to_u64().unwrap()
}

#[test]
fn test_upgrade_from_first_version() {
    let env = StateMachine::new();

    let ledger_wasm_first_version =
        std::fs::read(std::env::var("IC_ICRC1_LEDGER_FIRST_VERSION_WASM_PATH").unwrap()).unwrap();
    let init_args = Encode!(&InitArgs {
        minting_account: MINTER,
        fee_collector_account: None,
        initial_balances: vec![],
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
        max_memo_length: None,
        feature_flags: None,
    })
    .unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm_first_version, init_args, None)
        .unwrap();
    transfer(&env, ledger_id, MINTER, account(1), 1_000_000);
    transfer(&env, ledger_id, MINTER, account(1), 2_000_000);
    transfer(&env, ledger_id, MINTER, account(2), 3_000_000);
    transfer(&env, ledger_id, account(1), account(3), 1_000_000);
    let balance_1 = balance_of(&env, ledger_id, account(1));
    let balance_2 = balance_of(&env, ledger_id, account(2));
    let balance_3 = balance_of(&env, ledger_id, account(3));

    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");
    assert_eq!(balance_1, balance_of(&env, ledger_id, account(1)));
    assert_eq!(balance_2, balance_of(&env, ledger_id, account(2)));
    assert_eq!(balance_3, balance_of(&env, ledger_id, account(3)));

    // check that transfer works
    transfer(&env, ledger_id, MINTER, account(1), 1_000_000);
    transfer(&env, ledger_id, MINTER, account(1), 2_000_000);
    transfer(&env, ledger_id, MINTER, account(2), 3_000_000);
    transfer(&env, ledger_id, account(1), account(3), 1_000_000);
}
