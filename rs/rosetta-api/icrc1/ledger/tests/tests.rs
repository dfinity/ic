use ic_base_types::PrincipalId;
use ic_icrc1::endpoints::Value;
use ic_icrc1_ledger::{InitArgs, LedgerArgument};
use ic_icrc1_ledger_sm_tests::{
    ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY, BLOB_META_VALUE, FEE, INT_META_KEY, INT_META_VALUE,
    MINTER, NAT_META_KEY, NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY, TEXT_META_VALUE,
    TOKEN_NAME, TOKEN_SYMBOL,
};
use ic_ledger_canister_core::archive::ArchiveOptions;
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
        minting_account: MINTER.clone(),
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
