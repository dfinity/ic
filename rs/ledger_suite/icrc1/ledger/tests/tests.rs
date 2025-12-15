use candid::{CandidType, Decode, Encode, Nat, Principal};
use ic_agent::identity::Identity;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::{Block, Operation, Transaction};
use ic_icrc1_ledger::{
    ChangeFeeCollector, FeatureFlags, InitArgs, InitArgsBuilder as LedgerInitArgsBuilder,
    LedgerArgument, UpgradeArgs,
};
use ic_icrc1_test_utils::minter_identity;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_ledger_hash_of::{HASH_LENGTH, HashOf};
use ic_ledger_suite_in_memory_ledger::{AllowancesRecentlyPurged, verify_ledger_state};
use ic_ledger_suite_state_machine_helpers::{
    AllowanceProvider, get_all_ledger_and_archive_blocks, send_approval, send_transfer_from,
};
use ic_ledger_suite_state_machine_tests::MINTER;
use ic_ledger_suite_state_machine_tests::archiving::icrc_archives;
use ic_ledger_suite_state_machine_tests::fee_collector::BlockRetrieval;
use ic_ledger_suite_state_machine_tests_constants::{
    ARCHIVE_TRIGGER_THRESHOLD, BLOB_META_KEY, BLOB_META_VALUE, DECIMAL_PLACES, FEE, INT_META_KEY,
    INT_META_VALUE, NAT_META_KEY, NAT_META_VALUE, NUM_BLOCKS_TO_ARCHIVE, TEXT_META_KEY,
    TEXT_META_VALUE, TOKEN_NAME, TOKEN_SYMBOL,
};
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc::generic_value::Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};
use icrc_ledger_types::icrc2::allowance::Allowance;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use icrc_ledger_types::icrc3::archive::{GetArchivesArgs, GetArchivesResult, QueryArchiveFn};
use icrc_ledger_types::icrc3::blocks::{
    ArchivedBlocks, BlockWithId, GetBlocksRequest, GetBlocksResponse, GetBlocksResult,
};
use num_traits::ToPrimitive;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(not(feature = "u256-tokens"))]
pub type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
pub type Tokens = ic_icrc1_tokens_u256::U256;

#[derive(Clone, Eq, PartialEq, Debug, CandidType)]
pub struct LegacyInitArgs {
    pub minting_account: Account,
    pub fee_collector_account: Option<Account>,
    pub initial_balances: Vec<(Account, u64)>,
    pub transfer_fee: u64,
    pub token_name: String,
    pub token_symbol: String,
    pub metadata: Vec<(String, MetadataValue)>,
    pub archive_options: ArchiveOptions,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType)]
pub struct LegacyUpgradeArgs {
    pub metadata: Option<Vec<(String, MetadataValue)>>,
    pub token_name: Option<String>,
    pub token_symbol: Option<String>,
    pub transfer_fee: Option<u64>,
    pub change_fee_collector: Option<ChangeFeeCollector>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Debug, CandidType)]
pub enum LegacyLedgerArgument {
    Init(LegacyInitArgs),
    Upgrade(Option<LegacyUpgradeArgs>),
}

fn ledger_mainnet_wasm() -> Vec<u8> {
    #[cfg(not(feature = "u256-tokens"))]
    let mainnet_wasm = ledger_mainnet_u64_wasm();
    #[cfg(feature = "u256-tokens")]
    let mainnet_wasm = ledger_mainnet_u256_wasm();
    mainnet_wasm
}

fn ledger_mainnet_v2_wasm() -> Vec<u8> {
    #[cfg(not(feature = "u256-tokens"))]
    let mainnet_wasm = ledger_mainnet_v2_u64_wasm();
    #[cfg(feature = "u256-tokens")]
    let mainnet_wasm = ledger_mainnet_v2_u256_wasm();
    mainnet_wasm
}

fn ledger_mainnet_v2_noledgerversion_wasm() -> Vec<u8> {
    #[cfg(not(feature = "u256-tokens"))]
    let mainnet_wasm = ledger_mainnet_v2_noledgerversion_u64_wasm();
    #[cfg(feature = "u256-tokens")]
    let mainnet_wasm = ledger_mainnet_v2_noledgerversion_u256_wasm();
    mainnet_wasm
}

fn ledger_mainnet_v3_wasm() -> Vec<u8> {
    #[cfg(not(feature = "u256-tokens"))]
    let mainnet_wasm = ledger_mainnet_v3_u64_wasm();
    #[cfg(feature = "u256-tokens")]
    let mainnet_wasm = ledger_mainnet_v3_u256_wasm();
    mainnet_wasm
}

fn ledger_mainnet_v1_wasm() -> Vec<u8> {
    #[cfg(not(feature = "u256-tokens"))]
    let mainnet_wasm = ledger_mainnet_v1_u64_wasm();
    #[cfg(feature = "u256-tokens")]
    let mainnet_wasm = ledger_mainnet_v1_u256_wasm();
    mainnet_wasm
}

#[cfg(not(feature = "u256-tokens"))]
fn ledger_mainnet_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKBTC_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap())
        .unwrap()
}

#[cfg(not(feature = "u256-tokens"))]
fn ledger_mainnet_v2_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKBTC_IC_ICRC1_LEDGER_V2_VERSION_WASM_PATH").unwrap()).unwrap()
}

#[cfg(not(feature = "u256-tokens"))]
fn ledger_mainnet_v2_noledgerversion_u64_wasm() -> Vec<u8> {
    std::fs::read(
        std::env::var("CKBTC_IC_ICRC1_LEDGER_V2_NOLEDGERLEVRION_VERSION_WASM_PATH").unwrap(),
    )
    .unwrap()
}

#[cfg(not(feature = "u256-tokens"))]
fn ledger_mainnet_v3_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKBTC_IC_ICRC1_LEDGER_V3_VERSION_WASM_PATH").unwrap()).unwrap()
}

#[cfg(not(feature = "u256-tokens"))]
fn ledger_mainnet_v1_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKBTC_IC_ICRC1_LEDGER_V1_VERSION_WASM_PATH").unwrap()).unwrap()
}

#[cfg(feature = "u256-tokens")]
fn ledger_mainnet_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKETH_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap())
        .unwrap()
}

#[cfg(feature = "u256-tokens")]
fn ledger_mainnet_v2_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKETH_IC_ICRC1_LEDGER_V2_VERSION_WASM_PATH").unwrap()).unwrap()
}

#[cfg(feature = "u256-tokens")]
fn ledger_mainnet_v2_noledgerversion_u256_wasm() -> Vec<u8> {
    std::fs::read(
        std::env::var("CKETH_IC_ICRC1_LEDGER_V2_NOLEDGERLEVRION_VERSION_WASM_PATH").unwrap(),
    )
    .unwrap()
}

#[cfg(feature = "u256-tokens")]
fn ledger_mainnet_v3_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKETH_IC_ICRC1_LEDGER_V3_VERSION_WASM_PATH").unwrap()).unwrap()
}

#[cfg(feature = "u256-tokens")]
fn ledger_mainnet_v1_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("CKETH_IC_ICRC1_LEDGER_V1_VERSION_WASM_PATH").unwrap()).unwrap()
}

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icrc1-ledger",
        &[],
    )
}

fn ledger_wasm_lowupgradeinstructionlimits() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_LEDGER_WASM_INSTR_LIMITS_PATH").unwrap()).unwrap()
}

fn ledger_wasm_nextledgerversion() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_LEDGER_NEXT_VERSION_WASM_PATH").unwrap()).unwrap()
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

fn encode_init_args(args: ic_ledger_suite_state_machine_tests::InitArgs) -> LedgerArgument {
    LedgerArgument::Init(InitArgs {
        minting_account: MINTER,
        fee_collector_account: args.fee_collector_account,
        initial_balances: args.initial_balances,
        transfer_fee: args.transfer_fee,
        token_name: TOKEN_NAME.to_string(),
        decimals: Some(DECIMAL_PLACES),
        token_symbol: TOKEN_SYMBOL.to_string(),
        metadata: vec![
            MetadataValue::entry(NAT_META_KEY, NAT_META_VALUE),
            MetadataValue::entry(INT_META_KEY, INT_META_VALUE),
            MetadataValue::entry(TEXT_META_KEY, TEXT_META_VALUE),
            MetadataValue::entry(BLOB_META_KEY, BLOB_META_VALUE),
        ],
        archive_options: args.archive_options,
        max_memo_length: None,
        feature_flags: args.feature_flags,
        index_principal: args.index_principal,
    })
}

fn encode_init_args_with_small_sized_archive(
    args: ic_ledger_suite_state_machine_tests::InitArgs,
) -> LedgerArgument {
    match encode_init_args(args) {
        LedgerArgument::Init(mut init_args) => {
            init_args.archive_options.node_max_memory_size_bytes = Some(620);
            LedgerArgument::Init(init_args)
        }
        LedgerArgument::Upgrade(_) => {
            panic!("BUG: Expected Init argument")
        }
    }
}

fn encode_init_args_no_archiving(
    args: ic_ledger_suite_state_machine_tests::InitArgs,
) -> LedgerArgument {
    match encode_init_args(args) {
        LedgerArgument::Init(mut init_args) => {
            init_args.archive_options.trigger_threshold = 1_000_000_000;
            LedgerArgument::Init(init_args)
        }
        LedgerArgument::Upgrade(_) => {
            panic!("BUG: Expected Init argument")
        }
    }
}

fn encode_init_args_with_provided_metadata(
    args: ic_ledger_suite_state_machine_tests::InitArgs,
) -> LedgerArgument {
    match encode_init_args(args.clone()) {
        LedgerArgument::Init(mut init_args) => {
            init_args.metadata = args.metadata;
            LedgerArgument::Init(init_args)
        }
        LedgerArgument::Upgrade(_) => {
            panic!("BUG: Expected Init argument")
        }
    }
}

fn encode_upgrade_args() -> LedgerArgument {
    LedgerArgument::Upgrade(None)
}

#[test]
fn test_metadata() {
    ic_ledger_suite_state_machine_tests::test_metadata(ledger_wasm(), encode_init_args)
}

#[test]
fn test_icrc3_supported_block_types() {
    ic_ledger_suite_state_machine_tests::test_icrc3_supported_block_types(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_upgrade() {
    ic_ledger_suite_state_machine_tests::test_upgrade(ledger_wasm(), encode_init_args)
}

// #[test]
// fn test_install_mainnet_ledger_then_upgrade_then_downgrade() {
//     ic_ledger_suite_state_machine_tests::test_install_upgrade_downgrade(
//         ledger_mainnet_wasm(),
//         encode_init_args,
//         ledger_wasm(),
//         encode_upgrade_args,
//         ledger_mainnet_wasm(),
//         encode_upgrade_args,
//     )
// }

#[test]
fn test_upgrade_archive_options() {
    ic_ledger_suite_state_machine_tests::test_upgrade_archive_options(
        ledger_wasm(),
        encode_init_args_with_small_sized_archive,
    );
}

#[test]
fn test_tx_deduplication() {
    ic_ledger_suite_state_machine_tests::test_tx_deduplication(ledger_wasm(), encode_init_args);
}

#[test]
fn test_mint_burn() {
    ic_ledger_suite_state_machine_tests::test_mint_burn(ledger_wasm(), encode_init_args);
}

#[test]
fn test_mint_burn_fee_rejected() {
    ic_ledger_suite_state_machine_tests::test_mint_burn_fee_rejected(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_anonymous_transfers() {
    ic_ledger_suite_state_machine_tests::test_anonymous_transfers(ledger_wasm(), encode_init_args);
}

#[test]
fn test_anonymous_approval() {
    ic_ledger_suite_state_machine_tests::test_anonymous_approval(ledger_wasm(), encode_init_args);
}

#[test]
fn test_single_transfer() {
    ic_ledger_suite_state_machine_tests::test_single_transfer(ledger_wasm(), encode_init_args);
}

#[test]
fn test_account_canonicalization() {
    ic_ledger_suite_state_machine_tests::test_account_canonicalization(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_tx_time_bounds() {
    ic_ledger_suite_state_machine_tests::test_tx_time_bounds(ledger_wasm(), encode_init_args);
}

#[test]
fn test_archiving() {
    ic_ledger_suite_state_machine_tests::test_archiving(
        ledger_wasm(),
        encode_init_args,
        archive_wasm(),
    );
}

#[test]
fn test_get_blocks() {
    ic_ledger_suite_state_machine_tests::test_get_blocks(ledger_wasm(), encode_init_args);
}

// Generate random blocks and check that their CBOR encoding complies with the CDDL spec.
#[test]
fn block_encoding_agrees_with_the_schema() {
    ic_ledger_suite_state_machine_tests::block_encoding_agrees_with_the_schema::<Tokens>();
}

// Generate random blocks and check that their value encoding complies with the ICRC-3 spec.
#[test]
fn block_encoding_agrees_with_the_icrc3_schema() {
    ic_ledger_suite_state_machine_tests::block_encoding_agreed_with_the_icrc3_schema::<Tokens>();
}

// Generate random blocks and check that their value encoding complies with the ICRC-3 spec.
#[test]
fn block_encoding_agrees_with_the_icrc107_schema() {
    ic_ledger_suite_state_machine_tests::block_encoding_agreed_with_the_icrc107_schema::<Tokens>();
}

// Check that different blocks produce different hashes.
#[test]
fn transaction_hashes_are_unique() {
    ic_ledger_suite_state_machine_tests::transaction_hashes_are_unique::<Tokens>();
}

// Check that different blocks produce different hashes.
#[test]
fn block_hashes_are_unique() {
    ic_ledger_suite_state_machine_tests::block_hashes_are_unique::<Tokens>();
}

// Generate random blocks and check that the block hash is stable.
#[test]
fn block_hashes_are_stable() {
    ic_ledger_suite_state_machine_tests::block_hashes_are_stable::<Tokens>();
}

#[test]
fn check_transfer_model() {
    ic_ledger_suite_state_machine_tests::check_transfer_model(ledger_wasm(), encode_init_args);
}

#[test]
fn check_fee_collector() {
    ic_ledger_suite_state_machine_tests::fee_collector::test_fee_collector(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn check_fee_collector_blocks() {
    ic_ledger_suite_state_machine_tests::fee_collector::test_fee_collector_blocks(
        ledger_wasm(),
        encode_init_args,
        BlockRetrieval::Legacy,
    );
}

#[test]
fn check_fee_collector_icrc3_blocks() {
    ic_ledger_suite_state_machine_tests::fee_collector::test_fee_collector_blocks(
        ledger_wasm(),
        encode_init_args,
        BlockRetrieval::Icrc3,
    );
}

#[test]
fn check_memo_max_len() {
    ic_ledger_suite_state_machine_tests::test_memo_max_len(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_smoke() {
    ic_ledger_suite_state_machine_tests::test_approve_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expiration() {
    ic_ledger_suite_state_machine_tests::test_approve_expiration(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_self() {
    ic_ledger_suite_state_machine_tests::test_approve_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_expected_allowance() {
    ic_ledger_suite_state_machine_tests::test_approve_expected_allowance(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_approve_cant_pay_fee() {
    ic_ledger_suite_state_machine_tests::test_approve_cant_pay_fee(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_cap() {
    ic_ledger_suite_state_machine_tests::test_approve_cap::<LedgerArgument, Tokens>(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_approve_pruning() {
    ic_ledger_suite_state_machine_tests::test_approve_pruning(ledger_wasm(), encode_init_args);
}

#[test]
fn test_approve_from_minter() {
    ic_ledger_suite_state_machine_tests::test_approve_from_minter(ledger_wasm(), encode_init_args);
}

#[test]
fn test_allowance_listing_sequences() {
    ic_ledger_suite_state_machine_tests::test_allowance_listing_sequences(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_allowance_listing_values() {
    ic_ledger_suite_state_machine_tests::test_allowance_listing_values(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_allowance_listing_subaccount() {
    ic_ledger_suite_state_machine_tests::test_allowance_listing_subaccount(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_allowance_listing_take() {
    ic_ledger_suite_state_machine_tests::test_allowance_listing_take(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_transfer_from_smoke() {
    ic_ledger_suite_state_machine_tests::test_transfer_from_smoke(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_self() {
    ic_ledger_suite_state_machine_tests::test_transfer_from_self(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_minter() {
    ic_ledger_suite_state_machine_tests::test_transfer_from_minter(ledger_wasm(), encode_init_args);
}

#[test]
fn test_transfer_from_burn() {
    ic_ledger_suite_state_machine_tests::test_transfer_from_burn(ledger_wasm(), encode_init_args);
}

#[test]
fn test_archive_controllers() {
    ic_ledger_suite_state_machine_tests::test_archive_controllers(ledger_wasm());
}

#[test]
fn test_archive_no_additional_controllers() {
    ic_ledger_suite_state_machine_tests::test_archive_no_additional_controllers(ledger_wasm());
}

#[test]
fn test_archive_duplicate_controllers() {
    ic_ledger_suite_state_machine_tests::test_archive_duplicate_controllers(ledger_wasm());
}

#[test]
fn test_setting_fee_collector_to_minting_account() {
    ic_ledger_suite_state_machine_tests::test_setting_fee_collector_to_minting_account(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_icrc21_standard() {
    ic_ledger_suite_state_machine_tests::test_icrc21_standard(ledger_wasm(), encode_init_args);
}

#[test]
fn test_icrc21_fee_error() {
    ic_ledger_suite_state_machine_tests::test_icrc21_fee_error(ledger_wasm(), encode_init_args);
}

#[test]
fn test_archiving_lots_of_blocks_after_enabling_archiving() {
    ic_ledger_suite_state_machine_tests::archiving::test_archiving_lots_of_blocks_after_enabling_archiving(
        ledger_wasm(), encode_init_args,
        icrc_archives,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
    );
}

#[test]
fn test_archiving_in_chunks_returns_disjoint_block_range_locations() {
    ic_ledger_suite_state_machine_tests::archiving::test_archiving_in_chunks_returns_disjoint_block_range_locations(
        ledger_wasm(), encode_init_args,
        icrc_archives,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
    );
}

#[test]
fn test_archiving_respects_num_blocks_to_archive_upper_limit() {
    ic_ledger_suite_state_machine_tests::archiving::test_archiving_respects_num_blocks_to_archive_upper_limit(
        ledger_wasm(), encode_init_args, 250_000,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
        icrc_archives,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
    );
}

#[test]
fn test_get_blocks_returns_multiple_archive_callbacks() {
    ic_ledger_suite_state_machine_tests::archiving::test_get_blocks_returns_multiple_archive_callbacks(
        ledger_wasm(),
        encode_init_args,
        icrc_archives,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
    );
}

#[test]
fn test_archiving_fails_on_app_subnet_if_ledger_does_not_have_enough_cycles() {
    ic_ledger_suite_state_machine_tests::archiving::test_archiving_fails_on_app_subnet_if_ledger_does_not_have_enough_cycles(
        ledger_wasm(),
        encode_init_args,
        icrc_archives,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
    );
}

#[test]
fn test_archiving_succeeds_on_system_subnet_if_ledger_does_not_have_any_cycles() {
    ic_ledger_suite_state_machine_tests::archiving::test_archiving_succeeds_on_system_subnet_if_ledger_does_not_have_any_cycles(
        ledger_wasm(),
        encode_init_args,
        icrc_archives,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
    );
}

#[test]
fn test_archiving_succeeds_if_ledger_has_enough_cycles_to_attach() {
    ic_ledger_suite_state_machine_tests::archiving::test_archiving_succeeds_if_ledger_has_enough_cycles_to_attach(
        ledger_wasm(),
        encode_init_args,
        icrc_archives,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
    );
}

#[test]
fn test_archiving_skipped_if_cycles_to_create_archive_less_than_cost() {
    ic_ledger_suite_state_machine_tests::archiving::test_archiving_skipped_if_cycles_to_create_archive_less_than_cost(
        ledger_wasm(),
        encode_init_args,
        icrc_archives,
        ic_ledger_suite_state_machine_tests::archiving::query_icrc3_get_blocks,
    );
}

fn encode_icrc106_upgrade_args(index_principal: Option<Principal>) -> LedgerArgument {
    LedgerArgument::Upgrade(Some(UpgradeArgs {
        metadata: None,
        token_name: None,
        token_symbol: None,
        transfer_fee: None,
        change_fee_collector: None,
        max_memo_length: None,
        feature_flags: None,
        change_archive_options: None,
        index_principal,
    }))
}

#[test]
fn test_icrc106_unsupported_if_index_not_set() {
    ic_ledger_suite_state_machine_tests::icrc_106::test_icrc106_supported_even_if_index_not_set(
        ledger_wasm(),
        encode_init_args,
        encode_icrc106_upgrade_args,
    );
}

#[test]
fn test_icrc106_set_index_in_install() {
    ic_ledger_suite_state_machine_tests::icrc_106::test_icrc106_set_index_in_install(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_icrc106_set_index_in_install_with_mainnet_ledger_wasm() {
    ic_ledger_suite_state_machine_tests::icrc_106::test_icrc106_set_index_in_install_with_mainnet_ledger_wasm(
        ledger_mainnet_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_icrc106_set_index_in_upgrade() {
    ic_ledger_suite_state_machine_tests::icrc_106::test_icrc106_set_index_in_upgrade(
        ledger_wasm(),
        encode_init_args,
        encode_icrc106_upgrade_args,
    );
}

#[test]
fn test_upgrade_from_mainnet_ledger_version() {
    ic_ledger_suite_state_machine_tests::icrc_106::test_upgrade_downgrade_with_mainnet_ledger(
        ledger_mainnet_wasm(),
        ledger_wasm(),
        encode_init_args,
        encode_upgrade_args,
        encode_icrc106_upgrade_args,
    );
}

#[test]
fn test_icrc1_test_suite() {
    ic_ledger_suite_state_machine_tests::test_icrc1_test_suite(ledger_wasm(), encode_init_args);
}

#[test]
fn test_ledger_http_request_decoding_quota() {
    ic_ledger_suite_state_machine_tests::test_ledger_http_request_decoding_quota(
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_block_transformation() {
    ic_ledger_suite_state_machine_tests::icrc1_test_block_transformation::<LedgerArgument, Tokens>(
        ledger_mainnet_wasm(),
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_upgrade_serialization_from_v2() {
    icrc1_test_upgrade_serialization(ledger_mainnet_v2_wasm(), true);
}

#[test]
fn icrc1_test_upgrade_serialization_from_v3() {
    icrc1_test_upgrade_serialization(ledger_mainnet_v3_wasm(), true);
}

fn icrc1_test_upgrade_serialization(ledger_mainnet_wasm: Vec<u8>, mainnet_on_prev_version: bool) {
    let minter = Arc::new(minter_identity());
    let builder = LedgerInitArgsBuilder::with_symbol_and_name(TOKEN_SYMBOL, TOKEN_NAME)
        .with_minting_account(minter.sender().unwrap())
        .with_transfer_fee(FEE);
    let init_args = Encode!(&LedgerArgument::Init(builder.build())).unwrap();
    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    ic_ledger_suite_state_machine_tests::test_upgrade_serialization::<Tokens>(
        ledger_mainnet_wasm,
        ledger_wasm(),
        init_args,
        upgrade_args,
        minter,
        true,
        mainnet_on_prev_version,
        true,
    );
}

fn get_all_blocks(state_machine: &StateMachine, ledger_id: CanisterId) -> Vec<EncodedBlock> {
    let blocks = get_all_ledger_and_archive_blocks::<Tokens>(state_machine, ledger_id, None, None);
    blocks.into_iter().map(|b| b.encode()).collect()
}

#[test]
fn icrc1_test_multi_step_migration_from_v3() {
    ic_ledger_suite_state_machine_tests::icrc1_test_multi_step_migration(
        ledger_mainnet_v3_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
        get_all_blocks,
    );
}

#[test]
fn icrc1_test_multi_step_migration_from_v2() {
    ic_ledger_suite_state_machine_tests::icrc1_test_multi_step_migration(
        ledger_mainnet_v2_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
        get_all_blocks,
    );
}

#[test]
fn icrc1_test_multi_step_migration_from_v2_noledgerversion() {
    ic_ledger_suite_state_machine_tests::icrc1_test_multi_step_migration(
        ledger_mainnet_v2_noledgerversion_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
        get_all_blocks,
    );
}

#[test]
fn icrc1_test_downgrade_from_incompatible_version() {
    ic_ledger_suite_state_machine_tests::test_downgrade_from_incompatible_version(
        ledger_mainnet_wasm(),
        ledger_wasm_nextledgerversion(),
        ledger_wasm(),
        encode_init_args,
        true,
    );
}

#[test]
fn icrc1_test_stable_migration_endpoints_disabled_from_v3() {
    test_stable_migration_endpoints_disabled(ledger_mainnet_v3_wasm());
}

#[test]
fn icrc1_test_stable_migration_endpoints_disabled_from_v2() {
    test_stable_migration_endpoints_disabled(ledger_mainnet_v2_wasm());
}

fn test_stable_migration_endpoints_disabled(ledger_wasm_mainnet: Vec<u8>) {
    let get_blocks_arg = Encode!(&GetBlocksRequest {
        start: Nat::from(0u64),
        length: Nat::from(1u64),
    })
    .unwrap();
    let args: Vec<GetBlocksRequest> = vec![];
    let icrc3_get_blocks_arg = Encode!(&args).unwrap();
    ic_ledger_suite_state_machine_tests::icrc1_test_stable_migration_endpoints_disabled(
        ledger_wasm_mainnet,
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args_no_archiving,
        vec![
            ("get_blocks", get_blocks_arg.clone()),
            ("get_transactions", get_blocks_arg),
            ("icrc3_get_blocks", icrc3_get_blocks_arg),
            ("get_data_certificate", Encode!().unwrap()),
            ("icrc3_get_tip_certificate", Encode!().unwrap()),
        ],
    );
}

#[test]
fn icrc1_test_incomplete_migration_from_v3() {
    ic_ledger_suite_state_machine_tests::test_incomplete_migration(
        ledger_mainnet_v3_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_incomplete_migration_from_v2() {
    ic_ledger_suite_state_machine_tests::test_incomplete_migration(
        ledger_mainnet_v2_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_incomplete_migration_from_v2_noledgerversion() {
    ic_ledger_suite_state_machine_tests::test_incomplete_migration(
        ledger_mainnet_v2_noledgerversion_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_incomplete_migration_to_current_from_v3() {
    ic_ledger_suite_state_machine_tests::test_incomplete_migration_to_current(
        ledger_mainnet_v3_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_incomplete_migration_to_current_from_v2() {
    ic_ledger_suite_state_machine_tests::test_incomplete_migration_to_current(
        ledger_mainnet_v2_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_incomplete_migration_to_current_from_v2_noledgerversion() {
    ic_ledger_suite_state_machine_tests::test_incomplete_migration_to_current(
        ledger_mainnet_v2_noledgerversion_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_migration_resumes_from_frozen_from_v3() {
    ic_ledger_suite_state_machine_tests::test_migration_resumes_from_frozen(
        ledger_mainnet_v3_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_migration_resumes_from_frozen_from_v2() {
    ic_ledger_suite_state_machine_tests::test_migration_resumes_from_frozen(
        ledger_mainnet_v2_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_metrics_while_migrating_from_v3() {
    ic_ledger_suite_state_machine_tests::test_metrics_while_migrating(
        ledger_mainnet_v3_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_metrics_while_migrating_from_v2() {
    ic_ledger_suite_state_machine_tests::test_metrics_while_migrating(
        ledger_mainnet_v2_wasm(),
        ledger_wasm_lowupgradeinstructionlimits(),
        encode_init_args,
    );
}

#[test]
fn icrc1_test_upgrade_from_v1_not_possible() {
    ic_ledger_suite_state_machine_tests::test_upgrade_not_possible(
        ledger_mainnet_v1_wasm(),
        ledger_wasm(),
        "Cannot upgrade from scratch stable memory, please upgrade to memory manager first.",
        encode_init_args,
    );
}

#[test]
fn test_setting_forbidden_metadata_in_init_works_in_v3_ledger() {
    ic_ledger_suite_state_machine_tests::metadata::test_setting_forbidden_metadata_works_in_v3_ledger(
        ledger_mainnet_v3_wasm(),
        encode_init_args_with_provided_metadata,
    );
}

#[test]
fn test_setting_forbidden_metadata_not_possible() {
    ic_ledger_suite_state_machine_tests::metadata::test_setting_forbidden_metadata_not_possible(
        ledger_wasm(),
        encode_init_args_with_provided_metadata,
    );
}

#[test]
fn test_cycles_for_archive_creation_no_overwrite_of_none_in_upgrade() {
    ic_ledger_suite_state_machine_tests::test_cycles_for_archive_creation_no_overwrite_of_none_in_upgrade(
        ledger_mainnet_v2_wasm(),
        ledger_wasm(),
        encode_init_args,
    );
}

#[test]
fn test_cycles_for_archive_creation_default_spawns_archive() {
    ic_ledger_suite_state_machine_tests::test_cycles_for_archive_creation_default_spawns_archive(
        ledger_wasm(),
        encode_init_args,
    );
}

mod metrics {
    use crate::{encode_init_args, encode_upgrade_args, ledger_wasm};
    use ic_ledger_suite_state_machine_tests::metrics::LedgerSuiteType;

    #[test]
    fn should_export_num_archives_metrics() {
        ic_ledger_suite_state_machine_tests::metrics::assert_existence_of_ledger_num_archives_metric(
            ledger_wasm(),
            encode_init_args,
        );
    }

    #[test]
    fn should_export_heap_memory_usage_metrics() {
        ic_ledger_suite_state_machine_tests::metrics::assert_existence_of_heap_memory_bytes_metric(
            ledger_wasm(),
            encode_init_args,
        );
    }

    #[test]
    fn should_export_ledger_total_transactions_metrics() {
        ic_ledger_suite_state_machine_tests::metrics::assert_existence_of_ledger_total_transactions_metric(
            ledger_wasm(),
            encode_init_args,
            LedgerSuiteType::ICRC,
        );
    }

    #[test]
    fn should_set_ledger_upgrade_instructions_consumed_metric() {
        ic_ledger_suite_state_machine_tests::metrics::assert_ledger_upgrade_instructions_consumed_metric_set(
            ledger_wasm(),
            encode_init_args,
            encode_upgrade_args,
        );
    }

    #[test]
    fn should_compute_and_export_total_volume_metric() {
        ic_ledger_suite_state_machine_tests::metrics::should_compute_and_export_total_volume_metric(
            ledger_wasm(),
            encode_init_args,
        );
    }
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

#[test]
fn test_icrc2_feature_flag_doesnt_disable_icrc2_endpoints() {
    // Disable ICRC-2 and check the endpoints still work

    let env = StateMachine::new();
    let init_args = Encode!(&LedgerArgument::Init(InitArgs {
        minting_account: MINTER,
        fee_collector_account: None,
        initial_balances: vec![],
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
        max_memo_length: None,
        feature_flags: Some(FeatureFlags { icrc2: false }),
        index_principal: None,
    }))
    .unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm(), init_args, None)
        .unwrap();
    let user1 = account(1);
    let user2 = account(2);
    let user3 = account(3);

    // if ICRC-2 is enabled then none of the following operations
    // should trap

    assert_eq!(
        Account::get_allowance(&env, ledger_id, user1, user2),
        Allowance {
            allowance: 0u32.into(),
            expires_at: None
        }
    );

    let approval_result = send_approval(
        &env,
        ledger_id,
        user1.owner,
        &ApproveArgs {
            from_subaccount: None,
            spender: user3,
            amount: 1_000_000u32.into(),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    assert_eq!(
        approval_result,
        Err(ApproveError::InsufficientFunds {
            balance: 0u32.into()
        })
    );

    let transfer_from_result = send_transfer_from(
        &env,
        ledger_id,
        user3.owner,
        &TransferFromArgs {
            spender_subaccount: None,
            from: user1,
            to: user2,
            amount: 1_000_000u32.into(),
            fee: None,
            memo: None,
            created_at_time: None,
        },
    );
    assert_eq!(
        transfer_from_result,
        Err(TransferFromError::InsufficientAllowance {
            allowance: 0u32.into()
        })
    );
}

fn icrc3_get_archives(
    env: &StateMachine,
    ledger_id: CanisterId,
    args: GetArchivesArgs,
) -> GetArchivesResult {
    let args = Encode!(&args).unwrap();
    let res = env
        .query(ledger_id, "icrc3_get_archives", args)
        .expect("Unable to call icrc3_get_archives")
        .bytes();
    Decode!(&res, GetArchivesResult).unwrap()
}

fn icrc3_get_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    args: Vec<GetBlocksRequest>,
) -> GetBlocksResult {
    let args = Encode!(&args).unwrap();
    let res = env
        .query(ledger_id, "icrc3_get_blocks", args)
        .expect("Unable to call icrc3_get_blocks")
        .bytes();
    Decode!(&res, GetBlocksResult).unwrap()
}

fn get_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    args: GetBlocksRequest,
) -> GetBlocksResponse {
    let args = Encode!(&args).unwrap();
    let res = env
        .query(ledger_id, "get_blocks", args)
        .expect("Unable to call get_blocks")
        .bytes();
    Decode!(&res, GetBlocksResponse).unwrap()
}

// Runs the callback `f` returned by a Ledger against the state machine
// `env` with argument `arg`.
#[track_caller]
fn run_archive_fn<I, O>(env: &StateMachine, f: QueryArchiveFn<I, O>, arg: I) -> O
where
    I: CandidType,
    O: CandidType + for<'a> candid::Deserialize<'a>,
{
    let arg = Encode!(&arg).unwrap();
    let res = env
        .query(
            CanisterId::unchecked_from_principal(PrincipalId(f.canister_id)),
            f.method,
            arg,
        )
        .unwrap()
        .bytes();
    Decode!(&res, O).unwrap()
}

#[test]
fn test_icrc3_get_archives() {
    let env = StateMachine::new();
    let minting_account = account(111);

    let mint_block_size = Block {
        parent_hash: Some(HashOf::new([1; HASH_LENGTH])),
        transaction: Transaction {
            operation: Operation::Mint {
                to: minting_account,
                amount: Tokens::from(1_000_000u64),
                fee: None,
            },
            created_at_time: None,
            memo: None,
        },
        effective_fee: None,
        timestamp: 0,
        fee_collector: None,
        fee_collector_block_index: None,
        btype: None,
    }
    .encode()
    .size_bytes();
    // Make it so an archive can keep up to two blocks. There is a
    // bit of overhead so 2.5 * mint_block_size is used
    let node_max_memory_size_bytes = Some((2.5 * mint_block_size as f64).ceil() as u64);
    // Trigger block archival every 2 blocks local to the ledger and
    // archive both blocks immediately
    let trigger_threshold = 2;
    let num_blocks_to_archive = 2;

    let args = LedgerArgument::Init(InitArgs {
        minting_account,
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: Nat::from(0u64),
        decimals: None,
        token_name: "Not a Token".to_string(),
        token_symbol: "NAT".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold,
            num_blocks_to_archive,
            node_max_memory_size_bytes,
            max_message_size_bytes: None,
            controller_id: PrincipalId(minting_account.owner),
            more_controller_ids: None,
            cycles_for_archive_creation: Some(0),
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        index_principal: None,
    });
    let args = Encode!(&args).unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm(), args, None)
        .expect("Unable to install the ledger");

    // check that there are no archives if there are no blocks
    let actual = icrc3_get_archives(&env, ledger_id, GetArchivesArgs { from: None });
    assert_eq!(actual, vec![]);

    let actual = icrc3_get_archives(
        &env,
        ledger_id,
        GetArchivesArgs {
            from: Some(minting_account.owner),
        },
    );
    assert_eq!(actual, vec![]);

    // push 4 mint blocks to create 2 archives (see archive options above)
    for _block_id in 0..4 {
        let _ = transfer(&env, ledger_id, minting_account, account(1), 1_000_000);
    }
    let mut actual = icrc3_get_archives(&env, ledger_id, GetArchivesArgs { from: None });
    assert_eq!(2, actual.len());
    actual.sort_by(|i1, i2| i1.start.cmp(&i2.start));
    // the first archive contains blocks 0 and 1
    assert_eq!(0u64, actual[0].start);
    assert_eq!(1u64, actual[0].end);
    // the second archive contains blocks 2 and 3
    assert_eq!(2u64, actual[1].start);
    assert_eq!(3u64, actual[1].end);

    // query all the archives after the first one
    let from = actual.iter().map(|info| info.canister_id).min();
    let actual = icrc3_get_archives(&env, ledger_id, GetArchivesArgs { from });
    assert_eq!(1, actual.len());

    // query all the archives after the last one
    let from = Some(actual[0].canister_id);
    let actual = icrc3_get_archives(&env, ledger_id, GetArchivesArgs { from });
    assert_eq!(0, actual.len());
}

#[test]
fn test_icrc3_get_blocks() {
    let env = StateMachine::new();
    let minting_account = account(111);

    // Trigger block archival every 10 blocks local to the ledger and
    // archive all blocks immediately
    let trigger_threshold = 10;
    let num_blocks_to_archive = 10;

    let args = LedgerArgument::Init(InitArgs {
        minting_account,
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: Nat::from(0u64),
        decimals: None,
        token_name: "Not a Token".to_string(),
        token_symbol: "NAT".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold,
            num_blocks_to_archive,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId(minting_account.owner),
            more_controller_ids: None,
            cycles_for_archive_creation: Some(0),
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        index_principal: None,
    });
    let args = Encode!(&args).unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm(), args, None)
        .expect("Unable to install the ledger");

    // This test is split in 2:
    // 1. check that all the blocks and the archives
    //    containing them are returned and are consistent
    //    with `get_blocks`
    // 2. Use 1. to check various ranges

    ////////
    // 1. check that all the blocks and the archives

    let icrc3_get_blocks_ = |ranges: Vec<(u64, u64)>| {
        let ranges = ranges
            .into_iter()
            .map(|(start, length)| GetBlocksRequest {
                start: Nat::from(start),
                length: Nat::from(length),
            })
            .collect();
        icrc3_get_blocks(&env, ledger_id, ranges)
    };

    let get_blocks_ = |start: u64, length: u64| {
        let arg = GetBlocksRequest {
            start: Nat::from(start),
            length: Nat::from(length),
        };
        get_blocks(&env, ledger_id, arg)
    };

    fn check_old_vs_icrc3_blocks<T>(
        block_index: T,
        expected_block: Value,
        BlockWithId { id, block }: BlockWithId,
    ) where
        Nat: From<T>,
    {
        let block_index = Nat::from(block_index);
        assert_eq!(id, block_index);
        // block is an ICRC3Value while expected_block is a Value.
        // We can check they are "the same" by checking that their hash
        // is the same.
        assert_eq!(
            expected_block.hash(),
            block.clone().hash(),
            "Block {block_index} is different.\nExpected Block: {expected_block}\nActual   Block: {block}",
        )
    }

    // query empty range
    let res = icrc3_get_blocks_(vec![]);
    assert_eq!(res.log_length, 0u64);
    assert_eq!(res.blocks, vec![]);
    assert_eq!(res.archived_blocks, vec![]);

    // query the full range
    let res = icrc3_get_blocks_(vec![(0, u64::MAX)]);
    assert_eq!(res.log_length, 0u64);
    assert_eq!(res.blocks, vec![]);
    assert_eq!(res.archived_blocks, vec![]);

    // Create 1 archive with 10 blocks (1 mint and 9 transfers)
    let _ = transfer(
        &env,
        ledger_id,
        minting_account,
        account(1),
        1_000_000_000_000,
    );
    for _block_id in 1..10 {
        let _ = transfer(&env, ledger_id, account(1), account(2), 100_000_000);
    }

    // Add 4 blocks local to the Ledger
    for _block_id in 10..14 {
        let _ = transfer(&env, ledger_id, account(1), account(2), 100_000_000);
    }

    // Use the "old" API to fetch the blocks
    let expected_res = get_blocks_(0, u64::MAX);
    // sanity check
    assert_eq!(expected_res.chain_length, 14);
    assert_eq!(expected_res.blocks.len(), 4);
    assert_eq!(expected_res.archived_blocks.len(), 1);

    // Query empty range
    let actual_res = icrc3_get_blocks_(vec![]);
    assert_eq!(actual_res.log_length, 14u64);
    assert_eq!(actual_res.blocks, vec![]);
    assert_eq!(actual_res.archived_blocks, vec![]);

    // Query the full range and check everything in the response.
    // This set of check is the baseline for further testing
    let actual_res = icrc3_get_blocks_(vec![(0, u64::MAX)]);
    assert_eq!(actual_res.log_length, 14u64);

    // check the local blocks
    assert_eq!(actual_res.blocks.len(), 4);
    for (local_index, (actual_block, expected_block)) in actual_res
        .blocks
        .into_iter()
        .zip(expected_res.blocks.into_iter())
        .enumerate()
    {
        check_old_vs_icrc3_blocks(
            10 + local_index,
            expected_block.clone(),
            actual_block.clone(),
        );
    }

    // check the archived blocks info
    assert_eq!(actual_res.archived_blocks.len(), 1);
    let actual_archived = &actual_res.archived_blocks[0];
    let expected_archived = &expected_res.archived_blocks[0];
    // check that the archive id is correct
    assert_eq!(
        &expected_archived.callback.canister_id,
        &actual_archived.callback.canister_id,
    );
    assert_eq!("icrc3_get_blocks", &actual_archived.callback.method);
    // check that the arguments are correct
    assert_eq!(
        vec![GetBlocksRequest {
            start: expected_archived.start.clone(),
            length: expected_archived.length.clone(),
        }],
        actual_archived.args
    );

    // fetch the archived blocks and check them too
    let expected_archived_blocks = run_archive_fn(
        &env,
        expected_archived.callback.clone(),
        GetBlocksRequest {
            start: expected_archived.start.clone(),
            length: expected_archived.length.clone(),
        },
    );
    let actual_archived_blocks = run_archive_fn(
        &env,
        actual_archived.callback.clone(),
        actual_archived.args.clone(),
    );
    assert_eq!(expected_archived_blocks.blocks.len(), 10);
    assert_eq!(actual_archived_blocks.blocks.len(), 10);
    // the archive has no archived blocks
    assert_eq!(actual_archived_blocks.archived_blocks.len(), 0);
    // the archive only knows the length of its local chain
    assert_eq!(actual_archived_blocks.log_length, 10u64);

    for (block_index, (actual_block, expected_block)) in actual_archived_blocks
        .blocks
        .into_iter()
        .zip(expected_archived_blocks.blocks.into_iter())
        .enumerate()
    {
        check_old_vs_icrc3_blocks(block_index, expected_block.clone(), actual_block.clone());
    }

    ////////
    // 2. At this point we know that icrc3_get_blocks returns the correct
    // blocks when the full range is asked. We use that result to check
    // various inputs.

    let get_all_blocks = |ranges: Vec<(u64, u64)>| {
        let ranges = ranges
            .into_iter()
            .map(|(start, length)| GetBlocksRequest {
                start: Nat::from(start),
                length: Nat::from(length),
            })
            .collect();
        let mut res = icrc3_get_blocks(&env, ledger_id, ranges);
        let mut blocks = vec![];
        for ArchivedBlocks { callback, args } in res.archived_blocks {
            let mut archived_res = run_archive_fn(&env, callback, args);
            // sanity check
            assert_eq!(archived_res.archived_blocks.len(), 0);
            blocks.append(&mut archived_res.blocks);
        }
        blocks.append(&mut res.blocks);
        blocks
    };

    // Baseline to use to run all the rest of the tests.
    // We know this works because of the previous part of the test.
    let expected_blocks_by_id = get_all_blocks(vec![(0, u64::MAX)])
        .into_iter()
        .map(|BlockWithId { id, block }| (id, block))
        .collect::<BTreeMap<_, _>>();

    let expected_num_blocks = |ranges: &Vec<(u64, u64)>| {
        let mut count = 0;
        for (start, length) in ranges {
            let start = *start;
            let length = *length;
            if start >= expected_blocks_by_id.len() as u64 {
                continue;
            }
            let end = (start + length).min(expected_blocks_by_id.len() as u64);
            count += end - start;
        }
        count as usize
    };

    let check_icrc3_get_blocks = |ranges: Vec<(u64, u64)>| {
        let expected_block_count = expected_num_blocks(&ranges);
        let all_blocks = get_all_blocks(ranges.clone());
        assert_eq!(
            expected_block_count,
            all_blocks.len(),
            "Expected {} blocks but got {} blocks, total num blocks: {}, ranges: {:?}",
            expected_block_count,
            all_blocks.len(),
            expected_blocks_by_id.len(),
            &ranges
        );
        for (pos, BlockWithId { id, block }) in all_blocks.into_iter().enumerate() {
            let expected_block = match expected_blocks_by_id.get(&id) {
                None => panic!("Got block with id {id} at position {pos} which doesn't exist"),
                Some(expected_block) => expected_block,
            };
            assert_eq!(expected_block, &block, "id: {id}, position: {pos}");
        }
    };

    // sanity check
    check_icrc3_get_blocks(vec![]);
    check_icrc3_get_blocks(vec![(0, u64::MAX)]);

    // Run tests for various ranges

    // empty range and empty range multiple times
    check_icrc3_get_blocks(vec![(0, 0)]);
    check_icrc3_get_blocks(vec![(0, 0), (0, 0)]);

    // one block
    check_icrc3_get_blocks(vec![(0, 1)]);

    // two blocks but in two ranges
    check_icrc3_get_blocks(vec![(0, 1), (1, 1)]);

    // one block twice
    check_icrc3_get_blocks(vec![(1, 2), (1, 2)]);

    // out of range and out of range multiple times
    check_icrc3_get_blocks(vec![(15, 1)]);
    check_icrc3_get_blocks(vec![(15, 1), (15, 1)]);

    // first high block index
    check_icrc3_get_blocks(vec![(2, 3), (1, 1)]);

    // multiple ranges
    check_icrc3_get_blocks(vec![(2, 3), (1, 2), (0, 10), (10, 5)]);

    verify_ledger_state::<Tokens>(&env, ledger_id, None, AllowancesRecentlyPurged::Yes);
}

#[test]
fn test_icrc3_get_blocks_number_of_blocks_limit() {
    let env = StateMachine::new();
    let minting_account = account(111);

    // Create 1000 mint blocks
    const NUM_MINT_BLOCKS: usize = 1000;
    let initial_balances = (0..NUM_MINT_BLOCKS)
        .map(|i| (account(i as u64), Nat::from(1_000_000_000u64)))
        .collect();

    let args = LedgerArgument::Init(InitArgs {
        minting_account,
        fee_collector_account: None,
        initial_balances,
        transfer_fee: Nat::from(0u64),
        decimals: None,
        token_name: "Not a Token".to_string(),
        token_symbol: "NAT".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            // we don't want to archive ever
            trigger_threshold: 2 * NUM_MINT_BLOCKS,
            num_blocks_to_archive: 10,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: PrincipalId(minting_account.owner),
            more_controller_ids: None,
            cycles_for_archive_creation: Some(0),
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        index_principal: None,
    });

    let args = Encode!(&args).unwrap();
    let ledger_id = env
        .install_canister(ledger_wasm(), args, None)
        .expect("Unable to install the ledger");

    let check_icrc3_get_block_limit = |ranges: Vec<(u64, u64)>| {
        let req_ranges: Vec<_> = ranges
            .iter()
            .map(|(start, length)| GetBlocksRequest {
                start: Nat::from(*start),
                length: Nat::from(*length),
            })
            .collect();
        let res = icrc3_get_blocks(&env, ledger_id, req_ranges);
        // sanity check
        assert_eq!(res.log_length, NUM_MINT_BLOCKS);
        assert_eq!(res.archived_blocks.len(), 0);

        // check that no more than 100 blocks were returned
        // regardless of the input
        assert!(
            res.blocks.len() <= 100,
            "expected <= 100 blocks but got {} for ranges {ranges:?}",
            res.blocks.len()
        );
    };

    check_icrc3_get_block_limit(vec![(0, u64::MAX)]);
    check_icrc3_get_block_limit(vec![(0, u64::MAX), (0, u64::MAX)]);
    check_icrc3_get_block_limit(vec![(0, 101)]);
    check_icrc3_get_block_limit(vec![(0, 100), (0, 1)]);
    check_icrc3_get_block_limit(vec![(0, 1), (0, 100)]);
}

#[test]
fn test_icrc3_certificate_ledger_upgrade() {
    use ic_cbor::CertificateToCbor;
    use ic_certification::hash_tree::{HashTreeNode, SubtreeLookupResult};
    use ic_certification::{Certificate, HashTree};
    use ic_ledger_suite_state_machine_helpers::send_transfer;
    use icrc_ledger_types::icrc3::blocks::ICRC3DataCertificate;

    const NUM_BLOCKS: u64 = 10;

    let env = StateMachine::new();
    let minting_account = account(111);

    let init_args = ic_icrc1_ledger::InitArgsBuilder::for_tests()
        .with_minting_account(minting_account)
        // We need an initial balance so the block certificate is not None
        .with_initial_balance(account(1), 1_000_000u64)
        .with_transfer_fee(FEE)
        .build();

    // Install the ledger with a version serving the non-compliant ICRC-3 certificate.
    let ledger_id = env
        .install_canister(
            ledger_mainnet_v3_wasm(),
            Encode!(&(LedgerArgument::Init(init_args.clone()))).unwrap(),
            None,
        )
        .expect("Unable to install the ledger");
    // Add some transactions
    for _ in 0..NUM_BLOCKS {
        send_transfer(
            &env,
            ledger_id,
            minting_account.owner,
            &TransferArg {
                from_subaccount: None,
                to: account(1),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: 1_000_000u64.into(),
            },
        )
        .expect("mint should succeed");
    }

    let old_legacy_certificate = Decode!(
        &env.query(ledger_id, "get_data_certificate", Encode!(&()).unwrap())
            .unwrap()
            .bytes(),
        icrc_ledger_types::icrc3::blocks::DataCertificate
    )
    .unwrap();
    let old_icrc3_certificate = Decode!(
        &env.query(
            ledger_id,
            "icrc3_get_tip_certificate",
            Encode!(&()).unwrap()
        )
        .unwrap()
        .bytes(),
        Option<ICRC3DataCertificate>
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        old_legacy_certificate.certificate.clone().unwrap(),
        old_icrc3_certificate.certificate
    );
    assert_eq!(
        old_legacy_certificate.hash_tree,
        old_icrc3_certificate.hash_tree
    );

    fn lookup_hashtree(
        hash_tree: serde_bytes::ByteBuf,
        leaf_name: &str,
    ) -> Result<Vec<u8>, String> {
        let hash_tree: HashTree = ciborium::de::from_reader(hash_tree.as_slice()).unwrap();
        match hash_tree.lookup_subtree([leaf_name.as_bytes()]) {
            SubtreeLookupResult::Found(tree) => match tree.as_ref() {
                HashTreeNode::Leaf(result) => Ok(result.clone()),
                _ => Err("Expected a leaf node".to_string()),
            },
            _ => Err(format!(
                "Expected to find a leaf node: Hash tree: {hash_tree:?}, leaf_name: {leaf_name}"
            )
            .to_string()),
        }
    }

    // Verify that the new label for the last block hash is not present in the old hash tree.
    assert!(lookup_hashtree(old_icrc3_certificate.hash_tree.clone(), "last_block_hash").is_err());

    // Verify that the legacy label is present in the old hash tree.
    icrc_ledger_types::icrc::generic_value::Hash::try_from(
        lookup_hashtree(old_icrc3_certificate.hash_tree.clone(), "tip_hash").unwrap(),
    )
    .unwrap();

    // Verify that the label for the last block index is incorrectly encoded in the old hash tree.
    let old_last_block_index = u64::from_be_bytes(
        lookup_hashtree(old_icrc3_certificate.hash_tree.clone(), "last_block_index")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(NUM_BLOCKS, old_last_block_index);

    // Upgrade to the ledger that serves the correct ICRC-3 certificate.
    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");

    let new_legacy_certificate = Decode!(
        &env.query(ledger_id, "get_data_certificate", Encode!(&()).unwrap())
            .unwrap()
            .bytes(),
        icrc_ledger_types::icrc3::blocks::DataCertificate
    )
    .unwrap();
    let new_icrc3_certificate = Decode!(
        &env.query(
            ledger_id,
            "icrc3_get_tip_certificate",
            Encode!(&()).unwrap()
        )
        .unwrap()
        .bytes(),
        Option<ICRC3DataCertificate>
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        new_legacy_certificate.certificate.clone().unwrap(),
        new_icrc3_certificate.certificate
    );

    // Verify that the legacy label is not present in the hash tree.
    assert!(lookup_hashtree(new_icrc3_certificate.hash_tree.clone(), "tip_hash").is_err());

    // Verify that the new label for the last block hash is present in the hash tree.
    icrc_ledger_types::icrc::generic_value::Hash::try_from(
        lookup_hashtree(new_icrc3_certificate.hash_tree.clone(), "last_block_hash").unwrap(),
    )
    .unwrap();

    // Verify that the label for the last block index is correctly encoded in the hash tree.
    let new_last_block_index = leb128::read::unsigned(&mut std::io::Cursor::new(
        lookup_hashtree(new_icrc3_certificate.hash_tree.clone(), "last_block_index").unwrap(),
    ))
    .unwrap();
    assert_eq!(NUM_BLOCKS, new_last_block_index);

    // Verify that the hash tree is different after the ledger was upgraded.
    assert_ne!(
        old_icrc3_certificate.hash_tree,
        new_icrc3_certificate.hash_tree
    );

    let old_certificate = Certificate::from_cbor(old_icrc3_certificate.certificate.as_slice())
        .expect("Unable to deserialize CBOR encoded Certificate");
    let old_hash_tree: HashTree =
        ciborium::de::from_reader(old_icrc3_certificate.hash_tree.as_slice())
            .expect("Unable to deserialize CBOR encoded hash_tree");
    let new_certificate = Certificate::from_cbor(new_icrc3_certificate.certificate.as_slice())
        .expect("Unable to deserialize CBOR encoded Certificate");
    let new_hash_tree: HashTree =
        ciborium::de::from_reader(new_icrc3_certificate.hash_tree.as_slice())
            .expect("Unable to deserialize CBOR encoded hash_tree");
    assert!(
        is_valid_root_hash(&old_certificate, &old_hash_tree.digest(), ledger_id),
        "Certified data does not match root hash for old certificate before transaction"
    );

    // Compare the certified data of the new certificate with the digest of the old hash tree.
    // These should be different, since the new certified data uses the new labels, which are not
    // present in the old hash tree.
    assert!(
        !is_valid_root_hash(&new_certificate, &old_hash_tree.digest(), ledger_id),
        "New certified data matches old root hash after upgrade before transaction"
    );
    // Compare the certified data of the new certificate with the digest of the new hash tree.
    // These should be the same, since the new certified data, as well as the new hash tree, both
    // use the new labels.
    assert!(
        is_valid_root_hash(&new_certificate, &new_hash_tree.digest(), ledger_id),
        "New certified data does not match new root hash after upgrade before transaction"
    );

    // Send a transaction, which will update the certified data.
    send_transfer(
        &env,
        ledger_id,
        minting_account.owner,
        &TransferArg {
            from_subaccount: None,
            to: account(1),
            fee: None,
            created_at_time: None,
            memo: None,
            amount: 1_000_000u64.into(),
        },
    )
    .expect("mint should succeed");

    let new_icrc3_certificate = Decode!(
        &env.query(
            ledger_id,
            "icrc3_get_tip_certificate",
            Encode!(&()).unwrap()
        )
        .unwrap()
        .bytes(),
        Option<ICRC3DataCertificate>
    )
    .unwrap()
    .unwrap();

    // Verify that the label for the last block index is correctly encoded in the hash tree.
    let new_last_block_index = leb128::read::unsigned(&mut std::io::Cursor::new(
        lookup_hashtree(new_icrc3_certificate.hash_tree.clone(), "last_block_index").unwrap(),
    ))
    .unwrap();
    assert_eq!(NUM_BLOCKS + 1, new_last_block_index);

    let new_certificate = Certificate::from_cbor(new_icrc3_certificate.certificate.as_slice())
        .expect("Unable to deserialize CBOR encoded Certificate");
    let new_hash_tree: HashTree =
        ciborium::de::from_reader(new_icrc3_certificate.hash_tree.as_slice())
            .expect("Unable to deserialize CBOR encoded hash_tree");
    assert!(
        is_valid_root_hash(&new_certificate, &new_hash_tree.digest(), ledger_id),
        "Certified data does not match root hash "
    );
}

/// Check whether the certified data at path ["canister", ledger_canister_id, "certified_data"] is equal to root_hash.
fn is_valid_root_hash(
    certificate: &ic_certification::Certificate,
    root_hash: &icrc_ledger_types::icrc::generic_value::Hash,
    ledger_canister_id: CanisterId,
) -> bool {
    use ic_certification::LookupResult;

    let certified_data_path: [ic_certification::hash_tree::Label<Vec<u8>>; 3] = [
        "canister".into(),
        ledger_canister_id.get().0.as_slice().into(),
        "certified_data".into(),
    ];

    let cert_hash = match certificate.tree.lookup_path(&certified_data_path) {
        LookupResult::Found(v) => v,
        _ => {
            panic!("could not find certified_data for canister: {ledger_canister_id}")
        }
    };

    cert_hash == root_hash
}

mod verify_written_blocks {
    use super::*;
    use ic_icrc1_ledger::FeatureFlags;
    use ic_ledger_suite_state_machine_tests::{MINTER, system_time_to_nanos};
    use ic_state_machine_tests::{StateMachine, WasmResult};
    use icrc_ledger_types::icrc1::account::Account;
    use icrc_ledger_types::icrc1::transfer::{Memo, NumTokens, TransferArg};
    use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
    use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
    use icrc_ledger_types::icrc3::transactions::{
        Approve, Burn, GetTransactionsRequest, GetTransactionsResponse, Mint, Transaction, Transfer,
    };
    use num_traits::ToPrimitive;
    use serde_bytes::ByteBuf;

    const DEFAULT_FEE: u64 = 10_000;
    const DEFAULT_AMOUNT: u64 = 1_000_000;
    const DEFAULT_MEMO: [u8; 10] = [0u8; 10];

    #[test]
    fn test_verify_written_mint_block() {
        let ledger = Setup::new();
        let mint_args = TransferArg {
            from_subaccount: ledger.minter_account.subaccount,
            to: ledger.from_account,
            amount: Nat::from(10 * DEFAULT_AMOUNT),
            fee: Some(NumTokens::from(0u8)),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
        };
        ledger.mint(&mint_args).expect_mint(Mint {
            amount: mint_args.amount,
            to: mint_args.to,
            memo: mint_args.memo,
            created_at_time: mint_args.created_at_time,
            fee: None,
        });
    }

    #[test]
    fn test_verify_written_transfer_block() {
        let ledger = Setup::new();
        let from_account = ledger.from_account;
        let transfer_args = TransferArg {
            from_subaccount: ledger.from_account.subaccount,
            to: ledger.to_account,
            fee: Some(Nat::from(DEFAULT_FEE)),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            amount: Nat::from(DEFAULT_AMOUNT),
        };
        ledger
            .icrc1_transfer(from_account, &transfer_args)
            .expect_transfer(Transfer {
                amount: transfer_args.amount,
                from: from_account,
                to: transfer_args.to,
                spender: None,
                memo: transfer_args.memo,
                fee: transfer_args.fee,
                created_at_time: transfer_args.created_at_time,
            });
    }

    #[test]
    fn test_verify_written_initial_approve_block_and_approve_block_with_expected_allowance() {
        let ledger = Setup::new();
        let from_account = ledger.from_account;
        let spender_account = ledger.minter_account;
        let approve_args = ApproveArgs {
            from_subaccount: ledger.from_account.subaccount,
            spender: ledger.minter_account,
            amount: Nat::from(2 * DEFAULT_AMOUNT),
            expected_allowance: Some(Nat::from(0u8)),
            expires_at: Some(ledger.current_time_ns_since_unix_epoch + 1_000_000),
            fee: Some(Nat::from(DEFAULT_FEE)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        let mut approve_args_with_expected_allowance = approve_args.clone();
        approve_args_with_expected_allowance.expected_allowance = Some(approve_args.amount.clone());
        approve_args_with_expected_allowance.amount = Nat::from(2 * DEFAULT_AMOUNT);
        ledger
            .icrc2_approve(from_account, &approve_args)
            .expect_approve(Approve {
                amount: approve_args.amount,
                expected_allowance: approve_args.expected_allowance,
                expires_at: approve_args.expires_at,
                memo: approve_args.memo,
                fee: approve_args.fee,
                created_at_time: approve_args.created_at_time,
                from: from_account,
                spender: spender_account,
            })
            .icrc2_approve(from_account, &approve_args_with_expected_allowance)
            .expect_approve(Approve {
                amount: approve_args_with_expected_allowance.amount,
                expected_allowance: approve_args_with_expected_allowance.expected_allowance,
                expires_at: approve_args_with_expected_allowance.expires_at,
                memo: approve_args_with_expected_allowance.memo,
                fee: approve_args_with_expected_allowance.fee,
                created_at_time: approve_args_with_expected_allowance.created_at_time,
                from: from_account,
                spender: spender_account,
            });
    }

    #[test]
    fn test_verify_written_approve_and_burn_blocks() {
        let ledger = Setup::new();
        let from_account = ledger.from_account;
        let spender_account = ledger.minter_account;
        let approve_args = ApproveArgs {
            from_subaccount: ledger.from_account.subaccount,
            spender: ledger.minter_account,
            amount: Nat::from(2 * DEFAULT_AMOUNT),
            expected_allowance: Some(Nat::from(0u8)),
            expires_at: Some(ledger.current_time_ns_since_unix_epoch + 1_000_000),
            fee: Some(Nat::from(DEFAULT_FEE)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        let burn_args = TransferFromArgs {
            spender_subaccount: spender_account.subaccount,
            from: ledger.from_account,
            to: ledger.minter_account,
            amount: Nat::from(DEFAULT_AMOUNT),
            fee: Some(NumTokens::from(0u8)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        ledger
            .icrc2_approve(from_account, &approve_args)
            .expect_approve(Approve {
                amount: approve_args.amount,
                expected_allowance: approve_args.expected_allowance,
                expires_at: approve_args.expires_at,
                memo: approve_args.memo,
                fee: approve_args.fee,
                created_at_time: approve_args.created_at_time,
                from: from_account,
                spender: spender_account,
            })
            .minter_burn(&burn_args)
            .expect_burn(Burn {
                amount: burn_args.amount,
                from: burn_args.from,
                spender: Some(spender_account),
                memo: burn_args.memo,
                created_at_time: burn_args.created_at_time,
                fee: None,
            });
    }

    #[test]
    fn test_verify_written_approve_and_transfer_from_blocks() {
        let ledger = Setup::new();
        let from_account = ledger.from_account;
        let spender_account = ledger.spender_account;
        let approve_args = ApproveArgs {
            from_subaccount: ledger.from_account.subaccount,
            spender: ledger.spender_account,
            amount: Nat::from(2 * DEFAULT_AMOUNT),
            expected_allowance: Some(Nat::from(0u8)),
            expires_at: Some(ledger.current_time_ns_since_unix_epoch + 1_000_000),
            fee: Some(Nat::from(DEFAULT_FEE)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        let transfer_from_args = TransferFromArgs {
            spender_subaccount: ledger.spender_account.subaccount,
            from: ledger.from_account,
            to: ledger.to_account,
            amount: Nat::from(DEFAULT_AMOUNT),
            fee: Some(Nat::from(DEFAULT_FEE)),
            memo: Some(Memo(ByteBuf::from(DEFAULT_MEMO))),
            created_at_time: Some(ledger.current_time_ns_since_unix_epoch),
        };
        ledger
            .icrc2_approve(from_account, &approve_args)
            .expect_approve(Approve {
                amount: approve_args.amount,
                expected_allowance: approve_args.expected_allowance,
                expires_at: approve_args.expires_at,
                memo: approve_args.memo,
                fee: approve_args.fee,
                created_at_time: approve_args.created_at_time,
                from: from_account,
                spender: spender_account,
            })
            .icrc2_transfer_from(spender_account, &transfer_from_args)
            .expect_transfer(Transfer {
                amount: transfer_from_args.amount,
                from: from_account,
                to: transfer_from_args.to,
                spender: Some(spender_account),
                memo: transfer_from_args.memo,
                fee: transfer_from_args.fee,
                created_at_time: transfer_from_args.created_at_time,
            });
    }

    struct Setup {
        minter_account: Account,
        from_account: Account,
        to_account: Account,
        spender_account: Account,
        env: StateMachine,
        ledger_id: CanisterId,
        current_time_ns_since_unix_epoch: u64,
    }

    impl Setup {
        fn new() -> Self {
            let minter_account = Account {
                owner: MINTER.owner,
                subaccount: Some([42u8; 32]),
            };
            let from_account = Account {
                owner: PrincipalId::new_user_test_id(1).0,
                subaccount: Some([1u8; 32]),
            };
            let to_account = Account {
                owner: PrincipalId::new_user_test_id(2).0,
                subaccount: Some([2u8; 32]),
            };
            let spender_account = Account {
                owner: PrincipalId::new_user_test_id(3).0,
                subaccount: Some([3u8; 32]),
            };
            let initial_balances = vec![
                (from_account, Nat::from(10 * DEFAULT_AMOUNT)),
                (to_account, Nat::from(10 * DEFAULT_AMOUNT)),
                (spender_account, Nat::from(10 * DEFAULT_AMOUNT)),
            ];
            let ledger_arg_init = LedgerArgument::Init(InitArgs {
                minting_account: minter_account,
                fee_collector_account: None,
                initial_balances,
                transfer_fee: FEE.into(),
                token_name: TOKEN_NAME.to_string(),
                decimals: Some(DECIMAL_PLACES),
                token_symbol: TOKEN_SYMBOL.to_string(),
                metadata: vec![
                    MetadataValue::entry(NAT_META_KEY, NAT_META_VALUE),
                    MetadataValue::entry(INT_META_KEY, INT_META_VALUE),
                    MetadataValue::entry(TEXT_META_KEY, TEXT_META_VALUE),
                    MetadataValue::entry(BLOB_META_KEY, BLOB_META_VALUE),
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
                max_memo_length: None,
                feature_flags: Some(FeatureFlags { icrc2: true }),
                index_principal: None,
            });

            let args = Encode!(&ledger_arg_init).unwrap();
            let env = StateMachine::new();
            let ledger_id = env.install_canister(ledger_wasm(), args, None).unwrap();

            let current_time_ns_since_unix_epoch = system_time_to_nanos(env.time());

            Self {
                minter_account,
                from_account,
                to_account,
                spender_account,
                env,
                ledger_id,
                current_time_ns_since_unix_epoch,
            }
        }

        fn get_transaction(&self, block_index: BlockIndex) -> Transaction {
            let request = GetTransactionsRequest {
                start: block_index.into(),
                length: 1u8.into(),
            };

            let wasm_result_bytes = match self
                .env
                .query(
                    self.ledger_id,
                    "get_transactions",
                    Encode!(&request).unwrap(),
                )
                .expect("failed to query get_transactions on the ledger")
            {
                WasmResult::Reply(bytes) => bytes,
                WasmResult::Reject(reject) => {
                    panic!("Expected a successful reply, got a reject: {reject}")
                }
            };
            let mut response = Decode!(&wasm_result_bytes, GetTransactionsResponse).unwrap();
            assert_eq!(
                response.transactions.len(),
                1,
                "Expected exactly one transaction but got {:?}",
                response.transactions
            );
            response.transactions.pop().unwrap()
        }

        fn mint(self, mint_args: &TransferArg) -> TransactionAssert {
            let minter_account = self.minter_account;
            self.icrc1_transfer(minter_account, mint_args)
        }

        fn icrc1_transfer(self, from: Account, transfer_args: &TransferArg) -> TransactionAssert {
            let args = Encode!(transfer_args).unwrap();
            let res = self
                .env
                .execute_ingress_as(
                    PrincipalId::from(from.owner),
                    self.ledger_id,
                    "icrc1_transfer",
                    args,
                )
                .expect("Unable to perform icrc1_transfer")
                .bytes();
            let block_index = Decode!(&res, Result<Nat, TransferError>)
                .unwrap()
                .expect("Unable to decode icrc1_transfer error")
                .0
                .to_u64()
                .unwrap();
            TransactionAssert {
                ledger: self,
                block_index,
            }
        }

        fn icrc2_transfer_from(
            self,
            spender: Account,
            transfer_from_args: &TransferFromArgs,
        ) -> TransactionAssert {
            let args = Encode!(transfer_from_args).unwrap();
            let res = self
                .env
                .execute_ingress_as(
                    PrincipalId::from(spender.owner),
                    self.ledger_id,
                    "icrc2_transfer_from",
                    args,
                )
                .expect("Unable to perform icrc2_transfer_from")
                .bytes();
            let block_index = Decode!(&res, Result<Nat, TransferFromError>)
                .unwrap()
                .expect("Unable to decode icrc2_transfer_from error")
                .0
                .to_u64()
                .unwrap();
            TransactionAssert {
                ledger: self,
                block_index,
            }
        }

        fn icrc2_approve(self, from: Account, approve_args: &ApproveArgs) -> TransactionAssert {
            let args = Encode!(approve_args).unwrap();
            let res = self
                .env
                .execute_ingress_as(from.owner.into(), self.ledger_id, "icrc2_approve", args)
                .expect("Unable to perform icrc2_approve")
                .bytes();
            let block_index = Decode!(&res, Result<Nat, ApproveError>)
                .unwrap()
                .expect("Unable to decode icrc2_approve error")
                .0
                .to_u64()
                .unwrap();
            TransactionAssert {
                ledger: self,
                block_index,
            }
        }

        fn minter_burn(self, burn_args: &TransferFromArgs) -> TransactionAssert {
            let minter_account = self.minter_account;
            self.icrc2_transfer_from(minter_account, burn_args)
        }
    }

    struct TransactionAssert {
        ledger: Setup,
        block_index: BlockIndex,
    }

    impl TransactionAssert {
        fn expect_approve(self, expected_approve: Approve) -> Setup {
            let ledger_transaction = self.ledger.get_transaction(self.block_index);
            assert_eq!("approve", ledger_transaction.kind);
            let ledger_approve = ledger_transaction
                .approve
                .as_ref()
                .expect("expecting approve transaction");
            assert_eq!(ledger_approve, &expected_approve);
            self.ledger
        }

        fn expect_mint(self, expected_mint: Mint) -> Setup {
            let ledger_transaction = self.ledger.get_transaction(self.block_index);
            assert_eq!("mint", ledger_transaction.kind);
            let ledger_mint = ledger_transaction
                .mint
                .as_ref()
                .expect("expecting mint transaction");
            assert_eq!(ledger_mint, &expected_mint);
            self.ledger
        }

        fn expect_transfer(self, expected_transfer: Transfer) -> Setup {
            let ledger_transaction = self.ledger.get_transaction(self.block_index);
            assert_eq!("transfer", ledger_transaction.kind);
            let ledger_transfer = ledger_transaction
                .transfer
                .as_ref()
                .expect("expecting transfer transaction");
            assert_eq!(ledger_transfer, &expected_transfer);
            self.ledger
        }

        fn expect_burn(self, expected_burn: Burn) -> Setup {
            let ledger_transaction = self.ledger.get_transaction(self.block_index);
            assert_eq!("burn", ledger_transaction.kind);
            let ledger_burn = ledger_transaction
                .burn
                .as_ref()
                .expect("expecting burn transaction");
            assert_eq!(ledger_burn, &expected_burn);
            self.ledger
        }
    }
}
