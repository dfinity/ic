use assert_matches::assert_matches;
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
use ic_ledger_hash_of::{HashOf, HASH_LENGTH};
use ic_state_machine_tests::ErrorCode::CanisterCalledTrap;
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
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

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

fn ledger_u64_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_LEDGER_WASM_U64_PATH").unwrap()).unwrap()
}

fn ledger_u256_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_LEDGER_WASM_U256_PATH").unwrap()).unwrap()
}

pub const MINTER: Account = Account {
    owner: PrincipalId::new(0, [0u8; 29]).0,
    subaccount: None,
};

pub const FEE: u64 = 10_000;
pub const DECIMAL_PLACES: u8 = 8;
pub const TOKEN_SYMBOL: &str = "XTST";
pub const TOKEN_NAME: &str = "Test Token";
pub const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
pub const NUM_BLOCKS_TO_ARCHIVE: u64 = 5;

fn default_init_args() -> Vec<u8> {
    Encode!(&LedgerArgument::Init(InitArgs {
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
    .unwrap()
}

// TODO: enable and rewrite when FI-1653 is fixed.
#[test]
#[should_panic(expected = "assertion `left == right` failed: u256 representation is 32-bytes long")]
fn should_fail_ledger_upgrade_from_u64_to_u256_wasm() {
    let env = StateMachine::new();
    let ledger_id = env
        .install_canister(ledger_u64_wasm(), default_init_args(), None)
        .unwrap();
    // Create a large balance
    transfer(
        &env,
        ledger_id,
        MINTER,
        PrincipalId::new_user_test_id(1).0.into(),
        u64::MAX,
    );

    // Try to upgrade the ledger from using a u64 wasm to a u256 wasm
    let upgrade_args = Encode!(&LedgerArgument::Upgrade(None)).unwrap();
    env.upgrade_canister(ledger_id, ledger_u256_wasm(), upgrade_args)
        .expect("Unable to upgrade the ledger canister");
}
