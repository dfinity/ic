use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index_ng::{GetBlocksResponse, IndexArg, InitArg as IndexInitArg, Log, Status};
use ic_icrc1_ledger::{FeatureFlags, InitArgsBuilder as LedgerInitArgsBuilder, LedgerArgument};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_suite_state_machine_helpers::get_logs;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc::metadata_key::MetadataKey;
use icrc_ledger_types::icrc1::account::Account;
#[cfg(feature = "icrc3_disabled")]
use icrc_ledger_types::icrc3::archive::{ArchivedRange, QueryBlockArchiveFn};
#[cfg(not(feature = "icrc3_disabled"))]
use icrc_ledger_types::icrc3::blocks::{ArchivedBlocks, BlockWithId};
use icrc_ledger_types::icrc3::blocks::{BlockRange, GetBlocksRequest};
use num_traits::cast::ToPrimitive;
use std::time::Duration;

pub const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;

pub const FEE: u64 = 10_000;
pub const ARCHIVE_TRIGGER_THRESHOLD: u64 = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 10;
pub const MAX_BLOCKS_FROM_ARCHIVE: u64 = 10;
pub const MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT: u8 = 100; // No reason for this number.

// Metadata-related constants
const TOKEN_NAME: &str = "Test Token";
const TOKEN_SYMBOL: &str = "XTST";
const TEXT_META_KEY: &str = "test:image";
const TEXT_META_VALUE: &str = "grumpy_cat.png";
const BLOB_META_KEY: &str = "test:blob";
const BLOB_META_VALUE: &[u8] = b"\xca\xfe\xba\xbe";
const NAT_META_KEY: &str = "test:nat";
const NAT_META_VALUE: u128 = u128::MAX;
const INT_META_KEY: &str = "test:int";
const INT_META_VALUE: i128 = i128::MIN;

#[allow(dead_code)]
pub fn account(owner: u64, subaccount: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&subaccount.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(owner).0,
        subaccount: Some(sub),
    }
}

pub fn default_archive_options() -> ArchiveOptions {
    ArchiveOptions {
        trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD as usize,
        num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
        node_max_memory_size_bytes: None,
        max_message_size_bytes: None,
        controller_id: PrincipalId::new_user_test_id(100),
        more_controller_ids: None,
        cycles_for_archive_creation: Some(0),
        max_transactions_per_response: Some(MAX_BLOCKS_FROM_ARCHIVE),
    }
}

#[allow(dead_code)]
pub fn index_ng_wasm() -> Vec<u8> {
    let index_ng_wasm_path = std::env::var("IC_ICRC1_INDEX_NG_WASM_PATH").expect(
        "The Index-ng wasm path must be set using the env variable IC_ICRC1_INDEX_NG_WASM_PATH",
    );
    std::fs::read(&index_ng_wasm_path).unwrap_or_else(|e| {
        panic!(
            "failed to load Wasm file from path {} (env var IC_ICRC1_INDEX_NG_WASM_PATH): {}",
            index_ng_wasm_path, e
        )
    })
}

pub fn install_ledger(
    env: &StateMachine,
    initial_balances: Vec<(Account, u64)>,
    archive_options: ArchiveOptions,
    fee_collector_account: Option<Account>,
    minter_principal: Principal,
) -> CanisterId {
    let mut builder = LedgerInitArgsBuilder::with_symbol_and_name(TOKEN_SYMBOL, TOKEN_NAME)
        .with_minting_account(minter_principal)
        .with_transfer_fee(FEE)
        .with_metadata_entry(NAT_META_KEY, NAT_META_VALUE)
        .with_metadata_entry(INT_META_KEY, INT_META_VALUE)
        .with_metadata_entry(TEXT_META_KEY, TEXT_META_VALUE)
        .with_metadata_entry(BLOB_META_KEY, BLOB_META_VALUE)
        .with_archive_options(archive_options)
        .with_feature_flags(FeatureFlags { icrc2: true });
    if let Some(fee_collector_account) = fee_collector_account {
        builder = builder.with_fee_collector_account(fee_collector_account);
    }
    for (account, amount) in initial_balances {
        builder = builder.with_initial_balance(account, amount);
    }
    env.install_canister_with_cycles(
        ledger_wasm(),
        Encode!(&LedgerArgument::Init(builder.build())).unwrap(),
        None,
        ic_types::Cycles::new(STARTING_CYCLES_PER_CANISTER),
    )
    .unwrap()
}

fn icrc3_test_ledger() -> Vec<u8> {
    let ledger_wasm_path = std::env::var("IC_ICRC3_TEST_LEDGER_WASM_PATH").expect(
        "The Ledger wasm path must be set using the env variable IC_ICRC3_TEST_LEDGER_WASM_PATH",
    );
    std::fs::read(&ledger_wasm_path).unwrap_or_else(|e| {
        panic!(
            "failed to load Wasm file from path {} (env var IC_ICRC3_TEST_LEDGER_WASM_PATH): {}",
            ledger_wasm_path, e
        )
    })
}

#[allow(dead_code)]
pub fn install_icrc3_test_ledger(env: &StateMachine) -> CanisterId {
    env.install_canister_with_cycles(
        icrc3_test_ledger(),
        Encode!(&()).unwrap(),
        None,
        ic_types::Cycles::new(STARTING_CYCLES_PER_CANISTER),
    )
    .unwrap()
}

#[allow(dead_code)]
pub fn install_index_ng(env: &StateMachine, init_arg: IndexInitArg) -> CanisterId {
    let args = IndexArg::Init(init_arg);
    env.install_canister_with_cycles(
        index_ng_wasm(),
        Encode!(&args).unwrap(),
        None,
        ic_types::Cycles::new(STARTING_CYCLES_PER_CANISTER),
    )
    .unwrap()
}

pub fn ledger_wasm() -> Vec<u8> {
    let ledger_wasm_path = std::env::var("IC_ICRC1_LEDGER_WASM_PATH").expect(
        "The Ledger wasm path must be set using the env variable IC_ICRC1_LEDGER_WASM_PATH",
    );
    std::fs::read(&ledger_wasm_path).unwrap_or_else(|e| {
        panic!(
            "failed to load Wasm file from path {} (env var IC_ICRC1_LEDGER_WASM_PATH): {}",
            ledger_wasm_path, e
        )
    })
}

#[cfg(feature = "icrc3_disabled")]
pub fn ledger_get_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    start: u64,
    length: u64,
) -> icrc_ledger_types::icrc3::blocks::GetBlocksResponse {
    let req = GetBlocksRequest {
        start: Nat::from(start),
        length: Nat::from(length),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .query(ledger_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    Decode!(&res, icrc_ledger_types::icrc3::blocks::GetBlocksResponse)
        .expect("Failed to decode GetBlocksResponse")
}

// Retrieves blocks from the Ledger and the Archives.
#[cfg(feature = "icrc3_disabled")]
pub fn ledger_get_all_blocks_wo_icrc3(
    env: &StateMachine,
    ledger_id: CanisterId,
    start: u64,
    length: u64,
) -> GetBlocksResponse {
    let mut res = GetBlocksResponse {
        chain_length: ledger_get_blocks(env, ledger_id, 0, 0).chain_length,
        blocks: vec![],
    };
    while length > res.blocks.len() as u64 {
        let start = start + res.blocks.len() as u64;
        let length = length - res.blocks.len() as u64;
        let tmp_res = ledger_get_blocks(env, ledger_id, start, length);
        for archived_range in tmp_res.archived_blocks {
            let archived_res = archive_get_all_blocks(env, archived_range);
            res.blocks.extend(archived_res.blocks);
        }
        if tmp_res.blocks.is_empty() {
            break;
        }
        res.blocks.extend(tmp_res.blocks);
    }
    res
}

#[cfg(feature = "icrc3_disabled")]
#[inline(always)]
pub fn ledger_get_all_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    start: u64,
    length: u64,
) -> GetBlocksResponse {
    ledger_get_all_blocks_wo_icrc3(env, ledger_id, start, length)
}

#[cfg(not(feature = "icrc3_disabled"))]
#[inline(always)]
pub fn ledger_get_all_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    start: u64,
    length: u64,
) -> GetBlocksResponse {
    icrc3_get_all_blocks(env, ledger_id, start, length)
}

// Helper function that calls tick on env until either
// the index canister has synced all the blocks up to the
// last one in the ledger or enough attempts passed and therefore
// it fails.
pub fn wait_until_sync_is_completed(
    env: &StateMachine,
    index_id: CanisterId,
    ledger_id: CanisterId,
) {
    wait_until_sync_is_completed_or_error(env, index_id, ledger_id).unwrap()
}

/// Wait for the index to sync with the ledger.
/// Return the index error logs in case it is not able to sync.
pub fn wait_until_sync_is_completed_or_error(
    env: &StateMachine,
    index_id: CanisterId,
    ledger_id: CanisterId,
) -> Result<(), String> {
    let mut num_blocks_synced = u64::MAX;
    let mut chain_length = u64::MAX;
    for _i in 0..MAX_ATTEMPTS_FOR_INDEX_SYNC_WAIT {
        env.advance_time(Duration::from_secs(60));
        env.tick();
        num_blocks_synced = status(env, index_id).num_blocks_synced.0.to_u64().unwrap();
        chain_length = ledger_get_all_blocks(env, ledger_id, 0, 1).chain_length;
        if num_blocks_synced == chain_length {
            return Ok(());
        }
    }
    let log = parse_index_logs(&get_logs(env, index_id));
    let mut log_lines = String::new();
    for entry in log.entries {
        log_lines.push_str(&format!(
            "{} {}:{} {}\n",
            entry.timestamp, entry.file, entry.line, entry.message
        ));
    }
    Err(format!(
        "The index canister was unable to sync all the blocks with the ledger. Number of blocks synced {} but the Ledger chain length is {}.\nLogs:\n{}",
        num_blocks_synced, chain_length, log_lines
    ))
}

#[cfg(feature = "icrc3_disabled")]
fn archive_get_blocks(
    env: &StateMachine,
    archived: ArchivedRange<QueryBlockArchiveFn>,
) -> BlockRange {
    let req = GetBlocksRequest {
        start: archived.start,
        length: archived.length,
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest for archive node");
    let canister_id =
        CanisterId::unchecked_from_principal(PrincipalId(archived.callback.canister_id));
    let res = env
        .query(canister_id, archived.callback.method, req)
        .expect("Failed to send get_blocks request to archive")
        .bytes();
    Decode!(&res, BlockRange).expect("Failed to decode get_blocks response from archive node")
}

#[cfg(feature = "icrc3_disabled")]
fn archive_get_all_blocks(
    env: &StateMachine,
    archived: ArchivedRange<QueryBlockArchiveFn>,
) -> BlockRange {
    let mut res = BlockRange { blocks: vec![] };
    while res.blocks.len() < archived.length.clone() {
        let start = archived.start.clone() + res.blocks.len();
        let length = archived.length.clone() - res.blocks.len();
        let archived_range = ArchivedRange {
            start,
            length,
            callback: archived.callback.clone(),
        };
        let tmp_res = archive_get_blocks(env, archived_range);
        if tmp_res.blocks.is_empty() {
            break;
        }
        res.blocks.extend(tmp_res.blocks);
    }
    res
}

pub(crate) fn parse_index_logs(logs: &[u8]) -> Log {
    serde_json::from_slice(logs).expect("failed to parse index-ng log")
}

#[cfg(not(feature = "icrc3_disabled"))]
fn icrc3_get_all_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    start: u64,
    length: u64,
) -> GetBlocksResponse {
    let mut res = GetBlocksResponse {
        chain_length: icrc3_get_blocks(env, ledger_id, 0, 0)
            .log_length
            .0
            .to_u64()
            .expect("log_length should be a u64!"),
        blocks: vec![],
    };
    while length > res.blocks.len() as u64 {
        let start = start + res.blocks.len() as u64;
        let length = length - res.blocks.len() as u64;
        let tmp_res = icrc3_get_blocks(env, ledger_id, start, length);
        for archived_range in tmp_res.archived_blocks {
            let archived_res = icrc3_archive_get_all_blocks(env, archived_range);
            res.blocks.extend(archived_res.blocks);
        }
        if tmp_res.blocks.is_empty() {
            break;
        }
        for BlockWithId { block, .. } in tmp_res.blocks {
            res.blocks
                .push(icrc_ledger_types::icrc::generic_value::Value::from(block));
        }
    }
    res
}

#[cfg(not(feature = "icrc3_disabled"))]
fn icrc3_archive_get_blocks(
    env: &StateMachine,
    archived: ArchivedBlocks,
) -> icrc_ledger_types::icrc3::blocks::GetBlocksResult {
    let req = Encode!(&archived.args).expect("Failed to encode Vec of GetBlocksRequest");
    let canister_id =
        CanisterId::unchecked_from_principal(PrincipalId(archived.callback.canister_id));
    let res = env
        .query(canister_id, archived.callback.method, req)
        .expect("Failed to send icrc3_get_blocks request to archive")
        .bytes();
    Decode!(&res, icrc_ledger_types::icrc3::blocks::GetBlocksResult)
        .expect("Failed to decode icrc3_get_blocks response from archive node")
}

#[cfg(not(feature = "icrc3_disabled"))]
fn icrc3_archive_get_all_blocks(env: &StateMachine, archived: ArchivedBlocks) -> BlockRange {
    // sanity check: in these tests we expect a single range per archive
    assert_eq!(archived.args.len(), 1);
    let mut res = BlockRange { blocks: vec![] };
    while res.blocks.len() < archived.args[0].length.clone() {
        let start = archived.args[0].start.clone() + res.blocks.len();
        let length = archived.args[0].length.clone() - res.blocks.len();
        let archived_blocks = ArchivedBlocks {
            args: vec![GetBlocksRequest { start, length }],
            callback: archived.callback.clone(),
        };
        let tmp_res = icrc3_archive_get_blocks(env, archived_blocks);
        if tmp_res.blocks.is_empty() {
            break;
        }
        for BlockWithId { block, .. } in tmp_res.blocks {
            res.blocks
                .push(icrc_ledger_types::icrc::generic_value::Value::from(block));
        }
    }
    res
}

// Calls ICRC-3 get_blocks but uses a single range
#[cfg(not(feature = "icrc3_disabled"))]
fn icrc3_get_blocks(
    env: &StateMachine,
    ledger_id: CanisterId,
    start: u64,
    length: u64,
) -> icrc_ledger_types::icrc3::blocks::GetBlocksResult {
    let req = vec![GetBlocksRequest {
        start: Nat::from(start),
        length: Nat::from(length),
    }];
    let req = Encode!(&req).expect("Failed to encode Vec of GetBlocksRequest");
    let res = env
        .query(ledger_id, "icrc3_get_blocks", req)
        .expect("Failed to send icrc3_get_blocks request")
        .bytes();
    Decode!(&res, icrc_ledger_types::icrc3::blocks::GetBlocksResult)
        .expect("Failed to decode GetBlocksResult")
}

pub fn status(env: &StateMachine, index_id: CanisterId) -> Status {
    let res = env
        .query(index_id, "status", Encode!(&()).unwrap())
        .expect("Failed to send status")
        .bytes();
    Decode!(&res, Status).expect("Failed to decode status response")
}
