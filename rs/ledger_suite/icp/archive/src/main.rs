#![allow(deprecated)]
use candid::{Decode, candid_method};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::{
    api::{
        call::{arg_data_raw, reply, reply_raw},
        caller, print,
    },
    futures::{in_executor_context, in_query_executor_context},
    post_upgrade, query,
};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_icp_archive::ArchiveUpgradeArgument;
use ic_ledger_canister_core::range_utils;
use ic_ledger_canister_core::runtime::heap_memory_size_bytes;
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_metrics_encoder::MetricsEncoder;
use ic_stable_structures::{
    DefaultMemoryImpl, cell::Cell as StableCell, log::Log as StableLog,
    memory_manager::MemoryManager, storable::Bound,
};
use ic_stable_structures::{
    Storable,
    memory_manager::{MemoryId, VirtualMemory},
};
use icp_ledger::{
    Block, BlockRange, BlockRes, CandidBlock, GetBlocksArgs, GetBlocksError, GetBlocksRes,
    GetBlocksResult, GetEncodedBlocksResult, IterBlocksArgs, IterBlocksRes, from_proto_bytes,
    to_proto_bytes,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, cell::RefCell};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct ArchiveState {
    pub max_memory_size_bytes: u64,
    pub block_height_offset: u64,
    pub ledger_canister_id: CanisterId,
}

impl Default for ArchiveState {
    fn default() -> Self {
        Self {
            max_memory_size_bytes: 0,
            block_height_offset: 0,
            ledger_canister_id: CanisterId::ic_00(),
        }
    }
}

impl Storable for ArchiveState {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).unwrap_or_else(|err| {
            ic_cdk::api::trap(format!("{err:?}"));
        });
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        ciborium::de::from_reader(&bytes[..]).unwrap_or_else(|err| {
            ic_cdk::api::trap(format!("{err:?}"));
        })
    }

    const BOUND: Bound = Bound::Unbounded;
}

const DEFAULT_MAX_MEMORY_SIZE: u64 = 10 * 1024 * 1024 * 1024;

const MEMORY_VERSION_NO_MEM_MGR: u64 = 0;
const MEMORY_VERSION_MEM_MGR_INSTALLED: u64 = 1;

const STABLE_MEMORY_VERSION_MEMORY_ID: MemoryId = MemoryId::new(0);
const ARCHIVE_STATE_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(2);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(3);

thread_local! {
    /// Static memory manager to manage the memory available for stable structures.
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static LAST_UPGRADE_TIMESTAMP: RefCell<u64> = const { RefCell::new(0) };

    // Version of the stable memory layout
    static STABLE_MEMORY_VERSION: RefCell<StableCell<u64, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager|  RefCell::new(StableCell::init(memory_manager.borrow().get(STABLE_MEMORY_VERSION_MEMORY_ID), MEMORY_VERSION_NO_MEM_MGR)
        .expect("failed to initialize stable cell")));

    // Archive state
    static ARCHIVE_STATE: RefCell<StableCell<ArchiveState, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager|  RefCell::new(StableCell::init(memory_manager.borrow().get(ARCHIVE_STATE_MEMORY_ID), Default::default())
        .expect("failed to initialize stable cell")));

    static ARCHIVE_STATE_CACHE: RefCell<Option<ArchiveState>> = const { RefCell::new(None) };

    // Log of blocks.
    static BLOCKS: RefCell<StableLog<Vec<u8>, VirtualMemory<DefaultMemoryImpl>, VirtualMemory<DefaultMemoryImpl>>> =
        MEMORY_MANAGER.with(|memory_manager| RefCell::new(StableLog::init(memory_manager.borrow().get(BLOCK_LOG_INDEX_MEMORY_ID),
        memory_manager.borrow().get(BLOCK_LOG_DATA_MEMORY_ID)).expect("failed to initialize blocks stable memory")));
}

fn stable_memory_version() -> u64 {
    STABLE_MEMORY_VERSION.with(|cell| *cell.borrow().get())
}

fn set_stable_memory_version() {
    assert!(
        STABLE_MEMORY_VERSION
            .with(|cell| cell.borrow_mut().set(MEMORY_VERSION_MEM_MGR_INSTALLED))
            .is_ok()
    );
}

fn set_archive_state(archive_state: ArchiveState) {
    ARCHIVE_STATE_CACHE.with(|c| *c.borrow_mut() = Some(archive_state));
    assert!(
        ARCHIVE_STATE
            .with(|cell| cell.borrow_mut().set(archive_state))
            .is_ok()
    );
}

fn get_archive_state() -> ArchiveState {
    if let Some(archive_state) = ARCHIVE_STATE_CACHE.with(|c| *c.borrow()) {
        return archive_state;
    }
    let archive_state = ARCHIVE_STATE.with(|cell| *cell.borrow().get());
    ARCHIVE_STATE_CACHE.with(|c| *c.borrow_mut() = Some(archive_state));
    archive_state
}

fn max_memory_size_bytes() -> u64 {
    get_archive_state().max_memory_size_bytes
}

fn set_max_memory_size_bytes(max_memory_size_bytes: u64) {
    if max_memory_size_bytes < total_block_size() {
        ic_cdk::trap(format!(
            "Cannot set max_memory_size_bytes to {}, because it is lower than total_block_size {}.",
            max_memory_size_bytes,
            total_block_size()
        ));
    }
    let mut archive_state = get_archive_state();
    archive_state.max_memory_size_bytes = max_memory_size_bytes;
    set_archive_state(archive_state);
}

fn block_height_offset() -> u64 {
    get_archive_state().block_height_offset
}

fn set_block_height_offset(block_height_offset: u64) {
    let mut archive_state = get_archive_state();
    archive_state.block_height_offset = block_height_offset;
    set_archive_state(archive_state);
}

fn total_block_size() -> u64 {
    BLOCKS.with_borrow(|b| b.log_size_bytes())
}

fn ledger_canister_id() -> CanisterId {
    get_archive_state().ledger_canister_id
}

fn set_ledger_canister_id(ledger_canister_id: CanisterId) {
    let mut archive_state = get_archive_state();
    archive_state.ledger_canister_id = ledger_canister_id;
    set_archive_state(archive_state);
}

fn last_upgrade_timestamp() -> u64 {
    LAST_UPGRADE_TIMESTAMP.with(|t| *t.borrow())
}

fn set_last_upgrade_timestamp(timestamp: u64) {
    LAST_UPGRADE_TIMESTAMP.with(|t| *t.borrow_mut() = timestamp)
}

// Append the Blocks to the internal Vec
fn append_blocks(blocks: Vec<EncodedBlock>) {
    assert_eq!(
        PrincipalId::from(caller()),
        ledger_canister_id().get(),
        "Only Ledger canister is allowed to append blocks to an Archive Node"
    );
    print(format!(
        "[archive node] append_blocks(): archive size: {} blocks, appending {} blocks",
        blocks_len(),
        blocks.len()
    ));
    for block in &blocks {
        append_block(block);
    }
    if total_block_size() > max_memory_size_bytes() {
        ic_cdk::trap("No space left");
    }
    print(format!(
        "[archive node] append_blocks(): done. archive size: {} blocks",
        blocks_len()
    ));
}

fn blocks_len() -> u64 {
    BLOCKS.with_borrow(|blocks| blocks.len())
}

fn append_block(block: &EncodedBlock) {
    BLOCKS.with_borrow_mut(|blocks| match blocks.append(&block.0) {
        Ok(_) => {}
        Err(e) => ic_cdk::trap(format!("Could not append block to stable block log: {e:?}")),
    });
}

fn get_block_stable(index: u64) -> Option<EncodedBlock> {
    BLOCKS.with_borrow(|blocks| blocks.get(index).map(EncodedBlock::from_vec))
}

// Return the number of bytes the canister can still accommodate
fn remaining_capacity() -> u64 {
    let remaining_capacity = max_memory_size_bytes()
        .checked_sub(total_block_size())
        .unwrap();
    print(format!(
        "[archive node] remaining_capacity: {remaining_capacity} bytes"
    ));
    remaining_capacity
}

fn init(
    archive_main_canister_id: CanisterId,
    block_height_offset: u64,
    max_memory_size_bytes: Option<u64>,
) {
    match max_memory_size_bytes {
        None => {
            print(format!(
                "[archive node] init(): using default maximum memory size: {DEFAULT_MAX_MEMORY_SIZE} bytes and height offset {block_height_offset}"
            ));
        }
        Some(max_memory_size_bytes) => {
            print(format!(
                "[archive node] init(): using maximum memory size: {max_memory_size_bytes} bytes and height offset {block_height_offset}"
            ));
        }
    }

    set_block_height_offset(block_height_offset);
    set_max_memory_size_bytes(max_memory_size_bytes.unwrap_or(DEFAULT_MAX_MEMORY_SIZE));
    set_ledger_canister_id(archive_main_canister_id);
    set_stable_memory_version();
}

/// Get Block by BlockIndex. If the BlockIndex is outside the range stored in
/// this Node the result is None
fn get_block(block_height: BlockIndex) -> BlockRes {
    let adjusted_height = block_height.checked_sub(block_height_offset()).unwrap();
    let block: Option<EncodedBlock> = get_block_stable(adjusted_height);
    // Will never return CanisterId like its counterpart in Ledger. Want to
    // keep the same signature though
    BlockRes(block.map(Ok))
}

#[unsafe(export_name = "canister_query get_block_pb")]
fn get_block_() {
    in_query_executor_context(|| {
        let arg: BlockIndex =
            from_proto_bytes(arg_data_raw()).expect("failed to decode get_block_pb argument");
        let res = to_proto_bytes(get_block(arg)).expect("failed to encode get_block_pb response");
        reply_raw(&res)
    })
}

#[unsafe(export_name = "canister_init")]
fn main() {
    in_executor_context(|| {
        let bytes = arg_data_raw();
        let (archive_canister_id, block_height_offset, opt_max_size) =
            Decode!(&bytes, ic_base_types::CanisterId, u64, Option<u64>)
                .expect("failed to decode init arguments");
        init(archive_canister_id, block_height_offset, opt_max_size);
    })
}

#[unsafe(export_name = "canister_update remaining_capacity")]
fn remaining_capacity_() {
    in_executor_context(|| reply((remaining_capacity(),)))
}

#[unsafe(export_name = "canister_update append_blocks")]
fn append_blocks_() {
    in_executor_context(|| {
        let blocks = Decode!(&arg_data_raw(), Vec<EncodedBlock>)
            .expect("failed to decode append_blocks argument");
        append_blocks(blocks);
        reply(());
    })
}

/// Get multiple blocks by *offset into the container* (not BlockIndex) and
/// length. Note that this simply iterates the blocks available in the this
/// particular archive node without taking into account the ledger or the
/// remainder of the archive. For example, if the node contains blocks with
/// heights [100, 199] then iter_blocks(0, 1) will return the block with height
/// 100.
#[unsafe(export_name = "canister_query iter_blocks_pb")]
fn iter_blocks_() {
    in_query_executor_context(|| {
        let IterBlocksArgs { start, length } =
            from_proto_bytes(arg_data_raw()).expect("failed to decode iter_blocks_pb argument");
        let length = length.min(icp_ledger::max_blocks_per_request(&PrincipalId::from(
            caller(),
        )));
        let blocks_len = blocks_len() as usize;
        let start = start.min(blocks_len);
        let end = std::cmp::min(start + length, blocks_len);
        let mut blocks = vec![];
        for index in start..end {
            blocks.push(get_block_stable(index as u64).unwrap());
        }
        let res_proto = to_proto_bytes(IterBlocksRes(blocks))
            .expect("failed to encode iter_blocks_pb response");
        reply_raw(&res_proto)
    })
}

/// Get multiple Blocks by BlockIndex and length. If the query is outside the
/// range stored in the Node the result is an error.
#[unsafe(export_name = "canister_query get_blocks_pb")]
fn get_blocks_() {
    in_query_executor_context(|| {
        let GetBlocksArgs { start, length } =
            from_proto_bytes(arg_data_raw()).expect("failed to decode get_blocks_pb argument");
        let from_offset = block_height_offset();
        let length = length
            .min(usize::MAX as u64)
            .min(icp_ledger::max_blocks_per_request(&PrincipalId::from(caller())) as u64);
        let local_blocks_range = from_offset..from_offset + blocks_len();
        let requested_range = start..start + length;
        if !range_utils::is_subrange(&requested_range, &local_blocks_range) {
            let res = GetBlocksRes(Err(format!(
                "Requested blocks outside the range stored in the archive node. Requested [{} .. {}]. Available [{} .. {}].",
                requested_range.start,
                requested_range.end,
                local_blocks_range.start,
                local_blocks_range.end
            )));
            let res_proto = to_proto_bytes(res).expect("failed to encode get_blocks_pb response");
            reply_raw(&res_proto);
            return;
        }
        let mut blocks = vec![];
        let offset_requested_range =
            requested_range.start - from_offset..requested_range.end - from_offset;
        for index in offset_requested_range {
            blocks.push(get_block_stable(index).unwrap());
        }
        let res_proto = to_proto_bytes(GetBlocksRes(Ok(blocks)))
            .expect("failed to encode get_blocks_pb response");
        reply_raw(&res_proto);
    })
}

#[candid_method(query, rename = "get_blocks")]
fn get_blocks(GetBlocksArgs { start, length }: GetBlocksArgs) -> GetBlocksResult {
    Ok(BlockRange {
        blocks: read_encoded_blocks(start, length.min(usize::MAX as u64) as usize)?
            .into_iter()
            .map(|b| CandidBlock::from(Block::decode(b).expect("failed to decode a block")))
            .collect::<Vec<CandidBlock>>(),
    })
}
/// Get multiple Blocks by BlockIndex and length. If the query is outside the
/// range stored in the Node the result is an error.
#[unsafe(export_name = "canister_query get_blocks")]
fn get_blocks_candid_() {
    in_query_executor_context(|| {
        let args =
            Decode!(&arg_data_raw(), GetBlocksArgs).expect("failed to decode get_blocks argument");
        reply((get_blocks(args),));
    })
}

#[post_upgrade]
fn post_upgrade(upgrade_arg: Option<ArchiveUpgradeArgument>) {
    set_last_upgrade_timestamp(ic_cdk::api::time());

    let arg_max_memory_size_bytes = match upgrade_arg {
        Some(upgrade_arg) => upgrade_arg.max_memory_size_bytes,
        None => None,
    };

    // We do not support migration from scratch stable memory anymore
    assert_eq!(stable_memory_version(), MEMORY_VERSION_MEM_MGR_INSTALLED);
    if let Some(max_memory_size_bytes) = arg_max_memory_size_bytes {
        print(format!(
            "Changing the max_memory_size_bytes to {max_memory_size_bytes}"
        ));
        set_max_memory_size_bytes(max_memory_size_bytes);
    }
}

fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "archive_node_block_height_offset",
        block_height_offset() as f64,
        "Block height offset assigned to this instance of the archive canister.",
    )?;
    w.encode_gauge(
        "archive_node_max_memory_size_bytes",
        max_memory_size_bytes() as f64,
        "Maximum amount of memory this canister is allowed to use for blocks.",
    )?;
    // This value can increase/decrease in the current implementation.
    w.encode_gauge(
        "archive_node_blocks",
        blocks_len() as f64,
        "Number of blocks stored by this canister.",
    )?;
    w.encode_gauge(
        "archive_node_blocks_bytes",
        total_block_size() as f64,
        "Total amount of memory consumed by the blocks stored by this canister.",
    )?;
    w.encode_gauge(
        "archive_node_stable_memory_pages",
        ic_cdk::api::stable::stable_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "stable_memory_bytes",
        (ic_cdk::api::stable::stable_size() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "heap_memory_bytes",
        heap_memory_size_bytes() as f64,
        "Size of the heap memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "archive_node_last_upgrade_time_seconds",
        last_upgrade_timestamp() as f64 / 1_000_000_000.0,
        "IC timestamp of the last upgrade performed on this canister.",
    )?;
    Ok(())
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .header("Cache-Control", "no-store")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err}"))
                    .build()
            }
        }
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

#[candid_method(query, rename = "get_encoded_blocks")]
fn get_encoded_blocks(GetBlocksArgs { start, length }: GetBlocksArgs) -> GetEncodedBlocksResult {
    read_encoded_blocks(start, length.min(usize::MAX as u64) as usize)
}

fn read_encoded_blocks(start: u64, length: usize) -> Result<Vec<EncodedBlock>, GetBlocksError> {
    let block_range = range_utils::make_range(block_height_offset(), blocks_len() as usize);

    if start < block_range.start {
        return Err(GetBlocksError::BadFirstBlockIndex {
            requested_index: start,
            first_valid_index: block_range.start,
        });
    }

    let requested_range = range_utils::make_range(start, length);
    let effective_range = match range_utils::intersect(
        &block_range,
        &range_utils::take(
            &requested_range,
            icp_ledger::max_blocks_per_request(&PrincipalId::from(caller())),
        ),
    ) {
        Ok(range) => range,
        Err(range_utils::NoIntersection) => return Ok(vec![]),
    };

    let mut encoded_blocks = Vec::with_capacity(range_utils::range_len(&effective_range) as usize);
    for i in effective_range {
        encoded_blocks.push(get_block_stable(i - block_range.start).unwrap());
    }
    Ok(encoded_blocks)
}

/// Get multiple Blocks by BlockIndex and length. If the query is outside the
/// range stored in the Node the result is an error.
#[unsafe(export_name = "canister_query get_encoded_blocks")]
fn get_encoded_blocks_blocks_() {
    in_query_executor_context(|| {
        let args = Decode!(&arg_data_raw(), GetBlocksArgs)
            .expect("failed to decode get_encoded_blocks argument");
        reply((get_encoded_blocks(args),));
    })
}

#[unsafe(export_name = "canister_query __get_candid_interface_tmp_hack")]
fn get_canidid_interface() {
    in_query_executor_context(|| {
        reply((include_str!(env!("LEDGER_ARCHIVE_DID_PATH")),));
    })
}

#[test]
fn check_archive_candid_interface_compatibility() {
    use candid_parser::utils::CandidSource;

    candid::export_service!();

    let actual_interface = __export_service();
    let expected_interface_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ledger_archive.did");

    candid_parser::utils::service_equal(
        CandidSource::Text(&actual_interface),
        CandidSource::File(&expected_interface_path),
    )
    .expect("ledger archive canister interface is not equal with the ledger_archive.did file");
}
