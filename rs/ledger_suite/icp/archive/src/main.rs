use candid::candid_method;
use dfn_candid::candid_one;
use dfn_core::api::{caller, print, stable_memory_size_in_pages};
use dfn_core::{over_init, stable, BytesS};
use dfn_protobuf::protobuf;
use ic_ledger_canister_core::range_utils;
use ic_ledger_canister_core::runtime::heap_memory_size_bytes;
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_metrics_encoder::MetricsEncoder;
use ic_stable_structures::memory_manager::{MemoryId, VirtualMemory};
use ic_stable_structures::{
    cell::Cell as StableCell, log::Log as StableLog, memory_manager::MemoryManager,
    storable::Bound, DefaultMemoryImpl, Storable,
};
use icp_ledger::{
    Block, BlockRange, BlockRes, CandidBlock, GetBlocksArgs, GetBlocksError, GetBlocksRes,
    GetBlocksResult, GetEncodedBlocksResult, IterBlocksArgs, IterBlocksRes,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::io::Read;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ArchiveNodeState {
    pub max_memory_size_bytes: usize,
    pub block_height_offset: u64,
    pub blocks: Vec<EncodedBlock>,
    pub total_block_size: usize,
    pub ledger_canister_id: ic_base_types::CanisterId,
    #[serde(skip)]
    pub last_upgrade_timestamp: u64,
}

impl Default for ArchiveNodeState {
    fn default() -> Self {
        Self {
            max_memory_size_bytes: 0,
            block_height_offset: 0,
            blocks: vec![],
            total_block_size: 0,
            ledger_canister_id: ic_base_types::CanisterId::ic_00(),
            last_upgrade_timestamp: 0,
        }
    }
}

impl Storable for ArchiveNodeState {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).unwrap_or_else(|err| {
            ic_cdk::api::trap(&format!("{:?}", err));
        });
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        ciborium::de::from_reader(&bytes[..]).unwrap_or_else(|err| {
            ic_cdk::api::trap(&format!("{:?}", err));
        })
    }

    const BOUND: Bound = Bound::Unbounded;
}

const DEFAULT_MAX_MEMORY_SIZE: usize = 1024 * 1024 * 1024;

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);
const BLOCK_LOG_INDEX_MEMORY_ID: MemoryId = MemoryId::new(1);
const BLOCK_LOG_DATA_MEMORY_ID: MemoryId = MemoryId::new(2);

type VM = VirtualMemory<DefaultMemoryImpl>;
type StateCell = StableCell<ArchiveNodeState, VM>;
type BlockLog = StableLog<Vec<u8>, VM, VM>;

thread_local! {
    /// Static memory manager to manage the memory available for stable structures.
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE_CACHE: RefCell<Option<ArchiveNodeState>> = const { RefCell::new(None) };

    /// Scalar state of the archive.
    static STATE: RefCell<StateCell> = with_memory_manager(|memory_manager| {
        RefCell::new(StateCell::init(memory_manager.get(STATE_MEMORY_ID), ArchiveNodeState::default())
            .expect("failed to initialize stable cell"))
    });

    /// Append-only list of encoded blocks stored in stable memory.
    static BLOCKS: RefCell<BlockLog> = with_memory_manager(|memory_manager| {
        RefCell::new(BlockLog::init(memory_manager.get(BLOCK_LOG_INDEX_MEMORY_ID), memory_manager.get(BLOCK_LOG_DATA_MEMORY_ID))
            .expect("failed to initialize stable log"))
    });
}

fn get_archive_state() -> ArchiveNodeState {
    if let Some(state) = STATE_CACHE.with(|s| s.borrow().clone()) {
        return state;
    }
    let state = STATE.with(|cell| cell.borrow().get().clone());
    STATE_CACHE.with(|s| *s.borrow_mut() = Some(state.clone()));
    state
}

/// A helper function to access the scalar state.
fn set_archive_state(state: ArchiveNodeState) {
    assert!(STATE
        .with(|cell| cell.borrow_mut().set(state.clone()))
        .is_ok());
    STATE_CACHE.with(|s| *s.borrow_mut() = Some(state));
}

/// A helper function to access the memory manager.
fn with_memory_manager<R>(f: impl FnOnce(&MemoryManager<DefaultMemoryImpl>) -> R) -> R {
    MEMORY_MANAGER.with(|cell| f(&cell.borrow()))
}

/// A helper function to access the block list.
fn with_blocks<R>(f: impl FnOnce(&BlockLog) -> R) -> R {
    BLOCKS.with(|cell| f(&cell.borrow()))
}

impl ArchiveNodeState {
    pub fn new(
        archive_main_canister_id: ic_base_types::CanisterId,
        block_height_offset: u64,
        max_memory_size_bytes: Option<usize>,
    ) -> Self {
        Self {
            max_memory_size_bytes: max_memory_size_bytes.unwrap_or(DEFAULT_MAX_MEMORY_SIZE),
            block_height_offset,
            blocks: Vec::new(),
            total_block_size: 0,
            ledger_canister_id: archive_main_canister_id,
            last_upgrade_timestamp: 0,
        }
    }
}

// Append the Blocks to the internal Vec
fn append_blocks(blocks: Vec<EncodedBlock>) {
    let archive_state = get_archive_state();
    assert_eq!(
        dfn_core::api::caller(),
        archive_state.ledger_canister_id.get(),
        "Only Ledger canister is allowed to append blocks to an Archive Node"
    );
    print(format!(
        "[archive node] append_blocks(): archive size: {} blocks, appending {} blocks",
        blocks_len(),
        blocks.len()
    ));
    if archive_state.total_block_size > archive_state.max_memory_size_bytes {
        ic_cdk::trap("No space left");
    }
    for block in blocks {
        append_block(&block);
    }
    print(format!(
        "[archive node] append_blocks(): done. archive size: {} blocks",
        blocks_len()
    ));
}

fn blocks_len() -> u64 {
    with_blocks(|blocks| blocks.len())
}

fn append_block(block: &EncodedBlock) {
    with_blocks(|blocks| match blocks.append(&block.0) {
        Ok(_) => {}
        Err(e) => ic_cdk::trap(&format!(
            "Could not append block to stable block log: {:?}",
            e
        )),
    });
}

fn get_block_stable(index: u64) -> Option<EncodedBlock> {
    with_blocks(|blocks| blocks.get(index).map(EncodedBlock::from_vec))
}

// Return the number of bytes the canister can still accommodate
fn remaining_capacity() -> usize {
    let archive_state = get_archive_state();
    let remaining_capacity = archive_state
        .max_memory_size_bytes
        .checked_sub(archive_state.total_block_size)
        .unwrap();
    print(format!(
        "[archive node] remaining_capacity: {} bytes",
        remaining_capacity
    ));
    remaining_capacity
}

fn init(
    archive_main_canister_id: ic_base_types::CanisterId,
    block_height_offset: u64,
    max_memory_size_bytes: Option<usize>,
) {
    match max_memory_size_bytes {
        None => {
            print(format!(
                "[archive node] init(): using default maximum memory size: {} bytes and height offset {}",
                DEFAULT_MAX_MEMORY_SIZE,
                block_height_offset
            ));
        }
        Some(max_memory_size_bytes) => {
            print(format!(
                "[archive node] init(): using maximum memory size: {} bytes and height offset {}",
                max_memory_size_bytes, block_height_offset
            ));
        }
    }

    set_archive_state(ArchiveNodeState::new(
        archive_main_canister_id,
        block_height_offset,
        max_memory_size_bytes,
    ));
}

/// Get Block by BlockIndex. If the BlockIndex is outside the range stored in
/// this Node the result is None
fn get_block(block_height: BlockIndex) -> BlockRes {
    let archive_state = get_archive_state();
    let adjusted_height = block_height - archive_state.block_height_offset;
    let block: Option<EncodedBlock> = get_block_stable(adjusted_height);
    // Will never return CanisterId like its counterpart in Ledger. Want to
    // keep the same signature though
    BlockRes(block.map(Ok))
}

#[export_name = "canister_query get_block_pb"]
fn get_block_() {
    dfn_core::over(protobuf, get_block);
}

#[export_name = "canister_init"]
fn main() {
    dfn_core::over_init(
        |dfn_candid::Candid((archive_canister_id, block_height_offset, opt_max_size))| {
            init(archive_canister_id, block_height_offset, opt_max_size)
        },
    )
}

#[export_name = "canister_update remaining_capacity"]
fn remaining_capacity_() {
    dfn_core::over(dfn_candid::candid, |()| remaining_capacity());
}

#[export_name = "canister_update append_blocks"]
fn append_blocks_() {
    dfn_core::over(dfn_candid::candid_one, append_blocks);
}

/// Get multiple blocks by *offset into the container* (not BlockIndex) and
/// length. Note that this simply iterates the blocks available in the this
/// particular archive node without taking into account the ledger or the
/// remainder of the archive. For example, if the node contains blocks with
/// heights [100, 199] then iter_blocks(0, 1) will return the block with height
/// 100.
#[export_name = "canister_query iter_blocks_pb"]
fn iter_blocks_() {
    dfn_core::over(protobuf, |IterBlocksArgs { start, length }| {
        let length = length.min(icp_ledger::max_blocks_per_request(&caller()));
        let blocks_len = blocks_len() as usize;
        let start = start.min(blocks_len);
        let end = std::cmp::min(start + length, blocks_len);
        let mut blocks = vec![];
        for index in start..end {
            blocks.push(get_block_stable(index as u64).unwrap());
        }
        IterBlocksRes(blocks)
    });
}

/// Get multiple Blocks by BlockIndex and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_blocks_pb"]
fn get_blocks_() {
    dfn_core::over(protobuf, |GetBlocksArgs { start, length }| {
        let archive_state = get_archive_state();
        let from_offset = archive_state.block_height_offset;
        let length = length
            .min(usize::MAX as u64)
            .min(icp_ledger::max_blocks_per_request(&caller()) as u64);
        let local_blocks_range = from_offset..from_offset + blocks_len();
        let requested_range = start..start + length;
        if !range_utils::is_subrange(&requested_range, &local_blocks_range) {
            return GetBlocksRes(Err(format!("Requested blocks outside the range stored in the ledger node. Requested [{} .. {}]. Available [{} .. {}].",
                requested_range.start, requested_range.end, local_blocks_range.start, local_blocks_range.end)));
        }
        let mut blocks = vec![];
        for index in requested_range {
            blocks.push(get_block_stable(index as u64).unwrap());
        }
        GetBlocksRes(Ok(blocks))
    });
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
#[export_name = "canister_query get_blocks"]
fn get_blocks_candid_() {
    dfn_core::over(candid_one, get_blocks);
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        if memory_manager_installed() {
            print("Archive state already migrated to stable structures, exiting post_upgrade.");
            let state = get_archive_state();
            print(format!(
                "archive_state from stable: max_memory_size_bytes {}, height_offset: {}, blocks_len: {}, total_block_size: {}, ledger_canister_id: {}, last_upgrade_timestamp: {}",
                state.max_memory_size_bytes,
                state.block_height_offset,
                state.blocks.len(),
                state.total_block_size,
                state.ledger_canister_id,
                state.last_upgrade_timestamp,
            ));
            return;
        }

        let bytes = stable::get();
        let mut state: ArchiveNodeState = ciborium::de::from_reader(std::io::Cursor::new(&bytes))
            .expect("Decoding stable memory failed");
        state.last_upgrade_timestamp = dfn_core::api::time_nanos();

        for block in &state.blocks {
            append_block(block);
        }
        print(format!(
            "archive_state before: max_memory_size_bytes {}, height_offset: {}, blocks_len: {}, total_block_size: {}, ledger_canister_id: {}, last_upgrade_timestamp: {}",
            state.max_memory_size_bytes,
            state.block_height_offset,
            state.blocks.len(),
            state.total_block_size,
            state.ledger_canister_id,
            state.last_upgrade_timestamp,
        ));

        print(format!(
            "archive_migration heap blocks number: {}, stable blocks number: {}, instructions: {}",
            state.blocks.len(),
            blocks_len(),
            ic_cdk::api::instruction_counter()
        ));
        state.blocks.clear();

        set_archive_state(state);

        let state = get_archive_state();
        print(format!(
            "archive_state after: max_memory_size_bytes {}, height_offset: {}, blocks_len: {}, total_block_size: {}, ledger_canister_id: {}, last_upgrade_timestamp: {}",
            state.max_memory_size_bytes,
            state.block_height_offset,
            state.blocks.len(),
            state.total_block_size,
            state.ledger_canister_id,
            state.last_upgrade_timestamp,
        ));
    });
}

fn memory_manager_installed() -> bool {
    let mut magic_bytes_reader = ic_cdk::api::stable::StableReader::default();
    const MAGIC_BYTES: &[u8; 3] = b"MGR";
    let mut first_bytes = [0u8; 3];
    match magic_bytes_reader.read_exact(&mut first_bytes) {
        Ok(_) => first_bytes == *MAGIC_BYTES,
        Err(_) => false,
    }
}

fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let state = get_archive_state();
    w.encode_gauge(
        "archive_node_block_height_offset",
        state.block_height_offset as f64,
        "Block height offset assigned to this instance of the archive canister.",
    )?;
    w.encode_gauge(
        "archive_node_max_memory_size_bytes",
        state.max_memory_size_bytes as f64,
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
        state.total_block_size as f64,
        "Total amount of memory consumed by the blocks stored by this canister.",
    )?;
    w.encode_gauge(
        "archive_node_stable_memory_pages",
        stable_memory_size_in_pages() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "stable_memory_bytes",
        (stable_memory_size_in_pages() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "heap_memory_bytes",
        heap_memory_size_bytes() as f64,
        "Size of the heap memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "archive_node_last_upgrade_time_seconds",
        state.last_upgrade_timestamp as f64 / 1_000_000_000.0,
        "IC timestamp of the last upgrade performed on this canister.",
    )?;
    Ok(())
}

#[export_name = "canister_query http_request"]
fn http_request() {
    dfn_http_metrics::serve_metrics(encode_metrics);
}

#[candid_method(query, rename = "get_encoded_blocks")]
fn get_encoded_blocks(GetBlocksArgs { start, length }: GetBlocksArgs) -> GetEncodedBlocksResult {
    read_encoded_blocks(start, length.min(usize::MAX as u64) as usize)
}

fn read_encoded_blocks(start: u64, length: usize) -> Result<Vec<EncodedBlock>, GetBlocksError> {
    let archive_state = get_archive_state();

    let block_range =
        range_utils::make_range(archive_state.block_height_offset, blocks_len() as usize);

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
            icp_ledger::max_blocks_per_request(&caller()),
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
#[export_name = "canister_query get_encoded_blocks"]
fn get_encoded_blocks_blocks_() {
    dfn_core::over(candid_one, get_encoded_blocks);
}

#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn get_canidid_interface() {
    dfn_core::over(candid_one, |()| -> &'static str {
        include_str!(env!("LEDGER_ARCHIVE_DID_PATH"))
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
