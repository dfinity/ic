use ledger_canister::{
    metrics_encoder::MetricsEncoder, BlockHeight, BlockRange, BlockRes, CandidBlock, EncodedBlock,
    GetBlocksArgs, GetBlocksError, GetBlocksResult, IterBlocksArgs, MAX_BLOCKS_PER_REQUEST,
};

use candid::candid_method;
use dfn_candid::candid_one;
use dfn_core::api::{print, stable_memory_size_in_pages};
use dfn_core::{over_init, stable, BytesS};
use dfn_protobuf::protobuf;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

lazy_static::lazy_static! {
    // This is a bad default, but it works for the incident on 8/05/21 since that is the first
    // archive canister
    static ref ARCHIVE_STATE: RwLock<ArchiveNodeState> = RwLock::new(ArchiveNodeState::new(ic_nns_constants::LEDGER_CANISTER_ID, 0, None));
}

#[derive(Serialize, Deserialize, Debug)]
struct ArchiveNodeState {
    pub max_memory_size_bytes: usize,
    pub block_height_offset: u64,
    pub blocks: Vec<EncodedBlock>,
    pub total_block_size: usize,
    pub ledger_canister_id: ic_base_types::CanisterId,
    #[serde(skip)]
    pub last_upgrade_timestamp: u64,
}

const DEFAULT_MAX_MEMORY_SIZE: usize = 1024 * 1024 * 1024;

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
fn append_blocks(mut blocks: Vec<EncodedBlock>) {
    let mut archive_state = ARCHIVE_STATE.write().unwrap();
    assert_eq!(
        dfn_core::api::caller(),
        archive_state.ledger_canister_id.get(),
        "Only Ledger canister is allowed to append blocks to an Archive Node"
    );
    print(format!(
        "[archive node] append_blocks(): archive size: {} blocks, appending {} blocks",
        archive_state.blocks.len(),
        blocks.len()
    ));
    for block in &blocks {
        archive_state.total_block_size += block.size_bytes();
    }
    assert!(
        archive_state.total_block_size < archive_state.max_memory_size_bytes,
        "No space left"
    );
    archive_state.blocks.append(&mut blocks);
    print(format!(
        "[archive node] append_blocks(): done. archive size: {} blocks",
        archive_state.blocks.len()
    ));
}

// Return the number of bytes the canister can still accommodate
fn remaining_capacity() -> usize {
    let archive_state = ARCHIVE_STATE.read().unwrap();
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

    *ARCHIVE_STATE.write().unwrap() = ArchiveNodeState::new(
        archive_main_canister_id,
        block_height_offset,
        max_memory_size_bytes,
    );
}

/// Get Block by BlockHeight. If the BlockHeight is outside the range stored in
/// this Node the result is None
fn get_block(block_height: BlockHeight) -> BlockRes {
    let archive_state = ARCHIVE_STATE.read().unwrap();
    let adjusted_height = block_height - archive_state.block_height_offset;
    let block: Option<EncodedBlock> = archive_state.blocks.get(adjusted_height as usize).cloned();
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

/// Get multiple blocks by *offset into the container* (not BlockHeight) and
/// length. Note that this simply iterates the blocks available in the this
/// particular archive node without taking into account the ledger or the
/// remainder of the archive. For example, if the node contains blocks with
/// heights [100, 199] then iter_blocks(0, 1) will return the block with height
/// 100.
#[export_name = "canister_query iter_blocks_pb"]
fn iter_blocks_() {
    dfn_core::over(protobuf, |IterBlocksArgs { start, length }| {
        let archive_state = ARCHIVE_STATE.read().unwrap();
        let blocks = &archive_state.blocks;
        let length = length.min(MAX_BLOCKS_PER_REQUEST);
        ledger_canister::iter_blocks(blocks, start, length)
    });
}

/// Get multiple Blocks by BlockHeight and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_blocks_pb"]
fn get_blocks_() {
    dfn_core::over(protobuf, |GetBlocksArgs { start, length }| {
        let archive_state = ARCHIVE_STATE.read().unwrap();
        let blocks = &archive_state.blocks;
        let from_offset = archive_state.block_height_offset;
        let length = length.min(MAX_BLOCKS_PER_REQUEST);
        ledger_canister::get_blocks(blocks, from_offset, start, length)
    });
}

#[candid_method(query, rename = "get_blocks")]
fn get_blocks(GetBlocksArgs { start, length }: GetBlocksArgs) -> GetBlocksResult {
    use ledger_canister::range_utils;

    let archive_state = ARCHIVE_STATE.read().unwrap();
    let blocks = &archive_state.blocks;

    let block_range = range_utils::make_range(archive_state.block_height_offset, blocks.len());

    if start < block_range.start {
        return Err(GetBlocksError::BadFirstBlockIndex {
            requested_index: start,
            first_valid_index: block_range.start,
        });
    }

    let requested_range = range_utils::make_range(start, length);
    let effective_range = range_utils::intersect(
        &block_range,
        &range_utils::head(&requested_range, MAX_BLOCKS_PER_REQUEST),
    );

    let mut candid_blocks: Vec<CandidBlock> =
        Vec::with_capacity(range_utils::range_len(&effective_range) as usize);

    for i in effective_range {
        let encoded_block = &blocks[(i - block_range.start) as usize];
        let candid_block =
            CandidBlock::from(encoded_block.decode().expect("failed to decode a block"));
        candid_blocks.push(candid_block);
    }

    Ok(BlockRange {
        blocks: candid_blocks,
    })
}

/// Get multiple Blocks by BlockHeight and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_blocks"]
fn get_blocks_candid_() {
    dfn_core::over(candid_one, get_blocks);
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        let bytes = stable::get();
        let mut state = ARCHIVE_STATE.write().unwrap();
        *state = ciborium::de::from_reader(std::io::Cursor::new(&bytes))
            .expect("Decoding stable memory failed");
        state.last_upgrade_timestamp = dfn_core::api::time_nanos();
    });
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    dfn_core::setup::START.call_once(|| {
        dfn_core::printer::hook();
    });

    let archive_state = ARCHIVE_STATE
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ciborium::ser::into_writer(&*archive_state, stable::StableWriter::new()).unwrap();
}

fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let state = ARCHIVE_STATE.read().unwrap();
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
        state.blocks.len() as f64,
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
        "archive_node_stable_memory_bytes",
        (stable_memory_size_in_pages() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
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
    ledger_canister::http_request::serve_metrics(encode_metrics);
}

#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn get_canidid_interface() {
    dfn_core::over(candid_one, |()| -> &'static str {
        include_str!("../ledger_archive.did")
    })
}

#[test]
fn check_archive_candid_interface_compatibility() {
    use candid::utils::CandidSource;

    candid::export_service!();

    let actual_interface = __export_service();
    let expected_interface_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ledger_archive.did");

    candid::utils::service_compatible(
        CandidSource::Text(&actual_interface),
        CandidSource::File(&expected_interface_path),
    )
    .expect("ledger archive canister interface is not compatible with the ledger_archive.did file");
}
