use ledger_canister::{
    metrics_encoder::MetricsEncoder, BlockHeight, BlockRes, EncodedBlock, GetBlocksArgs,
    IterBlocksArgs,
};

use dfn_core::api::stable_memory_size_in_pages;
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
    pub ledger_canister_id: ic_types::CanisterId,
    #[serde(skip)]
    pub last_upgrade_timestamp: u64,
}

const DEFAULT_MAX_MEMORY_SIZE: usize = 1024 * 1024 * 1024;

impl ArchiveNodeState {
    pub fn new(
        archive_main_canister_id: ic_types::CanisterId,
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

// Helper to print messages in cyan
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::cyan(s).to_string());
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
    archive_main_canister_id: ic_types::CanisterId,
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
        ledger_canister::get_blocks(blocks, from_offset, start, length)
    });
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        let bytes = stable::get();
        let mut state = ARCHIVE_STATE.write().unwrap();
        *state = serde_cbor::from_slice(&bytes).expect("Decoding stable memory failed");
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
    let bytes = serde_cbor::to_vec(&*archive_state).unwrap();
    stable::set(&bytes);
}

fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let state = ARCHIVE_STATE.read().unwrap();
    w.encode_gauge(
        "archive_node_block_height_offset",
        state.block_height_offset as f64,
        "The block height offset assigned to this instanced of the archive canister.",
    )?;
    w.encode_gauge(
        "archive_node_max_memory_size_bytes",
        state.max_memory_size_bytes as f64,
        "The max amount of memory this canister is allowed to use for blocks.",
    )?;
    w.encode_gauge(
        "archive_node_block_count",
        state.blocks.len() as f64,
        "The number of blocks stored by this canister.",
    )?;
    w.encode_gauge(
        "archive_node_block_size_bytes_total",
        state.total_block_size as f64,
        "The total amount of memory consumed by the blocks stored by this canister.",
    )?;
    w.encode_gauge(
        "archive_node_stable_memory_pages",
        stable_memory_size_in_pages() as f64,
        "The size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "archive_node_last_upgrade_timestamp",
        state.last_upgrade_timestamp as f64,
        "The IC timestamp of the last upgrade performed on this canister in nanoseconds.",
    )?;
    Ok(())
}

#[export_name = "canister_query http_request"]
fn http_request() {
    ledger_canister::http_request::serve_metrics(encode_metrics);
}
