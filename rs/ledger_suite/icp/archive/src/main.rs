use candid::{candid_method, Decode};
use dfn_core::stable;
use ic_base_types::PrincipalId;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::{
    call::{arg_data_raw, reply, reply_raw},
    caller, print,
};
use ic_cdk::query;
use ic_ledger_canister_core::range_utils;
use ic_ledger_canister_core::runtime::heap_memory_size_bytes;
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_metrics_encoder::MetricsEncoder;
use icp_ledger::{
    from_proto_bytes, to_proto_bytes, Block, BlockRange, BlockRes, CandidBlock, GetBlocksArgs,
    GetBlocksError, GetBlocksResult, GetEncodedBlocksResult, IterBlocksArgs,
};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

lazy_static::lazy_static! {
    // This is a bad default, but it works for the incident on 8/05/21 since that is the first
    // archive canister
    static ref ARCHIVE_STATE: RwLock<ArchiveNodeState> = RwLock::new(ArchiveNodeState::new(ic_nns_constants::LEDGER_CANISTER_ID, 0, None));
}

#[derive(Debug, Deserialize, Serialize)]
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
        PrincipalId::from(caller()),
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
    if archive_state.total_block_size > archive_state.max_memory_size_bytes {
        ic_cdk::trap("No space left");
    }
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

/// Get Block by BlockIndex. If the BlockIndex is outside the range stored in
/// this Node the result is None
fn get_block(block_height: BlockIndex) -> BlockRes {
    let archive_state = ARCHIVE_STATE.read().unwrap();
    let adjusted_height = block_height - archive_state.block_height_offset;
    let block: Option<EncodedBlock> = archive_state.blocks.get(adjusted_height as usize).cloned();
    // Will never return CanisterId like its counterpart in Ledger. Want to
    // keep the same signature though
    BlockRes(block.map(Ok))
}

#[export_name = "canister_query get_block_pb"]
fn get_block_() {
    ic_cdk::setup();
    let arg: BlockIndex =
        from_proto_bytes(arg_data_raw()).expect("failed to decode get_block_pb argument");
    let res = to_proto_bytes(get_block(arg)).expect("failed to encode get_block_pb response");
    reply_raw(&res)
}

#[export_name = "canister_init"]
fn main() {
    ic_cdk::setup();
    let bytes = arg_data_raw();
    let (archive_canister_id, block_height_offset, opt_max_size) =
        Decode!(&bytes, ic_base_types::CanisterId, u64, Option<usize>)
            .expect("failed to decode init arguments");
    init(archive_canister_id, block_height_offset, opt_max_size);
}

#[export_name = "canister_update remaining_capacity"]
fn remaining_capacity_() {
    ic_cdk::setup();
    reply((remaining_capacity(),))
}

#[export_name = "canister_update append_blocks"]
fn append_blocks_() {
    ic_cdk::setup();
    let blocks = Decode!(&arg_data_raw(), Vec<EncodedBlock>)
        .expect("failed to decode append_blocks argument");
    append_blocks(blocks);
    reply(());
}

/// Get multiple blocks by *offset into the container* (not BlockIndex) and
/// length. Note that this simply iterates the blocks available in the this
/// particular archive node without taking into account the ledger or the
/// remainder of the archive. For example, if the node contains blocks with
/// heights [100, 199] then iter_blocks(0, 1) will return the block with height
/// 100.
#[export_name = "canister_query iter_blocks_pb"]
fn iter_blocks_() {
    ic_cdk::setup();
    let IterBlocksArgs { start, length } =
        from_proto_bytes(arg_data_raw()).expect("failed to decode iter_blocks_pb argument");
    let archive_state = ARCHIVE_STATE.read().unwrap();
    let blocks = &archive_state.blocks;
    let length = length.min(icp_ledger::max_blocks_per_request(&PrincipalId::from(
        caller(),
    )));
    let res = icp_ledger::iter_blocks(blocks, start, length);
    let res_proto = to_proto_bytes(res).expect("failed to encode iter_blocks_pb response");
    reply_raw(&res_proto)
}

/// Get multiple Blocks by BlockIndex and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_blocks_pb"]
fn get_blocks_() {
    ic_cdk::setup();
    let GetBlocksArgs { start, length } =
        from_proto_bytes(arg_data_raw()).expect("failed to decode get_blocks_pb argument");
    let archive_state = ARCHIVE_STATE.read().unwrap();
    let blocks = &archive_state.blocks;
    let from_offset = archive_state.block_height_offset;
    let length = length
        .min(usize::MAX as u64)
        .min(icp_ledger::max_blocks_per_request(&PrincipalId::from(caller())) as u64)
        as usize;
    let res = icp_ledger::get_blocks(blocks, from_offset, start, length);
    let res_proto = to_proto_bytes(res).expect("failed to encode get_blocks_pb response");
    reply_raw(&res_proto)
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
    ic_cdk::setup();
    let args =
        Decode!(&arg_data_raw(), GetBlocksArgs).expect("failed to decode get_blocks argument");
    reply((get_blocks(args),));
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    ic_cdk::setup();
    let bytes = stable::get();
    let mut state = ARCHIVE_STATE.write().unwrap();
    *state = ciborium::de::from_reader(std::io::Cursor::new(&bytes))
        .expect("Decoding stable memory failed");
    state.last_upgrade_timestamp = ic_cdk::api::time();
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    ic_cdk::setup();

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
        state.last_upgrade_timestamp as f64 / 1_000_000_000.0,
        "IC timestamp of the last upgrade performed on this canister.",
    )?;
    Ok(())
}

#[query(hidden = true, decoding_quota = 10000)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
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
        encoded_blocks.push(blocks[(i - block_range.start) as usize].clone());
    }
    Ok(encoded_blocks)
}

/// Get multiple Blocks by BlockIndex and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_encoded_blocks"]
fn get_encoded_blocks_blocks_() {
    ic_cdk::setup();
    let args = Decode!(&arg_data_raw(), GetBlocksArgs)
        .expect("failed to decode get_encoded_blocks argument");
    reply((get_encoded_blocks(args),));
}

#[export_name = "canister_query __get_candid_interface_tmp_hack"]
fn get_canidid_interface() {
    ic_cdk::setup();
    reply((include_str!(env!("LEDGER_ARCHIVE_DID_PATH")),));
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
