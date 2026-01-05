use candid::{Nat, Principal, candid_method};
use ic_cdk::call::Call;
use ic_cdk::{init, query, update};
use ic_certification::{
    HashTree,
    hash_tree::{Label, empty, fork, label, leaf},
};
use ic_icrc1::endpoints::StandardRecord;
use ic_icrc3_test_ledger::{AddBlockResult, ArchiveBlocksArgs};
use ic_ledger_canister_core::range_utils;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc::generic_value::{ICRC3Value, Value};
use icrc_ledger_types::icrc::metadata_key::MetadataKey;
use icrc_ledger_types::icrc3::archive::{ArchivedRange, QueryArchiveFn, QueryBlockArchiveFn};
use icrc_ledger_types::icrc3::blocks::{ArchivedBlocks, ICRC3DataCertificate};
use icrc_ledger_types::icrc3::blocks::{
    BlockWithId, GetBlocksRequest, GetBlocksResponse, GetBlocksResult,
};
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::{cell::RefCell, ops::Range};

type BlockStorage = BTreeMap<u64, ICRC3Value>;

#[derive(Clone)]
struct ArchiveInfo {
    pub archive_id: Principal,
    pub block_range: Range<u64>,
}

thread_local! {
    static BLOCKS: RefCell<BlockStorage> = const { RefCell::new(BTreeMap::new()) };
    static ICRC3_ENABLED: RefCell<bool> = const { RefCell::new(true) };
    static ARCHIVES: RefCell<Vec<ArchiveInfo>> = const { RefCell::new(vec![]) };
}

fn next_block_id() -> u64 {
    BLOCKS.with(|blocks| match blocks.borrow().last_key_value() {
        Some((k, _)) => *k + 1,
        None => first_non_archive_index(),
    })
}

fn first_non_archive_index() -> u64 {
    ARCHIVES.with(|archives| match archives.borrow().last() {
        Some(archive) => archive.block_range.end,
        None => 0u64,
    })
}

/// Add a block to the ledger storage
#[candid_method(update)]
#[update]
pub fn add_block(block: ICRC3Value) -> AddBlockResult {
    let next_id = next_block_id();
    let result = BLOCKS.with(|blocks| {
        blocks.borrow_mut().insert(next_id, block);
        Ok(Nat::from(next_id))
    });
    ic_cdk::api::certified_data_set(construct_hash_tree().digest());
    result
}

/// Add a block to the ledger storage with the given id.
#[candid_method(update)]
#[update]
pub fn add_block_with_id(block_with_id: BlockWithId) -> AddBlockResult {
    let next_id = next_block_id();
    if next_id > 0 {
        assert_eq!(block_with_id.id, next_id);
    }
    let result = BLOCKS.with(|blocks| {
        let mut blocks = blocks.borrow_mut();
        blocks.insert(block_with_id.id.0.to_u64().unwrap(), block_with_id.block);
        Ok(block_with_id.id)
    });
    ic_cdk::api::certified_data_set(construct_hash_tree().digest());
    result
}

/// Archive the oldest `args.num_blocks` to the archive at given `args.archive_id`.
#[candid_method(update)]
#[update]
pub async fn archive_blocks(args: ArchiveBlocksArgs) -> Result<u64, String> {
    let mut blocks_to_archive = vec![];

    BLOCKS.with(|blocks| {
        let mut blocks = blocks.borrow_mut();
        while !blocks.is_empty() && (blocks_to_archive.len() as u64) < args.num_blocks {
            blocks_to_archive.push(blocks.pop_first().unwrap());
        }
    });

    if blocks_to_archive.is_empty() {
        return Ok(0);
    }

    let start_index = blocks_to_archive.first().unwrap().0;
    let archive_blocks_len = blocks_to_archive.len() as u64;

    ARCHIVES.with(|archives| {
        let mut archives = archives.borrow_mut();
        let last_archive = archives.last_mut();
        match last_archive {
            Some(last_archive) => {
                if last_archive.archive_id == args.archive_id {
                    last_archive.block_range = last_archive.block_range.start
                        ..last_archive.block_range.end + archive_blocks_len
                } else {
                    archives.push(ArchiveInfo {
                        archive_id: args.archive_id,
                        block_range: start_index..start_index + archive_blocks_len,
                    });
                }
            }
            None => archives.push(ArchiveInfo {
                archive_id: args.archive_id,
                block_range: start_index..start_index + archive_blocks_len,
            }),
        };
    });

    for block in blocks_to_archive {
        let block_id = block.0;
        let result = Call::unbounded_wait(args.archive_id, "add_block_with_id")
            .with_arg(&BlockWithId {
                id: Nat::from(block_id),
                block: block.1,
            })
            .await
            .map_err(|e| e.to_string())?
            .candid::<AddBlockResult>()
            .map_err(|e| e.to_string())??;
        assert_eq!(result, Nat::from(block_id));
    }

    Ok(archive_blocks_len)
}

#[query]
fn icrc3_get_tip_certificate() -> Option<ICRC3DataCertificate> {
    let certificate = ByteBuf::from(ic_cdk::api::data_certificate()?);
    let hash_tree = construct_hash_tree();
    let mut tree_buf = vec![];
    ciborium::ser::into_writer(&hash_tree, &mut tree_buf).unwrap();
    Some(ICRC3DataCertificate {
        certificate,
        hash_tree: ByteBuf::from(tree_buf),
    })
}

const MAX_U64_ENCODING_BYTES: usize = 10;

fn construct_hash_tree() -> HashTree {
    BLOCKS.with(|blocks| {
        let blocks = blocks.borrow();
        match blocks.last_key_value() {
            Some((last_block_index, last_block)) => {
                let last_block_index_label = Label::from("last_block_index");
                let last_block_hash_label = Label::from("last_block_hash");

                let mut last_block_index_encoded = Vec::with_capacity(MAX_U64_ENCODING_BYTES);
                leb128::write::unsigned(&mut last_block_index_encoded, *last_block_index)
                    .expect("Failed to write LEB128");

                fork(
                    label(
                        last_block_hash_label,
                        leaf(last_block.clone().hash().to_vec()),
                    ),
                    label(last_block_index_label, leaf(last_block_index_encoded)),
                )
            }
            None => empty(),
        }
    })
}

#[query(name = "icrc1_supported_standards")]
#[candid_method(query, rename = "icrc1_supported_standards")]
fn supported_standards() -> Vec<StandardRecord> {
    let icrc3_enabled = ICRC3_ENABLED.with(|icrc3_enabled| *icrc3_enabled.borrow());
    let mut standards = vec![];
    if icrc3_enabled {
        standards.push(StandardRecord {
            name: "ICRC-3".to_string(),
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3".to_string(),
        });
    }
    standards.push(StandardRecord {
        name: "ICRC-10".to_string(),
        url: "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-10/ICRC-10.md".to_string(),
    });
    standards
}

#[query]
fn icrc10_supported_standards() -> Vec<StandardRecord> {
    supported_standards()
}

/// Get blocks from the ledger (ICRC-3 compatible)
#[candid_method(query)]
#[query]
pub fn icrc3_get_blocks(requests: Vec<GetBlocksRequest>) -> GetBlocksResult {
    let total_blocks = next_block_id();
    BLOCKS.with(|blocks| {
        let blocks = blocks.borrow();

        let mut local_blocks = vec![];
        let mut archived_blocks = vec![];

        // Process all requests
        for request in requests {
            let mut blocks_res = get_blocks_for_request(&blocks, request);
            local_blocks.append(&mut blocks_res.local_blocks);

            let archived_ranges: Vec<
                ArchivedRange<QueryArchiveFn<Vec<GetBlocksRequest>, GetBlocksResult>>,
            > = blocks_res
                .archives
                .into_iter()
                .map(|(canister_id, slice)| ArchivedRange {
                    start: Nat::from(slice.start),
                    length: Nat::from(range_utils::range_len(&slice)),
                    callback: QueryArchiveFn::<Vec<GetBlocksRequest>, GetBlocksResult>::new(
                        canister_id,
                        "icrc3_get_blocks",
                    ),
                })
                .collect();
            let mut archived_blocks_by_callback = BTreeMap::new();
            for ArchivedRange {
                start,
                length,
                callback,
            } in archived_ranges
            {
                let request = GetBlocksRequest { start, length };
                archived_blocks_by_callback
                    .entry(callback)
                    .or_insert(vec![])
                    .push(request);
            }
            for (callback, args) in archived_blocks_by_callback {
                archived_blocks.push(ArchivedBlocks { args, callback });
            }
        }

        GetBlocksResult {
            log_length: Nat::from(total_blocks),
            blocks: local_blocks,
            archived_blocks,
        }
    })
}

#[candid_method(query)]
#[query]
pub fn get_blocks(request: GetBlocksRequest) -> GetBlocksResponse {
    let chain_length = next_block_id();
    BLOCKS.with(|blocks| {
        let blocks = blocks.borrow();

        let start = request.start.0.to_u64().unwrap_or(0);
        let length = request.length.0.to_u64().unwrap_or(0);
        let requested_range = start..start + length;

        let blocks_res = get_blocks_for_request(&blocks, request);

        let local_blocks = blocks_res
            .local_blocks
            .iter()
            .map(|b| Value::from(b.block.clone()))
            .collect();

        let first_index = match blocks.first_key_value() {
            Some((idx, _)) => {
                let local_range = *idx..chain_length;
                match range_utils::intersect(&local_range, &requested_range) {
                    Ok(intersection) => intersection.start,
                    Err(_) => first_non_archive_index(),
                }
            }
            None => first_non_archive_index(),
        };

        let archived_blocks: Vec<ArchivedRange<QueryBlockArchiveFn>> = blocks_res
            .archives
            .into_iter()
            .map(|(canister_id, slice)| ArchivedRange {
                start: Nat::from(slice.start),
                length: Nat::from(range_utils::range_len(&slice)),
                callback: QueryBlockArchiveFn::new(canister_id, "get_blocks"),
            })
            .collect();

        GetBlocksResponse {
            chain_length,
            blocks: local_blocks,
            archived_blocks,
            first_index: Nat::from(first_index),
            certificate: None,
        }
    })
}

struct BlocksResponse {
    pub local_blocks: Vec<BlockWithId>,
    pub archives: Vec<(Principal, Range<u64>)>,
}

fn get_blocks_for_request(blocks: &BlockStorage, request: GetBlocksRequest) -> BlocksResponse {
    let mut result = BlocksResponse {
        local_blocks: vec![],
        archives: vec![],
    };

    let start = request.start.0.to_u64().unwrap_or(0);
    let length = request.length.0.to_u64().unwrap_or(0);

    // Get blocks in the requested range
    for block in blocks.range(start..start + length) {
        result.local_blocks.push(BlockWithId {
            id: Nat::from(*block.0),
            block: block.1.clone(),
        });
    }

    ARCHIVES.with(|archives| {
        let request_range = start..start + length;
        for archive in &*archives.borrow() {
            let arch_range = range_utils::intersect(&archive.block_range, &request_range);
            if let Ok(arch_range) = arch_range {
                result.archives.push((archive.archive_id, arch_range));
            }
        }
    });

    result
}

#[query]
fn icrc1_metadata() -> Vec<(MetadataKey, MetadataValue)> {
    vec![
        MetadataValue::entry(MetadataKey::ICRC1_DECIMALS, 0u64),
        MetadataValue::entry(MetadataKey::ICRC1_NAME, ""),
        MetadataValue::entry(MetadataKey::ICRC1_SYMBOL, "XTST"),
        MetadataValue::entry(MetadataKey::ICRC1_FEE, 0u64),
    ]
}

#[candid_method(update)]
#[update]
pub fn set_icrc3_enabled(enabled: bool) {
    ICRC3_ENABLED.with(|icrc3_enabled| *icrc3_enabled.borrow_mut() = enabled);
}

#[init]
fn init() {
    ic_cdk::api::certified_data_set(construct_hash_tree().digest());
}

fn main() {}

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{CandidSource, service_equal};

    candid::export_service!();

    let new_interface = __export_service();

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let old_interface = manifest_dir.join("icrc3_test_ledger.did");
    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap_or_else(|e| {
        panic!(
            "the icrc3_test_ledger interface is not compatible with {}: {:?}",
            old_interface.display(),
            e
        )
    });
}
