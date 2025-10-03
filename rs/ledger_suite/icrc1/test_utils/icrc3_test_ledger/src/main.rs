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
use icrc_ledger_types::icrc3::archive::{ArchivedRange, QueryBlockArchiveFn};
use icrc_ledger_types::icrc3::blocks::ICRC3DataCertificate;
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
        None => 0u64,
    })
}

/// Add a block to the ledger storage
#[candid_method(update)]
#[update]
pub fn add_block(block: ICRC3Value) -> AddBlockResult {
    let mut next_id = next_block_id();
    let result = BLOCKS.with(|blocks| {
        let mut blocks = blocks.borrow_mut();

        let block_id = next_id;
        blocks.insert(block_id, block);
        next_id += 1;

        Ok(Nat::from(block_id))
    });
    ic_cdk::api::certified_data_set(construct_hash_tree().digest());
    result
}

/// Archive the oldest `num_blocks` to the archive at given `archive_id`.
#[candid_method(update)]
#[update]
pub async fn archive_blocks(args: ArchiveBlocksArgs) -> u64 {
    let mut blocks_to_archive = vec![];

    BLOCKS.with(|blocks| {
        let mut blocks = blocks.borrow_mut();
        while !blocks.is_empty() && (blocks_to_archive.len() as u64) < args.num_blocks {
            blocks_to_archive.push(blocks.pop_first().unwrap());
        }
    });

    if blocks_to_archive.is_empty() {
        return 0;
    }

    let first_block_index = blocks_to_archive.first().unwrap().0;
    let last_block_index = blocks_to_archive.last().unwrap().0;

    ARCHIVES.with(|archives| {
        let mut archives = archives.borrow_mut();
        let last_archive = archives.last().cloned();
        match last_archive {
            Some(archive) => {
                if archive.archive_id == args.archive_id {
                    let updated_archive = ArchiveInfo {
                        block_range: archive.block_range.start..last_block_index + 1,
                        ..archive
                    };
                    let last_idx = archives.len() - 1;
                    archives[last_idx] = updated_archive;
                } else {
                    archives.push(ArchiveInfo {
                        archive_id: args.archive_id,
                        block_range: first_block_index..last_block_index + 1,
                    });
                }
            }
            None => archives.push(ArchiveInfo {
                archive_id: args.archive_id,
                block_range: first_block_index..last_block_index + 1,
            }),
        };
    });

    for block in &blocks_to_archive {
        let result = Call::unbounded_wait(args.archive_id, "add_block")
            .with_arg(&block.1)
            .await
            .expect("failed to add block to archive")
            .candid::<AddBlockResult>()
            .expect("Could not decode AddBlockResult")
            .expect("adding block failed");
        assert_eq!(result, Nat::from(block.0));
    }

    blocks_to_archive.len() as u64
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
    let next_id = next_block_id();
    BLOCKS.with(|blocks| {
        let blocks = blocks.borrow();
        let total_blocks = next_id;

        let mut result_blocks = Vec::new();

        // Process all requests
        for request in requests {
            let mut blocks_res = get_blocks_for_request(&blocks, request);
            result_blocks.append(&mut blocks_res.local_blocks);
        }

        GetBlocksResult {
            log_length: Nat::from(total_blocks),
            blocks: result_blocks,
            archived_blocks: vec![], // No archiving in this simple implementation
        }
    })
}

#[candid_method(query)]
#[query]
pub fn get_blocks(request: GetBlocksRequest) -> GetBlocksResponse {
    let next_id = next_block_id();
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

        let first_non_archive = ARCHIVES.with(|archives| match archives.borrow().last() {
            Some(archive) => archive.block_range.end,
            None => 0u64,
        });
        let first_index = match blocks.first_key_value() {
            Some((idx, _)) => {
                let local_range = *idx..next_id;
                match range_utils::intersect(&local_range, &requested_range) {
                    Ok(intersection) => intersection.start,
                    Err(_) => first_non_archive,
                }
            }
            None => first_non_archive,
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
            chain_length: next_id,
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
fn icrc1_metadata() -> Vec<(String, MetadataValue)> {
    vec![
        MetadataValue::entry("icrc1:decimals", 0u64),
        MetadataValue::entry("icrc1:name", ""),
        MetadataValue::entry("icrc1:symbol", "XTST"),
        MetadataValue::entry("icrc1:fee", 0u64),
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
