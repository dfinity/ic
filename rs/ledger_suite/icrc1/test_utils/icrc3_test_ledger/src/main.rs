use candid::{candid_method, Nat};
use ic_cdk::{query, update};
use ic_certification::{
    hash_tree::{empty, fork, label, leaf, Label},
    HashTree,
};
use ic_icrc1::endpoints::StandardRecord;
use ic_icrc3_test_ledger::AddBlockResult;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc3::blocks::ICRC3DataCertificate;
use icrc_ledger_types::icrc3::blocks::{
    BlockWithId, GenericBlock, GetBlocksRequest, GetBlocksResponse, GetBlocksResult,
};
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::collections::BTreeMap;

type BlockStorage = BTreeMap<u64, ICRC3Value>;

thread_local! {
    static BLOCKS: RefCell<BlockStorage> = const { RefCell::new(BTreeMap::new()) };
    static NEXT_BLOCK_ID: RefCell<u64> = const { RefCell::new(0) };
}

/// Add a block to the ledger storage
#[candid_method(update)]
#[update]
pub fn add_block(block: ICRC3Value) -> AddBlockResult {
    let result = BLOCKS.with(|blocks| {
        NEXT_BLOCK_ID.with(|next_id| {
            let mut blocks = blocks.borrow_mut();
            let mut next_id = next_id.borrow_mut();

            let block_id = *next_id;
            blocks.insert(block_id, block);
            *next_id += 1;

            Ok(Nat::from(block_id))
        })
    });
    ic_cdk::api::certified_data_set(construct_hash_tree().digest());
    result
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
    let standards = vec![
        StandardRecord {
            name: "ICRC-3".to_string(),
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3".to_string(),
        },
        StandardRecord {
            name: "ICRC-10".to_string(),
            url: "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-10/ICRC-10.md".to_string(),
        },
    ];
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
    BLOCKS.with(|blocks| {
        NEXT_BLOCK_ID.with(|next_id| {
            let blocks = blocks.borrow();
            let total_blocks = *next_id.borrow();

            let mut result_blocks = Vec::new();

            // Process all requests
            for request in requests {
                let start = request.start.0.to_u64().unwrap_or(0);
                let length = request.length.0.to_u64().unwrap_or(0) as usize;

                // Get blocks in the requested range
                for block_id in start..std::cmp::min(start + length as u64, total_blocks) {
                    if let Some(block) = blocks.get(&block_id) {
                        result_blocks.push(BlockWithId {
                            id: Nat::from(block_id),
                            block: block.clone(),
                        });
                    }
                }
            }

            GetBlocksResult {
                log_length: Nat::from(total_blocks),
                blocks: result_blocks,
                archived_blocks: vec![], // No archiving in this simple implementation
            }
        })
    })
}

#[candid_method(query)]
#[query]
pub fn get_blocks(request: GetBlocksRequest) -> GetBlocksResponse {
    BLOCKS.with(|blocks| {
        NEXT_BLOCK_ID.with(|next_id| {
            let blocks = blocks.borrow();
            let total_blocks = *next_id.borrow();

            let mut result_blocks = Vec::new();

            let start = request.start.0.to_u64().unwrap_or(0);
            let length = request.length.0.to_u64().unwrap_or(0) as usize;

            // Get blocks in the requested range
            for block_id in start..std::cmp::min(start + length as u64, total_blocks) {
                if let Some(block) = blocks.get(&block_id) {
                    result_blocks.push(GenericBlock::from(block.clone()));
                }
            }

            GetBlocksResponse {
                chain_length: total_blocks,
                blocks: result_blocks,
                archived_blocks: vec![], // No archiving in this simple implementation
                first_index: Nat::from(start),
                certificate: None,
            }
        })
    })
}

pub fn get_block_count() -> u64 {
    NEXT_BLOCK_ID.with(|next_id| *next_id.borrow())
}

fn main() {}

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{service_equal, CandidSource};

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
