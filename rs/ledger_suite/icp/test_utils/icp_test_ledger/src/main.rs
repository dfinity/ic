#![allow(deprecated)]
use candid::Nat;
use ic_cdk::api::call::{arg_data_raw, reply_raw};
use ic_cdk::futures::internals::in_query_executor_context;
use ic_cdk::{init, query, update};
use ic_icp_test_ledger::AddBlockResult;
use ic_ledger_core::block::{BlockType, EncodedBlock};
use icp_ledger::{
    Block, CandidBlock, GetBlocksArgs, QueryBlocksResponse, QueryEncodedBlocksResponse,
};
use icp_ledger::{from_proto_bytes, protobuf, to_proto_bytes};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::collections::BTreeMap;

type BlockStorage = BTreeMap<u64, EncodedBlock>;

thread_local! {
    static BLOCKS: RefCell<BlockStorage> = const { RefCell::new(BTreeMap::new()) };
}

fn next_block_id() -> u64 {
    BLOCKS.with(|blocks| match blocks.borrow().last_key_value() {
        Some((k, _)) => *k + 1,
        None => 0u64,
    })
}

/// Add a decoded block to the ledger storage
#[update]
pub fn add_block(block: CandidBlock) -> AddBlockResult {
    let next_id = next_block_id();
    let block: Block = block
        .try_into()
        .map_err(|e| format!("Failed to convert CandidBlock to Block: {}", e))?;
    let encoded_block = block.encode();
    BLOCKS.with(|blocks| {
        blocks.borrow_mut().insert(next_id, encoded_block);
        Ok(Nat::from(next_id))
    })
}

/// Add a raw encoded block to the ledger storage
#[update]
pub fn add_raw_block(encoded_block: ByteBuf) -> AddBlockResult {
    let next_id = next_block_id();
    let encoded = EncodedBlock::from_vec(encoded_block.into_vec());
    BLOCKS.with(|blocks| {
        blocks.borrow_mut().insert(next_id, encoded);
        Ok(Nat::from(next_id))
    })
}

/// Query blocks in decoded form
#[query]
pub fn query_blocks(GetBlocksArgs { start, length }: GetBlocksArgs) -> QueryBlocksResponse {
    let chain_length = next_block_id();
    BLOCKS.with(|blocks| {
        let blocks = blocks.borrow();

        let length = length.min(usize::MAX as u64) as usize;
        let end = (start + length as u64).min(chain_length);

        let mut result_blocks = Vec::new();
        for i in start..end {
            if let Some(encoded_block) = blocks.get(&i) {
                let decoded_block = Block::decode(encoded_block.clone())
                    .expect("bug: failed to decode encoded block");
                result_blocks.push(CandidBlock::from(decoded_block));
            }
        }

        let first_block_index = match result_blocks.is_empty() {
            true => chain_length,
            false => start,
        };

        QueryBlocksResponse {
            chain_length,
            certificate: None,
            blocks: result_blocks,
            first_block_index,
            archived_blocks: vec![],
        }
    })
}

/// Query blocks in encoded form
#[query]
pub fn query_encoded_blocks(
    GetBlocksArgs { start, length }: GetBlocksArgs,
) -> QueryEncodedBlocksResponse {
    let chain_length = next_block_id();
    BLOCKS.with(|blocks| {
        let blocks = blocks.borrow();

        let length = length.min(usize::MAX as u64) as usize;
        let end = (start + length as u64).min(chain_length);

        let mut result_blocks = Vec::new();
        for i in start..end {
            if let Some(encoded_block) = blocks.get(&i) {
                result_blocks.push(encoded_block.clone());
            }
        }

        let first_block_index = match result_blocks.is_empty() {
            true => chain_length,
            false => start,
        };

        QueryEncodedBlocksResponse {
            chain_length,
            certificate: None,
            blocks: result_blocks,
            first_block_index,
            archived_blocks: vec![],
        }
    })
}

/// Return archives (empty for test ledger)
#[query]
pub fn archives() -> icp_ledger::Archives {
    icp_ledger::Archives { archives: vec![] }
}

/// Return tip of chain (for compatibility with wait_until_sync_is_completed)
#[query]
pub fn tip_of_chain() -> icp_ledger::TipOfChainRes {
    let chain_length = next_block_id();
    icp_ledger::TipOfChainRes {
        certification: None,
        tip_index: if chain_length > 0 {
            chain_length - 1
        } else {
            0
        },
    }
}

/// Protobuf version of tip_of_chain (for compatibility)
#[unsafe(export_name = "canister_query tip_of_chain_pb")]
fn tip_of_chain_pb() {
    in_query_executor_context(|| {
        let _: protobuf::TipOfChainRequest =
            from_proto_bytes(arg_data_raw()).expect("failed to decode tip_of_chain_pb argument");
        let res =
            to_proto_bytes(tip_of_chain()).expect("failed to encode tip_of_chain_pb response");
        reply_raw(&res)
    })
}

#[init]
fn init() {}

fn main() {}

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{CandidSource, service_equal};

    ic_cdk::export_candid!();

    let new_interface = __export_service();

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let old_interface = manifest_dir.join("icp_test_ledger.did");
    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap_or_else(|e| {
        panic!(
            "the icp_test_ledger interface is not compatible with {}: {:?}",
            old_interface.display(),
            e
        )
    });
}

#[test]
fn check_shared_types_match_ledger() {
    use candid::types::subtype::equal;
    use candid_parser::utils::CandidSource;

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let ledger_did_file = manifest_dir.join("../../ledger.did");
    let test_ledger_did_file = manifest_dir.join("icp_test_ledger.did");

    let mut ledger_env = CandidSource::File(ledger_did_file.as_path())
        .load()
        .unwrap()
        .0;
    let test_ledger_env = CandidSource::File(test_ledger_did_file.as_path())
        .load()
        .unwrap()
        .0;

    // Types that must match exactly between icp_test_ledger.did and ledger.did
    let shared_types = [
        "BlockIndex",
        "TimeStamp",
        "Tokens",
        "AccountIdentifier",
        "SubAccount",
        "Memo",
        "Operation",
        "Transaction",
        "Block",
        "GetBlocksArgs",
        "QueryArchiveError",
        "ArchivedBlocksRange",
        "QueryBlocksResponse",
        "ArchivedEncodedBlocksRange",
        "QueryEncodedBlocksResponse",
        "Archive",
        "Archives",
        "TipOfChainRes",
    ];

    for type_name in shared_types {
        let ledger_type = ledger_env
            .find_type(type_name)
            .unwrap_or_else(|_| panic!("Type '{}' not found in ledger.did", type_name))
            .to_owned();
        let test_ledger_type = test_ledger_env
            .find_type(type_name)
            .unwrap_or_else(|_| panic!("Type '{}' not found in icp_test_ledger.did", type_name))
            .to_owned();

        let mut gamma = std::collections::HashSet::new();
        let merged_type = ledger_env.merge_type(test_ledger_env.clone(), test_ledger_type);

        equal(&mut gamma, &ledger_env, &ledger_type, &merged_type).unwrap_or_else(|e| {
            panic!(
                "Type '{}' in icp_test_ledger.did does not match ledger.did: {:?}",
                type_name, e
            )
        });
    }
}
