use crate::test_utils::TestLedger;
use ic_ledger_canister_blocks_synchronizer::blocks::Blocks;
use ic_ledger_canister_blocks_synchronizer_test_utils::create_tmp_dir;
use ic_ledger_canister_blocks_synchronizer_test_utils::sample_data::Scribe;
use ic_rosetta_api::models::CallRequest;
use ic_rosetta_api::models::QueryBlockRangeRequest;
use ic_rosetta_api::models::QueryBlockRangeResponse;
use ic_rosetta_api::request_handler::RosettaRequestHandler;
use ic_rosetta_api::MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST;
use rosetta_core::objects::ObjectMap;
use std::sync::Arc;

mod test_utils;

#[actix_rt::test]
async fn test_query_block_range() {
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 1000);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    let mut block_indices = Vec::new();

    // Test with empty rosetta
    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    let response: QueryBlockRangeResponse = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),

            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(QueryBlockRangeRequest {
                highest_block_index: 100,
                number_of_blocks: 10,
            })
            .unwrap(),
        })
        .await
        .unwrap()
        .result
        .try_into()
        .unwrap();
    assert!(response.blocks.is_empty());

    for hb in &scribe.blockchain {
        blocks.push(hb).unwrap();
        blocks.set_hashed_block_to_verified(&hb.index).unwrap();
        block_indices.push(hb.index);
    }
    block_indices.sort();

    // Test with non-empty rosetta
    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);

    let highest_block_index = block_indices.last().unwrap();
    // Call with 0 numbers of blocks
    let response: QueryBlockRangeResponse = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),
            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(QueryBlockRangeRequest {
                highest_block_index: *highest_block_index,
                number_of_blocks: 0,
            })
            .unwrap(),
        })
        .await
        .unwrap()
        .result
        .try_into()
        .unwrap();
    assert!(response.blocks.is_empty());
    // Call with higher index than there are blocks in the database
    let response = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),
            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(QueryBlockRangeRequest {
                highest_block_index: (block_indices.len() * 2) as u64,
                number_of_blocks: std::cmp::max(
                    block_indices.len() as u64,
                    MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST,
                ),
            })
            .unwrap(),
        })
        .await
        .unwrap();
    let query_block_response: QueryBlockRangeResponse = response.result.try_into().unwrap();
    // If the blocks measured from the highest block index asked for are not in the database the service should return an empty array of blocks
    if block_indices.len() >= MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize {
        assert_eq!(query_block_response.blocks.len(), 0);
        assert!(!response.idempotent);
    }
    // If some of the blocks measured from the highest block index asked for are in the database the service should return the blocks that are in the database
    else {
        if block_indices.len() * 2 > MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize {
            assert_eq!(
                query_block_response.blocks.len(),
                block_indices
                    .len()
                    .saturating_sub(
                        (block_indices.len() * 2)
                            .saturating_sub(MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize)
                    )
                    .saturating_sub(1)
            );
        } else {
            assert_eq!(query_block_response.blocks.len(), block_indices.len());
        }
        assert!(!response.idempotent);
    }
    let number_of_blocks = (block_indices.len() / 2) as u64;
    let query_blocks_request = QueryBlockRangeRequest {
        highest_block_index: *highest_block_index,
        number_of_blocks,
    };

    let query_blocks_response = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),

            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(query_blocks_request.clone()).unwrap(),
        })
        .await
        .unwrap();
    assert!(query_blocks_response.idempotent);
    let response: QueryBlockRangeResponse = query_blocks_response.result.try_into().unwrap();

    let querried_blocks = response.blocks;
    assert_eq!(
        querried_blocks.len(),
        std::cmp::min(number_of_blocks, MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST) as usize
    );
    if !querried_blocks.is_empty() {
        assert_eq!(
            querried_blocks.first().unwrap().block_identifier.index,
            highest_block_index
                .saturating_sub(std::cmp::min(
                    number_of_blocks,
                    MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST
                ))
                .saturating_add(1)
        );
        assert_eq!(
            querried_blocks.last().unwrap().block_identifier.index,
            *highest_block_index
        );
    }

    let query_blocks_request = QueryBlockRangeRequest {
        highest_block_index: *highest_block_index,
        number_of_blocks: MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST + 1,
    };

    let query_blocks_response: QueryBlockRangeResponse = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),

            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(query_blocks_request).unwrap(),
        })
        .await
        .unwrap()
        .result
        .try_into()
        .unwrap();
    assert_eq!(
        query_blocks_response.blocks.len(),
        std::cmp::min(
            MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize,
            block_indices.len()
        )
    );
}
