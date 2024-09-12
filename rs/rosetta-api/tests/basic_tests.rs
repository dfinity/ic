use crate::test_utils::TestLedger;
use ic_ledger_canister_blocks_synchronizer::blocks::Blocks;
use ic_ledger_canister_blocks_synchronizer::blocks::HashedBlock;
use ic_ledger_canister_blocks_synchronizer_test_utils::create_tmp_dir;
use ic_ledger_canister_blocks_synchronizer_test_utils::sample_data::Scribe;
use ic_ledger_core::block::BlockType;
use ic_ledger_core::tokens::CheckedAdd;
use ic_rosetta_api::convert::{from_hash, to_hash};
use ic_rosetta_api::errors::ApiError;
use ic_rosetta_api::models::CallRequest;
use ic_rosetta_api::models::PartialBlockIdentifier;
use ic_rosetta_api::models::QueryBlockRangeRequest;
use ic_rosetta_api::models::QueryBlockRangeResponse;
use ic_rosetta_api::models::{
    BlockIdentifier, BlockRequest, BlockTransaction, BlockTransactionRequest,
    SearchTransactionsRequest, SearchTransactionsResponse,
};
use ic_rosetta_api::request_handler::RosettaRequestHandler;
use ic_rosetta_api::MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST;
use icp_ledger::{self, AccountIdentifier, Block, BlockIndex, Tokens};
use rosetta_core::objects::ObjectMap;
use std::collections::BTreeMap;
use std::sync::Arc;

mod test_utils;

fn verify_balances(scribe: &Scribe, blocks: &Blocks, start_idx: usize) {
    for hb in scribe.blockchain.iter().skip(start_idx) {
        assert_eq!(*hb, blocks.get_hashed_block(&hb.index).unwrap());
        assert!(blocks.is_verified_by_hash(&hb.hash).unwrap());
        for (account, amount) in scribe.balance_history.get(hb.index as usize).unwrap() {
            assert_eq!(
                blocks.get_account_balance(account, &hb.index).unwrap(),
                *amount
            );
        }
    }
    let mut sum_icpt = Tokens::ZERO;
    let latest = blocks.get_latest_verified_hashed_block().unwrap();
    for amount in scribe.balance_history.back().unwrap().values() {
        sum_icpt = sum_icpt.checked_add(amount).unwrap();
    }
    let accounts = blocks.get_all_accounts().unwrap();
    let mut total = Tokens::ZERO;
    for account in accounts {
        let amount = blocks.get_account_balance(&account, &latest.index).unwrap();
        total = total.checked_add(&amount).unwrap();
    }
    assert_eq!(sum_icpt, total);
}

async fn query_search_transactions(
    req_handler: &RosettaRequestHandler,
    acc: &icp_ledger::AccountIdentifier,
    max_block: Option<i64>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<SearchTransactionsResponse, ApiError> {
    let mut msg = SearchTransactionsRequest::builder(req_handler.network_id())
        .with_account_identifier(ic_rosetta_api::convert::to_model_account_identifier(acc))
        .build();
    msg.max_block = max_block;
    msg.offset = offset;
    msg.limit = limit;
    req_handler.search_transactions(msg).await
}

async fn verify_account_search(
    scribe: &Scribe,
    req_handler: &RosettaRequestHandler,
    oldest_idx: u64,
    last_verified_idx: u64,
) {
    let mut history = BTreeMap::new();

    let mut index = |account: AccountIdentifier, block_index: u64| {
        history
            .entry(account)
            .or_insert_with(Vec::new)
            .push(block_index);
    };

    for hb in &scribe.blockchain {
        match Block::decode(hb.block.clone())
            .unwrap()
            .transaction
            .operation
        {
            icp_ledger::Operation::Burn { from, .. } => {
                index(from, hb.index);
            }
            icp_ledger::Operation::Mint { to, .. } => {
                index(to, hb.index);
            }
            icp_ledger::Operation::Transfer {
                from, to, spender, ..
            } => {
                index(from, hb.index);
                if from != to {
                    index(to, hb.index);
                }
                // https://github.com/rust-lang/rust-clippy/issues/4530
                #[allow(clippy::unnecessary_unwrap)]
                if spender.is_some() && spender.unwrap() != from && spender.unwrap() != to {
                    index(spender.unwrap(), hb.index);
                }
            }
            icp_ledger::Operation::Approve { from, spender, .. } => {
                assert_ne!(from, spender);
                index(from, hb.index);
            }
        }
    }

    let middle_idx = (scribe.blockchain.len() as u64 - 1 + oldest_idx) / 2;
    for acc in &scribe.accounts {
        let mut h2: Vec<BlockIndex> = history
            .get(acc)
            .unwrap()
            .clone()
            .into_iter()
            .filter(|i| *i >= oldest_idx && *i <= last_verified_idx)
            .collect();

        let search_res = query_search_transactions(req_handler, acc, None, None, None)
            .await
            .unwrap();
        let mut h: Vec<BlockIndex> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockIndex)
            .collect();
        h.sort_by(|a, b| a.partial_cmp(b).unwrap());
        h2.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(h, h2);

        let limit = 3;
        let h1: Vec<BlockIndex> = history
            .get(acc)
            .unwrap()
            .clone()
            .into_iter()
            .filter(|i| *i <= middle_idx && *i >= oldest_idx && *i <= last_verified_idx)
            .collect();

        let search_res = query_search_transactions(
            req_handler,
            acc,
            Some(middle_idx as i64),
            None,
            Some(limit as i64),
        )
        .await
        .unwrap();
        let h: Vec<BlockIndex> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockIndex)
            .collect();

        let next_offset = if h1.len() > limit {
            Some(limit as i64)
        } else {
            None
        };

        let mut h1_limit = h1.clone();
        h1_limit.truncate(limit);
        h1_limit.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(h, h1_limit);
        assert_eq!(search_res.next_offset, next_offset);

        let offset = 1;
        let search_res = query_search_transactions(
            req_handler,
            acc,
            Some(middle_idx as i64),
            Some(offset),
            Some(limit as i64),
        )
        .await
        .unwrap();
        let h: Vec<BlockIndex> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockIndex)
            .collect();

        let next_offset = if h1.len() > limit + offset as usize {
            Some(limit as i64 + offset)
        } else {
            None
        };

        let mut h1_offset = h1.clone();
        h1_offset = h1_offset.split_off(offset as usize);
        h1_offset.truncate(limit);
        h1_offset.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(h, h1_offset);
        assert_eq!(search_res.next_offset, next_offset);
    }
}

#[actix_rt::test]
async fn load_from_store_test() {
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    let mut last_verified = 0;
    for hb in &scribe.blockchain {
        blocks.push(hb).unwrap();
        if hb.index < 20 {
            blocks.set_hashed_block_to_verified(&hb.index).unwrap();
            last_verified = hb.index;
        }
    }

    let some_acc = scribe.accounts.front().cloned().unwrap();

    assert!(blocks.is_verified_by_idx(&10).unwrap());
    assert!(blocks.get_account_balance(&some_acc, &10).is_ok());
    assert!(!blocks.is_verified_by_idx(&20).unwrap());
    assert!(blocks.get_account_balance(&some_acc, &20).is_err());

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    verify_account_search(&scribe, &req_handler, 0, last_verified).await;

    drop(req_handler);

    let blocks = Blocks::new_persistent(location, false).unwrap();
    assert!(blocks.is_verified_by_idx(&10).unwrap());
    assert!(blocks.get_account_balance(&some_acc, &10).is_ok());
    assert!(!blocks.is_verified_by_idx(&20).unwrap());
    assert!(blocks.get_account_balance(&some_acc, &20).is_err());
    last_verified = (scribe.blockchain.len() - 1) as u64;
    blocks.set_hashed_block_to_verified(&last_verified).unwrap();

    assert!(blocks.get_account_balance(&some_acc, &20).is_ok());

    drop(blocks);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    verify_balances(&scribe, &blocks, 0);

    // now load pruned
    blocks
        .try_prune(&Some((scribe.blockchain.len() - 11) as u64), 0)
        .unwrap();

    assert!(blocks.is_verified_by_idx(&9).is_err());
    assert!(blocks.is_verified_by_idx(&10).unwrap());
    verify_balances(&scribe, &blocks, 10);
    // height 10 is the first block available for balance query, but not for
    // transaction search. Transaction search is available from 11
    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    verify_account_search(&scribe, &req_handler, 11, last_verified).await;

    drop(req_handler);

    let blocks = Blocks::new_persistent(location, false).unwrap();
    verify_balances(&scribe, &blocks, 10);

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    verify_account_search(&scribe, &req_handler, 11, last_verified).await;

    let resp = req_handler
        .search_transactions(SearchTransactionsRequest::builder(req_handler.network_id()).build())
        .await
        .unwrap();

    assert_eq!(resp.total_count as u64, last_verified - 10 + 1);
    assert_eq!(resp.transactions.len() as u64, last_verified - 10 + 1);
    assert_eq!(resp.next_offset, None);
    assert_eq!(
        resp.transactions.first().unwrap().block_identifier.index,
        last_verified
    );
    assert_eq!(resp.transactions.last().unwrap().block_identifier.index, 10);
}

// remove this test if it's in the way of a new spec
#[actix_rt::test]
async fn load_unverified_test() {
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    for hb in &scribe.blockchain {
        blocks.push(hb).unwrap();
        if hb.index < 20 {
            blocks.set_hashed_block_to_verified(&hb.index).unwrap();
        }
    }

    blocks
        .try_prune(&Some((scribe.blockchain.len() - 51) as u64), 0)
        .unwrap();

    assert!(blocks.is_verified_by_idx(&49).is_err());
    assert!(!blocks.is_verified_by_idx(&50).unwrap());

    drop(blocks);

    let blocks = Blocks::new_persistent(location, false).unwrap();
    let last_verified = (scribe.blockchain.len() - 1) as u64;
    blocks.set_hashed_block_to_verified(&last_verified).unwrap();

    assert!(blocks.is_verified_by_idx(&49).is_err());
    assert!(blocks.is_verified_by_idx(&50).unwrap());

    verify_balances(&scribe, &blocks, 50);

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    verify_account_search(&scribe, &req_handler, 51, last_verified).await;
}

#[actix_rt::test]
async fn store_batch_test() {
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    for hb in &scribe.blockchain {
        if hb.index < 21 {
            blocks.push(hb).unwrap();
        }
    }

    assert_eq!(
        blocks.get_hashed_block(&20).unwrap(),
        *scribe.blockchain.get(20).unwrap()
    );
    assert!(blocks.get_hashed_block(&21).is_err());

    let mut part2: Vec<HashedBlock> = scribe.blockchain.iter().skip(21).cloned().collect();

    let mut part3 = part2.split_off(10);
    part3.push(scribe.blockchain.get(30).unwrap().clone()); // this will cause an error

    blocks.push_batch(part2.clone()).unwrap();

    assert_eq!(
        blocks.get_hashed_block(&30).unwrap(),
        *scribe.blockchain.get(30).unwrap()
    );
    assert!(blocks.get_hashed_block(&31).is_err());

    assert!(blocks.push_batch(part3.clone()).is_err());
    assert_eq!(
        blocks.get_hashed_block(&30).unwrap(),
        *scribe.blockchain.get(30).unwrap()
    );
    assert!(blocks.get_hashed_block(&31).is_err());

    part3.pop();

    blocks.push_batch(part3).unwrap();
    let last_idx = scribe.blockchain.back().unwrap().index;
    assert_eq!(
        blocks.get_hashed_block(&last_idx).unwrap(),
        *scribe.blockchain.back().unwrap()
    );
    assert!(blocks.get_hashed_block(&(last_idx + 1)).is_err());

    blocks.set_hashed_block_to_verified(&last_idx).unwrap();
    verify_balances(&scribe, &blocks, 0);
}

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
