use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_test_agent;
use crate::common::utils::query_encoded_blocks;
use crate::common::utils::test_identity;
use crate::common::utils::wait_for_rosetta_to_sync_up_to_block;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_icrc1_test_utils::{DEFAULT_TRANSFER_FEE, minter_identity, valid_transactions_strategy};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::block::BlockType;
use ic_rosetta_api::MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST;
use ic_rosetta_api::convert::to_hash;
use ic_rosetta_api::models::BlockIdentifier;
use ic_rosetta_api::models::CallRequest;
use ic_rosetta_api::models::PartialBlockIdentifier;
use ic_rosetta_api::models::QueryBlockRangeRequest;
use ic_rosetta_api::models::QueryBlockRangeResponse;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::TransactionIdentifier;
use rosetta_core::objects::ObjectMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::runtime::Runtime;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 50;
    pub static ref NUM_TEST_CASES: u32 = 1;
    pub static ref MINTING_IDENTITY: Arc<BasicIdentity> = Arc::new(minter_identity());
}

#[test]
fn test_fetching_blocks() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(valid_transactions_strategy(
                (*MINTING_IDENTITY).clone(),
                DEFAULT_TRANSFER_FEE,
                *MAX_NUM_GENERATED_BLOCKS,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let rosetta_testing_environment = RosettaTestingEnvironment::builder()
                        .with_transfer_args_for_block_generating(args_with_caller.clone())
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;
                    let agent = get_test_agent(
                        rosetta_testing_environment
                            .pocket_ic
                            .url()
                            .unwrap()
                            .port()
                            .unwrap(),
                    )
                    .await;

                    // Fetch all blocks on the ledger
                    let encoded_blocks = query_encoded_blocks(&agent, 0, u64::MAX).await;

                    for (index, eb) in encoded_blocks.blocks.into_iter().enumerate() {
                        let block_hash = icp_ledger::Block::block_hash(&eb);
                        let decoded_block = icp_ledger::Block::decode(eb.clone()).unwrap();

                        // Fetch the block by index
                        let rosetta_block = rosetta_testing_environment
                            .rosetta_client
                            .block(
                                rosetta_testing_environment.network_identifier.clone(),
                                PartialBlockIdentifier {
                                    index: Some(index as u64),
                                    hash: None,
                                },
                            )
                            .await
                            .unwrap()
                            .block
                            .unwrap();
                        assert_eq!(
                            to_hash(&rosetta_block.block_identifier.hash).unwrap(),
                            block_hash
                        );

                        // Fetch the block by hash
                        let rosetta_block = rosetta_testing_environment
                            .rosetta_client
                            .block(
                                rosetta_testing_environment.network_identifier.clone(),
                                PartialBlockIdentifier {
                                    index: None,
                                    hash: Some(rosetta_block.block_identifier.hash.clone()),
                                },
                            )
                            .await
                            .unwrap()
                            .block
                            .unwrap();
                        assert_eq!(
                            to_hash(&rosetta_block.block_identifier.hash).unwrap(),
                            block_hash
                        );
                        assert_eq!(rosetta_block.block_identifier.index as usize, index);

                        let ledger_transactions = decoded_block.transaction;
                        let block_transaction = rosetta_testing_environment
                            .rosetta_client
                            .block_transaction(
                                rosetta_testing_environment.network_identifier.clone(),
                                TransactionIdentifier {
                                    hash: rosetta_block.block_identifier.hash.clone(),
                                },
                                BlockIdentifier {
                                    index: index as u64,
                                    hash: rosetta_block.block_identifier.hash.clone(),
                                },
                            )
                            .await
                            .unwrap()
                            .transaction;
                        assert_eq!(
                            ledger_transactions.hash(),
                            to_hash(&block_transaction.transaction_identifier.hash).unwrap()
                        );
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_fetching_block_ranges() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: *NUM_TEST_CASES,
        ..Default::default()
    });

    runner
        .run(
            &(valid_transactions_strategy(
                (*MINTING_IDENTITY).clone(),
                DEFAULT_TRANSFER_FEE,
                *MAX_NUM_GENERATED_BLOCKS,
                SystemTime::now(),
            )
            .no_shrink(),),
            |(args_with_caller,)| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let env = RosettaTestingEnvironment::builder()
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;
                    let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;

                    let response: QueryBlockRangeResponse = env
                        .rosetta_client
                        .call(CallRequest {
                            network_identifier: env.network_identifier.clone(),
                            method_name: "query_block_range".to_owned(),
                            parameters: ObjectMap::try_from(QueryBlockRangeRequest {
                                highest_block_index: args_with_caller.len() as u64,
                                number_of_blocks: args_with_caller.len() as u64,
                            })
                            .unwrap(),
                        })
                        .await
                        .unwrap()
                        .result
                        .try_into()
                        .unwrap();
                    assert!(response.blocks.is_empty());

                    env.generate_blocks(args_with_caller.clone()).await;
                    wait_for_rosetta_to_sync_up_to_block(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        args_with_caller.len() as u64,
                    )
                    .await;

                    let chain_length = query_encoded_blocks(&agent, u64::MAX, u64::MAX)
                        .await
                        .chain_length;

                    let highest_block_index = chain_length.saturating_sub(1);

                    // Lets fetch all blocks
                    let mut query_blocks_request = QueryBlockRangeRequest {
                        highest_block_index,
                        number_of_blocks: MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST,
                    };
                    let query_blocks_response: QueryBlockRangeResponse = env
                        .rosetta_client
                        .call(CallRequest {
                            network_identifier: env.network_identifier.clone(),
                            method_name: "query_block_range".to_owned(),
                            parameters: ObjectMap::try_from(query_blocks_request.clone()).unwrap(),
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
                            chain_length as usize
                        )
                    );

                    // From this point on, we will only test the case where the number of blocks created is greater than 0
                    if args_with_caller.is_empty() {
                        return;
                    }
                    // Lets try to fetch blocks which are out of scope
                    query_blocks_request.highest_block_index = highest_block_index * 10;
                    let query_blocks_response: QueryBlockRangeResponse = env
                        .rosetta_client
                        .call(CallRequest {
                            network_identifier: env.network_identifier.clone(),
                            method_name: "query_block_range".to_owned(),
                            parameters: ObjectMap::try_from(query_blocks_request.clone()).unwrap(),
                        })
                        .await
                        .unwrap()
                        .result
                        .try_into()
                        .unwrap();

                    assert_eq!(query_blocks_response.blocks.len() as u64, chain_length);

                    // Lets try to request more blocks than allowed by the max fetchable blocks
                    query_blocks_request.highest_block_index = highest_block_index;
                    query_blocks_request.number_of_blocks =
                        MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST + 1;
                    let query_blocks_response: QueryBlockRangeResponse = env
                        .rosetta_client
                        .call(CallRequest {
                            network_identifier: env.network_identifier.clone(),
                            method_name: "query_block_range".to_owned(),
                            parameters: ObjectMap::try_from(query_blocks_request.clone()).unwrap(),
                        })
                        .await
                        .unwrap()
                        .result
                        .try_into()
                        .unwrap();

                    assert_eq!(query_blocks_response.blocks.len(), chain_length as usize);

                    // If the number of blocks requested is 0, the response should only contain the genesis block
                    query_blocks_request.highest_block_index = 0;
                    let query_blocks_response: QueryBlockRangeResponse = env
                        .rosetta_client
                        .call(CallRequest {
                            network_identifier: env.network_identifier.clone(),
                            method_name: "query_block_range".to_owned(),
                            parameters: ObjectMap::try_from(query_blocks_request.clone()).unwrap(),
                        })
                        .await
                        .unwrap()
                        .result
                        .try_into()
                        .unwrap();
                    let genesis_block_hash = icp_ledger::Block::block_hash(
                        query_encoded_blocks(&agent, 0, 1)
                            .await
                            .blocks
                            .first()
                            .unwrap(),
                    );
                    assert_eq!(query_blocks_response.blocks.len(), 1);
                    assert_eq!(
                        to_hash(
                            &query_blocks_response
                                .blocks
                                .first()
                                .unwrap()
                                .block_identifier
                                .hash
                        )
                        .unwrap(),
                        genesis_block_hash
                    );

                    // If we reduce the highest block index asked for by 1, we should get all blocks except the tip block
                    query_blocks_request.highest_block_index =
                        highest_block_index.saturating_sub(1);
                    let query_blocks_response: QueryBlockRangeResponse = env
                        .rosetta_client
                        .call(CallRequest {
                            network_identifier: env.network_identifier.clone(),
                            method_name: "query_block_range".to_owned(),
                            parameters: ObjectMap::try_from(query_blocks_request.clone()).unwrap(),
                        })
                        .await
                        .unwrap()
                        .result
                        .try_into()
                        .unwrap();
                    assert_eq!(
                        query_blocks_response.blocks.len(),
                        highest_block_index as usize
                    );
                    assert_eq!(
                        to_hash(
                            &query_blocks_response
                                .blocks
                                .first()
                                .unwrap()
                                .block_identifier
                                .hash
                        )
                        .unwrap(),
                        genesis_block_hash
                    );

                    // If we set the highest block index and the number of blocks to 0 we should get an empty response
                    query_blocks_request.highest_block_index = 0;
                    query_blocks_request.number_of_blocks = 0;
                    let query_blocks_response: QueryBlockRangeResponse = env
                        .rosetta_client
                        .call(CallRequest {
                            network_identifier: env.network_identifier.clone(),
                            method_name: "query_block_range".to_owned(),
                            parameters: ObjectMap::try_from(query_blocks_request.clone()).unwrap(),
                        })
                        .await
                        .unwrap()
                        .result
                        .try_into()
                        .unwrap();
                    assert!(query_blocks_response.blocks.is_empty());
                });
                Ok(())
            },
        )
        .unwrap();
}
