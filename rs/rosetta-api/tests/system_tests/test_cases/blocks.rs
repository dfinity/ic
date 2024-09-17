use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_test_agent;
use crate::common::utils::query_encoded_blocks;
use crate::common::utils::test_identity;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy, DEFAULT_TRANSFER_FEE};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::block::BlockType;
use ic_rosetta_api::convert::to_hash;
use ic_rosetta_api::models::BlockIdentifier;
use ic_rosetta_api::models::PartialBlockIdentifier;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::TransactionIdentifier;
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
