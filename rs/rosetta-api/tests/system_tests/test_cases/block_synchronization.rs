use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_test_agent;
use crate::common::utils::query_encoded_blocks;
use crate::common::utils::test_identity;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy, DEFAULT_TRANSFER_FEE};
use ic_ledger_core::block::BlockType;
use ic_rosetta_api::convert::to_hash;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
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
fn test_block_synchronization() {
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

                    let network_status = rosetta_testing_environment
                        .rosetta_client
                        .network_status(rosetta_testing_environment.network_identifier.clone())
                        .await
                        .unwrap();
                    let encoded_blocks = query_encoded_blocks(&agent, None, 1).await;
                    println!("Encoded blocks: {:?}", encoded_blocks);
                    assert_eq!(encoded_blocks.blocks.len(), 1);
                    let ledger_tip = encoded_blocks.blocks[0].clone();

                    println!(
                        "Block timestamp: {:?}",
                        network_status.current_block_timestamp
                    );
                    assert_eq!(
                        to_hash(&network_status.current_block_identifier.hash).unwrap(),
                        icp_ledger::Block::block_hash(&ledger_tip),
                        "Block hashes do not match: Expected Block {:?} but got Block {:?}",
                        network_status.current_block_identifier,
                        ledger_tip
                    );
                });

                Ok(())
            },
        )
        .unwrap();
}
