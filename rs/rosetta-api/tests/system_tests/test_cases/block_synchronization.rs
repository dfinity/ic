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
                    assert_eq!(encoded_blocks.blocks.len(), 1);
                    let ledger_tip = encoded_blocks.blocks[0].clone();

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

#[test]
fn test_rosetta_ledger_upgrade() {
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
                *MAX_NUM_GENERATED_BLOCKS*2,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let rosetta_testing_environment = RosettaTestingEnvironment::builder()
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
                    assert_eq!(encoded_blocks.blocks.len(), 1);
                    let ledger_tip = encoded_blocks.blocks[0].clone();
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

// #[tokio::test]
// async fn test_rosetta_ledger_upgrade() {
//     let mut env = TestEnv::setup(false, true).await.unwrap();

//     // Currently, the ledger canister version is that of this branch
//     // We need to reinstall it to the mainnet version
//     let ledger_wasm_mainnet =
//         std::fs::read(std::env::var("ICP_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap()).unwrap();
//     env.pocket_ic
//         .reinstall_canister(
//             env.ledger_id,
//             ledger_wasm_mainnet,
//             icp_ledger_init(env.sender_id),
//             None,
//         )
//         .await
//         .unwrap();

//     // Let's create a few transactions to make sure rosetta is working with the mainnet ledger version
//     for _ in 0..100 {
//         let transfer_arg = TransferArg {
//             from_subaccount: None,
//             to: Account::from(Principal::anonymous()),
//             fee: None,
//             created_at_time: None,
//             memo: None,
//             amount: Nat::from(1u64),
//         };
//         let arg = Encode!(&transfer_arg).unwrap();
//         env.pocket_ic
//             .update_call(env.ledger_id, env.sender_id, "icrc1_transfer", arg)
//             .await
//             .unwrap();
//     }

//     // We should now have 100 blocks
//     // Let's restart rosetta to make sure it can handle the mainnet ledger version
//     env.restart_rosetta_node(false, false).await.unwrap();
//     env.rosetta.wait_until_synced_up_to(100).await.unwrap();

//     // Let's check the network status
//     let network_status = env.rosetta.network_status().await.unwrap();
//     let current_block = env
//         .rosetta
//         .block(PartialBlockIdentifier {
//             index: Some(100),
//             hash: None,
//         })
//         .await
//         .unwrap()
//         .block
//         .unwrap();
//     let genesis_block = env
//         .rosetta
//         .block(PartialBlockIdentifier {
//             index: Some(0),
//             hash: None,
//         })
//         .await
//         .unwrap()
//         .block
//         .unwrap();
//     assert_eq!(
//         network_status.current_block_identifier,
//         current_block.block_identifier
//     );
//     assert_eq!(
//         network_status.genesis_block_identifier,
//         genesis_block.block_identifier
//     );

//     // Now we upgrade the ledger canister to the latest version of the current branch
//     let ledger_wasm_current_branch = icp_ledger_wasm_bytes();
//     env.pocket_ic
//         .upgrade_canister(
//             env.ledger_id,
//             ledger_wasm_current_branch,
//             Encode!(&LedgerCanisterUpgradePayload(
//                 LedgerCanisterPayload::Upgrade(None)
//             ))
//             .unwrap(),
//             None,
//         )
//         .await
//         .unwrap();

//     // Let's create a few transactions to make sure rosetta is working with the current branch ledger version
//     for _ in 0..100 {
//         let transfer_arg = TransferArg {
//             from_subaccount: None,
//             to: Account::from(Principal::anonymous()),
//             fee: None,
//             created_at_time: None,
//             memo: None,
//             amount: Nat::from(1u64),
//         };
//         let arg = Encode!(&transfer_arg).unwrap();
//         env.pocket_ic
//             .update_call(env.ledger_id, env.sender_id, "icrc1_transfer", arg)
//             .await
//             .unwrap();
//     }

//     // We should now have 200 blocks
//     env.restart_rosetta_node(false, false).await.unwrap();
//     env.rosetta.wait_until_synced_up_to(200).await.unwrap();

//     // Let's check the network status
//     let network_status = env.rosetta.network_status().await.unwrap();
//     let current_block = env
//         .rosetta
//         .block(PartialBlockIdentifier {
//             index: Some(200),
//             hash: None,
//         })
//         .await
//         .unwrap()
//         .block
//         .unwrap();
//     let genesis_block = env
//         .rosetta
//         .block(PartialBlockIdentifier {
//             index: Some(0),
//             hash: None,
//         })
//         .await
//         .unwrap()
//         .block
//         .unwrap();
//     assert_eq!(
//         network_status.current_block_identifier,
//         current_block.block_identifier
//     );
//     assert_eq!(
//         network_status.genesis_block_identifier,
//         genesis_block.block_identifier
//     );
// }

