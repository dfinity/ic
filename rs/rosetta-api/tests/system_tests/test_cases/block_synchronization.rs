use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_test_agent;
use crate::common::utils::memo_bytebuf_to_u64;
use crate::common::utils::query_encoded_blocks;
use crate::common::utils::test_identity;
use crate::common::utils::wait_for_rosetta_to_sync_up_to_block;
use candid::Encode;
use candid::Principal;
use ic_agent::identity::BasicIdentity;
use ic_agent::Identity;
use ic_icp_rosetta_client::RosettaTransferArgs;
use ic_icp_rosetta_runner::RosettaOptions;
use ic_icrc1_test_utils::ArgWithCaller;
use ic_icrc1_test_utils::LedgerEndpointArg;
use ic_icrc1_test_utils::{minter_identity, valid_transactions_strategy, DEFAULT_TRANSFER_FEE};
use ic_icrc1_tokens_u256::U256;
use ic_ledger_core::block::BlockType;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_rosetta_api::convert::to_hash;
use ic_rosetta_api::models::PartialBlockIdentifier;
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
fn test_ledger_upgrade_synchronization() {
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
                *MAX_NUM_GENERATED_BLOCKS * 2,
                SystemTime::now(),
            )
            .no_shrink()),
            |args_with_caller| {
                let rt = Runtime::new().unwrap();
                rt.block_on(async {
                    let mut env = RosettaTestingEnvironment::builder()
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;

                    // Currently, the ledger canister version is that of this branch
                    // We need to reinstall it to the mainnet version
                    let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);

                    let ledger_wasm_mainnet = std::fs::read(
                        std::env::var("ICP_LEDGER_DEPLOYED_VERSION_WASM_PATH").unwrap(),
                    )
                    .unwrap();
                    env.pocket_ic
                        .reinstall_canister(
                            ledger_canister_id,
                            ledger_wasm_mainnet,
                            Encode!(&icp_ledger::LedgerCanisterInitPayload::builder()
                                .minting_account(MINTING_IDENTITY.sender().unwrap().into())
                                .build()
                                .unwrap())
                            .unwrap(),
                            None,
                        )
                        .await
                        .unwrap();

                    let pockt_ic_url = env.pocket_ic.url().unwrap();

                    let (first_block_batch, second_block_batch) =
                        args_with_caller.split_at(args_with_caller.len() / 2);

                    for arg_with_caller in first_block_batch {
                        let icrc1_transaction: ic_icrc1::Transaction<U256> = arg_with_caller
                            .clone()
                            .to_transaction(Account::from(MINTING_IDENTITY.sender().unwrap()));

                        // Rosetta does not support mint and burn operations
                        // To keep the balances in sync we need to call the ledger agent directly and then go to the next iteration of args with caller
                        if matches!(
                            icrc1_transaction.operation,
                            ic_icrc1::Operation::Mint { .. }
                        ) || matches!(
                            icrc1_transaction.operation,
                            ic_icrc1::Operation::Burn { .. }
                        ) {
                            env.generate_blocks(vec![arg_with_caller.clone()]).await;
                            continue;
                        }

                        let transfer_args = match arg_with_caller.arg.clone() {
                            LedgerEndpointArg::TransferArg(mut transfer_args) => {
                                transfer_args.from_subaccount = None;
                                transfer_args.to.subaccount = None;
                                transfer_args
                            }
                            _ => panic!("Expected TransferArg"),
                        };
                        let mut args_builder =
                            RosettaTransferArgs::builder(transfer_args.to, transfer_args.amount);
                        if let Some(from_subaccount) = transfer_args.from_subaccount {
                            args_builder = args_builder.with_from_subaccount(from_subaccount);
                        }
                        if let Some(memo) = transfer_args.memo {
                            args_builder =
                                args_builder.with_memo(memo_bytebuf_to_u64(&memo.0).unwrap());
                        }
                        if let Some(created_at_time) = transfer_args.created_at_time {
                            args_builder = args_builder.with_created_at_time(created_at_time);
                        }
                        env.rosetta_client
                            .transfer(
                                args_builder.build(),
                                env.network_identifier.clone(),
                                arg_with_caller.caller.clone(),
                            )
                            .await
                            .unwrap();
                    }

                    // We should now have 100 blocks
                    // Let's restart rosetta to make sure it can handle the mainnet ledger version
                    env = env
                        .restart_rosetta_node(
                            RosettaOptions::builder(pockt_ic_url.to_string()).build(),
                        )
                        .await
                        .unwrap();

                    wait_for_rosetta_to_sync_up_to_block(
                        &env.rosetta_client,
                        env.network_identifier.clone(),
                        first_block_batch.len() as u64,
                    )
                    .await
                    .unwrap();

                    // Let's check the network status
                    let network_status = env.rosetta_client.network_status(env.network_identifier.clone()).await.unwrap();
                    let ledger_tip = query_encoded_blocks(&get_test_agent(pockt_ic_url.clone().port().unwrap()), None, 1).await.blocks[0].clone();
                    assert_eq!(
                        to_hash(&network_status.current_block_identifier.hash).unwrap(),
                        icp_ledger::Block::block_hash(&ledger_tip),
                        "Block hashes do not match: Expected Block {:?} but got Block {:?}",
                        network_status.current_block_identifier,
                        ledger_tip
                    );

                    // Now we upgrade the ledger canister to the latest version of the current branch
                    let ledger_wasm_current_branch = icp_ledger_wasm_bytes();
                    env.pocket_ic
                        .upgrade_canister(
                            env.ledger_id,
                            ledger_wasm_current_branch,
                            Encode!(&LedgerCanisterUpgradePayload(
                                LedgerCanisterPayload::Upgrade(None)
                            ))
                            .unwrap(),
                            None,
                        )
                        .await
                        .unwrap();
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
