use crate::common::system_test_environment::RosettaTestingEnvironment;
use crate::common::utils::get_test_agent;
use crate::common::utils::query_encoded_blocks;
use crate::common::utils::test_identity;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_icp_rosetta_client::RosettaClient;
use ic_icrc1_test_utils::{DEFAULT_TRANSFER_FEE, minter_identity, valid_transactions_strategy};
use ic_ledger_core::block::BlockType;
use ic_rosetta_api::convert::to_hash;
use ic_rosetta_api::request_types::ApproveMetadata;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as TestRunnerConfig;
use proptest::test_runner::TestRunner;
use rosetta_core::identifiers::TransactionIdentifier;
use rosetta_core::objects::BlockTransaction;
use rosetta_core::request_types::SearchTransactionsRequest;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::runtime::Runtime;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 50;
    pub static ref NUM_TEST_CASES: u32 = 1;
    pub static ref MINTING_IDENTITY: Arc<BasicIdentity> = Arc::new(minter_identity());
}

async fn traverse_all_transactions(
    rosetta_client: &RosettaClient,
    mut search_transactions_request: SearchTransactionsRequest,
) -> Vec<BlockTransaction> {
    let mut transactions = vec![];
    loop {
        let result = rosetta_client
            .search_transactions(&search_transactions_request)
            .await
            .unwrap();
        transactions.extend(result.clone().transactions);
        search_transactions_request.offset = result.next_offset;

        if search_transactions_request.offset.is_none() {
            break;
        }
    }

    transactions
}

#[test]
fn test_search_transactions_by_hash() {
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
                    let tip_block_indentifier = rosetta_testing_environment
                        .rosetta_client
                        .network_status(rosetta_testing_environment.network_identifier.clone())
                        .await
                        .unwrap()
                        .current_block_identifier;

                    let tip_block = rosetta_testing_environment
                        .rosetta_client
                        .block(
                            rosetta_testing_environment.network_identifier.clone(),
                            tip_block_indentifier.clone().into(),
                        )
                        .await
                        .unwrap()
                        .block
                        .unwrap();
                    let tx_hash = tip_block.transactions[0]
                        .transaction_identifier
                        .hash
                        .clone();

                    let transaction = rosetta_testing_environment
                        .rosetta_client
                        .search_transactions(
                            &SearchTransactionsRequest::builder(
                                rosetta_testing_environment.network_identifier.clone(),
                            )
                            .with_transaction_identifier(TransactionIdentifier { hash: tx_hash })
                            .build(),
                        )
                        .await
                        .unwrap();

                    assert_eq!(
                        transaction.transactions[0].block_identifier,
                        tip_block_indentifier
                    );

                    assert_eq!(transaction.next_offset, None);
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_search_transactions_by_index() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        max_shrink_iters: 0,
        cases: 1,
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
                    let env = RosettaTestingEnvironment::builder()
                        .with_transfer_args_for_block_generating(args_with_caller.clone())
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;

                    let mut search_transactions_request =
                        SearchTransactionsRequest::builder(env.network_identifier.clone()).build();

                    let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;

                    if !args_with_caller.is_empty() {
                        // The maximum number of transactions that can be returned is the length of the entire blockchain
                        let query_blocks_response =
                            query_encoded_blocks(&agent, u64::MAX, u64::MAX).await;

                        let maximum_number_returnable_transactions =
                            query_blocks_response.chain_length;
                        // If no filters are provided the service should return all transactions or the maximum of transactions per request
                        let result = env
                            .rosetta_client
                            .search_transactions(&search_transactions_request)
                            .await
                            .unwrap();
                        assert_eq!(
                            result.total_count,
                            maximum_number_returnable_transactions as i64
                        );
                        assert_eq!(result.transactions.len() as i64, result.total_count);

                        search_transactions_request =
                            SearchTransactionsRequest::builder(env.network_identifier.clone())
                                .build();

                        // Let's check that setting the max_block option works as intended
                        search_transactions_request.max_block =
                            Some(maximum_number_returnable_transactions.saturating_sub(1) as i64);
                        let result = env
                            .rosetta_client
                            .search_transactions(&search_transactions_request)
                            .await
                            .unwrap();
                        assert_eq!(
                            result.transactions.len(),
                            maximum_number_returnable_transactions as usize
                        );

                        // The transactions should be returned in descending order of block index
                        assert_eq!(
                            to_hash(&result.transactions.first().unwrap().block_identifier.hash)
                                .unwrap(),
                            icp_ledger::Block::block_hash(
                                query_blocks_response.blocks.first().unwrap()
                            )
                        );

                        // If we set the limit to something below the maximum number of blocks we should only receive that number of blocks
                        search_transactions_request.max_block = None;
                        search_transactions_request.limit = Some(1);
                        let result = env
                            .rosetta_client
                            .search_transactions(&search_transactions_request)
                            .await
                            .unwrap();
                        assert_eq!(result.transactions.len(), 1);

                        search_transactions_request =
                            SearchTransactionsRequest::builder(env.network_identifier.clone())
                                .build();
                        search_transactions_request.limit = Some(1);

                        // If we always only retrieve a single transaction we should be able to traverse through all transactions in the blockchain
                        let response = traverse_all_transactions(
                            &env.rosetta_client,
                            search_transactions_request.clone(),
                        )
                        .await;

                        assert_eq!(
                            response.len() as u64,
                            maximum_number_returnable_transactions
                        );
                        // Make sure all transactions are unique
                        assert_eq!(
                            response.len(),
                            response.into_iter().collect::<HashSet<_>>().len()
                        );
                    }
                });
                Ok(())
            },
        )
        .unwrap()
}

#[test]
fn test_search_transactions_by_account() {
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
                    let env = RosettaTestingEnvironment::builder()
                        .with_transfer_args_for_block_generating(args_with_caller.clone())
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;
                    let agent = get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await;

                    if !args_with_caller.is_empty() {
                        let icp_blocks = query_encoded_blocks(&agent, u64::MAX, u64::MAX)
                            .await
                            .blocks
                            .into_iter()
                            .map(|block| icp_ledger::Block::decode(block).unwrap())
                            .collect::<Vec<icp_ledger::Block>>();
                        // Collect all account identifiers that are involved in the generated
                        // transactions, but for each transaction, only the accounts whose balances
                        // are changed, or, in case of an approve operation, the spender account.
                        // The reason for not including the spender account in the transfer
                        // operation is that since the balance of the account is not affected,
                        // Rosetta will not generate an operation for it.
                        let account_identifiers = icp_blocks
                            .clone()
                            .iter()
                            .flat_map(|block| match block.transaction.operation {
                                icp_ledger::Operation::Transfer { from, to, .. } => vec![from, to],
                                icp_ledger::Operation::Mint { to, .. } => vec![to],
                                icp_ledger::Operation::Burn { from, .. } => vec![from],
                                icp_ledger::Operation::Approve { from, spender, .. } => {
                                    vec![from, spender]
                                }
                            })
                            .collect::<HashSet<icp_ledger::AccountIdentifier>>();

                        let mut search_transactions_request =
                            SearchTransactionsRequest::builder(env.network_identifier.clone())
                                .build();

                        for account_id in account_identifiers.into_iter() {
                            // We make sure that the service returns the correct number of transactions for each account
                            search_transactions_request.account_identifier =
                                Some(account_id.into());

                            let result = traverse_all_transactions(
                                &env.rosetta_client,
                                search_transactions_request.clone(),
                            )
                            .await;
                            let search_account = search_transactions_request
                                .account_identifier
                                .clone()
                                .unwrap();
                            assert!(
                                result.clone().into_iter().all(|block_transaction| {
                                    block_transaction.transaction.operations.into_iter().any(
                                        |operation| {
                                            let involved_accounts =
                                                if operation.type_.as_str() == "APPROVE" {
                                                    vec![
                                                        operation.account.unwrap(),
                                                        ApproveMetadata::try_from(
                                                            operation.metadata.clone(),
                                                        )
                                                        .unwrap()
                                                        .spender
                                                        .into(),
                                                    ]
                                                } else {
                                                    vec![operation.account.unwrap()]
                                                };
                                            involved_accounts.contains(&search_account)
                                        },
                                    )
                                }),
                                "Account: {:?} not found in transactions: {:?}",
                                search_transactions_request.account_identifier,
                                result
                            );

                            assert!(!result.is_empty());
                            // Make sure every fetched transaction is unique
                            assert_eq!(
                                result.len(),
                                result.into_iter().collect::<HashSet<_>>().len()
                            );
                        }

                        search_transactions_request.account_identifier = Some(
                            icp_ledger::AccountIdentifier::from(Account {
                                owner: ic_base_types::PrincipalId::new_anonymous().into(),
                                subaccount: Some([9; 32]),
                            })
                            .into(),
                        );
                        let result = traverse_all_transactions(
                            &env.rosetta_client,
                            search_transactions_request.clone(),
                        )
                        .await;
                        // If the account does not exist the service should return an empty list
                        assert_eq!(result.len(), 0);
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_search_transactions_by_operation_type() {
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
                    let env = RosettaTestingEnvironment::builder()
                        .with_transfer_args_for_block_generating(args_with_caller.clone())
                        .with_minting_account(MINTING_IDENTITY.sender().unwrap().into())
                        .build()
                        .await;

                    if !args_with_caller.is_empty() {
                        let mut search_transactions_request =
                            SearchTransactionsRequest::builder(env.network_identifier.clone())
                                .build();
                        let icp_blocks = query_encoded_blocks(
                            &get_test_agent(env.pocket_ic.url().unwrap().port().unwrap()).await,
                            0,
                            u64::MAX,
                        )
                        .await
                        .blocks
                        .into_iter()
                        .map(|block| icp_ledger::Block::decode(block).unwrap())
                        .collect::<Vec<icp_ledger::Block>>();
                        let operation_counts =
                            icp_blocks.iter().fold(HashMap::new(), |mut ops, s| {
                                let ops_type = match s.transaction.operation {
                                    icp_ledger::Operation::Transfer { .. } => "Transfer",
                                    icp_ledger::Operation::Mint { .. } => "Mint",
                                    icp_ledger::Operation::Burn { .. } => "Burn",
                                    icp_ledger::Operation::Approve { .. } => "Approve",
                                }
                                .to_string();
                                *ops.entry(ops_type).or_insert(0) += 1;
                                ops
                            });
                        for operation in operation_counts.keys().clone() {
                            // We make sure that the service returns the correct number of transactions for each account
                            search_transactions_request.type_ = Some(operation.clone());

                            let result = traverse_all_transactions(
                                &env.rosetta_client,
                                search_transactions_request.clone(),
                            )
                            .await;
                            assert!(result.clone().into_iter().all(|block_transaction| {
                                block_transaction.transaction.operations.into_iter().any(
                                    |operation| {
                                        // ICP Rosetta returns Transfers as Transactions and not as Transfer
                                        if operation.type_ == "TRANSACTION" {
                                            search_transactions_request.type_
                                                == Some("Transfer".to_string())
                                        } else {
                                            search_transactions_request
                                                .type_
                                                .clone()
                                                .map(|t| t.to_uppercase())
                                                == Some(operation.type_)
                                        }
                                    },
                                )
                            }));

                            assert_eq!(result.len(), *operation_counts.get(operation).unwrap());
                            // Make sure every fetched transaction is unique
                            assert_eq!(
                                result.len(),
                                result.into_iter().collect::<HashSet<_>>().len()
                            );
                        }

                        search_transactions_request.type_ = Some("INVALID_OPERATION".to_string());
                        let result = traverse_all_transactions(
                            &env.rosetta_client,
                            search_transactions_request.clone(),
                        )
                        .await;
                        // If the operation type does not exist the service should return an empty list
                        assert_eq!(result.len(), 0);
                    }
                });
                Ok(())
            },
        )
        .unwrap();
}
