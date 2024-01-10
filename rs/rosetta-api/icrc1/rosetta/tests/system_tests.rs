use crate::common::local_replica;
use crate::common::local_replica::test_identity;
use axum::http::StatusCode;
use candid::{Nat, Principal};
use ic_agent::{identity::Secp256k1Identity, Identity};
use ic_base_types::CanisterId;
pub use ic_canister_client_sender::Ed25519KeyPair as EdKeypair;
use ic_icrc1_ledger_sm_tests::DECIMAL_PLACES;
use ic_icrc1_ledger_sm_tests::{FEE, TOKEN_SYMBOL};
use ic_icrc_rosetta::common::constants::DEFAULT_BLOCKCHAIN;
use ic_icrc_rosetta::common::types::{BurnMetadata, TransferMetadata};
use ic_icrc_rosetta::common::utils::utils::icrc1_rosetta_block_to_rosetta_core_block;
use ic_icrc_rosetta::{
    common::{
        storage::types::RosettaBlock,
        types::{ApproveMetadata, OperationType},
    },
    construction_api::types::ConstructionMetadataRequestOptions,
    Metadata,
};
use ic_icrc_rosetta_client::RosettaClient;
use ic_icrc_rosetta_runner::{start_rosetta, RosettaOptions, DEFAULT_DECIMAL_PLACES};
use ic_starter_tests::{start_replica, ReplicaBins, ReplicaStarterConfig};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::{
    icrc::generic_value::Value,
    icrc1::{account::Account, transfer::TransferArg},
    icrc2::approve::ApproveArgs,
    icrc3::blocks::GetBlocksRequest,
};
use lazy_static::lazy_static;
use rosetta_core::identifiers::*;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::objects::*;
use rosetta_core::request_types::*;
use rosetta_core::response_types::*;
use serde_json::Number;
use std::{path::PathBuf, sync::Arc, time::Duration};

mod common;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref TEST_ACCOUNT_2: Account = test_identity_2().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 20;
    pub static ref NUM_TEST_CASES: u32 = 5;
}

pub fn test_identity_2() -> Secp256k1Identity {
    Secp256k1Identity::from_pem(
        &b"-----BEGIN EC PRIVATE KEY-----
MHQCAQEEICJxApEbuZznKFpV+VKACRK30i6+7u5Z13/DOl18cIC+oAcGBSuBBAAK
oUQDQgAEPas6Iag4TUx+Uop+3NhE6s3FlayFtbwdhRVjvOar0kPTfE/N8N6btRnd
74ly5xXEBNSXiENyxhEuzOZrIWMCNQ==
-----END EC PRIVATE KEY-----
        "[..],
    )
    .expect("failed to parse identity from PEM")
}

fn path_from_env(var: &str) -> PathBuf {
    std::fs::canonicalize(
        std::env::var(var).unwrap_or_else(|_| panic!("Environment variable {} is not set", var)),
    )
    .unwrap()
}

fn replica_bins() -> ReplicaBins {
    let canister_launcher = path_from_env("CANISTER_LAUNCHER");
    let replica_bin = path_from_env("REPLICA_BIN");
    let sandbox_launcher = path_from_env("SANDBOX_LAUNCHER");
    let starter_bin = path_from_env("STARTER_BIN");
    ReplicaBins {
        canister_launcher,
        replica_bin,
        sandbox_launcher,
        starter_bin,
    }
}

fn rosetta_bin() -> PathBuf {
    path_from_env("ROSETTA_BIN_PATH")
}

#[tokio::test]
async fn test_network_list() {
    let context = start_replica(&replica_bins(), &ReplicaStarterConfig::default())
        .await
        .expect("Unable to start the replica");
    let replica_url = format!("http://localhost:{}", context.port);

    let context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            network_url: Some(replica_url),
            ..RosettaOptions::default()
        },
    )
    .await;
    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", context.port))
        .expect("Unable to parse url");
    let network_list = client
        .network_list()
        .await
        .expect("Unable to call network_list")
        .network_identifiers;
    let expected = NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        CanisterId::try_from(Principal::anonymous().as_slice())
            .unwrap()
            .to_string(),
    );
    assert_eq!(network_list, vec![expected]);
}

#[tokio::test]
async fn test_network_status() {
    let replica_context = local_replica::start_new_local_replica().await;
    let replica_url = format!("http://localhost:{}", replica_context.port);
    // Deploy an ICRC-1 ledger canister
    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_default_args(&replica_context).await;
    let ledger_id = Principal::from(icrc_ledger_canister_id);

    // Create a testing agent
    let agent = Arc::new(Icrc1Agent {
        agent: local_replica::get_testing_agent(&replica_context).await,
        ledger_canister_id: icrc_ledger_canister_id.into(),
    });

    // Transfer some tokens to generate a new block.
    let _ = agent
        .transfer(TransferArg {
            from_subaccount: TEST_ACCOUNT.subaccount,
            to: Account {
                owner: icrc_ledger_canister_id.into(),
                subaccount: None,
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(10_000_000),
        })
        .await
        .expect("Failed to generate a new block");

    let rosetta_context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            ledger_id,
            network_url: Some(replica_url),
            offline: false,
            ..RosettaOptions::default()
        },
    )
    .await;

    // Get the blocks from the ledger to compare against rosetta
    let get_blocks_response = agent
        .get_blocks(GetBlocksRequest {
            start: Nat::from(0),
            length: Nat::from(10),
        })
        .await
        .expect("Failed to get blocks");
    assert!(
        !get_blocks_response.blocks.is_empty(),
        "there should be blocks in the ledger"
    );

    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", rosetta_context.port))
        .expect("Unable to parse url");
    let network_identifier = NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        CanisterId::try_from(ledger_id.as_slice())
            .unwrap()
            .to_string(),
    );

    let rosetta_response = client
        .network_status(network_identifier.clone())
        .await
        .expect("Unable to call network_status");

    let expected_current_block =
        RosettaBlock::from_generic_block(get_blocks_response.blocks[1].clone(), 1).unwrap();

    assert_eq!(
        get_blocks_response.chain_length,
        rosetta_response.current_block_identifier.index + 1,
        "Chain length does not match"
    );
    assert_eq!(
        rosetta_response.current_block_identifier.index, 1,
        "current_block_identifier index should be 1"
    );
    assert_eq!(
        hex::encode(get_blocks_response.blocks[0].hash()),
        rosetta_response.genesis_block_identifier.hash,
        "Genesis block hashes do not match"
    );
    assert_eq!(
        hex::encode(get_blocks_response.blocks[1].hash()),
        rosetta_response.current_block_identifier.hash,
        "Current block hashes do not match"
    );
    assert_eq!(
        hex::encode(get_blocks_response.blocks[0].hash()),
        rosetta_response.oldest_block_identifier.unwrap().hash,
        "Genesis block hashes do not match"
    );
    assert_eq!(
        Duration::from_nanos(expected_current_block.timestamp).as_millis() as u64,
        rosetta_response.current_block_timestamp
    );
}

// Creates a block for each type of transaction operation and returns
// the blocks created.
async fn create_blocks(
    mut icrc_agent: Icrc1Agent,
    icrc_ledger_canister_id: CanisterId,
) -> Vec<Value> {
    // Transfer some tokens to make a `Mint` operation.
    icrc_agent
        .transfer(TransferArg {
            from_subaccount: TEST_ACCOUNT.subaccount,
            to: *TEST_ACCOUNT_2,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(100_000_000_000u64),
        })
        .await
        .expect("Failed to generate a new transfer operation")
        .expect("Failed to mint");

    // Transfer some tokens to make a `Transfer` operation.
    icrc_agent.agent.set_identity(test_identity_2());
    icrc_agent
        .transfer(TransferArg {
            from_subaccount: TEST_ACCOUNT_2.subaccount,
            to: Account {
                owner: icrc_ledger_canister_id.into(),
                subaccount: None,
            },
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(100_000_000),
        })
        .await
        .expect("Failed to generate a new transfer operation")
        .expect("Failed to transfer");

    // Transfer some tokens to make a `Burn` operation.
    icrc_agent
        .transfer(TransferArg {
            from_subaccount: TEST_ACCOUNT_2.subaccount,
            to: *TEST_ACCOUNT,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(100_000_000),
        })
        .await
        .expect("Failed to generate a new burn operation")
        .expect("Failed to burn");

    // Approve some tokens to generate a block with an `Approve` operation.
    icrc_agent
        .approve(ApproveArgs {
            from_subaccount: TEST_ACCOUNT_2.subaccount,
            spender: Account {
                owner: icrc_ledger_canister_id.into(),
                subaccount: None,
            },
            amount: Nat::from(100_000_000),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        })
        .await
        .expect("Failed to generate a new approve operation")
        .expect("Failed to approve");

    // Get the blocks from the ledger to compare against rosetta
    let get_blocks_response = icrc_agent
        .get_blocks(GetBlocksRequest {
            start: Nat::from(0),
            length: Nat::from(10),
        })
        .await
        .expect("Failed to get blocks");
    assert!(
        !get_blocks_response.blocks.is_empty(),
        "there should be blocks in the ledger"
    );

    get_blocks_response.blocks
}

fn expected_operations(
    icrc_ledger_canister_id: CanisterId,
    Metadata { decimals, symbol }: Metadata,
) -> Vec<Vec<Operation>> {
    let currency = Currency {
        symbol: symbol.clone(),
        decimals: decimals.into(),
        metadata: None,
    };
    vec![
        vec![Operation::new(
            0,
            OperationType::Mint.to_string(),
            Some((*TEST_ACCOUNT).into()),
            Some(Amount::new("1000000000000".to_string(), currency.clone())),
            None,
            None,
        )],
        vec![Operation::new(
            0,
            OperationType::Mint.to_string(),
            Some((*TEST_ACCOUNT_2).into()),
            Some(Amount::new("100000000000".to_string(), currency.clone())),
            None,
            None,
        )],
        vec![Operation::new(
            0,
            OperationType::Transfer.to_string(),
            Some(Account::from(icrc_ledger_canister_id.get().0).into()),
            Some(Amount::new("100000000".to_string(), currency.clone())),
            None,
            Some(
                TransferMetadata {
                    from_account: (*TEST_ACCOUNT_2).into(),
                    spender_account: None,
                    fee_set_by_user: None,
                }
                .into(),
            ),
        )],
        vec![Operation::new(
            0,
            OperationType::Burn.to_string(),
            None,
            Some(Amount::new("100000000".to_string(), currency.clone())),
            None,
            Some(
                BurnMetadata {
                    from_account: (*TEST_ACCOUNT_2).into(),
                    spender_account: None,
                }
                .into(),
            ),
        )],
        vec![Operation {
            operation_identifier: OperationIdentifier::new(0),
            account: Some(Account::from(icrc_ledger_canister_id.get().0).into()),
            _type: OperationType::Approve.to_string(),
            amount: Some(Amount::new("100000000".to_owned(), currency.clone())),
            metadata: Some(
                ApproveMetadata {
                    approver_account: (*TEST_ACCOUNT_2).into(),
                    expected_allowance: None,
                    expires_at: None,
                    fee_set_by_user: None,
                }
                .into(),
            ),
            related_operations: None,
            status: None,
            coin_change: None,
        }],
    ]
}

fn create_expected_rosetta_responses(
    blocks: Vec<Value>,
    icrc_ledger_canister_id: CanisterId,
    metadata: Metadata,
) -> Vec<BlockResponse> {
    // map the blocks to the expected operations to create the expected /block
    // responses
    let mut responses = vec![];
    let expected_operations = expected_operations(icrc_ledger_canister_id, metadata.clone());

    for (index, (block, _)) in blocks
        .into_iter()
        .zip(expected_operations.into_iter())
        .enumerate()
    {
        let block = RosettaBlock::from_generic_block(block, index as u64).unwrap();

        responses.push(BlockResponse::new(
            icrc1_rosetta_block_to_rosetta_core_block(
                block,
                Currency {
                    symbol: metadata.symbol.clone(),
                    decimals: metadata.decimals.into(),
                    metadata: None,
                },
            )
            .ok(),
        ));
    }

    responses
}

#[tokio::test]
async fn test_block() {
    let replica_context = local_replica::start_new_local_replica().await;
    let replica_url = format!("http://localhost:{}", replica_context.port);

    // Deploy an ICRC-1 ledger canister
    let init_args = local_replica::icrc_ledger_default_args_builder(&replica_context)
        .await
        .with_feature_flags(ic_icrc1_ledger::FeatureFlags { icrc2: true })
        .build();
    let metadata = Metadata {
        decimals: init_args.decimals.unwrap_or(DEFAULT_DECIMAL_PLACES),
        symbol: init_args.token_symbol.clone(),
    };

    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_custom_args(&replica_context, init_args).await;
    let ledger_id = Principal::from(icrc_ledger_canister_id);

    let ic_agent = local_replica::get_testing_agent(&replica_context).await;

    // Create a testing agent
    let icrc_agent = Icrc1Agent {
        agent: ic_agent,
        ledger_canister_id: icrc_ledger_canister_id.into(),
    };

    // Create the blocks and expected rosetta responses.
    let blocks = create_blocks(icrc_agent, icrc_ledger_canister_id).await;
    let expected_responses =
        create_expected_rosetta_responses(blocks, icrc_ledger_canister_id, metadata);

    let rosetta_context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            ledger_id,
            network_url: Some(replica_url),
            offline: false,
            ..RosettaOptions::default()
        },
    )
    .await;

    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", rosetta_context.port))
        .expect("Unable to parse url");
    let network_identifier = NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        CanisterId::try_from(ledger_id.as_slice())
            .unwrap()
            .to_string(),
    );

    for (index, expected_response) in expected_responses.into_iter().enumerate() {
        let partial_block_identifier = match index % 3 {
            1 => PartialBlockIdentifier {
                index: Some(index as u64),
                hash: None,
            },
            2 => PartialBlockIdentifier {
                index: None,
                hash: Some(
                    expected_response
                        .block
                        .clone()
                        .unwrap()
                        .block_identifier
                        .hash
                        .clone(),
                ),
            },
            _ => PartialBlockIdentifier {
                index: Some(index as u64),
                hash: Some(
                    expected_response
                        .block
                        .clone()
                        .unwrap()
                        .block_identifier
                        .hash
                        .clone(),
                ),
            },
        };

        let received_block_response: BlockResponse = client
            .block(network_identifier.clone(), partial_block_identifier)
            .await
            .expect("Failed to find block in Rosetta");

        assert_eq!(received_block_response, expected_response);
    }
}

fn create_expected_block_hashes_and_block_transaction_responses(
    blocks: Vec<Value>,
    icrc_ledger_canister_id: CanisterId,
    metadata: Metadata,
) -> Vec<(String, BlockTransactionResponse)> {
    // map the blocks to the expected operations to create the expected /block
    // responses
    let mut responses = vec![];
    let expected_operations = expected_operations(icrc_ledger_canister_id, metadata);

    for (index, (block, operations)) in blocks
        .into_iter()
        .zip(expected_operations.into_iter())
        .enumerate()
    {
        let block = RosettaBlock::from_generic_block(block, index as u64).unwrap();
        let block_hash = hex::encode(&block.block_hash);
        let transaction_hash = hex::encode(&block.transaction_hash);
        let mut metadata = ObjectMap::new();
        if index == 0 {
            metadata.insert(
                "created_at_time".to_string(),
                serde_json::Value::Number(Number::from(block.timestamp)),
            );
        }

        responses.push((
            block_hash,
            BlockTransactionResponse {
                transaction: Transaction {
                    transaction_identifier: TransactionIdentifier {
                        hash: transaction_hash,
                    },
                    operations,
                    metadata: if !metadata.is_empty() {
                        Some(metadata)
                    } else {
                        None
                    },
                },
            },
        ));
    }

    responses
}

#[tokio::test]
async fn test_block_transaction() {
    let replica_context = local_replica::start_new_local_replica().await;
    let replica_url = format!("http://localhost:{}", replica_context.port);

    // Deploy an ICRC-1 ledger canister
    let init_args = local_replica::icrc_ledger_default_args_builder(&replica_context)
        .await
        .with_feature_flags(ic_icrc1_ledger::FeatureFlags { icrc2: true })
        .build();
    let metadata = Metadata {
        decimals: init_args.decimals.unwrap_or(DEFAULT_DECIMAL_PLACES),
        symbol: init_args.token_symbol.clone(),
    };

    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_custom_args(&replica_context, init_args).await;
    let ledger_id = Principal::from(icrc_ledger_canister_id);

    let ic_agent = local_replica::get_testing_agent(&replica_context).await;

    // Create a testing agent
    let icrc_agent = Icrc1Agent {
        agent: ic_agent,
        ledger_canister_id: icrc_ledger_canister_id.into(),
    };

    // Create the blocks and expected rosetta responses.
    let blocks = create_blocks(icrc_agent, icrc_ledger_canister_id).await;
    let expected_responses = create_expected_block_hashes_and_block_transaction_responses(
        blocks,
        icrc_ledger_canister_id,
        metadata,
    );

    let rosetta_context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            ledger_id,
            network_url: Some(replica_url),
            offline: false,
            ..RosettaOptions::default()
        },
    )
    .await;

    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", rosetta_context.port))
        .expect("Unable to parse url");
    let network_identifier = NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        CanisterId::try_from(ledger_id.as_slice())
            .unwrap()
            .to_string()
            .to_string(),
    );

    for (index, (expected_block_hash, expected_response)) in
        expected_responses.into_iter().enumerate()
    {
        let block_identifier = BlockIdentifier {
            index: index as u64,
            hash: expected_block_hash,
        };

        let transaction_identifier = expected_response.transaction.transaction_identifier.clone();

        let received_block_response: BlockTransactionResponse = client
            .block_transaction(
                network_identifier.clone(),
                block_identifier,
                transaction_identifier,
            )
            .await
            .expect("Failed to find block transaction in Rosetta");
        assert_eq!(received_block_response, expected_response);
    }
}

#[tokio::test]
async fn test_mempool() {
    let replica_context = local_replica::start_new_local_replica().await;
    let replica_url = format!("http://localhost:{}", replica_context.port);
    // Deploy an ICRC-1 ledger canister
    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_default_args(&replica_context).await;
    let ledger_id = Principal::from(icrc_ledger_canister_id);

    let rosetta_context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            ledger_id,
            network_url: Some(replica_url),
            offline: false,
            ..RosettaOptions::default()
        },
    )
    .await;

    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", rosetta_context.port))
        .expect("Unable to parse url");
    let network_identifier = NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        CanisterId::try_from(ledger_id.as_slice())
            .unwrap()
            .to_string(),
    );

    let transaction_identifiers = client
        .mempool(network_identifier.clone())
        .await
        .expect("Unable to call mempool")
        .transaction_identifiers;
    assert_eq!(transaction_identifiers, vec![]);

    let transaction_id = TransactionIdentifier {
        hash: "1234".to_string(),
    };
    let mempool_transaction_request =
        MempoolTransactionRequest::new(network_identifier, transaction_id);
    let response = client
        .mempool_transaction(mempool_transaction_request)
        .await;
    assert_eq!(
        response.expect_err("expected an error").status().unwrap(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn test_construction_preprocess() {
    let replica_context = local_replica::start_new_local_replica().await;
    let replica_url = format!("http://localhost:{}", replica_context.port);

    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_default_args(&replica_context).await;
    let ledger_id = Principal::from(icrc_ledger_canister_id);

    let context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            ledger_id,
            network_url: Some(replica_url),
            offline: false,
            ..RosettaOptions::default()
        },
    )
    .await;

    let network_identifier = NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        CanisterId::try_from(ledger_id.as_slice())
            .unwrap()
            .to_string(),
    );

    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", context.port))
        .expect("Unable to parse url");

    let construction_preprocess_response = client
        .construction_preprocess(vec![], network_identifier)
        .await
        .expect("Unable to call Construction Preprocess");
    let expected = ConstructionPreprocessResponse {
        options: Some(
            ConstructionMetadataRequestOptions {
                suggested_fee: true,
            }
            .into(),
        ),
        required_public_keys: None,
    };
    assert_eq!(construction_preprocess_response, expected);
}

#[tokio::test]
async fn test_construction_derive() {
    let replica_context = local_replica::start_new_local_replica().await;
    let replica_url = format!("http://localhost:{}", replica_context.port);
    // Deploy an ICRC-1 ledger canister
    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_default_args(&replica_context).await;
    let ledger_id = Principal::from(icrc_ledger_canister_id);

    let rosetta_context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            ledger_id,
            network_url: Some(replica_url),
            offline: false,
            ..RosettaOptions::default()
        },
    )
    .await;

    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", rosetta_context.port))
        .expect("Unable to parse url");
    let network_identifier = NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        CanisterId::try_from(ledger_id.as_slice())
            .unwrap()
            .to_string(),
    );

    let key_pair = EdKeypair::generate_from_u64(10);
    let principal_id = key_pair.generate_principal_id().unwrap();
    let public_key = ic_rosetta_test_utils::to_public_key(&key_pair);
    let account = Account {
        owner: principal_id.into(),
        subaccount: None,
    };

    let request = ConstructionDeriveRequest {
        network_identifier: network_identifier.clone(),
        public_key: public_key.clone(),
        metadata: None,
    };
    let account_identifier = client
        .construction_derive(request.clone())
        .await
        .expect("Unable to call /construction/derive")
        .account_identifier
        .expect("/construction/derive did not return an account identifier");
    assert_eq!(account_identifier, account.into());
}

#[tokio::test]
async fn test_construction_metadata() {
    let replica_context = local_replica::start_new_local_replica().await;
    let replica_url = format!("http://localhost:{}", replica_context.port);

    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_default_args(&replica_context).await;
    let ledger_id = Principal::from(icrc_ledger_canister_id);

    let context = start_rosetta(
        &rosetta_bin(),
        RosettaOptions {
            ledger_id,
            network_url: Some(replica_url),
            offline: false,
            ..RosettaOptions::default()
        },
    )
    .await;

    let network_identifier = NetworkIdentifier::new(
        DEFAULT_BLOCKCHAIN.to_owned(),
        CanisterId::try_from(ledger_id.as_slice())
            .unwrap()
            .to_string(),
    );

    let client = RosettaClient::from_str_url(&format!("http://0.0.0.0:{}", context.port))
        .expect("Unable to parse url");

    let _construction_preprocess_response = client
        .construction_preprocess(vec![], network_identifier.clone())
        .await
        .expect("Unable to call Construction Preprocess");
    let construction_metadata = ConstructionPreprocessResponse {
        options: Some(
            ConstructionMetadataRequestOptions {
                suggested_fee: true,
            }
            .into(),
        ),
        required_public_keys: None,
    };

    let construction_metadata_response = client
        .construction_metadata(
            construction_metadata.options.try_into().unwrap(),
            network_identifier.clone(),
        )
        .await
        .expect("Unable to call Construction Metadata");
    assert!(construction_metadata_response.metadata.is_empty());
    assert_eq!(
        construction_metadata_response.suggested_fee,
        Some(vec![Amount::new(
            FEE.to_string(),
            Currency {
                symbol: TOKEN_SYMBOL.to_owned(),
                decimals: DECIMAL_PLACES as u32,
                metadata: None
            }
        )])
    );

    let empty_construction_metadata_response = client
        .construction_metadata(
            ConstructionMetadataRequestOptions {
                suggested_fee: false,
            },
            network_identifier,
        )
        .await
        .expect("Unable to call Construction Metadata");

    assert!(empty_construction_metadata_response.metadata.is_empty());
    assert!(empty_construction_metadata_response.suggested_fee.is_none());
}
