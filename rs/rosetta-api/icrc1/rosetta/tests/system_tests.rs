use crate::common::local_replica;
use crate::common::local_replica::test_identity;
use candid::{Nat, Principal};
use ic_agent::Identity;
use ic_base_types::CanisterId;
use ic_icrc_rosetta::common::{storage::types::RosettaBlock, types::NetworkIdentifier};
use ic_icrc_rosetta_client::RosettaClient;
use ic_icrc_rosetta_runner::{start_rosetta, RosettaOptions};
use ic_starter_tests::{start_replica, ReplicaBins, ReplicaStarterConfig};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::{
    icrc1::{account::Account, transfer::TransferArg},
    icrc3::blocks::GetBlocksRequest,
};
use lazy_static::lazy_static;
use std::{path::PathBuf, sync::Arc, time::Duration};

mod common;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 20;
    pub static ref NUM_TEST_CASES: u32 = 5;
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
    let expected = NetworkIdentifier::for_ledger_id(
        CanisterId::try_from(Principal::anonymous().as_slice()).unwrap(),
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
    let network_identifier =
        NetworkIdentifier::for_ledger_id(CanisterId::try_from(ledger_id.as_slice()).unwrap());

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
