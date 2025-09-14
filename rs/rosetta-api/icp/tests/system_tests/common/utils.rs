use crate::common::constants::MAX_ROSETTA_SYNC_ATTEMPTS;
use candid::{Decode, Encode};
use ic_agent::Agent;
use ic_agent::Identity;
use ic_agent::identity::BasicIdentity;
use ic_icp_rosetta_client::RosettaClient;
use ic_ledger_core::block::BlockType;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_governance_api::{GovernanceError, ListNeurons, ListNeuronsResponse};
use ic_rosetta_api::convert::to_hash;
use icp_ledger::{
    AccountIdentifier, BinaryAccountBalanceArgs, GetBlocksArgs, QueryEncodedBlocksResponse, Tokens,
};
use pocket_ic::nonblocking::PocketIc;
use rosetta_core::identifiers::NetworkIdentifier;
use std::sync::Arc;
use url::Url;

pub fn test_identity() -> BasicIdentity {
    BasicIdentity::from_pem(
        &b"-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIJKDIfd1Ybt48Z23cVEbjL2DGj1P5iDYmthcrptvBO3z
oSMDIQCJuBJPWt2WWxv0zQmXcXMjY+fP0CJSsB80ztXpOFd2ZQ==
-----END PRIVATE KEY-----"[..],
    )
    .expect("failed to parse identity from PEM")
}

pub async fn get_test_agent(port: u16) -> Agent {
    get_custom_agent(Arc::new(test_identity()), port).await
}

pub async fn get_custom_agent(basic_identity: Arc<dyn Identity>, port: u16) -> Agent {
    // The local replica will be running on the localhost
    let replica_url = Url::parse(&format!("http://localhost:{port}")).unwrap();

    // Setup the agent
    let agent = Agent::builder()
        .with_url(replica_url.clone())
        .with_http_client(reqwest::Client::new())
        .with_identity(basic_identity)
        .build()
        .unwrap();

    // For verification the agent needs the root key of the IC running on the local replica
    agent.fetch_root_key().await.unwrap();
    agent
}

pub async fn wait_for_rosetta_to_catch_up_with_icp_ledger(
    rosetta_client: &RosettaClient,
    network_identifier: NetworkIdentifier,
    agent: &Agent,
) {
    let chain_length = query_encoded_blocks(agent, u64::MAX, 1).await.chain_length;
    let last_block = wait_for_rosetta_to_sync_up_to_block(
        rosetta_client,
        network_identifier,
        chain_length.saturating_sub(1),
    )
    .await
    .unwrap();
    assert_eq!(
        chain_length.saturating_sub(1),
        last_block,
        "Failed to sync with the ledger"
    );
}

pub async fn wait_for_rosetta_to_sync_up_to_block(
    rosetta_client: &RosettaClient,
    network_identifier: NetworkIdentifier,
    block_index: u64,
) -> Option<u64> {
    for _ in 0..MAX_ROSETTA_SYNC_ATTEMPTS {
        let response = rosetta_client
            .network_status(network_identifier.clone())
            .await;
        if let Ok(status) = response {
            let last_block = status.current_block_identifier.index;
            if last_block >= block_index {
                return Some(last_block);
            }
        } else {
            eprintln!("Failed to get network status: {response:?}");
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("Failed to sync with the ledger");
}

pub async fn assert_rosetta_blockchain_is_valid(
    rosetta_client: &RosettaClient,
    network_identifier: NetworkIdentifier,
    agent: &Agent,
) {
    // Let's check the network status
    let network_status = rosetta_client
        .network_status(network_identifier.clone())
        .await
        .unwrap();
    let ledger_tip = query_encoded_blocks(agent, u64::MAX, u64::MAX).await.blocks[0].clone();
    assert_eq!(
        to_hash(&network_status.current_block_identifier.hash).unwrap(),
        icp_ledger::Block::block_hash(&ledger_tip),
        "Block hashes do not match: Expected Block {:?} but got Block {:?}",
        network_status.current_block_identifier,
        ledger_tip
    );
}

pub fn memo_bytebuf_to_u64(bytebuf: &[u8]) -> Option<u64> {
    // Ensure we have at least 8 bytes.
    if bytebuf.len() < 8 {
        return None; // Handle insufficient bytes.
    }

    // Extract the first 8 bytes (assuming we want to use the first 8 bytes).
    let byte_array: [u8; 8] = bytebuf[0..8]
        .try_into()
        .expect("slice with incorrect length");

    // Convert the byte array into a u64.
    let value = u64::from_le_bytes(byte_array); // Or use from_be_bytes for big-endian.

    Some(value)
}

/// This function calls the 'query_encoded_blocks' endpoint on the ledger canister.
/// The user can specify the minimum block height and the number of blocks to query.
/// If the minimum block height is greater than the current chain tip index, the function will cap the start index to the current chain tip index.
/// If the number of blocks to query is greater than the chain length, the function will cap the length to the chain length.
pub async fn query_encoded_blocks(
    agent: &Agent,
    min_block_height: u64,
    num_blocks: u64,
) -> QueryEncodedBlocksResponse {
    let response = Decode!(
        &agent
            .query(&LEDGER_CANISTER_ID.into(), "query_encoded_blocks")
            .with_arg(
                Encode!(&GetBlocksArgs {
                    start: 0,
                    length: 1,
                })
                .unwrap()
            )
            .call()
            .await
            .unwrap(),
        QueryEncodedBlocksResponse
    )
    .unwrap();

    let current_chain_tip_index = response.chain_length.saturating_sub(1);
    let block_request = GetBlocksArgs {
        start: std::cmp::min(min_block_height, current_chain_tip_index),
        length: std::cmp::min(num_blocks, response.chain_length),
    };
    Decode!(
        &agent
            .query(&LEDGER_CANISTER_ID.into(), "query_encoded_blocks")
            .with_arg(Encode!(&block_request).unwrap())
            .call()
            .await
            .unwrap(),
        QueryEncodedBlocksResponse
    )
    .unwrap()
}

pub async fn list_neurons(agent: &Agent) -> ListNeuronsResponse {
    Decode!(
        &agent
            .query(&GOVERNANCE_CANISTER_ID.into(), "list_neurons")
            .with_arg(
                Encode!(&ListNeurons {
                    neuron_ids: vec![],
                    include_neurons_readable_by_caller: true,
                    include_empty_neurons_readable_by_caller: Some(true),
                    include_public_neurons_in_full_neurons: None,
                    page_number: None,
                    page_size: None,
                    neuron_subaccounts: None
                })
                .unwrap()
            )
            .call()
            .await
            .unwrap(),
        ListNeuronsResponse
    )
    .unwrap()
}

pub async fn update_neuron(agent: &Agent, neuron: ic_nns_governance_api::Neuron) {
    let result = Decode!(
        &agent
            .update(&GOVERNANCE_CANISTER_ID.into(), "update_neuron")
            .with_arg(Encode!(&neuron).unwrap())
            .call_and_wait()
            .await
            .unwrap(),
        Option<GovernanceError>
    )
    .unwrap();
    assert!(result.is_none(), "Failed to update neuron: {result:?}");
}

// Get the balance by directly calling the PocketIC, without agent. Useful
// if the agent time is behind the PocketIC time due to advanving the PocketIC time.
pub async fn account_balance(pocket_ic: &PocketIc, account: &AccountIdentifier) -> Tokens {
    let arg = Encode!(&BinaryAccountBalanceArgs {
        account: account.to_address(),
    })
    .unwrap();
    match pocket_ic
        .query_call(
            candid::Principal::from(LEDGER_CANISTER_ID),
            candid::Principal::anonymous(),
            "account_balance",
            arg,
        )
        .await
    {
        Err(err) => {
            panic!("failed to get the balance of account id: {account}, error msg: {err}");
        }
        Ok(res) => Decode!(&res, Tokens)
            .unwrap_or_else(|_| panic!("error decoding account_balance response")),
    }
}
