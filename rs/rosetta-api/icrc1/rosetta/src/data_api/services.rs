use crate::common::{storage::storage_client::StorageClient, types::Error};
use ic_base_types::CanisterId;
use ic_rosetta_api::DEFAULT_BLOCKCHAIN;
use rosetta_core::{identifiers::*, miscellaneous::*, objects::*, response_types::*};
use std::{sync::Arc, time::Duration};

const ROSETTA_VERSION: &str = "1.4.13";
const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn network_list(ledger_id: &CanisterId) -> NetworkListResponse {
    NetworkListResponse {
        network_identifiers: vec![NetworkIdentifier::new(
            DEFAULT_BLOCKCHAIN.to_owned(),
            ledger_id.to_string(),
        )],
    }
}

pub fn network_options(ledger_id: &CanisterId) -> NetworkOptionsResponse {
    NetworkOptionsResponse {
        version: Version {
            rosetta_version: ROSETTA_VERSION.to_string(),
            node_version: NODE_VERSION.to_string(),
            middleware_version: None,
            metadata: None,
        },
        allow: Allow {
            operation_statuses: vec![],
            operation_types: vec![],
            errors: vec![Error::invalid_network_id(&NetworkIdentifier::new(
                DEFAULT_BLOCKCHAIN.to_owned(),
                ledger_id.to_string(),
            ))
            .into()],
            historical_balance_lookup: true,
            timestamp_start_index: None,
            call_methods: vec![],
            balance_exemptions: vec![],
            mempool_coins: false,
            block_hash_case: None,
            transaction_hash_case: None,
        },
    }
}

pub fn network_status(storage_client: Arc<StorageClient>) -> Result<NetworkStatusResponse, Error> {
    let current_block = storage_client
        .get_block_with_highest_block_idx()
        .map_err(|e| Error::unable_to_find_block(format!("Error retrieving current block: {}", e)))?
        .ok_or_else(|| Error::unable_to_find_block("Current block not found".into()))?;

    let genesis_block = storage_client
        .get_block_at_idx(0)
        .map_err(|e| Error::unable_to_find_block(format!("Error retrieving genesis block: {}", e)))?
        .ok_or_else(|| Error::unable_to_find_block("Genesis block not found".into()))?;
    let genesis_block_identifier = BlockIdentifier::from(&genesis_block);

    Ok(NetworkStatusResponse {
        current_block_identifier: BlockIdentifier::from(&current_block),
        current_block_timestamp: Duration::from_nanos(current_block.timestamp).as_millis() as u64,
        genesis_block_identifier: genesis_block_identifier.clone(),
        oldest_block_identifier: Some(genesis_block_identifier),
        sync_status: None,
        peers: vec![],
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::storage::types::RosettaBlock;
    use ic_icrc1_test_utils::valid_blockchain_with_gaps_strategy;
    use proptest::prelude::*;

    const BLOCKHAIN_LENGTH: usize = 1000;

    proptest! {
           #[test]
        fn test_network_status_service((blockchain,_) in valid_blockchain_with_gaps_strategy(BLOCKHAIN_LENGTH)){
            let storage_client_memory = Arc::new(StorageClient::new_in_memory().unwrap());
            let mut rosetta_blocks = vec![];
            for (index,block) in blockchain.clone().into_iter().enumerate(){
                rosetta_blocks.push(RosettaBlock::from_icrc_ledger_block(block,index as u64).unwrap());
            }

            // If there is no block in the database the service should return an error
            let network_status_err = network_status(storage_client_memory.clone()).unwrap_err();
            assert!(network_status_err.0.message.contains("Unable to find block"));

            storage_client_memory.store_blocks(rosetta_blocks).unwrap();
            let block_with_highest_idx = storage_client_memory.get_block_with_highest_block_idx().unwrap().unwrap();
            let genesis_block = storage_client_memory.get_block_with_lowest_block_idx().unwrap().unwrap();

            let network_status_response = network_status(storage_client_memory.clone()).unwrap();

            assert_eq!(NetworkStatusResponse {
                current_block_identifier: BlockIdentifier::from(&block_with_highest_idx),
                current_block_timestamp: Duration::from_nanos(block_with_highest_idx.timestamp).as_millis() as u64,
                genesis_block_identifier: BlockIdentifier::from(&genesis_block).clone(),
                oldest_block_identifier: Some(BlockIdentifier::from(&genesis_block)),
                sync_status: None,
                peers: vec![],
            },network_status_response)
        }
    }
}
