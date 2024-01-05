use crate::{
    common::{
        storage::storage_client::StorageClient,
        types::{BlockResponseBuilder, BlockTransactionResponseBuilder, Error},
        utils::utils::get_rosetta_block_from_partial_block_identifier,
    },
    Metadata,
};
use candid::Principal;
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_rosetta_api::DEFAULT_BLOCKCHAIN;
use rosetta_core::{identifiers::*, miscellaneous::*, objects::*, response_types::*};
use std::{sync::Arc, time::Duration};

const ROSETTA_VERSION: &str = "1.4.13";
const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn network_list(ledger_id: &Principal) -> NetworkListResponse {
    NetworkListResponse {
        network_identifiers: vec![NetworkIdentifier::new(
            DEFAULT_BLOCKCHAIN.to_owned(),
            ledger_id.to_string(),
        )],
    }
}

pub fn network_options(ledger_id: &Principal) -> NetworkOptionsResponse {
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
            errors: vec![Error::invalid_network_id(&format!(
                "Invalid NetworkIdentifier. Expected Identifier: {:?} ",
                NetworkIdentifier::new(DEFAULT_BLOCKCHAIN.to_owned(), ledger_id.to_string())
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
        .map_err(|e| Error::unable_to_find_block(&e))?
        .ok_or_else(|| Error::unable_to_find_block(&"Current block not found".to_owned()))?;

    let genesis_block = storage_client
        .get_block_at_idx(0)
        .map_err(|e| {
            Error::unable_to_find_block(&format!("Error retrieving genesis block: {:?}", e))
        })?
        .ok_or_else(|| Error::unable_to_find_block(&"Genesis block not found".to_owned()))?;
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

pub fn block_transaction(
    storage_client: Arc<StorageClient>,
    block_identifier: BlockIdentifier,
    transaction_identifier: TransactionIdentifier,
    metadata: Metadata,
) -> Result<BlockTransactionResponse, Error> {
    let rosetta_block = storage_client
        .get_block_at_idx(block_identifier.index)
        .map_err(|e| Error::unable_to_find_block(&format!("Unable to retrieve block: {:?}", e)))?
        .ok_or_else(|| {
            Error::unable_to_find_block(&format!(
                "Block at index {} could not be found",
                block_identifier.index
            ))
        })?;
    if hex::encode(&rosetta_block.block_hash) != block_identifier.hash {
        return Err(Error::invalid_block_identifier(&format!("Both index {} and hash {} were provided but they do not match the same block. Actual index {} and hash {}",block_identifier.index,block_identifier.hash,rosetta_block.index,hex::encode(&rosetta_block.block_hash))));
    }

    let transaction = rosetta_block
        .get_transaction()
        .map_err(|e| Error::failed_to_build_block_response(&e))?;

    if transaction.hash().to_string() != transaction_identifier.hash {
        return Err(Error::invalid_transaction_identifier());
    }

    let currency = Currency {
        symbol: metadata.symbol.clone(),
        decimals: metadata.decimals.into(),
        ..Default::default()
    };

    let mut builder = BlockTransactionResponseBuilder::default()
        .with_transaction(transaction)
        .with_currency(currency);

    if let Some(fee) = rosetta_block
        .get_effective_fee()
        .map_err(|e| Error::failed_to_build_block_response(&e))?
    {
        builder = builder.with_effective_fee(fee);
    }

    let response = builder
        .build()
        .map_err(|e| Error::failed_to_build_block_response(&e))?;

    Ok(response)
}

pub fn block(
    storage_client: Arc<StorageClient>,
    partial_block_identifier: PartialBlockIdentifier,
    metadata: Metadata,
) -> Result<BlockResponse, Error> {
    let rosetta_block =
        get_rosetta_block_from_partial_block_identifier(partial_block_identifier, storage_client)
            .map_err(|err| Error::invalid_block_identifier(&err))?;
    let currency = Currency {
        symbol: metadata.symbol.clone(),
        decimals: metadata.decimals.into(),
        ..Default::default()
    };

    let response = BlockResponseBuilder::default()
        .with_rosetta_block(rosetta_block)
        .with_currency(currency)
        .build()
        .map_err(|e| Error::failed_to_build_block_response(&e))?;

    Ok(response)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::{
        storage::types::{RosettaBlock, Tokens},
        types::BlockTransactionResponseBuilder,
    };
    use ic_icrc1_test_utils::valid_blockchain_strategy;
    use proptest::prelude::*;

    const BLOCKHAIN_LENGTH: usize = 1000;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 10,
            ..ProptestConfig::default()
        })]
                       #[test]
                    fn test_network_status_service(blockchain in valid_blockchain_strategy::<Tokens>(BLOCKHAIN_LENGTH)){
                        let storage_client_memory = Arc::new(StorageClient::new_in_memory().unwrap());
                        let mut rosetta_blocks = vec![];
                        for (index,block) in blockchain.clone().into_iter().enumerate(){
                            rosetta_blocks.push(RosettaBlock::from_icrc_ledger_block(block,index as u64).unwrap());
                        }

                        // If there is no block in the database the service should return an error
                        let network_status_err = network_status(storage_client_memory.clone()).unwrap_err();
                        assert!(network_status_err.0.message.contains("Unable to find block"));
                        if !blockchain.is_empty() {

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

                    #[test]
                    fn test_block_service(blockchain in valid_blockchain_strategy::<Tokens>(BLOCKHAIN_LENGTH)){
                        let storage_client_memory = Arc::new(StorageClient::new_in_memory().unwrap());
                        let invalid_block_hash = "0x1234".to_string();
                        let invalid_block_idx = blockchain.len() as u64 + 1;
                        let valid_block_idx = (blockchain.len() as u64).saturating_sub(1);
                        let mut rosetta_blocks = vec![];

                        for (index,block) in blockchain.clone().into_iter().enumerate(){
                            rosetta_blocks.push(RosettaBlock::from_icrc_ledger_block(block,index as u64).unwrap());
                        }

                        storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();

                        let metadata = Metadata{
                            symbol: "ICP".to_string(),
                            decimals: 8
                        };

                        let mut block_identifier = PartialBlockIdentifier{
                            index: None,
                            hash: None
                        };

                        // If the neither the index nor the hash is set the service should return an error
                        let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                        assert!(block_res.unwrap_err().0.description.unwrap().contains("Neither block index nor block hash were provided"));

                        block_identifier = PartialBlockIdentifier{
                            index: Some(invalid_block_idx),
                            hash: None
                        };

                        // If the block identifier index does not exist the service should return an error
                        let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                        assert!(block_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {} could not be found",invalid_block_idx)));

                        block_identifier = PartialBlockIdentifier{
                            index: None,
                            hash: Some(hex::encode(invalid_block_hash.clone()))
                        };

                        // If the block identifier hash does not exist the service should return an error
                        let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                        assert!(block_res.unwrap_err().0.description.unwrap().contains(&format!("Block with hash {} could not be found",hex::encode(invalid_block_hash.clone()))));

                        block_identifier = PartialBlockIdentifier{
                            index: None,
                            hash: Some(invalid_block_hash.clone())
                        };

                        // If the block identifier hash is invalid the service should return an error
                        let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                        assert!(block_res.unwrap_err().0.description.unwrap().contains("Invalid block hash provided"));

                        if !blockchain.is_empty() {
                            let valid_block_hash = hex::encode(&rosetta_blocks[valid_block_idx as usize].block_hash);

                            block_identifier = PartialBlockIdentifier{
                                index: Some(valid_block_idx),
                                hash: None
                            };

                        // If the block identifier index is valid the service should return the block
                        let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                        assert_eq!(block_res.unwrap(),BlockResponseBuilder::default()
                        .with_rosetta_block(rosetta_blocks[valid_block_idx as usize].clone())
                        .with_currency(Currency {
                            symbol: metadata.symbol.clone(),
                            decimals: metadata.decimals.into(),
                            ..Default::default()
                        })
                        .build().unwrap());

                            block_identifier = PartialBlockIdentifier{
                                index: None,
                                hash: Some(valid_block_hash.clone())
                            };

                            // If the block identifier hash is valid the service should return the block
                            let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                            assert_eq!(block_res.unwrap(),BlockResponseBuilder::default()
                            .with_rosetta_block(rosetta_blocks[valid_block_idx as usize].clone())
                            .with_currency(Currency {
                                symbol: metadata.symbol.clone(),
                                decimals: metadata.decimals.into(),
                                ..Default::default()
                            })
                            .build().unwrap());

                            block_identifier = PartialBlockIdentifier{
                                index: Some(valid_block_idx),
                                hash: Some(invalid_block_hash.clone())
                            };

                            // If the block identifier index and hash are provided but do not match the same block the service should return an error
                            let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(format!("Both index {} and hash {} were provided but they do not match the same block",valid_block_idx.clone(),invalid_block_hash.clone()).as_str()));

                            block_identifier = PartialBlockIdentifier{
                                index: Some(invalid_block_idx),
                                hash: Some(invalid_block_hash.clone())
                            };

                            // If the block identifier index and hash are provided but neither of them match a block the service should return an error
                            let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {} could not be found",invalid_block_idx.clone())));

                            block_identifier = PartialBlockIdentifier{
                                index: Some(invalid_block_idx),
                                hash: Some(valid_block_hash.clone())
                            };

                            // If the block identifier index is invalid and the hash is valid the service should return an error
                            let block_res = block(storage_client_memory.clone(),block_identifier,metadata.clone());
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(format!("Block at index {} could not be found",invalid_block_idx).as_str()));
                }
            }

            #[test]
            fn test_block_transaction_service(blockchain in valid_blockchain_strategy::<Tokens>(BLOCKHAIN_LENGTH)){
                let storage_client_memory = Arc::new(StorageClient::new_in_memory().unwrap());
                let invalid_block_hash = "0x1234".to_string();
                let invalid_block_idx = blockchain.len() as u64 + 1;
                let valid_block_idx = (blockchain.len() as u64).saturating_sub(1);
                let mut rosetta_blocks = vec![];

                for (index,block) in blockchain.clone().into_iter().enumerate(){
                    rosetta_blocks.push(RosettaBlock::from_icrc_ledger_block(block,index as u64).unwrap());
                }

                let metadata = Metadata{
                    symbol: "ICP".to_string(),
                    decimals: 8
                };

                let mut block_identifier = BlockIdentifier{
                    index: invalid_block_idx,
                    hash: invalid_block_hash.clone()
                };

                let mut transaction_identifier = TransactionIdentifier{
                    hash: invalid_block_hash.clone()
                };

                // If the storage is empty the service should return an error
                let block_transaction_res = block_transaction(storage_client_memory.clone(),block_identifier.clone(),transaction_identifier.clone(),metadata.clone());
                assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {} could not be found",invalid_block_idx)));

                storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();

                // If the block identifier index is invalid the service should return an error
                let block_transaction_res = block_transaction(storage_client_memory.clone(),block_identifier.clone(),transaction_identifier.clone(),metadata.clone());
                assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {} could not be found",invalid_block_idx)));

                if !blockchain.is_empty() {
                    let valid_block_hash = hex::encode(&rosetta_blocks[valid_block_idx as usize].block_hash);
                    let valid_tx_hash = rosetta_blocks[valid_block_idx as usize].get_transaction().unwrap().hash().to_string();

                    block_identifier = BlockIdentifier{
                        index: valid_block_idx,
                        hash: valid_block_hash.clone()
                    };

                    transaction_identifier = TransactionIdentifier{
                        hash: valid_tx_hash.clone()
                    };

                    // If the block identifier index and hash are valid the service should return the block
                    let block_transaction_res = block_transaction(storage_client_memory.clone(),block_identifier.clone(),transaction_identifier.clone(),metadata.clone());
                    let mut expected_block_transaction_res = BlockTransactionResponseBuilder::default().with_currency(Currency {
                        symbol: metadata.symbol.clone(),
                        decimals: metadata.decimals.into(),
                        ..Default::default()
                    })
                    .with_transaction(rosetta_blocks[valid_block_idx as usize].clone().get_transaction().unwrap());

                    if let Some(fee) = rosetta_blocks[valid_block_idx as usize].clone()
                    .get_effective_fee()
                    .unwrap(){
                        expected_block_transaction_res = expected_block_transaction_res.with_effective_fee(fee);
                    }

                    assert_eq!(block_transaction_res.unwrap(),expected_block_transaction_res.build().unwrap());

                    transaction_identifier = TransactionIdentifier{
                        hash: invalid_block_hash.clone()
                    };

                    // If the transaction identifier hash does not match a transaction in the block the service should return an error
                    let block_transaction_res = block_transaction(storage_client_memory.clone(),block_identifier.clone(),transaction_identifier.clone(),metadata.clone());
                    assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains("Invalid transaction identifier provided"));

                    block_identifier = BlockIdentifier{
                        index: valid_block_idx,
                        hash: invalid_block_hash.clone()
                    };

                    // If the block identifier hash is invalid the service should return an error
                    let block_transaction_res = block_transaction(storage_client_memory.clone(),block_identifier.clone(),transaction_identifier.clone(),metadata.clone());
                    assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains(format!("Both index {} and hash {} were provided but they do not match the same block",valid_block_idx.clone(),invalid_block_hash.clone()).as_str()));
                }
        }
    }
}
