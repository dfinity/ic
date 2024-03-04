use crate::common::{
    constants::{NODE_VERSION, ROSETTA_VERSION},
    storage::storage_client::StorageClient,
    types::Error,
    utils::utils::{
        convert_timestamp_to_millis, get_rosetta_block_from_block_identifier,
        get_rosetta_block_from_partial_block_identifier, icrc1_rosetta_block_to_rosetta_core_block,
        icrc1_rosetta_block_to_rosetta_core_transaction,
    },
};
use candid::Nat;
use candid::Principal;
use ic_ledger_core::tokens::Zero;
use ic_rosetta_api::DEFAULT_BLOCKCHAIN;
use icrc_ledger_types::icrc1::account::Account;
use num_bigint::BigUint;
use rosetta_core::{identifiers::*, miscellaneous::Version, objects::*, response_types::*};

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

pub fn network_status(storage_client: &StorageClient) -> Result<NetworkStatusResponse, Error> {
    let current_block = storage_client
        .get_block_with_highest_block_idx()
        .map_err(|e| Error::unable_to_find_block(&e))?
        .ok_or_else(|| Error::unable_to_find_block(&"Current block not found".to_owned()))?;

    let genesis_block = storage_client
        .get_block_at_idx(0)
        .map_err(|e| {
            Error::unable_to_find_block(&format!("Error retrieving genesis block: {:?}", e))
        })?
        .ok_or_else(|| {
            Error::unable_to_find_block(
                &"Genesis block not found! Perhaps the initial sync is still running?".to_owned(),
            )
        })?;
    let genesis_block_identifier = BlockIdentifier::from(genesis_block);

    Ok(NetworkStatusResponse {
        current_block_timestamp: convert_timestamp_to_millis(current_block.get_timestamp())
            .map_err(|err| Error::parsing_unsuccessful(&err))?,
        current_block_identifier: BlockIdentifier::from(current_block),
        genesis_block_identifier: genesis_block_identifier.clone(),
        oldest_block_identifier: Some(genesis_block_identifier),
        sync_status: None,
        peers: vec![],
    })
}

pub fn block_transaction(
    storage_client: &StorageClient,
    block_identifier: &BlockIdentifier,
    transaction_identifier: &TransactionIdentifier,
    decimals: u8,
    symbol: String,
) -> Result<BlockTransactionResponse, Error> {
    let rosetta_block =
        get_rosetta_block_from_block_identifier(block_identifier.clone(), storage_client)
            .map_err(|err| Error::invalid_block_identifier(&err))?;

    if &rosetta_block.clone().get_block_identifier() != block_identifier {
        return Err(Error::invalid_block_identifier(&format!("Both index {} and hash {} were provided but they do not match the same block. Actual index {} and hash {}",block_identifier.index,block_identifier.hash,rosetta_block.index,hex::encode(rosetta_block.clone().get_block_hash()))));
    }

    if &rosetta_block.clone().get_transaction_identifier() != transaction_identifier {
        return Err(Error::invalid_transaction_identifier());
    }

    let currency = Currency {
        symbol,
        decimals: decimals.into(),
        ..Default::default()
    };

    Ok(rosetta_core::response_types::BlockTransactionResponse {
        transaction: icrc1_rosetta_block_to_rosetta_core_transaction(rosetta_block, currency)
            .map_err(|e| Error::failed_to_build_block_response(&e))?,
    })
}

pub fn block(
    storage_client: &StorageClient,
    partial_block_identifier: &PartialBlockIdentifier,
    decimals: u8,
    symbol: String,
) -> Result<BlockResponse, Error> {
    let rosetta_block =
        get_rosetta_block_from_partial_block_identifier(partial_block_identifier, storage_client)
            .map_err(|err| Error::invalid_block_identifier(&err))?;
    let currency = Currency {
        symbol,
        decimals: decimals.into(),
        ..Default::default()
    };

    Ok(BlockResponse::new(Some(
        icrc1_rosetta_block_to_rosetta_core_block(rosetta_block, currency)
            .map_err(|err| Error::parsing_unsuccessful(&err))?,
    )))
}

pub fn account_balance(
    storage_client: &StorageClient,
    account_identifier: &AccountIdentifier,
    partial_block_identifier: &Option<PartialBlockIdentifier>,
    decimals: u8,
    symbol: String,
) -> Result<AccountBalanceResponse, Error> {
    let rosetta_block = match partial_block_identifier {
        Some(block_id) => get_rosetta_block_from_partial_block_identifier(block_id, storage_client)
            .map_err(|err| Error::invalid_block_identifier(&err))?,
        None => storage_client
            .get_block_with_highest_block_idx()
            .map_err(|e| Error::unable_to_find_block(&e))?
            .ok_or_else(|| Error::unable_to_find_block(&"Current block not found".to_owned()))?,
    };

    let balance = storage_client
        .get_account_balance_at_block_idx(
            &(Account::try_from(account_identifier.clone())
                .map_err(|err| Error::parsing_unsuccessful(&err))?),
            rosetta_block.index,
        )
        .map_err(|e| Error::unable_to_find_account_balance(&e))?
        .unwrap_or(Nat(BigUint::zero()));

    Ok(AccountBalanceResponse {
        block_identifier: rosetta_block.get_block_identifier(),
        balances: vec![Amount {
            value: balance.to_string(),
            currency: Currency {
                symbol,
                decimals: decimals.into(),
                metadata: None,
            },
            metadata: None,
        }],
        metadata: None,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::storage::types::RosettaBlock;
    use crate::Metadata;
    use ic_icrc1::blocks::encoded_block_to_generic_block;
    use ic_icrc1_test_utils::valid_blockchain_strategy;
    use ic_icrc1_tokens_u256::U256;
    use ic_ledger_core::block::BlockType;
    use proptest::prelude::*;
    use std::sync::Arc;

    const BLOCKHAIN_LENGTH: usize = 1000;

    fn compare_transaction(
        mut a: rosetta_core::objects::Transaction,
        mut b: rosetta_core::objects::Transaction,
    ) {
        a.operations.iter_mut().for_each(|op| {
            op.related_operations = op.related_operations.clone().map(|mut x| {
                x.sort_by(|a, b| a.index.cmp(&b.index));
                x
            })
        });
        b.operations.iter_mut().for_each(|op| {
            op.related_operations = op.related_operations.clone().map(|mut x| {
                x.sort_by(|a, b| a.index.cmp(&b.index));
                x
            })
        });
        assert_eq!(a, b);
    }

    fn compare_blocks(mut a: rosetta_core::objects::Block, mut b: rosetta_core::objects::Block) {
        for (tx_a, tx_b) in a.transactions.iter_mut().zip(b.transactions.iter_mut()) {
            compare_transaction(tx_a.clone(), tx_b.clone());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 10,
            ..ProptestConfig::default()
        })]
                       #[test]
                    fn test_network_status_service(blockchain in valid_blockchain_strategy::<U256>(BLOCKHAIN_LENGTH)){
                        let storage_client_memory = Arc::new(StorageClient::new_in_memory().unwrap());
                        let mut rosetta_blocks = vec![];
                        for (index,block) in blockchain.clone().into_iter().enumerate(){
                            rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.encode()),index as u64).unwrap());
                        }

                        // If there is no block in the database the service should return an error
                        let network_status_err = network_status(&storage_client_memory).unwrap_err();
                        assert!(network_status_err.0.message.contains("Unable to find block"));
                        if !blockchain.is_empty() {

                        storage_client_memory.store_blocks(rosetta_blocks).unwrap();
                        let block_with_highest_idx = storage_client_memory.get_block_with_highest_block_idx().unwrap().unwrap();
                        let genesis_block = storage_client_memory.get_block_with_lowest_block_idx().unwrap().unwrap();

                        let network_status_response = network_status(&storage_client_memory).unwrap();

                        assert_eq!(NetworkStatusResponse {
                            current_block_identifier: BlockIdentifier::from(block_with_highest_idx.clone()),
                            current_block_timestamp: convert_timestamp_to_millis(block_with_highest_idx.get_timestamp()).map_err(|err| Error::parsing_unsuccessful(&err)).unwrap(),
                            genesis_block_identifier: BlockIdentifier::from(genesis_block.clone()),
                            oldest_block_identifier: Some(BlockIdentifier::from(genesis_block)),
                            sync_status: None,
                            peers: vec![],
                        },network_status_response)
                    }
                    }

                    #[test]
                    fn test_block_service(blockchain in valid_blockchain_strategy::<U256>(BLOCKHAIN_LENGTH)){
                        let storage_client_memory = Arc::new(StorageClient::new_in_memory().unwrap());
                        let invalid_block_hash = "0x1234".to_string();
                        let invalid_block_idx = blockchain.len() as u64 + 1;
                        let valid_block_idx = (blockchain.len() as u64).saturating_sub(1);
                        let mut rosetta_blocks = vec![];

                        for (index,block) in blockchain.clone().into_iter().enumerate(){
                            rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.encode()),index as u64).unwrap());
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
                        let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());
                        assert!(block_res.unwrap_err().0.description.unwrap().contains("Neither block index nor block hash were provided"));

                        block_identifier = PartialBlockIdentifier{
                            index: Some(invalid_block_idx),
                            hash: None
                        };

                        // If the block identifier index does not exist the service should return an error
                        let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());
                        assert!(block_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {} could not be found",invalid_block_idx)));

                        block_identifier = PartialBlockIdentifier{
                            index: None,
                            hash: Some(hex::encode(invalid_block_hash.clone()))
                        };

                        // If the block identifier hash does not exist the service should return an error
                        let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());
                        assert!(block_res.unwrap_err().0.description.unwrap().contains(&format!("Block with hash {} could not be found",hex::encode(invalid_block_hash.clone()))));

                        block_identifier = PartialBlockIdentifier{
                            index: None,
                            hash: Some(invalid_block_hash.clone())
                        };

                        // If the block identifier hash is invalid the service should return an error
                        let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());
                        assert!(block_res.unwrap_err().0.description.unwrap().contains("Invalid block hash provided"));

                        if !blockchain.is_empty() {
                            let valid_block_hash = hex::encode(rosetta_blocks[valid_block_idx as usize].clone().get_block_hash());

                            block_identifier = PartialBlockIdentifier{
                                index: Some(valid_block_idx),
                                hash: None
                            };

                        // If the block identifier index is valid the service should return the block
                        let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone()).unwrap();
                        let expected_block_res = BlockResponse {
                            block: Some(
                                icrc1_rosetta_block_to_rosetta_core_block(rosetta_blocks[valid_block_idx as usize].clone(), Currency {
                                    symbol: metadata.symbol.clone(),
                                    decimals: metadata.decimals.into(),
                                    ..Default::default()
                                }).unwrap(),
                            ),
                            other_transactions:None};

                            compare_blocks(block_res.block.unwrap(),expected_block_res.clone().block.unwrap());

                            block_identifier = PartialBlockIdentifier{
                                index: None,
                                hash: Some(valid_block_hash.clone())
                            };

                            // If the block identifier hash is valid the service should return the block
                            let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone()).unwrap();
                            compare_blocks(block_res.block.unwrap(),expected_block_res.block.unwrap());

                            block_identifier = PartialBlockIdentifier{
                                index: Some(valid_block_idx),
                                hash: Some(invalid_block_hash.clone())
                            };

                            // If the block identifier index and hash are provided but do not match the same block the service should return an error
                            let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(format!("Both index {} and hash {} were provided but they do not match the same block",valid_block_idx.clone(),invalid_block_hash.clone()).as_str()));

                            block_identifier = PartialBlockIdentifier{
                                index: Some(invalid_block_idx),
                                hash: Some(invalid_block_hash.clone())
                            };

                            // If the block identifier index and hash are provided but neither of them match a block the service should return an error
                            let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {} could not be found",invalid_block_idx.clone())));

                            block_identifier = PartialBlockIdentifier{
                                index: Some(invalid_block_idx),
                                hash: Some(valid_block_hash.clone())
                            };

                            // If the block identifier index is invalid and the hash is valid the service should return an error
                            let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(format!("Block at index {} could not be found",invalid_block_idx).as_str()));
                }
            }

            #[test]
            fn test_block_transaction_service(blockchain in valid_blockchain_strategy::<U256>(BLOCKHAIN_LENGTH)){
                let storage_client_memory = Arc::new(StorageClient::new_in_memory().unwrap());
                let invalid_block_hash = "0x1234".to_string();
                let invalid_block_idx = blockchain.len() as u64 + 1;
                let valid_block_idx = (blockchain.len() as u64).saturating_sub(1);
                let mut rosetta_blocks = vec![];

                for (index,block) in blockchain.clone().into_iter().enumerate(){
                    rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.encode()),index as u64).unwrap());
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
                let block_transaction_res = block_transaction(&storage_client_memory,&block_identifier,&transaction_identifier,metadata.decimals,metadata.symbol.clone());
                assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {} could not be found",invalid_block_idx)));

                storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();

                // If the block identifier index is invalid the service should return an error
                let block_transaction_res = block_transaction(&storage_client_memory,&block_identifier,&transaction_identifier,metadata.decimals,metadata.symbol.clone());
                assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {} could not be found",invalid_block_idx)));

                if !blockchain.is_empty() {
                    let valid_block_hash = hex::encode(rosetta_blocks[valid_block_idx as usize].clone().get_block_hash());
                    let valid_tx_hash = hex::encode(rosetta_blocks[valid_block_idx as usize].clone().get_transaction_hash().as_ref());

                    block_identifier = BlockIdentifier{
                        index: valid_block_idx,
                        hash: valid_block_hash.clone()
                    };

                    transaction_identifier = TransactionIdentifier{
                        hash: valid_tx_hash.clone()
                    };

                    // If the block identifier index and hash are valid the service should return the block
                    let block_transaction_res = block_transaction(&storage_client_memory,&block_identifier,&transaction_identifier,metadata.decimals,metadata.symbol.clone()).unwrap();
                    let expected_block_transaction_res = rosetta_core::response_types::BlockTransactionResponse { transaction: icrc1_rosetta_block_to_rosetta_core_transaction(rosetta_blocks[valid_block_idx as usize].clone(), Currency {
                        symbol: metadata.symbol.clone(),
                        decimals: metadata.decimals.into(),
                        ..Default::default()
                    }).unwrap() };

                    // Sort the related operations so the equality check passes
                    compare_transaction(block_transaction_res.transaction.clone(),expected_block_transaction_res.transaction.clone());

                    transaction_identifier = TransactionIdentifier{
                        hash: invalid_block_hash.clone()
                    };

                    // If the transaction identifier hash does not match a transaction in the block the service should return an error
                    let block_transaction_res = block_transaction(&storage_client_memory,&block_identifier,&transaction_identifier,metadata.decimals,metadata.symbol.clone());
                    assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains("Invalid transaction identifier provided"));

                    block_identifier = BlockIdentifier{
                        index: valid_block_idx,
                        hash: invalid_block_hash.clone()
                    };

                    // If the block identifier hash is invalid the service should return an error
                    let block_transaction_res = block_transaction(&storage_client_memory,&block_identifier,&transaction_identifier,metadata.decimals,metadata.symbol.clone());
                    assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains(format!("Both index {} and hash {} were provided but they do not match the same block",valid_block_idx.clone(),invalid_block_hash.clone()).as_str()));
                }
        }
    }
}
