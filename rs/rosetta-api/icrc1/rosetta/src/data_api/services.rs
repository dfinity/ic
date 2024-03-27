use crate::common::constants::DEFAULT_BLOCKCHAIN;
use crate::common::constants::MAX_TRANSACTIONS_PER_SEARCH_TRANSACTIONS_REQUEST;
use crate::common::constants::STATUS_COMPLETED;
use crate::common::storage::types::IcrcOperation;
use crate::common::storage::types::RosettaBlock;
use crate::common::types::OperationType;
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
use icrc_ledger_types::icrc1::account::Account;
use num_bigint::{BigInt, BigUint};
use rosetta_core::miscellaneous::OperationStatus;
use rosetta_core::request_types::SearchTransactionsRequest;
use rosetta_core::response_types::SearchTransactionsResponse;
use rosetta_core::{identifiers::*, miscellaneous::Version, objects::*, response_types::*};
use strum::IntoEnumIterator;

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
            operation_statuses:vec![OperationStatus::new("COMPLETED".to_string(), true)],
            operation_types: OperationType::iter().map(|op| op.to_string()).collect(),
            errors: vec![
                Error::invalid_network_id(&format!(
                    "Invalid NetworkIdentifier. Expected Identifier: {:?} ",
                    NetworkIdentifier::new(DEFAULT_BLOCKCHAIN.to_owned(), ledger_id.to_string())
                ))
                .into(),
                Error::unable_to_find_block(&"Unable to find block".to_owned()).into(),
                Error::invalid_block_identifier(&"Unable to find block".to_owned()).into(),
                Error::failed_to_build_block_response(
                    &"Faild to create a response for fetching blocks.".to_owned(),
                )
                .into(),
                Error::invalid_transaction_identifier().into(),
                Error::mempool_transaction_missing().into(),
                Error::parsing_unsuccessful(&"Failed to parse in between types.".to_owned()).into(),
                Error::unsupported_operation(OperationType::Transfer).into(),
                Error::ledger_communication_unsuccessful(&"Rosetta could not communicate with the ICRC-1 Ledger successfully.".to_owned()).into(),
                Error::unable_to_find_account_balance(&"The balance for the given account could not be fetched.".to_owned()).into(),
                Error::request_processing_error(&"The input of the user resulted in an error while trying to process the request.".to_owned()).into(),
                Error::processing_construction_failed(&"An error while processing an construction api endpoint occured.".to_owned()).into(),
                Error::invalid_metadata(&"The metadata provided by the user is invalid.".to_owned()).into(),
            ],
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
    let mut transaction = icrc1_rosetta_block_to_rosetta_core_transaction(rosetta_block, currency)
        .map_err(|err| Error::failed_to_build_block_response(&err))?;
    transaction.operations.iter_mut().for_each(|op| {
        op.status = Some(STATUS_COMPLETED.to_string());
    });

    Ok(rosetta_core::response_types::BlockTransactionResponse { transaction })
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

    let mut block = icrc1_rosetta_block_to_rosetta_core_block(rosetta_block, currency)
        .map_err(|err| Error::parsing_unsuccessful(&err))?;
    block.transactions.iter_mut().for_each(|tx| {
        tx.operations.iter_mut().for_each(|op| {
            op.status = Some(STATUS_COMPLETED.to_string());
        });
    });

    Ok(BlockResponse::new(Some(block)))
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
        balances: vec![Amount::new(
            BigInt::from(balance),
            Currency {
                symbol,
                decimals: decimals.into(),
                metadata: None,
            },
        )],
        metadata: None,
    })
}

pub fn search_transactions(
    storage_client: &StorageClient,
    request: SearchTransactionsRequest,
    symbol: String,
    decimals: u8,
) -> Result<SearchTransactionsResponse, Error> {
    let currency = Currency {
        symbol,
        decimals: decimals as u32,
        metadata: None,
    };

    if request.coin_identifier.is_some() {
        return Err(Error::request_processing_error(
            &"Coin identifier not supported in search/transactions endpoint".to_owned(),
        ));
    }

    if request.status.is_some() {
        return Err(Error::request_processing_error(
            &"Status not supported in search/transactions endpoint".to_owned(),
        ));
    }

    if request.operator.is_some() {
        return Err(Error::request_processing_error(
            &"Operator not supported in search/transactions endpoint".to_owned(),
        ));
    }

    if request.address.is_some() {
        return Err(Error::request_processing_error(
            &"Address not supported in search/transactions endpoint".to_owned(),
        ));
    }

    if request.success.is_some() {
        return Err(Error::request_processing_error(
            &"Successful only not supported in search/transactions endpoint".to_owned(),
        ));
    }

    if request.currency.is_some() {
        return Err(Error::request_processing_error(
            &"Currency not supported in search/transactions endpoint".to_owned(),
        ));
    }

    let rosetta_block_with_highest_block_index = storage_client
        .get_block_with_highest_block_idx()
        .map_err(|e| Error::unable_to_find_block(&e))?
        .ok_or_else(|| {
            Error::unable_to_find_block(&"There exist no blocks in the database".to_owned())
        })?;

    let max_block: u64 = request
        .max_block
        .unwrap_or(rosetta_block_with_highest_block_index.index as i64)
        .try_into()
        .map_err(|err| {
            Error::request_processing_error(&format!("Max block has to be a valid u64: {}", err))
        })?;

    let limit: u64 = request
        .limit
        .unwrap_or(MAX_TRANSACTIONS_PER_SEARCH_TRANSACTIONS_REQUEST as i64)
        .try_into()
        .map_err(|err| {
            Error::request_processing_error(&format!("Limit has to be a valid u64: {}", err))
        })?;

    let offset: u64 = request.offset.unwrap_or(0).try_into().map_err(|err| {
        Error::request_processing_error(&format!("Offset has to be a valid u64: {}", err))
    })?;

    if max_block < offset {
        return Err(Error::request_processing_error(
            &"Max block has to be greater than or equal to offset".to_owned(),
        ));
    }

    let operation_type = request
        .type_
        .map(|op| {
            op.parse::<OperationType>().map_err(|err| {
                Error::request_processing_error(&format!(
                    "Operation type has to be a valid OperationType: {}",
                    err
                ))
            })
        })
        .transpose()?;

    let account = request
        .account_identifier
        .map(|acc| {
            Account::try_from(acc).map_err(|err| {
                Error::request_processing_error(&format!(
                    "Account identifier has to be a valid AccountIdentifier: {}",
                    err
                ))
            })
        })
        .transpose()?;

    // A filter function that makes sure that any option the user provided is checked against
    fn select_transaction(
        rosetta_block: &RosettaBlock,
        offset: u64,
        max_block: u64,
        account: Option<Account>,
        operation_type: Option<OperationType>,
        transaction_identifier: Option<TransactionIdentifier>,
    ) -> bool {
        // The offset is measured from the block with the highest index. Any block that comes after the block with the highest index minus the offset is filtered out.
        if rosetta_block.index > max_block.saturating_sub(offset) {
            return false;
        }

        // If the operation type is set, we only select transactions that match the operation type
        if let Some(operation_type) = operation_type {
            if operation_type.to_string().to_uppercase()
                != match rosetta_block.block.transaction.operation {
                    IcrcOperation::Transfer { .. } => "TRANSFER",
                    IcrcOperation::Mint { .. } => "MINT",
                    IcrcOperation::Burn { .. } => "BURN",
                    IcrcOperation::Approve { .. } => "APPROVE",
                }
            {
                return false;
            }
        }

        // If the account is set and the transaction does not involve the account we filter it out
        if let Some(account) = account {
            if !match rosetta_block.block.transaction.operation {
                IcrcOperation::Transfer {
                    from, to, spender, ..
                } => spender.map_or(vec![from, to], |spender| vec![from, to, spender]),

                IcrcOperation::Mint { to, .. } => vec![to],

                IcrcOperation::Burn { from, spender, .. } => {
                    spender.map_or(vec![from], |spender| vec![from, spender])
                }

                IcrcOperation::Approve { from, spender, .. } => vec![from, spender],
            }
            .contains(&account)
            {
                return false;
            }
        }

        // If the transaction identifier is set we only select transactions that match the transaction identifier
        if let Some(transaction_identifier) = transaction_identifier {
            if transaction_identifier != rosetta_block.clone().get_transaction_identifier() {
                return false;
            }
        }

        true
    }

    let mut transactions = vec![];

    let mut end = max_block.min(
        rosetta_block_with_highest_block_index
            .index
            .saturating_sub(offset),
    );

    // We only want to iterate over limit number of blocks.
    let mut start = end.saturating_sub(limit);
    let mut last_traversed_block_index;

    // We iterate over all transactions with a window of size limit at a time
    // This guarantees that memory usage is kept low
    'outer_loop: loop {
        for rosetta_block in storage_client
            .get_blocks_by_index_range(start, end)
            .map_err(|err| Error::request_processing_error(&err))?
            .into_iter()
            // The transactions are supposed to be returned in reversed order, meaning from highest block index to lowest
            .rev()
        {
            last_traversed_block_index = rosetta_block.index;
            // If the transaction matches the filter function we add it to the list of transactions
            if select_transaction(
                &rosetta_block,
                offset,
                max_block,
                account,
                operation_type.clone(),
                request.transaction_identifier.clone(),
            ) {
                transactions.push(BlockTransaction {
                    block_identifier: rosetta_block.clone().get_block_identifier(),
                    transaction: icrc1_rosetta_block_to_rosetta_core_transaction(
                        rosetta_block,
                        currency.clone(),
                    )
                    .map_err(|err| Error::parsing_unsuccessful(&err))?,
                });
            };

            // If we have reached the limit or the last traversed block is the genesis block we can stop traversing
            if transactions.len() == limit as usize || last_traversed_block_index == 0 {
                break 'outer_loop;
            }
        }

        end = start.saturating_sub(1);
        start = start.saturating_sub(limit);
    }

    transactions.iter_mut().for_each(|tx| {
        tx.transaction.operations.iter_mut().for_each(|op| {
            op.status = Some(STATUS_COMPLETED.to_string());
        })
    });

    Ok(SearchTransactionsResponse {
        total_count: transactions.len() as i64,
        transactions,
        // If the traversion of transactions has reached the genesis block we can stop traversing
        next_offset: if last_traversed_block_index == 0 {
            None
        } else {
            Some(max_block.saturating_sub(last_traversed_block_index.saturating_sub(1)) as i64)
        },
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
    use proptest::test_runner::Config as TestRunnerConfig;
    use proptest::test_runner::TestRunner;
    use std::sync::Arc;

    const BLOCKCHAIN_LENGTH: usize = 1000;

    fn compare_blocks(mut a: rosetta_core::objects::Block, mut b: rosetta_core::objects::Block) {
        for (tx_a, tx_b) in a.transactions.iter_mut().zip(b.transactions.iter_mut()) {
            assert_eq!(tx_a, tx_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 10,
            ..ProptestConfig::default()
        })]
                       #[test]
                    fn test_network_status_service(blockchain in valid_blockchain_strategy::<U256>(BLOCKCHAIN_LENGTH)){
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
                    fn test_block_service(blockchain in valid_blockchain_strategy::<U256>(BLOCKCHAIN_LENGTH)){
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
                        let mut expected_block_res = BlockResponse {
                            block: Some(
                                icrc1_rosetta_block_to_rosetta_core_block(rosetta_blocks[valid_block_idx as usize].clone(), Currency {
                                    symbol: metadata.symbol.clone(),
                                    decimals: metadata.decimals.into(),
                                    ..Default::default()
                                }).unwrap(),
                            ),
                            other_transactions:None};
                            expected_block_res.block.iter_mut().for_each(|block| block.transactions.iter_mut().for_each(|tx| {
                                tx.operations.iter_mut().for_each(|op| {
                                    op.status = Some(STATUS_COMPLETED.to_string());
                                })
                            }));

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
            fn test_block_transaction_service(blockchain in valid_blockchain_strategy::<U256>((MAX_TRANSACTIONS_PER_SEARCH_TRANSACTIONS_REQUEST*5).try_into().unwrap())){
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
                    let mut expected_block_transaction_res = rosetta_core::response_types::BlockTransactionResponse { transaction: icrc1_rosetta_block_to_rosetta_core_transaction(rosetta_blocks[valid_block_idx as usize].clone(), Currency {
                        symbol: metadata.symbol.clone(),
                        decimals: metadata.decimals.into(),
                        ..Default::default()
                    }).unwrap() };
                    expected_block_transaction_res.transaction.operations.iter_mut().for_each(|op| {
                            op.status = Some(STATUS_COMPLETED.to_string());
                        });

                    // Sort the related operations so the equality check passes
                    assert_eq!(block_transaction_res.transaction, expected_block_transaction_res.transaction);

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

    #[test]
    fn test_search_transactions() {
        let mut runner = TestRunner::new(TestRunnerConfig {
            max_shrink_iters: 0,
            cases: 1,
            ..Default::default()
        });

        runner
            .run(
                &(valid_blockchain_strategy::<U256>(BLOCKCHAIN_LENGTH).no_shrink()),
                |blockchain| {
                    let storage_client_memory = StorageClient::new_in_memory().unwrap();
                    let mut rosetta_blocks = vec![];

                    for (index, block) in blockchain.clone().into_iter().enumerate() {
                        rosetta_blocks.push(
                            RosettaBlock::from_generic_block(
                                encoded_block_to_generic_block(&block.encode()),
                                index as u64,
                            )
                            .unwrap(),
                        );
                    }

                    storage_client_memory
                        .store_blocks(rosetta_blocks.clone())
                        .unwrap();
                    let mut search_transactions_request = SearchTransactionsRequest {
                        ..Default::default()
                    };

                    fn traverse_all_transactions(
                        storage_client: &StorageClient,
                        mut search_transactions_request: SearchTransactionsRequest,
                    ) -> Vec<BlockTransaction> {
                        let mut transactions = vec![];
                        loop {
                            let result = search_transactions(
                                storage_client,
                                search_transactions_request.clone(),
                                "ICP".to_string(),
                                8,
                            )
                            .unwrap();
                            transactions.extend(result.clone().transactions);
                            search_transactions_request.offset = result.next_offset;

                            if search_transactions_request.offset.is_none() {
                                break;
                            }
                        }

                        transactions
                    }

                    if !blockchain.is_empty() {
                        // The maximum number of transactions that can be returned is the minimum between the maximum number of transactions per request or the entire blockchain
                        let maximum_number_returnable_transactions = rosetta_blocks
                            .len()
                            .min(MAX_TRANSACTIONS_PER_SEARCH_TRANSACTIONS_REQUEST as usize);

                        // If no filters are provided the service should return all transactions or the maximum of transactions per request
                        let result = search_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                            "ICP".to_string(),
                            8,
                        )
                        .unwrap();
                        assert_eq!(
                            result.total_count,
                            maximum_number_returnable_transactions as i64
                        );
                        assert_eq!(result.transactions.len() as i64, result.total_count);

                        // We traverse through all the blocks and check if the transactions are returned correctly if the transaction identifier is provided
                        for rosetta_block in rosetta_blocks.iter() {
                            search_transactions_request.transaction_identifier =
                                Some(rosetta_block.clone().get_transaction_identifier());
                            let result = search_transactions(
                                &storage_client_memory,
                                search_transactions_request.clone(),
                                "ICP".to_string(),
                                8,
                            )
                            .unwrap();

                            let num_of_transactions_with_hash = rosetta_blocks
                                .iter()
                                .filter(|block| {
                                    (*block).clone().get_transaction_hash()
                                        == rosetta_block.clone().get_transaction_hash()
                                })
                                .count();

                            // The total count should be the number of transactions with the same transaction identifier
                            assert_eq!(result.total_count, num_of_transactions_with_hash as i64);
                            // If we provide a transaction identifier the service should return the transactions that match the transaction identifier
                            let mut expected_transaction =
                                icrc1_rosetta_block_to_rosetta_core_transaction(
                                    rosetta_block.clone(),
                                    Currency {
                                        symbol: "ICP".to_string(),
                                        decimals: 8,
                                        metadata: None,
                                    },
                                )
                                .unwrap();
                            expected_transaction.operations.iter_mut().for_each(|op| {
                                op.status = Some(STATUS_COMPLETED.to_string());
                            });
                            assert_eq!(result.transactions[0].transaction, expected_transaction);
                            // If the transaction identifier is provided the next offset should be None
                            assert_eq!(result.next_offset, None);
                        }

                        search_transactions_request = SearchTransactionsRequest {
                            ..Default::default()
                        };

                        // Let's check that setting the max_block option works as intended
                        search_transactions_request.max_block =
                            Some(rosetta_blocks.last().unwrap().index as i64);
                        let result = search_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                            "ICP".to_string(),
                            8,
                        )
                        .unwrap();
                        assert_eq!(
                            result.transactions.len(),
                            maximum_number_returnable_transactions
                        );

                        // The transactiosn should be returned in descending order of block index
                        assert_eq!(
                            result.transactions.first().unwrap().block_identifier,
                            rosetta_blocks
                                .last()
                                .unwrap()
                                .clone()
                                .get_block_identifier()
                        );

                        // If we set the limit to something below the maximum number of blocks we should only receive that number of blocks
                        search_transactions_request.max_block = None;
                        search_transactions_request.limit = Some(1);
                        let result = search_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                            "ICP".to_string(),
                            8,
                        )
                        .unwrap();
                        assert_eq!(result.transactions.len(), 1);

                        // The expected offset is the index of the highest block fetched minus the limit
                        let expected_offset = 1;

                        assert_eq!(
                            result.next_offset,
                            if rosetta_blocks.len() > 1 {
                                Some(expected_offset)
                            } else {
                                None
                            }
                        );

                        search_transactions_request.limit = None;

                        // Setting the offset to greater than 0 only makes sense if the storage contains more than 1 block
                        search_transactions_request.offset =
                            Some(rosetta_blocks.len().saturating_sub(1).min(1) as i64);

                        let result = search_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                            "ICP".to_string(),
                            8,
                        )
                        .unwrap();
                        assert_eq!(
                            result.transactions.len(),
                            if rosetta_blocks.len() == 1 {
                                1
                            } else {
                                rosetta_blocks.len().saturating_sub(1)
                            }
                            .min(MAX_TRANSACTIONS_PER_SEARCH_TRANSACTIONS_REQUEST as usize)
                        );

                        search_transactions_request.offset = None;
                        search_transactions_request.max_block = Some(10);
                        let result = traverse_all_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                        );

                        // The service should return the correct number of transactions if the max block is set, max block is an index so if the index is 10 there are 11 blocks/transactions to search through
                        assert_eq!(result.len(), rosetta_blocks.len().min(10 + 1));

                        search_transactions_request = SearchTransactionsRequest {
                            ..Default::default()
                        };

                        // We make sure that the service returns the correct number of transactions for each operation type
                        search_transactions_request.type_ = Some("TRANSFER".to_string());
                        let num_of_transfer_transactions = rosetta_blocks
                            .iter()
                            .filter(|block| {
                                matches!(
                                    block.block.transaction.operation,
                                    IcrcOperation::Transfer { .. }
                                )
                            })
                            .count();
                        let result = traverse_all_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                        );
                        assert_eq!(result.len(), num_of_transfer_transactions);

                        search_transactions_request.type_ = Some("BURN".to_string());
                        let num_of_burn_transactions = rosetta_blocks
                            .iter()
                            .filter(|block| {
                                matches!(
                                    block.block.transaction.operation,
                                    IcrcOperation::Burn { .. }
                                )
                            })
                            .count();
                        let result = traverse_all_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                        );
                        assert_eq!(result.len(), num_of_burn_transactions);

                        search_transactions_request.type_ = Some("MINT".to_string());
                        let num_of_mint_transactions = rosetta_blocks
                            .iter()
                            .filter(|block| {
                                matches!(
                                    block.block.transaction.operation,
                                    IcrcOperation::Mint { .. }
                                )
                            })
                            .count();
                        let result = traverse_all_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                        );
                        assert_eq!(result.len(), num_of_mint_transactions);

                        search_transactions_request.type_ = Some("APPROVE".to_string());
                        let num_of_approve_transactions = rosetta_blocks
                            .iter()
                            .filter(|block| {
                                matches!(
                                    block.block.transaction.operation,
                                    IcrcOperation::Approve { .. }
                                )
                            })
                            .count();
                        let result = traverse_all_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                        );
                        assert_eq!(result.len(), num_of_approve_transactions);

                        search_transactions_request = SearchTransactionsRequest {
                            ..Default::default()
                        };

                        // We make sure that the service returns the correct number of transactions for each account
                        search_transactions_request.account_identifier = Some(
                            match rosetta_blocks[0].block.transaction.operation {
                                IcrcOperation::Transfer { from, .. } => from,
                                IcrcOperation::Mint { to, .. } => to,
                                IcrcOperation::Burn { from, .. } => from,
                                IcrcOperation::Approve { from, .. } => from,
                            }
                            .into(),
                        );

                        let num_of_transactions_with_account = rosetta_blocks
                            .iter()
                            .filter(|block| match block.block.transaction.operation {
                                IcrcOperation::Transfer {
                                    from, to, spender, ..
                                } => spender
                                    .map_or(vec![from, to], |spender| vec![from, to, spender])
                                    .contains(
                                        &search_transactions_request
                                            .account_identifier
                                            .clone()
                                            .unwrap()
                                            .try_into()
                                            .unwrap(),
                                    ),
                                IcrcOperation::Mint { to, .. } => {
                                    to == search_transactions_request
                                        .account_identifier
                                        .clone()
                                        .unwrap()
                                        .try_into()
                                        .unwrap()
                                }
                                IcrcOperation::Burn { from, spender, .. } => spender
                                    .map_or(vec![from], |spender| vec![from, spender])
                                    .contains(
                                        &search_transactions_request
                                            .account_identifier
                                            .clone()
                                            .unwrap()
                                            .try_into()
                                            .unwrap(),
                                    ),
                                IcrcOperation::Approve { from, spender, .. } => [from, spender]
                                    .contains(
                                        &search_transactions_request
                                            .account_identifier
                                            .clone()
                                            .unwrap()
                                            .try_into()
                                            .unwrap(),
                                    ),
                            })
                            .count();

                        let result = traverse_all_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                        );
                        assert_eq!(result.len(), num_of_transactions_with_account);
                        let involved_accounts = result[0]
                            .transaction
                            .operations
                            .iter()
                            .map(|op| op.account.clone().unwrap())
                            .collect::<Vec<AccountIdentifier>>();
                        assert!(involved_accounts.contains(
                            &search_transactions_request
                                .account_identifier
                                .clone()
                                .unwrap()
                        ));
                    }
                    Ok(())
                },
            )
            .unwrap()
    }
}
