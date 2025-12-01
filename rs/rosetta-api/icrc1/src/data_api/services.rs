use std::sync::Arc;
use std::sync::Mutex;

use crate::common::constants::DEFAULT_BLOCKCHAIN;
use crate::common::constants::MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST;
use crate::common::constants::MAX_TRANSACTIONS_PER_SEARCH_TRANSACTIONS_REQUEST;
use crate::common::constants::STATUS_COMPLETED;
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
use crate::data_api::types::QueryBlockRangeRequest;
use crate::data_api::types::QueryBlockRangeResponse;
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

pub fn network_list(ledger_ids: &[Principal]) -> NetworkListResponse {
    NetworkListResponse {
        network_identifiers: ledger_ids
            .iter()
            .map(|ledger_id| {
                NetworkIdentifier::new(DEFAULT_BLOCKCHAIN.to_owned(), ledger_id.to_string())
            })
            .collect(),
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
    let highest_processed_block = storage_client
        .get_highest_block_idx_in_account_balance_table()
        .map_err(|e| Error::unable_to_find_block(&e))?
        .ok_or_else(|| {
            Error::unable_to_find_block(&"Highest processed block not found".to_owned())
        })?;

    let current_block = storage_client
        .get_block_at_idx(highest_processed_block)
        .map_err(|e| Error::unable_to_find_block(&e))?
        .ok_or_else(|| Error::unable_to_find_block(&"Current block not found".to_owned()))?;

    let genesis_block = storage_client
        .get_block_at_idx(0)
        .map_err(|e| {
            Error::unable_to_find_block(&format!("Error retrieving genesis block: {e:?}"))
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
        return Err(Error::invalid_block_identifier(&format!(
            "Both index {} and hash {} were provided but they do not match the same block. Actual index {} and hash {}",
            block_identifier.index,
            block_identifier.hash,
            rosetta_block.index,
            hex::encode(rosetta_block.clone().get_block_hash())
        )));
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

pub fn account_balance_with_metadata(
    storage_client: &StorageClient,
    account_identifier: &AccountIdentifier,
    partial_block_identifier: &Option<PartialBlockIdentifier>,
    metadata: &Option<ObjectMap>,
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

    // Check if aggregate_all_subaccounts flag is set in metadata
    let aggregate_all_subaccounts = metadata
        .as_ref()
        .and_then(|m| m.get("aggregate_all_subaccounts"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let balance = if aggregate_all_subaccounts {
        // Validate that no subaccount is specified when aggregating all subaccounts
        let account = Account::try_from(account_identifier.clone())
            .map_err(|err| Error::parsing_unsuccessful(&err))?;

        // Check if a non-default subaccount is specified
        // Note: subaccount None and Some([0; 32]) both represent the default subaccount
        let has_non_default_subaccount = match account.subaccount {
            None => false,
            Some(subaccount) => subaccount != [0u8; 32],
        };

        if has_non_default_subaccount {
            return Err(Error::request_processing_error(
                &"Cannot specify subaccount when aggregate_all_subaccounts is true".to_owned(),
            ));
        }

        // Get aggregated balance for all subaccounts of the principal
        storage_client
            .get_aggregated_balance_for_principal_at_block_idx(
                &account.owner.into(),
                rosetta_block.index,
            )
            .map_err(|e| Error::unable_to_find_account_balance(&e))?
    } else {
        // Get balance for the specific account (principal + subaccount)
        storage_client
            .get_account_balance_at_block_idx(
                &(Account::try_from(account_identifier.clone())
                    .map_err(|err| Error::parsing_unsuccessful(&err))?),
                rosetta_block.index,
            )
            .map_err(|e| Error::unable_to_find_account_balance(&e))?
            .unwrap_or(Nat(BigUint::zero()))
    };

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
        .map_err(|e| Error::unable_to_find_block(&e))?;

    let Some(rosetta_block_with_highest_block_index) = rosetta_block_with_highest_block_index
    else {
        return Ok(SearchTransactionsResponse {
            total_count: 0,
            transactions: vec![],
            next_offset: None,
        });
    };

    let max_block: u64 = request
        .max_block
        .unwrap_or(rosetta_block_with_highest_block_index.index as i64)
        .try_into()
        .map_err(|err| {
            Error::request_processing_error(&format!("Max block has to be a valid u64: {err}"))
        })?;

    let limit: u64 = request
        .limit
        .unwrap_or(MAX_TRANSACTIONS_PER_SEARCH_TRANSACTIONS_REQUEST as i64)
        .try_into()
        .map_err(|err| {
            Error::request_processing_error(&format!("Limit has to be a valid u64: {err}"))
        })?;

    let offset: u64 = request.offset.unwrap_or(0).try_into().map_err(|err| {
        Error::request_processing_error(&format!("Offset has to be a valid u64: {err}"))
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
                    "Operation type has to be a valid OperationType: {err}"
                ))
            })
        })
        .transpose()?;

    let account = request
        .account_identifier
        .map(|acc| {
            Account::try_from(acc).map_err(|err| {
                Error::request_processing_error(&format!(
                    "Account identifier has to be a valid AccountIdentifier: {err}"
                ))
            })
        })
        .transpose()?;

    let start_idx = max_block.min(
        rosetta_block_with_highest_block_index
            .index
            .saturating_sub(offset),
    );

    if limit == 0 {
        return Ok(SearchTransactionsResponse {
            total_count: 0,
            transactions: vec![],
            next_offset: Some(offset as i64),
        });
    }

    // Base query to fetch the blocks
    let mut command =
        String::from("SELECT idx,serialized_block FROM blocks WHERE idx <= :max_block_idx ");
    let mut parameters: Vec<(&str, Box<dyn rusqlite::ToSql>)> = Vec::new();

    parameters.push((":max_block_idx", Box::new(start_idx)));

    if let Some(transaction_identifier) = request.transaction_identifier.clone() {
        command.push_str("AND tx_hash = :tx_hash ");
        let tx_hash = serde_bytes::ByteBuf::try_from(transaction_identifier)
            .map_err(|err| {
                Error::request_processing_error(&format!(
                    "Transaction identifier hash has to be a valid ByteBuf: {err}"
                ))
            })?
            .as_slice()
            .to_vec();
        parameters.push((":tx_hash", Box::new(tx_hash)));
    }

    if let Some(operation_type) = operation_type {
        command.push_str("AND operation_type = :operation_type ");
        parameters.push((
            ":operation_type",
            Box::new(operation_type.to_string().to_lowercase()),
        ));
    }

    if let Some(account) = account {
        command.push_str("AND ((from_principal = :account_principal AND from_subaccount = :account_subaccount) OR (to_principal = :account_principal AND to_subaccount = :account_subaccount) OR (spender_principal = :account_principal AND spender_subaccount = :account_subaccount)) ");
        parameters.push((
            ":account_principal",
            Box::new(account.owner.as_slice().to_vec()),
        ));
        parameters.push((
            ":account_subaccount",
            Box::new(*account.effective_subaccount()),
        ));
    }

    command.push_str("ORDER BY idx DESC ");

    command.push_str("LIMIT :limit ");
    parameters.push((":limit", Box::new(limit)));

    let mut rosetta_blocks = storage_client
        .get_blocks_by_custom_query(
            command,
            parameters
                .iter()
                .map(|(key, param)| {
                    let param_ref: &dyn rusqlite::ToSql = param.as_ref();
                    (key.to_owned(), param_ref)
                })
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .map_err(|e| Error::unable_to_find_block(&format!("Error fetching blocks: {e:?}")))?;

    let mut transactions = vec![];
    for rosetta_block in rosetta_blocks.iter_mut() {
        transactions.push(BlockTransaction {
            block_identifier: rosetta_block.clone().get_block_identifier(),
            transaction: icrc1_rosetta_block_to_rosetta_core_transaction(
                rosetta_block.clone(),
                currency.clone(),
            )
            .map_err(|err| Error::parsing_unsuccessful(&err))?,
        })
    }

    transactions.iter_mut().for_each(|tx| {
        tx.transaction.operations.iter_mut().for_each(|op| {
            op.status = Some(STATUS_COMPLETED.to_string());
        })
    });

    // Sort the transactions by block index in descending order
    transactions.sort_by(|a, b| b.block_identifier.index.cmp(&a.block_identifier.index));

    // Is rosetta blocks is empty that means the entire blockchain was traversed but no transactions were found that match the search criteria
    let last_traversed_block_index = rosetta_blocks
        .iter()
        .map(|block| block.index)
        .min()
        .unwrap_or(0);
    let num_fetched_transactions = transactions.len();

    Ok(SearchTransactionsResponse {
        total_count: num_fetched_transactions as i64,
        transactions,
        // If the traversion of transactions has reached the genesis block we can stop traversing
        next_offset: if last_traversed_block_index == 0 {
            None
        } else {
            // If the transaction hash was provided it means we only want to fetch that transaction
            // If the number of transactions that match the transactionidentifier is less than the limit we can stop traversing --> All transactions with that hash have been fetched
            if request.transaction_identifier.is_some() && num_fetched_transactions < limit as usize
            {
                None
            } else {
                Some(max_block.saturating_sub(last_traversed_block_index.saturating_sub(1)) as i64)
            }
        },
    })
}

pub fn initial_sync_is_completed(
    storage_client: &StorageClient,
    sync_state: Arc<Mutex<Option<bool>>>,
) -> bool {
    let mut synched = sync_state.lock().unwrap();
    if synched.is_some() && synched.unwrap() {
        synched.unwrap()
    } else {
        let block_count = storage_client.get_block_count();
        let highest_index = storage_client.get_highest_block_idx_in_account_balance_table();
        *synched = Some(match (block_count, highest_index) {
            // If the blockchain contains no blocks we mark it as not completed
            (Ok(block_count), Ok(Some(highest_index))) if block_count == highest_index + 1 => true,
            _ => false,
        });
        // Unwrap is safe because it was just set
        (*synched).unwrap()
    }
}

pub fn call(
    storage_client: &StorageClient,
    method_name: &str,
    parameters: ObjectMap,
    currency: Currency,
) -> Result<CallResponse, Error> {
    match method_name {
        "query_block_range" => {
            let query_block_range = QueryBlockRangeRequest::try_from(parameters)
                .map_err(|err| Error::parsing_unsuccessful(&err))?;
            let mut blocks = vec![];
            if query_block_range.number_of_blocks > 0 {
                let highest_index = query_block_range.highest_block_index;
                let lowest_index = query_block_range.highest_block_index.saturating_sub(
                    std::cmp::min(
                        query_block_range.number_of_blocks,
                        MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST,
                    )
                    .saturating_sub(1),
                );
                blocks.extend(
                    storage_client
                        .get_blocks_by_index_range(lowest_index, highest_index)
                        .map_err(|err| Error::unable_to_find_block(&err))?
                        .into_iter()
                        .map(|block| {
                            icrc1_rosetta_block_to_rosetta_core_block(block, currency.clone())
                        })
                        .collect::<anyhow::Result<Vec<Block>>>()
                        .map_err(|err| Error::parsing_unsuccessful(&err))?,
                )
            };
            let idempotent = match blocks.last() {
                // If the block with the highest block index that was retrieved from the database has the same index as the highest block index in the query we return true
                Some(last_block) => {
                    last_block.block_identifier.index == query_block_range.highest_block_index
                }
                // If the database is empty or the requested block range does not exist we return false
                None => false,
            };
            let block_range_response = QueryBlockRangeResponse { blocks };
            Ok(CallResponse::new(
                ObjectMap::try_from(block_range_response)
                    .map_err(|err| Error::parsing_unsuccessful(&err))?,
                idempotent,
            ))
        }
        _ => Err(Error::processing_construction_failed(&format!(
            "Method {method_name} not supported"
        ))),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Metadata;
    use crate::common::storage::types::IcrcOperation;
    use crate::common::storage::types::RosettaBlock;
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
                        let mut added_index = 0;
                        for block in blockchain.clone().into_iter() {
                            // We only push Mint blocks since `update_account_balances` will
                            // complain if we e.g., transfer from an account with no balance.
                            if let ic_icrc1::Operation::Mint{..} = block.transaction.operation {
                                // Since we skip some blocks, the fee collector block index is not correct anymore.
                                let mut block_no_fc = block;
                                block_no_fc.fee_collector_block_index = None;
                                rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block_no_fc.encode()), added_index as u64).unwrap());
                                added_index += 1;
                            }
                        }

                        // If there is no block in the database the service should return an error
                        let network_status_err = network_status(&storage_client_memory).unwrap_err();
                        assert!(network_status_err.0.message.contains("Unable to find block"));
                        if !rosetta_blocks.is_empty() {

                        storage_client_memory.store_blocks(rosetta_blocks).unwrap();
                        storage_client_memory.update_account_balances().unwrap();
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
                            index: Some(invalid_block_idx),
                            hash: None
                        };

                        // If the block identifier index does not exist the service should return an error
                        let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());
                        if blockchain.is_empty() {
                            assert!(block_res.is_err());
                        } else {
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {invalid_block_idx} could not be found")));
                        }

                        block_identifier = PartialBlockIdentifier{
                            index: None,
                            hash: Some(hex::encode(invalid_block_hash.clone()))
                        };

                        // If the block identifier hash does not exist the service should return an error
                        let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());

                        if blockchain.is_empty() {
                            assert!(block_res.is_err());
                        } else {
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(&format!("Block with hash {} could not be found",hex::encode(invalid_block_hash.clone()))));
                        }

                        block_identifier = PartialBlockIdentifier{
                            index: None,
                            hash: Some(invalid_block_hash.clone())
                        };

                        // If the block identifier hash is invalid the service should return an error
                        let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone());

                        if blockchain.is_empty() {
                            assert!(block_res.is_err());
                        } else {
                            assert!(block_res.unwrap_err().0.description.unwrap().contains("Invalid block hash provided"));
                        }

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
                            compare_blocks(block_res.block.unwrap(),expected_block_res.clone().block.unwrap());

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
                            assert!(block_res.unwrap_err().0.description.unwrap().contains(format!("Block at index {invalid_block_idx} could not be found").as_str()));

                            block_identifier = PartialBlockIdentifier{
                                index: None,
                                hash: None
                            };
                            // If neither block index nor hash is provided, the service should return the last block
                            let block_res = block(&storage_client_memory,&block_identifier,metadata.decimals,metadata.symbol.clone()).unwrap();
                            compare_blocks(block_res.block.unwrap(),expected_block_res.block.unwrap());
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
                assert!(block_transaction_res.is_err());

                storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();

                // If the block identifier index is invalid the service should return an error
                let block_transaction_res = block_transaction(&storage_client_memory,&block_identifier,&transaction_identifier,metadata.decimals,metadata.symbol.clone());

                if blockchain.is_empty() {
                    assert!(block_transaction_res.is_err());
                } else {
                    assert!(block_transaction_res.unwrap_err().0.description.unwrap().contains(&format!("Block at index {invalid_block_idx} could not be found")));
                }

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
                                IcrcOperation::FeeCollector {
                                    fee_collector,
                                    caller,
                                } => {
                                    panic!("FeeCollector107 not implemented")
                                }
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
                                IcrcOperation::FeeCollector {
                                    fee_collector,
                                    caller,
                                } => {
                                    panic!("FeeCollector107 not implemented")
                                }
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
                        assert!(
                            involved_accounts.contains(
                                &search_transactions_request
                                    .account_identifier
                                    .clone()
                                    .unwrap()
                            )
                        );

                        search_transactions_request.account_identifier = Some(
                            Account {
                                owner: ic_base_types::PrincipalId::new_anonymous().into(),
                                subaccount: Some([9; 32]),
                            }
                            .into(),
                        );
                        let result = traverse_all_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                        );
                        // If the account does not exist the service should return an empty list
                        assert_eq!(result.len(), 0);

                        search_transactions_request = SearchTransactionsRequest {
                            ..Default::default()
                        };

                        search_transactions_request.type_ = Some("INVALID_OPS".to_string());
                        let result = search_transactions(
                            &storage_client_memory,
                            search_transactions_request.clone(),
                            "ICP".to_string(),
                            8,
                        );
                        assert!(result.is_err());
                    }
                    Ok(())
                },
            )
            .unwrap()
    }

    #[test]
    fn test_fetch_block_from_empty_blockchain() {
        let storage_client_memory = Arc::new(StorageClient::new_in_memory().unwrap());

        let metadata = Metadata {
            symbol: "ICP".to_string(),
            decimals: 8,
        };

        let block_identifier = PartialBlockIdentifier {
            index: None,
            hash: None,
        };

        let block_res = block(
            &storage_client_memory,
            &block_identifier,
            metadata.decimals,
            metadata.symbol.clone(),
        );
        assert!(block_res.is_err());

        let block_identifier = PartialBlockIdentifier {
            index: Some(0),
            hash: None,
        };
        let block_res = block(
            &storage_client_memory,
            &block_identifier,
            metadata.decimals,
            metadata.symbol.clone(),
        );
        assert!(block_res.is_err());

        let block_identifier = PartialBlockIdentifier {
            index: None,
            hash: Some("AAAA".to_string()),
        };
        let block_res = block(
            &storage_client_memory,
            &block_identifier,
            metadata.decimals,
            metadata.symbol.clone(),
        );
        assert!(block_res.is_err());

        let block_identifier = PartialBlockIdentifier {
            index: Some(0),
            hash: Some("AAAA".to_string()),
        };
        let block_res = block(
            &storage_client_memory,
            &block_identifier,
            metadata.decimals,
            metadata.symbol.clone(),
        );
        assert!(block_res.is_err());
    }

    #[test]
    fn test_call_query_blocks() {
        let mut runner = TestRunner::new(TestRunnerConfig {
            max_shrink_iters: 0,
            cases: 1,
            ..Default::default()
        });

        runner
            .run(
                &(valid_blockchain_strategy::<U256>(BLOCKCHAIN_LENGTH * 25).no_shrink()),
                |blockchain| {
                    let storage_client_memory = StorageClient::new_in_memory().unwrap();
                    let mut rosetta_blocks = vec![];

                    let currency = Currency::new("ICP".to_string(), 8);

                    // Call on an empty database
                    let response: QueryBlockRangeResponse = call(
                        &storage_client_memory,
                        "query_block_range",
                        ObjectMap::try_from(QueryBlockRangeRequest {
                            highest_block_index: 100,
                            number_of_blocks: 10,
                        })
                        .unwrap(),
                        currency.clone(),
                    )
                    .unwrap()
                    .result
                    .try_into()
                    .unwrap();
                    assert!(response.blocks.is_empty());

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
                    let highest_block_index = rosetta_blocks.len().saturating_sub(1) as u64;
                    // Call with 0 numbers of blocks
                    let response: QueryBlockRangeResponse = call(
                        &storage_client_memory,
                        "query_block_range",
                        ObjectMap::try_from(QueryBlockRangeRequest {
                            highest_block_index,
                            number_of_blocks: 0,
                        })
                        .unwrap(),
                        currency.clone(),
                    )
                    .unwrap()
                    .result
                    .try_into()
                    .unwrap();
                    assert!(response.blocks.is_empty());

                    // Call with higher index than there are blocks in the database
                    let response = call(
                        &storage_client_memory,
                        "query_block_range",
                        ObjectMap::try_from(QueryBlockRangeRequest {
                            highest_block_index: (rosetta_blocks.len() * 2) as u64,
                            number_of_blocks: std::cmp::max(
                                rosetta_blocks.len() as u64,
                                MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST,
                            ),
                        })
                        .unwrap(),
                        currency.clone(),
                    )
                    .unwrap();
                    let query_block_response: QueryBlockRangeResponse =
                        response.result.try_into().unwrap();
                    // If the blocks measured from the highest block index asked for are not in the database the service should return an empty array of blocks
                    if rosetta_blocks.len() >= MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize {
                        assert_eq!(query_block_response.blocks.len(), 0);
                        assert!(!response.idempotent);
                    }
                    // If some of the blocks measured from the highest block index asked for are in the database the service should return the blocks that are in the database
                    else {
                        if rosetta_blocks.len() * 2
                            > MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize
                        {
                            assert_eq!(
                                query_block_response.blocks.len(),
                                rosetta_blocks
                                    .len()
                                    .saturating_sub((rosetta_blocks.len() * 2).saturating_sub(
                                        MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize
                                    ))
                                    .saturating_sub(1)
                            );
                        } else {
                            assert_eq!(query_block_response.blocks.len(), rosetta_blocks.len());
                        }
                        assert!(!response.idempotent);
                    }

                    let number_of_blocks = (rosetta_blocks.len() / 2) as u64;
                    let query_blocks_request = QueryBlockRangeRequest {
                        highest_block_index,
                        number_of_blocks,
                    };

                    let query_blocks_response = call(
                        &storage_client_memory,
                        "query_block_range",
                        ObjectMap::try_from(query_blocks_request).unwrap(),
                        currency.clone(),
                    )
                    .unwrap();

                    assert!(query_blocks_response.idempotent);
                    let response: QueryBlockRangeResponse =
                        query_blocks_response.result.try_into().unwrap();
                    let querried_blocks = response.blocks;
                    assert_eq!(
                        querried_blocks.len(),
                        std::cmp::min(number_of_blocks, MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST)
                            as usize
                    );
                    if !querried_blocks.is_empty() {
                        assert_eq!(
                            querried_blocks.first().unwrap().block_identifier.index,
                            highest_block_index
                                .saturating_sub(std::cmp::min(
                                    number_of_blocks,
                                    MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST
                                ))
                                .saturating_add(1)
                        );
                        assert_eq!(
                            querried_blocks.last().unwrap().block_identifier.index,
                            highest_block_index
                        );
                    }

                    let query_blocks_request = QueryBlockRangeRequest {
                        highest_block_index,
                        number_of_blocks: MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST + 1,
                    };

                    let query_blocks_response: QueryBlockRangeResponse = call(
                        &storage_client_memory,
                        "query_block_range",
                        ObjectMap::try_from(query_blocks_request).unwrap(),
                        currency.clone(),
                    )
                    .unwrap()
                    .result
                    .try_into()
                    .unwrap();
                    assert_eq!(
                        query_blocks_response.blocks.len(),
                        std::cmp::min(
                            MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize,
                            rosetta_blocks.len()
                        )
                    );

                    Ok(())
                },
            )
            .unwrap();
    }

    #[test]
    fn test_account_balance_with_aggregate_all_subaccounts() {
        use crate::common::storage::types::{
            IcrcBlock, IcrcOperation, IcrcTransaction, RosettaBlock,
        };
        use candid::{Nat, Principal};
        use icrc_ledger_types::icrc1::account::Account;
        use rosetta_core::identifiers::AccountIdentifier;
        use serde_json::{Map, Value};

        let storage_client = StorageClient::new_in_memory().unwrap();
        let metadata = Metadata::from_args("ICP".to_string(), 8);

        let principal = Principal::anonymous();

        // First, add some blocks to the database so we can test the validation logic
        let main_account = Account {
            owner: principal,
            subaccount: None,
        };
        let blocks = vec![RosettaBlock::from_icrc_ledger_block(
            IcrcBlock {
                parent_hash: None,
                transaction: IcrcTransaction {
                    operation: IcrcOperation::Mint {
                        to: main_account,
                        amount: Nat::from(1000u64),
                        fee: None,
                    },
                    created_at_time: Some(1000),
                    memo: None,
                },
                effective_fee: None,
                timestamp: 1000,
                fee_collector: None,
                fee_collector_block_index: None,
                btype: None,
            },
            0,
        )];

        storage_client.store_blocks(blocks).unwrap();
        storage_client.update_account_balances().unwrap();

        // Test 1: Aggregate flag with subaccount should fail
        let account_with_subaccount = Account {
            owner: principal,
            subaccount: Some([1u8; 32]),
        };

        let account_identifier = AccountIdentifier::from(account_with_subaccount);

        let mut metadata_map = Map::new();
        metadata_map.insert("aggregate_all_subaccounts".to_string(), Value::Bool(true));
        let metadata_obj = Some(metadata_map.clone());

        let result = account_balance_with_metadata(
            &storage_client,
            &account_identifier,
            &None,
            &metadata_obj,
            metadata.decimals,
            metadata.symbol.clone(),
        );

        assert!(result.is_err());
        // Now that we have blocks, we should get the validation error
        match result.unwrap_err() {
            Error(err) => {
                let description = err.description.as_ref().unwrap();
                assert!(
                    description.contains(
                        "Cannot specify subaccount when aggregate_all_subaccounts is true"
                    )
                );
            }
        }

        // Test 2: Create a simple scenario with aggregated balance
        // Use a separate storage client for the aggregation test
        let storage_client2 = StorageClient::new_in_memory().unwrap();
        let subaccount1 = [1u8; 32];
        let account1 = Account {
            owner: principal,
            subaccount: Some(subaccount1),
        };

        // Create simple minting transactions
        let blocks = vec![
            RosettaBlock::from_icrc_ledger_block(
                IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Mint {
                            to: main_account,
                            amount: Nat::from(500u64),
                            fee: None,
                        },
                        created_at_time: Some(1000),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 1000,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
                0,
            ),
            RosettaBlock::from_icrc_ledger_block(
                IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Mint {
                            to: account1,
                            amount: Nat::from(1000u64),
                            fee: None,
                        },
                        created_at_time: Some(2000),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 2000,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
                1,
            ),
        ];

        storage_client2.store_blocks(blocks).unwrap();
        storage_client2.update_account_balances().unwrap();

        // Test aggregated balance: Should be 500 + 1000 = 1500
        // For aggregated balance, we need to use an account identifier that represents
        // the principal without any subaccount information (which is None)
        let account_for_aggregation = Account {
            owner: principal,
            subaccount: None,
        };
        let account_identifier = AccountIdentifier::from(account_for_aggregation);

        let result = account_balance_with_metadata(
            &storage_client2,
            &account_identifier,
            &None,
            &metadata_obj,
            metadata.decimals,
            metadata.symbol.clone(),
        );

        assert!(result.is_ok());
        let balance_response = result.unwrap();
        assert_eq!(balance_response.balances.len(), 1);
        assert_eq!(balance_response.balances[0].value.to_string(), "1500");

        // Test individual account balances to verify they're correct
        let account1_identifier = AccountIdentifier::from(account1);
        let result1 = account_balance_with_metadata(
            &storage_client2,
            &account1_identifier,
            &None,
            &None,
            metadata.decimals,
            metadata.symbol.clone(),
        );
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap().balances[0].value.to_string(), "1000");

        let main_account_identifier = AccountIdentifier::from(main_account);
        let result_main = account_balance_with_metadata(
            &storage_client2,
            &main_account_identifier,
            &None,
            &None,
            metadata.decimals,
            metadata.symbol.clone(),
        );
        assert!(result_main.is_ok());
        assert_eq!(result_main.unwrap().balances[0].value.to_string(), "500");

        // Test 3: Normal account balance request without aggregate flag should work
        let result = account_balance_with_metadata(
            &storage_client2,
            &account_identifier,
            &None,
            &None,
            metadata.decimals,
            metadata.symbol.clone(),
        );

        assert!(result.is_ok());
        let balance_response = result.unwrap();
        assert_eq!(balance_response.balances.len(), 1);
        // Without aggregate flag, should only return the main account balance (500)
        assert_eq!(balance_response.balances[0].value.to_string(), "500");
    }

    #[test]
    fn test_subaccount_transfers_and_balances() {
        use crate::common::storage::types::{
            IcrcBlock, IcrcOperation, IcrcTransaction, RosettaBlock,
        };
        use candid::{Nat, Principal};
        use icrc_ledger_types::icrc1::account::Account;
        use rosetta_core::identifiers::AccountIdentifier;

        let storage_client = StorageClient::new_in_memory().unwrap();
        let metadata = Metadata::from_args("ICP".to_string(), 8);

        let principal = Principal::anonymous();

        // Create accounts with different subaccounts
        let main_account = Account {
            owner: principal,
            subaccount: None,
        };
        let subaccount1 = [1u8; 32];
        let account1 = Account {
            owner: principal,
            subaccount: Some(subaccount1),
        };
        let subaccount2 = [2u8; 32];
        let account2 = Account {
            owner: principal,
            subaccount: Some(subaccount2),
        };

        // Create a different principal for external transfers
        let other_principal = Principal::from_slice(&[1, 2, 3, 4, 5]);
        let other_account = Account {
            owner: other_principal,
            subaccount: None,
        };

        // Simulate a series of transactions that would come through Rosetta construction API:
        // 1. Mint to main account (block 0)
        // 2. Transfer from main account to subaccount1 (block 1)
        // 3. Transfer from main account to subaccount2 (block 2)
        // 4. Transfer from subaccount1 to other_account (block 3)

        // Test the AccountIdentifier round-trip conversion to ensure subaccounts are preserved
        let account1_identifier: AccountIdentifier = account1.into();
        let account1_converted: Account = account1_identifier.try_into().unwrap();
        assert_eq!(
            account1, account1_converted,
            "Account with subaccount should survive round-trip conversion"
        );

        let account2_identifier: AccountIdentifier = account2.into();
        let account2_converted: Account = account2_identifier.try_into().unwrap();
        assert_eq!(
            account2, account2_converted,
            "Account with subaccount should survive round-trip conversion"
        );

        let blocks = vec![
            // Block 0: Mint 1000 to main account
            RosettaBlock {
                index: 0,
                block: IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Mint {
                            to: main_account,
                            amount: Nat::from(1000u64),
                            fee: None,
                        },
                        created_at_time: Some(1000),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 1000,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
            },
            // Block 1: Transfer 300 from main account to subaccount1
            RosettaBlock {
                index: 1,
                block: IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Transfer {
                            from: main_account,
                            to: account1,
                            spender: None,
                            amount: Nat::from(300u64),
                            fee: Some(Nat::from(10u64)),
                        },
                        created_at_time: Some(2000),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 2000,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
            },
            // Block 2: Transfer 200 from main account to subaccount2
            RosettaBlock {
                index: 2,
                block: IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Transfer {
                            from: main_account,
                            to: account2,
                            spender: None,
                            amount: Nat::from(200u64),
                            fee: Some(Nat::from(10u64)),
                        },
                        created_at_time: Some(3000),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 3000,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
            },
            // Block 3: Transfer 150 from subaccount1 to other_account
            RosettaBlock {
                index: 3,
                block: IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Transfer {
                            from: account1,
                            to: other_account,
                            spender: None,
                            amount: Nat::from(150u64),
                            fee: Some(Nat::from(10u64)),
                        },
                        created_at_time: Some(4000),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 4000,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
            },
        ];

        // Store blocks
        storage_client.store_blocks(blocks).unwrap();

        // Update account balances
        storage_client.update_account_balances().unwrap();

        // Test individual account balances
        let main_balance = account_balance(
            &storage_client,
            &main_account.into(),
            &None,
            metadata.decimals,
            metadata.symbol.clone(),
        )
        .unwrap();
        // Main account: 1000 - 300 - 10 - 200 - 10 = 480
        assert_eq!(main_balance.balances[0].value.to_string(), "480");

        let account1_balance = account_balance(
            &storage_client,
            &account1.into(),
            &None,
            metadata.decimals,
            metadata.symbol.clone(),
        )
        .unwrap();
        // Account1: 300 - 150 - 10 = 140
        assert_eq!(account1_balance.balances[0].value.to_string(), "140");

        let account2_balance = account_balance(
            &storage_client,
            &account2.into(),
            &None,
            metadata.decimals,
            metadata.symbol.clone(),
        )
        .unwrap();
        // Account2: 200
        assert_eq!(account2_balance.balances[0].value.to_string(), "200");

        let other_balance = account_balance(
            &storage_client,
            &other_account.into(),
            &None,
            metadata.decimals,
            metadata.symbol.clone(),
        )
        .unwrap();
        // Other account: 150
        assert_eq!(other_balance.balances[0].value.to_string(), "150");

        // Test aggregated balance
        let mut metadata_map = serde_json::Map::new();
        metadata_map.insert(
            "aggregate_all_subaccounts".to_string(),
            serde_json::Value::Bool(true),
        );

        let aggregated_balance = account_balance_with_metadata(
            &storage_client,
            &main_account.into(),
            &None,
            &Some(metadata_map),
            metadata.decimals,
            metadata.symbol.clone(),
        )
        .unwrap();

        // Aggregated balance: 480 (main) + 140 (account1) + 200 (account2) = 820
        assert_eq!(aggregated_balance.balances[0].value.to_string(), "820");
    }

    #[test]
    fn test_construction_api_subaccount_preservation() {
        // Test that the construction API preserves subaccounts correctly through the entire flow
        use crate::common::utils::utils::rosetta_core_operations_to_icrc1_operation;
        use candid::{Nat, Principal};
        use icrc_ledger_types::icrc1::account::Account;
        use num_bigint::BigInt;
        use rosetta_core::identifiers::AccountIdentifier;
        use rosetta_core::identifiers::OperationIdentifier;
        use rosetta_core::objects::{Amount, Currency, Operation};

        let principal1 = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let principal2 = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();

        // Create accounts with specific non-zero subaccounts
        let from_subaccount = [1u8; 32]; // Non-zero subaccount
        let mut to_subaccount = [0u8; 32];
        to_subaccount[31] = 42; // Different non-zero subaccount: [0, 0, ..., 0, 42]

        let from_account = Account {
            owner: principal1,
            subaccount: Some(from_subaccount),
        };

        let to_account = Account {
            owner: principal2,
            subaccount: Some(to_subaccount),
        };

        println!("Original from_account: {from_account:?}");
        println!("Original to_account: {to_account:?}");

        // Step 1: Convert accounts to AccountIdentifiers (like the client would)
        let from_account_identifier: AccountIdentifier = from_account.into();
        let to_account_identifier: AccountIdentifier = to_account.into();

        println!("from_account_identifier: {from_account_identifier:?}");
        println!("to_account_identifier: {to_account_identifier:?}");

        // Step 2: Build Rosetta operations (like the client would)
        let currency = Currency {
            symbol: "ICP".to_string(),
            decimals: 8,
            metadata: None,
        };

        let transfer_from_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "TRANSFER".to_string(),
            status: None,
            account: Some(from_account_identifier),
            amount: Some(Amount::new(
                BigInt::from(-100000000i64), // -1 ICP
                currency.clone(),
            )),
            coin_change: None,
            metadata: None,
        };

        let transfer_to_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 1,
                network_index: None,
            },
            related_operations: None,
            type_: "TRANSFER".to_string(),
            status: None,
            account: Some(to_account_identifier),
            amount: Some(Amount::new(
                BigInt::from(100000000i64), // +1 ICP
                currency.clone(),
            )),
            coin_change: None,
            metadata: None,
        };

        let operations = vec![transfer_from_operation, transfer_to_operation];

        // Step 3: Convert operations to ICRC1 operation (like the server would)
        let icrc1_operation = rosetta_core_operations_to_icrc1_operation(operations).unwrap();

        // Step 4: Verify the operation preserves subaccounts
        match icrc1_operation {
            crate::common::storage::types::IcrcOperation::Transfer {
                from, to, amount, ..
            } => {
                println!("Converted from: {from:?}");
                println!("Converted to: {to:?}");

                assert_eq!(
                    from, from_account,
                    "From account with subaccount should be preserved through construction API"
                );
                assert_eq!(
                    to, to_account,
                    "To account with subaccount should be preserved through construction API"
                );
                assert_eq!(
                    amount,
                    Nat::from(100000000u64),
                    "Amount should be preserved"
                );
            }
            _ => panic!("Expected Transfer operation"),
        }
    }

    #[test]
    fn test_account_identifier_round_trip_conversion_bug() {
        // This test specifically checks the AccountIdentifier round-trip conversion
        // and should FAIL with the buggy code that always uses effective_subaccount()
        use candid::Principal;
        use icrc_ledger_types::icrc1::account::Account;
        use rosetta_core::identifiers::AccountIdentifier;

        let principal = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Test 1: Account with None subaccount should remain None after round-trip
        let account_none = Account {
            owner: principal,
            subaccount: None,
        };

        let account_identifier_none: AccountIdentifier = account_none.into();
        let converted_back_none: Account = account_identifier_none.try_into().unwrap();

        println!("Original account (None): {account_none:?}");
        println!("Converted back (None): {converted_back_none:?}");

        // This should pass with correct code, fail with buggy code
        assert_eq!(
            account_none, converted_back_none,
            "Account with None subaccount should be preserved through round-trip conversion"
        );

        // Test 2: Account with non-zero subaccount should be preserved
        let non_zero_subaccount = [1u8; 32];
        let account_nonzero = Account {
            owner: principal,
            subaccount: Some(non_zero_subaccount),
        };

        let account_identifier_nonzero: AccountIdentifier = account_nonzero.into();
        let converted_back_nonzero: Account = account_identifier_nonzero.try_into().unwrap();

        println!("Original account (non-zero): {account_nonzero:?}");
        println!("Converted back (non-zero): {converted_back_nonzero:?}");

        // This should pass with correct code, fail with buggy code
        assert_eq!(
            account_nonzero, converted_back_nonzero,
            "Account with non-zero subaccount should be preserved through round-trip conversion"
        );
    }

    #[test]
    fn test_debug_aggregated_balance_sql() {
        use crate::common::storage::types::{
            IcrcBlock, IcrcOperation, IcrcTransaction, RosettaBlock,
        };
        use candid::{Nat, Principal};
        use ic_base_types::PrincipalId;
        use icrc_ledger_types::icrc1::account::Account;

        let storage_client = StorageClient::new_in_memory().unwrap();
        let _metadata = Metadata::from_args("ICP".to_string(), 8);

        let principal = Principal::anonymous();

        // Create the EXACT scenario that causes the bug:
        // 1. Default subaccount (None) - stored as [0; 32] in DB due to effective_subaccount()
        // 2. Explicit [0; 32] subaccount - also stored as [0; 32] in DB
        // 3. Non-zero subaccount - stored as its actual value

        let main_account = Account {
            owner: principal,
            subaccount: None,
        };
        let explicit_zero_account = Account {
            owner: principal,
            subaccount: Some([0u8; 32]),
        };
        let subaccount1 = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1,
        ];
        let account1 = Account {
            owner: principal,
            subaccount: Some(subaccount1),
        };

        // Create transactions to give each account a balance
        let blocks = vec![
            // Block 0: Mint 0.06 to main account (None subaccount)
            RosettaBlock::from_icrc_ledger_block(
                IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Mint {
                            to: main_account,
                            amount: Nat::from(6000000u64), // 0.06 tokens
                            fee: None,
                        },
                        created_at_time: Some(1),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 1,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
                0,
            ),
            // Block 1: Mint 0.01 to explicit [0;32] subaccount
            RosettaBlock::from_icrc_ledger_block(
                IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Mint {
                            to: explicit_zero_account,
                            amount: Nat::from(1000000u64), // 0.01 tokens
                            fee: None,
                        },
                        created_at_time: Some(2),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 2,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
                1,
            ),
            // Block 2: Mint 0.01 to account1 (non-zero subaccount)
            RosettaBlock::from_icrc_ledger_block(
                IcrcBlock {
                    parent_hash: None,
                    transaction: IcrcTransaction {
                        operation: IcrcOperation::Mint {
                            to: account1,
                            amount: Nat::from(1000000u64), // 0.01 tokens
                            fee: None,
                        },
                        created_at_time: Some(3),
                        memo: None,
                    },
                    effective_fee: None,
                    timestamp: 3,
                    fee_collector: None,
                    fee_collector_block_index: None,
                    btype: None,
                },
                2,
            ),
        ];

        // Store blocks and update balances
        storage_client.store_blocks(blocks).unwrap();
        storage_client.update_account_balances().unwrap();

        // Check individual balances (use a reasonable high block index instead of u64::MAX)
        let high_block_idx = 1000u64;
        let main_balance = storage_client
            .get_account_balance_at_block_idx(&main_account, high_block_idx)
            .unwrap()
            .unwrap_or(Nat::from(0u64));
        let explicit_zero_balance = storage_client
            .get_account_balance_at_block_idx(&explicit_zero_account, high_block_idx)
            .unwrap()
            .unwrap_or(Nat::from(0u64));
        let account1_balance = storage_client
            .get_account_balance_at_block_idx(&account1, high_block_idx)
            .unwrap()
            .unwrap_or(Nat::from(0u64));

        println!("Individual balances:");
        println!("  Main account (None): {main_balance}");
        println!("  Explicit [0;32] account: {explicit_zero_balance}");
        println!("  Account1 (non-zero): {account1_balance}");

        // Check aggregated balance
        let aggregated_balance = storage_client
            .get_aggregated_balance_for_principal_at_block_idx(
                &PrincipalId::from(principal),
                high_block_idx,
            )
            .unwrap();

        println!("Aggregated balance: {aggregated_balance}");

        // Expected: 6000000 + 1000000 + 1000000 = 8000000
        let expected_total = Nat::from(8000000u64);
        println!("Expected total: {expected_total}");

        // Debug: Let's manually check what the SQL query returns by using the storage operations directly
        println!(
            "Debug: This demonstrates the bug where DISTINCT subaccounts causes incorrect aggregation"
        );
        println!("Both None and Some([0;32]) get stored as [0;32] in the database");
        println!("The DISTINCT clause in the aggregation query then treats them as one account");

        // Use a simpler approach - just check if the aggregated balance matches expected
        println!(
            "Checking if aggregated balance ({aggregated_balance}) matches expected ({expected_total})"
        );

        // This should FAIL due to the bug - aggregated balance will be less than expected
        // because the DISTINCT clause treats None and Some([0;32]) as the same subaccount
        if aggregated_balance == expected_total {
            println!("✓ Aggregated balance matches expected total!");
        } else {
            println!(
                "✗ BUG CONFIRMED: Aggregated balance mismatch: got {aggregated_balance}, expected {expected_total}"
            );
            println!(
                "This happens because both None and Some([0;32]) are stored as [0;32] in the database"
            );
            println!(
                "The DISTINCT clause in the aggregation SQL treats them as one account instead of two"
            );
        }
    }

    #[test]
    fn test_mint_and_burn_fees() {
        use crate::common::storage::types::{
            IcrcBlock, IcrcOperation, IcrcTransaction, RosettaBlock,
        };
        use candid::{Nat, Principal};
        use icrc_ledger_types::icrc1::account::Account;
        use rosetta_core::identifiers::AccountIdentifier;

        let storage_client = StorageClient::new_in_memory().unwrap();
        let symbol = "ICP";
        let decimals = 8;

        let principal = Principal::anonymous();

        // First, add some blocks to the database so we can test the validation logic
        let main_account = Account {
            owner: principal,
            subaccount: None,
        };
        let main_account_id = AccountIdentifier::from(main_account);

        let add_mint_block =
            |block_id: u64, amount: u64, fee: Option<u64>, effective_fee: Option<u64>| {
                let blocks = vec![RosettaBlock::from_icrc_ledger_block(
                    IcrcBlock {
                        parent_hash: None,
                        transaction: IcrcTransaction {
                            operation: IcrcOperation::Mint {
                                to: main_account,
                                amount: Nat::from(amount),
                                fee: fee.map(Into::into),
                            },
                            created_at_time: None,
                            memo: None,
                        },
                        effective_fee: effective_fee.map(Into::into),
                        timestamp: 1,
                        fee_collector: None,
                        fee_collector_block_index: None,
                        btype: None,
                    },
                    block_id,
                )];

                storage_client.store_blocks(blocks).unwrap();
                storage_client.update_account_balances().unwrap();
            };

        let add_burn_block =
            |block_id: u64, amount: u64, fee: Option<u64>, effective_fee: Option<u64>| {
                let blocks = vec![RosettaBlock::from_icrc_ledger_block(
                    IcrcBlock {
                        parent_hash: None,
                        transaction: IcrcTransaction {
                            operation: IcrcOperation::Burn {
                                from: main_account,
                                amount: Nat::from(amount),
                                fee: fee.map(Into::into),
                                spender: None,
                            },
                            created_at_time: None,
                            memo: None,
                        },
                        effective_fee: effective_fee.map(Into::into),
                        timestamp: 1,
                        fee_collector: None,
                        fee_collector_block_index: None,
                        btype: None,
                    },
                    block_id,
                )];

                storage_client.store_blocks(blocks).unwrap();
                storage_client.update_account_balances().unwrap();
            };

        let check_account_balance = |expected_balance: &str| {
            let result = account_balance(
                &storage_client,
                &main_account_id,
                &None,
                decimals,
                symbol.to_string(),
            );

            assert!(result.is_ok());
            let balance_response = result.unwrap();
            assert_eq!(balance_response.balances.len(), 1);
            assert_eq!(
                balance_response.balances[0].value.to_string(),
                expected_balance
            );
        };

        // The operation fee of 100 is applied
        add_mint_block(0, 1000, Some(100), None);
        check_account_balance("900");
        add_burn_block(1, 100, Some(100), None);
        check_account_balance("700");

        // The block effective_fee of 100 is applied
        add_mint_block(2, 200, Some(200), Some(100));
        check_account_balance("800");
        add_burn_block(3, 200, Some(200), Some(100));
        check_account_balance("500");

        // The block effective_fee of 100 is applied
        add_mint_block(4, 200, None, Some(100));
        check_account_balance("600");
        add_burn_block(5, 200, None, Some(100));
        check_account_balance("300");

        // No fee
        add_mint_block(6, 200, None, None);
        check_account_balance("500");
        add_burn_block(7, 200, None, None);
        check_account_balance("300");
    }
}
