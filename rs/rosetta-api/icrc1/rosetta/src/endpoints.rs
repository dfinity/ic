use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, response::Result, Json};
use ic_icrc_rosetta::{
    common::types::{
        BlockRequest, BlockResponse, BlockTransactionRequest, BlockTransactionResponse, Error,
    },
    AppState,
};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_rosetta_api::models::MempoolResponse;
use rosetta_core::identifiers::BlockIdentifier;
use rosetta_core::identifiers::NetworkIdentifier;
use rosetta_core::objects::Currency;
use rosetta_core::request_types::MetadataRequest;
use rosetta_core::request_types::NetworkRequest;
use rosetta_core::response_types::Allow;
use rosetta_core::response_types::NetworkListResponse;
use rosetta_core::response_types::NetworkOptionsResponse;
use rosetta_core::response_types::NetworkStatusResponse;
use rosetta_core::response_types::Version;
use serde_bytes::ByteBuf;

const ROSETTA_VERSION: &str = "1.4.13";
const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_BLOCKCHAIN: &str = "Internet Computer";

fn verify_network_id(network_identifier: &NetworkIdentifier, state: &AppState) -> Result<()> {
    let expected =
        &NetworkIdentifier::new(DEFAULT_BLOCKCHAIN.to_owned(), state.ledger_id.to_string());

    if network_identifier != expected {
        return Err(Error::invalid_network_id(expected).into());
    }
    Ok(())
}

pub async fn health() -> (StatusCode, Json<()>) {
    (StatusCode::OK, Json(()))
}

pub async fn network_list(
    State(state): State<Arc<AppState>>,
    _request: Json<MetadataRequest>,
) -> Json<NetworkListResponse> {
    Json(NetworkListResponse {
        network_identifiers: vec![NetworkIdentifier::new(
            DEFAULT_BLOCKCHAIN.to_owned(),
            state.ledger_id.to_string(),
        )],
    })
}

pub async fn network_options(
    State(state): State<Arc<AppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<NetworkOptionsResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(NetworkOptionsResponse {
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
                state.ledger_id.to_string(),
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
    }))
}

pub async fn network_status(
    State(state): State<Arc<AppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<NetworkStatusResponse>> {
    verify_network_id(&request.network_identifier, &state)?;

    let current_block = state
        .storage
        .get_block_with_highest_block_idx()
        .map_err(|e| Error::unable_to_find_block(format!("Error retrieving current block: {}", e)))?
        .ok_or_else(|| Error::unable_to_find_block("Current block not found".into()))?;

    let genesis_block = state
        .storage
        .get_block_at_idx(0)
        .map_err(|e| Error::unable_to_find_block(format!("Error retrieving genesis block: {}", e)))?
        .ok_or_else(|| Error::unable_to_find_block("Genesis block not found".into()))?;
    let genesis_block_identifier = BlockIdentifier::from(&genesis_block);

    Ok(Json(NetworkStatusResponse {
        current_block_identifier: BlockIdentifier::from(&current_block),
        current_block_timestamp: Duration::from_nanos(current_block.timestamp).as_millis() as u64,
        genesis_block_identifier: genesis_block_identifier.clone(),
        oldest_block_identifier: Some(genesis_block_identifier),
        sync_status: None,
        peers: vec![],
    }))
}

pub async fn block(
    State(state): State<Arc<AppState>>,
    request: Json<BlockRequest>,
) -> Result<Json<BlockResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    let rosetta_block = match (
        request.block_identifier.index,
        request.block_identifier.hash.as_ref(),
    ) {
        (None, Some(hash)) => {
            let hash_bytes = hex::decode(hash).map_err(|e| {
                Error::unable_to_find_block(format!("Invalid block hash provided: {}", e))
            })?;
            let hash_buf = ByteBuf::from(hash_bytes);
            state
                .storage
                .get_block_by_hash(hash_buf)
                .map_err(|e| {
                    Error::unable_to_find_block(format!("Unable to retrieve block: {}", e))
                })?
                .ok_or_else(|| {
                    Error::unable_to_find_block(format!(
                        "Block with hash {} could not be found",
                        hash
                    ))
                })?
        }
        (Some(block_idx), None) => state
            .storage
            .get_block_at_idx(block_idx)
            .map_err(|e| Error::unable_to_find_block(format!("Unable to retrieve block: {}", e)))?
            .ok_or_else(|| {
                Error::unable_to_find_block(format!(
                    "Block at index {} could not be found",
                    block_idx
                ))
            })?,
        (Some(block_idx), Some(hash)) => {
            let rosetta_block = state
                .storage
                .get_block_at_idx(block_idx)
                .map_err(|e| {
                    Error::unable_to_find_block(format!("Unable to retrieve block: {}", e))
                })?
                .ok_or_else(|| {
                    Error::unable_to_find_block(format!(
                        "Block at index {} could not be found",
                        block_idx
                    ))
                })?;
            if &hex::encode(&rosetta_block.block_hash) != hash {
                return Err(Error::invalid_block_identifier().into());
            }
            rosetta_block
        }
        (None, None) => return Err(Error::invalid_block_identifier().into()),
    };

    let currency = Currency {
        symbol: state.metadata.symbol.clone(),
        decimals: state.metadata.decimals.into(),
        ..Default::default()
    };

    let response = BlockResponse::builder()
        .with_rosetta_block(rosetta_block)
        .with_currency(currency)
        .build()
        .map_err(|e| Error::failed_to_build_block_response(e.to_string()))?;

    Ok(Json(response))
}

pub async fn block_transaction(
    State(state): State<Arc<AppState>>,
    request: Json<BlockTransactionRequest>,
) -> Result<Json<BlockTransactionResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    let rosetta_block = state
        .storage
        .get_block_at_idx(request.block_identifier.index)
        .map_err(|e| Error::unable_to_find_block(format!("Unable to retrieve block: {}", e)))?
        .ok_or_else(|| {
            Error::unable_to_find_block(format!(
                "Block at index {} could not be found",
                request.block_identifier.index
            ))
        })?;
    if hex::encode(&rosetta_block.block_hash) != request.block_identifier.hash {
        return Err(Error::invalid_block_identifier().into());
    }

    let transaction = rosetta_block
        .get_transaction()
        .map_err(|e| Error::failed_to_build_block_response(e.to_string()))?;

    if transaction.hash().to_string() != request.transaction_identifier.hash {
        return Err(Error::invalid_transaction_identifier().into());
    }

    let currency = Currency {
        symbol: state.metadata.symbol.clone(),
        decimals: state.metadata.decimals.into(),
        ..Default::default()
    };

    let effective_fee = rosetta_block
        .get_effective_fee()
        .map_err(|e| Error::failed_to_build_block_response(e.to_string()))?;

    let mut builder = BlockTransactionResponse::builder()
        .with_transaction(transaction)
        .with_currency(currency);

    if let Some(effective_fee) = effective_fee {
        builder = builder.with_effective_fee(effective_fee);
    }

    let response = builder
        .build()
        .map_err(|e| Error::failed_to_build_block_response(e.to_string()))?;

    Ok(Json(response))
}

pub async fn mempool(
    State(state): State<Arc<AppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<MempoolResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(MempoolResponse::new(vec![])))
}
