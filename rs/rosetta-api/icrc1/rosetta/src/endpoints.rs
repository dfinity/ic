use axum::{extract::State, response::Result, Json};
use ic_icrc_rosetta::common::types::{BlockResponseBuilder, BlockTransactionResponseBuilder};
use ic_icrc_rosetta::common::utils::utils::verify_network_id;
use ic_icrc_rosetta::{common::types::Error, AppState};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_rosetta_api::models::MempoolResponse;
use rosetta_core::objects::*;
use rosetta_core::request_types::*;
use rosetta_core::response_types::*;
use serde_bytes::ByteBuf;
use std::sync::Arc;

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

    let response = BlockResponseBuilder::default()
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

    let mut builder = BlockTransactionResponseBuilder::default()
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
