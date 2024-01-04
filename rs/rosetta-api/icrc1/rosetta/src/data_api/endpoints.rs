use super::services;
use crate::{
    common::{types::Error, utils::utils::verify_network_id},
    AppState,
};
use axum::{extract::State, http::StatusCode, response::Result, Json};
use ic_rosetta_api::models::MempoolResponse;
use rosetta_core::{request_types::*, response_types::*};
use std::sync::Arc;

pub async fn health() -> (StatusCode, Json<()>) {
    (StatusCode::OK, Json(()))
}

pub async fn network_list(
    State(state): State<Arc<AppState>>,
    _request: Json<MetadataRequest>,
) -> Json<NetworkListResponse> {
    Json(services::network_list(
        &state.icrc1_agent.ledger_canister_id,
    ))
}

pub async fn network_options(
    State(state): State<Arc<AppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<NetworkOptionsResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(services::network_options(
        &state.icrc1_agent.ledger_canister_id,
    )))
}

pub async fn network_status(
    State(state): State<Arc<AppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<NetworkStatusResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(services::network_status(state.storage.clone())?))
}

pub async fn block(
    State(state): State<Arc<AppState>>,
    request: Json<BlockRequest>,
) -> Result<Json<BlockResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(services::block(
        state.storage.clone(),
        request.block_identifier.clone(),
        state.metadata.clone(),
    )?))
}

pub async fn block_transaction(
    State(state): State<Arc<AppState>>,
    request: Json<BlockTransactionRequest>,
) -> Result<Json<BlockTransactionResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(services::block_transaction(
        state.storage.clone(),
        request.block_identifier.clone(),
        request.transaction_identifier.clone(),
        state.metadata.clone(),
    )?))
}

pub async fn mempool(
    State(state): State<Arc<AppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<MempoolResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(MempoolResponse::new(vec![])))
}

pub async fn mempool_transaction(
    State(state): State<Arc<AppState>>,
    request: Json<MempoolTransactionRequest>,
) -> Result<Json<MempoolTransactionResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Err(Error::mempool_transaction_missing().into())
}
