use super::services::{self, initial_sync_is_completed};
use crate::{
    MultiTokenAppState,
    common::{types::Error, utils::utils::get_state_from_network_id},
};
use axum::{Json, extract::State, http::StatusCode, response::Result};
use ic_rosetta_api::models::MempoolResponse;
use rosetta_core::{request_types::*, response_types::*};
use std::sync::Arc;

// This endpoint is used to determine whether ICRC Rosetta is ready to be querried for data.
// It returns Status Code 200 if an initial sync of the blockchain has been done
// This means that no gaps in the blockchain exist and the genesis block has already been fetched
pub async fn ready(State(state): State<Arc<MultiTokenAppState>>) -> (StatusCode, Json<()>) {
    if state
        .token_states
        .values()
        .all(|state| initial_sync_is_completed(&state.storage, state.synched.clone()))
    {
        (StatusCode::OK, Json(()))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(()))
    }
}

pub async fn health() -> (StatusCode, Json<()>) {
    (StatusCode::OK, Json(()))
}

pub async fn network_list(
    State(state): State<Arc<MultiTokenAppState>>,
    _request: Json<MetadataRequest>,
) -> Json<NetworkListResponse> {
    let response = services::network_list(
        &state
            .token_states
            .values()
            .map(|state| state.icrc1_agent.ledger_canister_id)
            .collect::<Vec<_>>(),
    );
    Json(response)
}
pub async fn network_options(
    State(state): State<Arc<MultiTokenAppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<NetworkOptionsResponse>> {
    let state = get_state_from_network_id(&request.0.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Ok(Json(services::network_options(
        &state.icrc1_agent.ledger_canister_id,
    )))
}

pub async fn network_status(
    State(state): State<Arc<MultiTokenAppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<NetworkStatusResponse>> {
    let state = get_state_from_network_id(&request.0.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Ok(Json(services::network_status(&state.storage)?))
}

pub async fn block(
    State(state): State<Arc<MultiTokenAppState>>,
    request: Json<BlockRequest>,
) -> Result<Json<BlockResponse>> {
    let state = get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Ok(Json(services::block(
        &state.storage,
        &request.0.block_identifier,
        state.metadata.decimals,
        state.metadata.symbol.clone(),
    )?))
}

pub async fn block_transaction(
    State(state): State<Arc<MultiTokenAppState>>,
    request: Json<BlockTransactionRequest>,
) -> Result<Json<BlockTransactionResponse>> {
    let state = get_state_from_network_id(&request.0.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Ok(Json(services::block_transaction(
        &state.storage,
        &request.0.block_identifier,
        &request.0.transaction_identifier,
        state.metadata.decimals,
        state.metadata.symbol.clone(),
    )?))
}

pub async fn mempool(
    State(state): State<Arc<MultiTokenAppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<MempoolResponse>> {
    get_state_from_network_id(&request.0.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Ok(Json(MempoolResponse::new(vec![])))
}

pub async fn mempool_transaction(
    State(state): State<Arc<MultiTokenAppState>>,
    request: Json<MempoolTransactionRequest>,
) -> Result<Json<MempoolTransactionResponse>> {
    get_state_from_network_id(&request.0.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Err(Error::mempool_transaction_missing().into())
}

pub async fn account_balance(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<AccountBalanceRequest>,
) -> Result<Json<AccountBalanceResponse>> {
    let state = get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Ok(Json(services::account_balance_with_metadata(
        &state.storage,
        &request.account_identifier,
        &request.block_identifier,
        &request.metadata,
        state.metadata.decimals,
        state.metadata.symbol.clone(),
    )?))
}

pub async fn search_transactions(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<SearchTransactionsRequest>,
) -> Result<Json<SearchTransactionsResponse>> {
    let state = get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Ok(Json(services::search_transactions(
        &state.storage,
        request,
        state.metadata.symbol.clone(),
        state.metadata.decimals,
    )?))
}

pub async fn call(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<CallRequest>,
) -> Result<Json<CallResponse>> {
    let state = get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&format!("{err:?}")))?;
    Ok(Json(services::call(
        &state.storage,
        &request.method_name,
        request.parameters,
        rosetta_core::objects::Currency::new(
            state.metadata.symbol.clone(),
            state.metadata.decimals.into(),
        ),
    )?))
}
