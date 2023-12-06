use super::services;
use crate::{common::utils::utils::verify_network_id, AppState};
use axum::{extract::State, http::StatusCode, response::Result, Json};
use rosetta_core::{request_types::*, response_types::*};
use std::sync::Arc;

pub async fn health() -> (StatusCode, Json<()>) {
    (StatusCode::OK, Json(()))
}

pub async fn network_list(
    State(state): State<Arc<AppState>>,
    _request: Json<MetadataRequest>,
) -> Json<NetworkListResponse> {
    Json(services::network_list(&state.ledger_id))
}

pub async fn network_options(
    State(state): State<Arc<AppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<NetworkOptionsResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(services::network_options(&state.ledger_id)))
}

pub async fn network_status(
    State(state): State<Arc<AppState>>,
    request: Json<NetworkRequest>,
) -> Result<Json<NetworkStatusResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(services::network_status(state.storage.clone())?))
}
