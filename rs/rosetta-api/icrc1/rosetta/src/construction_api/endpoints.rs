use super::services;
use crate::{common::utils::utils::verify_network_id, AppState};
use axum::{extract::State, response::Result, Json};
use rosetta_core::{request_types::*, response_types::*};
use std::sync::Arc;

pub async fn construction_preprocess(
    State(state): State<Arc<AppState>>,
    request: Json<ConstructionPreprocessRequest>,
) -> Result<Json<ConstructionPreprocessResponse>> {
    verify_network_id(&request.network_identifier, &state)?;
    Ok(Json(services::construction_preprocess()))
}
