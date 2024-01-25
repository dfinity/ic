use super::services;
use crate::{
    common::{types::Error, utils::utils::verify_network_id},
    AppState,
};
use axum::{extract::State, response::Result, Json};
use rosetta_core::{request_types::*, response_types::*};
use std::sync::Arc;

pub async fn construction_derive(
    State(state): State<Arc<AppState>>,
    request: Json<ConstructionDeriveRequest>,
) -> Result<Json<ConstructionDeriveResponse>> {
    verify_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(services::construction_derive(
        request.public_key.clone(),
    )?))
}

pub async fn construction_preprocess(
    State(state): State<Arc<AppState>>,
    request: Json<ConstructionPreprocessRequest>,
) -> Result<Json<ConstructionPreprocessResponse>> {
    verify_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(services::construction_preprocess()))
}

pub async fn construction_metadata(
    State(state): State<Arc<AppState>>,
    request: Json<ConstructionMetadataRequest>,
) -> Result<Json<ConstructionMetadataResponse>> {
    verify_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(
        services::construction_metadata(
            request
                .options
                .clone()
                .try_into()
                .map_err(|err: String| Error::parsing_unsuccessful(&err))?,
            state.icrc1_agent.clone(),
            state.metadata.clone().into(),
        )
        .await?,
    ))
}
