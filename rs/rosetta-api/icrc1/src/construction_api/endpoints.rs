use super::{services, types::ConstructionPayloadsRequestMetadata};
use crate::{
    MultiTokenAppState,
    common::{types::Error, utils::utils::get_state_from_network_id},
};
use axum::{Json, extract::State, response::Result};
use rosetta_core::{request_types::*, response_types::*};
use std::sync::Arc;
use std::time::SystemTime;

pub async fn construction_derive(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<ConstructionDeriveRequest>,
) -> Result<Json<ConstructionDeriveResponse>> {
    get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(services::construction_derive(
        request.public_key.clone(),
    )?))
}

pub async fn construction_preprocess(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<ConstructionPreprocessRequest>,
) -> Result<Json<ConstructionPreprocessResponse>> {
    get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(services::construction_preprocess(request.operations)?))
}

pub async fn construction_metadata(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<ConstructionMetadataRequest>,
) -> Result<Json<ConstructionMetadataResponse>> {
    let state = get_state_from_network_id(&request.network_identifier, &state)
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

pub async fn construction_submit(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<ConstructionSubmitRequest>,
) -> Result<Json<ConstructionSubmitResponse>> {
    let state = get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(
        services::construction_submit(
            request.signed_transaction,
            state.ledger_id,
            state.icrc1_agent.clone(),
        )
        .await?,
    ))
}

pub async fn construction_hash(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<ConstructionHashRequest>,
) -> Result<Json<ConstructionHashResponse>> {
    get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(services::construction_hash(
        request.signed_transaction,
    )?))
}

pub async fn construction_combine(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<ConstructionCombineRequest>,
) -> Result<Json<ConstructionCombineResponse>> {
    get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(services::construction_combine(
        request.unsigned_transaction,
        request.signatures,
    )?))
}

pub async fn construction_payloads(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<ConstructionPayloadsRequest>,
) -> Result<Json<ConstructionPayloadsResponse>> {
    let state = get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(services::construction_payloads(
        request.operations,
        request
            .metadata
            .as_ref()
            .map(|m| ConstructionPayloadsRequestMetadata::try_from(m.clone()))
            .transpose()?,
        &state.icrc1_agent.ledger_canister_id,
        request.public_keys.unwrap_or_else(Vec::new),
        SystemTime::now(),
    )?))
}

pub async fn construction_parse(
    State(state): State<Arc<MultiTokenAppState>>,
    Json(request): Json<ConstructionParseRequest>,
) -> Result<Json<ConstructionParseResponse>> {
    let state = get_state_from_network_id(&request.network_identifier, &state)
        .map_err(|err| Error::invalid_network_id(&err))?;
    Ok(Json(services::construction_parse(
        request.transaction,
        request.signed,
        state.metadata.clone().into(),
    )?))
}
