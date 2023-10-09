use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, response::Result, Json};
use ic_icrc_rosetta::{
    common::types::{
        Allow, BlockIdentifier, Error, MetadataRequest, NetworkIdentifier, NetworkListResponse,
        NetworkOptionsResponse, NetworkRequest, NetworkStatusResponse, Version,
    },
    AppState,
};

const ROSETTA_VERSION: &str = "1.4.13";
const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

fn verify_network_id(network_identifier: &NetworkIdentifier, state: &AppState) -> Result<()> {
    let expected = &NetworkIdentifier::for_ledger_id(state.ledger_id);

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
        network_identifiers: vec![NetworkIdentifier::for_ledger_id(state.ledger_id)],
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
            errors: vec![Error::invalid_network_id(
                &NetworkIdentifier::for_ledger_id(state.ledger_id),
            )],
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
    }))
}
