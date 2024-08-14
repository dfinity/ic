//! Module that deals with requests to /api/v2/status
use crate::common::{self, Cbor};

use axum::{extract::State, Router};
use crossbeam::atomic::AtomicCell;
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    messages::{Blob, HttpStatusResponse, ReplicaHealthStatus},
    replica_version::REPLICA_BINARY_HASH,
    ReplicaVersion, SubnetId,
};
use std::sync::Arc;

// TODO(NET-776)
// The IC API version reported on status requests.
const IC_API_VERSION: &str = "0.18.0";

#[derive(Clone)]
pub(crate) struct StatusService {
    log: ReplicaLogger,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    replica_health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

impl StatusService {
    pub(crate) fn route() -> &'static str {
        "/api/v2/status"
    }
}

impl StatusService {
    pub fn build_router(
        log: ReplicaLogger,
        nns_subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        replica_health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Router {
        let state = Self {
            log,
            nns_subnet_id,
            registry_client,
            replica_health_status,
            state_reader,
        };
        Router::new().route_service(
            StatusService::route(),
            axum::routing::get(status).with_state(state),
        )
    }
}

pub(crate) async fn status(State(state): State<StatusService>) -> Cbor<HttpStatusResponse> {
    // The root key is the public key of this Internet Computer instance,
    // and is the public key of the root (i.e. NNS) subnet.
    let root_key = common::get_root_threshold_public_key(
        &state.log,
        state.registry_client.as_ref(),
        state.registry_client.get_latest_version(),
        &state.nns_subnet_id,
    )
    .and_then(|key| {
        public_key_to_der(&key.into_bytes())
            .map_err(|err| warn!(state.log, "Failed to parse threshold root key to DER {err}"))
            .ok()
    });

    let response = HttpStatusResponse {
        ic_api_version: IC_API_VERSION.to_string(),
        // For test networks, and networks that we still reset
        // rather often, let them indicate the root public key
        // in /api/v2/status, so that agents can fetch them.
        // This is convenient, but of course NOT SECURE.
        //
        // USE WITH EXTREME CAUTION.
        root_key: root_key.map(Blob),
        impl_version: Some(ReplicaVersion::default().to_string()),
        impl_hash: REPLICA_BINARY_HASH.get().map(|s| s.to_string()),
        replica_health_status: Some(state.replica_health_status.load()),
        certified_height: Some(state.state_reader.latest_certified_height()),
    };
    Cbor(response)
}
