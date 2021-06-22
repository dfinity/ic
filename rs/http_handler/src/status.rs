//! Module that deals with requests to /api/v1/status
use crate::common;
use hyper::{Body, Response};
use ic_config::http_handler::Config;
use ic_interfaces::state_manager::StateReader;
use ic_logger::{trace, warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    messages::{Blob, HttpStatusResponse, ReplicaHealthStatus},
    replica_version::REPLICA_BINARY_HASH,
    ReplicaVersion, SubnetId,
};

/// Handles a call to /api/v1/status
pub(crate) fn handle(
    log: &ReplicaLogger,
    config: &Config,
    nns_subnet_id: SubnetId,
    state_reader: &dyn StateReader<State = ReplicatedState>,
    replica_health_status: ReplicaHealthStatus,
) -> Response<Body> {
    trace!(log, "in handle status");

    // The root key is the public key of this Internet Computer instance,
    // and is the public key of the root (i.e. NNS) subnet.
    //
    // Eventually this should only be reported in development instances,
    // but as long as we keep restarting even our live instances, we have to
    // consider them development instances.
    let root_key = if config.show_root_key_in_status {
        let subnets = &state_reader
            .get_latest_state()
            .take()
            .metadata
            .network_topology
            .subnets;
        if subnets.len() == 1 {
            // In single-subnet instances (e.g. `dfx start`, which has no NNS)
            // we use this single subnet’s key
            Some(Blob(subnets.values().next().unwrap().public_key.clone()))
        } else if let Some(snt) = subnets.get(&nns_subnet_id) {
            // NNS subnet
            Some(Blob(snt.public_key.clone()))
        } else {
            warn!(
                log,
                "Cannot identify root subnet, will not report root key in status"
            );
            None
        }
    } else {
        None
    };

    let response = HttpStatusResponse {
        ic_api_version: "0.18.0".to_string(),
        root_key,
        impl_version: Some(ReplicaVersion::default().to_string()),
        impl_hash: REPLICA_BINARY_HASH.get().map(|s| s.to_string()),
        replica_health_status: Some(replica_health_status),
    };
    common::cbor_response(&response)
}
