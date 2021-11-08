//! Module that deals with requests to /api/v2/status
use crate::common;
use hyper::{Body, Response};
use ic_config::http_handler::Config;
use ic_interfaces::state_manager::StateReader;
use ic_logger::{trace, warn, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    canonical_error::CanonicalError,
    messages::{Blob, HttpStatusResponse, ReplicaHealthStatus},
    replica_version::REPLICA_BINARY_HASH,
    ReplicaVersion, SubnetId,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tower::{limit::ConcurrencyLimit, load_shed::LoadShed, Service, ServiceBuilder};

// Max number of inflight /api/v2/status requests across all connections.
const MAX_CONCURRENT_STATUS_REQUESTS: usize = 1000;

// TODO(NET-776)
// The IC API version reported on status requests.
const IC_API_VERSION: &str = "0.18.0";

#[derive(Clone)]
pub(crate) struct StatusService {
    log: ReplicaLogger,
    config: Config,
    nns_subnet_id: SubnetId,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    replica_health_status: Arc<RwLock<ReplicaHealthStatus>>,
}

impl StatusService {
    pub(crate) fn new(
        log: ReplicaLogger,
        config: Config,
        nns_subnet_id: SubnetId,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        replica_health_status: Arc<RwLock<ReplicaHealthStatus>>,
    ) -> LoadShed<ConcurrencyLimit<StatusService>> {
        let base_service = Self {
            log,
            config,
            nns_subnet_id,
            state_reader,
            replica_health_status,
        };

        ServiceBuilder::new()
            .load_shed()
            .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
                MAX_CONCURRENT_STATUS_REQUESTS,
            ))
            .service(base_service)
    }
}

impl Service<()> for StatusService {
    type Response = Response<Body>;
    type Error = CanonicalError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _empty: ()) -> Self::Future {
        trace!(self.log, "in handle status");

        // The root key is the public key of this Internet Computer instance,
        // and is the public key of the root (i.e. NNS) subnet.
        let root_key = if self.config.show_root_key_in_status {
            let subnets = &self
                .state_reader
                .get_latest_state()
                .take()
                .metadata
                .network_topology
                .subnets;
            if subnets.len() == 1 {
                // In single-subnet instances (e.g. `dfx start`, which has no NNS)
                // we use this single subnet’s key
                Some(Blob(subnets.values().next().unwrap().public_key.clone()))
            } else if let Some(snt) = subnets.get(&self.nns_subnet_id) {
                // NNS subnet
                Some(Blob(snt.public_key.clone()))
            } else {
                warn!(
                    self.log,
                    "Cannot identify root subnet, will not report root key in status"
                );
                None
            }
        } else {
            None
        };

        let response = HttpStatusResponse {
            ic_api_version: IC_API_VERSION.to_string(),
            root_key,
            impl_version: Some(ReplicaVersion::default().to_string()),
            impl_hash: REPLICA_BINARY_HASH.get().map(|s| s.to_string()),
            replica_health_status: Some(self.replica_health_status.read().unwrap().clone()),
        };
        Box::pin(async move { Ok(common::cbor_response(&response)) })
    }
}
