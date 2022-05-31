//! Module that deals with requests to /api/v2/status
use crate::{common, state_reader_executor::StateReaderExecutor, EndpointService};
use hyper::{Body, Response};
use ic_config::http_handler::Config;
use ic_logger::{trace, warn, ReplicaLogger};
use ic_types::{
    messages::{Blob, HttpStatusResponse, ReplicaHealthStatus},
    replica_version::REPLICA_BINARY_HASH,
    ReplicaVersion, SubnetId,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tower::{
    limit::concurrency::GlobalConcurrencyLimitLayer, util::BoxCloneService, BoxError, Service,
    ServiceBuilder,
};

// TODO(NET-776)
// The IC API version reported on status requests.
const IC_API_VERSION: &str = "0.18.0";
const MAX_STATUS_CONCURRENT_REQUESTS: usize = 100;

#[derive(Clone)]
pub(crate) struct StatusService {
    log: ReplicaLogger,
    config: Config,
    nns_subnet_id: SubnetId,
    state_reader_executor: StateReaderExecutor,
    replica_health_status: Arc<RwLock<ReplicaHealthStatus>>,
}

impl StatusService {
    pub(crate) fn new_service(
        log: ReplicaLogger,
        config: Config,
        nns_subnet_id: SubnetId,
        state_reader_executor: StateReaderExecutor,
        replica_health_status: Arc<RwLock<ReplicaHealthStatus>>,
    ) -> EndpointService {
        let base_service = Self {
            log,
            config,
            nns_subnet_id,
            state_reader_executor,
            replica_health_status,
        };
        BoxCloneService::new(
            ServiceBuilder::new()
                .layer(GlobalConcurrencyLimitLayer::new(
                    MAX_STATUS_CONCURRENT_REQUESTS,
                ))
                .service(base_service),
        )
    }
}

impl Service<Body> for StatusService {
    type Response = Response<Body>;
    type Error = BoxError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _unused: Body) -> Self::Future {
        trace!(self.log, "in handle status");

        let log = self.log.clone();
        let nns_subnet_id = self.nns_subnet_id;
        let root_key_status = self.config.show_root_key_in_status;
        let state_reader_executor = self.state_reader_executor.clone();
        let replica_health_status = self.replica_health_status.read().unwrap().clone();
        Box::pin(async move {
            // The root key is the public key of this Internet Computer instance,
            // and is the public key of the root (i.e. NNS) subnet.
            let root_key = if root_key_status {
                let latest_state = match state_reader_executor.get_latest_state().await {
                    Ok(ls) => ls,
                    Err(e) => {
                        return Ok(common::make_plaintext_response(e.status, e.message));
                    }
                };

                let subnets = &latest_state.take().metadata.network_topology.subnets;
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
                ic_api_version: IC_API_VERSION.to_string(),
                root_key,
                impl_version: Some(ReplicaVersion::default().to_string()),
                impl_hash: REPLICA_BINARY_HASH.get().map(|s| s.to_string()),
                replica_health_status: Some(replica_health_status),
            };

            Ok(common::cbor_response(&response))
        })
    }
}
