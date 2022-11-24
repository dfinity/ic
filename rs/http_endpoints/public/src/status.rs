//! Module that deals with requests to /api/v2/status
use crate::{common, EndpointService};
use crossbeam::atomic::AtomicCell;
use hyper::{Body, Response};
use ic_config::http_handler::Config;
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{warn, ReplicaLogger};
use ic_types::{
    messages::{Blob, HttpStatusResponse, ReplicaHealthStatus},
    replica_version::REPLICA_BINARY_HASH,
    ReplicaVersion, SubnetId,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
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
    registry_client: Arc<dyn RegistryClient>,
    replica_health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
}

impl StatusService {
    pub(crate) fn new_service(
        log: ReplicaLogger,
        config: Config,
        nns_subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        replica_health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    ) -> EndpointService {
        let base_service = Self {
            log,
            config,
            nns_subnet_id,
            registry_client,
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
        let log = self.log.clone();
        let nns_subnet_id = self.nns_subnet_id;
        let root_key_status = self.config.show_root_key_in_status;
        let replica_health_status = self.replica_health_status.clone();
        // The root key is the public key of this Internet Computer instance,
        // and is the public key of the root (i.e. NNS) subnet.
        let root_key = if root_key_status {
            common::get_root_threshold_public_key(
                &log,
                self.registry_client.clone(),
                self.registry_client.get_latest_version(),
                &nns_subnet_id,
            )
            .and_then(|key| {
                public_key_to_der(&key.into_bytes())
                    .map_err(|err| {
                        warn!(self.log, "Failed to parse threshold root key to DER {err}")
                    })
                    .ok()
            })
        } else {
            None
        };
        let response = HttpStatusResponse {
            ic_api_version: IC_API_VERSION.to_string(),
            root_key: root_key.map(Blob),
            impl_version: Some(ReplicaVersion::default().to_string()),
            impl_hash: REPLICA_BINARY_HASH.get().map(|s| s.to_string()),
            replica_health_status: Some(replica_health_status.load()),
        };
        Box::pin(async move { Ok(common::cbor_response(&response)) })
    }
}
