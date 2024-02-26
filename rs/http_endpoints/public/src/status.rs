//! Module that deals with requests to /api/v2/status
use crate::{common, state_reader_executor::StateReaderExecutor, EndpointService};
use axum::body::Body;
use crossbeam::atomic::AtomicCell;
use http::Request;
use hyper::Response;
use ic_crypto_utils_threshold_sig_der::public_key_to_der;
use ic_interfaces_registry::RegistryClient;
use ic_logger::{warn, ReplicaLogger};
use ic_types::{
    messages::{Blob, HttpStatusResponse, ReplicaHealthStatus},
    replica_version::REPLICA_BINARY_HASH,
    ReplicaVersion, SubnetId,
};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{util::BoxCloneService, Service};

// TODO(NET-776)
// The IC API version reported on status requests.
const IC_API_VERSION: &str = "0.18.0";

#[derive(Clone)]
pub(crate) struct StatusService {
    log: ReplicaLogger,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    replica_health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    state_read_executor: StateReaderExecutor,
}

impl StatusService {
    pub(crate) fn new_service(
        log: ReplicaLogger,
        nns_subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        replica_health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
        state_read_executor: StateReaderExecutor,
    ) -> EndpointService {
        let base_service = Self {
            log,
            nns_subnet_id,
            registry_client,
            replica_health_status,
            state_read_executor,
        };
        BoxCloneService::new(base_service)
    }
}

impl Service<Request<Body>> for StatusService {
    type Response = Response<Body>;
    type Error = Infallible;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _unused: Request<Body>) -> Self::Future {
        let log = self.log.clone();
        let nns_subnet_id = self.nns_subnet_id;
        let replica_health_status = self.replica_health_status.clone();
        // The root key is the public key of this Internet Computer instance,
        // and is the public key of the root (i.e. NNS) subnet.
        let root_key = common::get_root_threshold_public_key(
            &log,
            self.registry_client.as_ref(),
            self.registry_client.get_latest_version(),
            &nns_subnet_id,
        )
        .and_then(|key| {
            public_key_to_der(&key.into_bytes())
                .map_err(|err| warn!(self.log, "Failed to parse threshold root key to DER {err}"))
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
            replica_health_status: Some(replica_health_status.load()),
            certified_height: Some(self.state_read_executor.latest_certified_height()),
        };
        Box::pin(async move { Ok(common::cbor_response(&response).0) })
    }
}
