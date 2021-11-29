//! Module that serves the human-readable replica dashboard, which provide
//! information about the state of the replica.

use crate::common::{make_response, CONTENT_TYPE_HTML};
use askama::Template;
use hyper::{Body, Response, StatusCode};
use ic_config::http_handler::Config;
use ic_interfaces::state_manager::StateReader;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{canonical_error::internal_error, Height, ReplicaVersion};
use ic_utils::ic_features::cow_state_feature;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{limit::ConcurrencyLimit, BoxError, Service, ServiceBuilder};

const MAX_CONCURRENT_DASHBOARD_REQUESTS: usize = 1000;

// See build.rs
include!(concat!(env!("OUT_DIR"), "/dashboard.rs"));

#[derive(Clone)]
pub(crate) struct DashboardService {
    config: Config,
    subnet_type: SubnetType,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

impl DashboardService {
    pub(crate) fn new(
        config: Config,
        subnet_type: SubnetType,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> ConcurrencyLimit<DashboardService> {
        let base_service = Self {
            config,
            subnet_type,
            state_reader,
        };
        ServiceBuilder::new()
            .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
                MAX_CONCURRENT_DASHBOARD_REQUESTS,
            ))
            .service(base_service)
    }
}

impl Service<Body> for DashboardService {
    type Response = Response<Body>;
    type Error = BoxError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + Sync>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _unused: Body) -> Self::Future {
        use hyper::header;
        // get_latest_state returns a new struct, not a ref. We have to store it,
        // otherwise lifetime issues show up in the template.
        let labeled_state = self.state_reader.get_latest_state();

        // See https://github.com/djc/askama/issues/333
        let canisters: Vec<&ic_replicated_state::CanisterState> =
            labeled_state.get_ref().canisters_iter().collect();

        let cow_memory_manager_enabled =
            cow_state_feature::is_enabled(cow_state_feature::cow_state);

        let dashboard = Dashboard {
            subnet_type: self.subnet_type,
            http_config: &self.config,
            height: labeled_state.height(),
            replicated_state: labeled_state.get_ref(),
            canisters: &canisters,
            cow_memory_manager_enabled,
            replica_version: ReplicaVersion::default(),
        };

        let res = match dashboard.render() {
            Ok(content) => {
                let mut response = Response::new(Body::from(content));
                *response.status_mut() = StatusCode::OK;
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    header::HeaderValue::from_static(CONTENT_TYPE_HTML),
                );
                response
            }
            // If there was an internal error, the error description is text, not HTML, and
            // therefore we don't attach the header
            Err(e) => make_response(internal_error(&format!("Internal error: {}", e))),
        };
        Box::pin(async move { Ok(res) })
    }
}
