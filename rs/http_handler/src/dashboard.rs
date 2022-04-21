//! Module that serves the human-readable replica dashboard, which provide
//! information about the state of the replica.

use crate::{
    common::{make_plaintext_response, CONTENT_TYPE_HTML},
    state_reader_executor::StateReaderExecutor,
};
use askama::Template;
use hyper::{Body, Response, StatusCode};
use ic_config::http_handler::Config;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{BoxError, Service};

// See build.rs
include!(concat!(env!("OUT_DIR"), "/dashboard.rs"));

pub(crate) struct DashboardService {
    config: Config,
    subnet_type: SubnetType,
    state_reader_executor: StateReaderExecutor,
}

impl DashboardService {
    pub(crate) fn new(
        config: Config,
        subnet_type: SubnetType,
        state_reader_executor: StateReaderExecutor,
    ) -> DashboardService {
        Self {
            config,
            subnet_type,
            state_reader_executor,
        }
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
        let http_config = self.config.clone();
        let subnet_type = self.subnet_type;
        let state_reader_executor = self.state_reader_executor.clone();
        Box::pin(async move {
            let labeled_state = match state_reader_executor.get_latest_state().await {
                Ok(ls) => ls,
                Err(e) => return Ok(make_plaintext_response(e.status, e.message)),
            };

            // See https://github.com/djc/askama/issues/333
            let canisters: Vec<&ic_replicated_state::CanisterState> =
                labeled_state.get_ref().canisters_iter().collect();

            let dashboard = Dashboard {
                subnet_type,
                http_config: &http_config,
                height: labeled_state.height(),
                replicated_state: labeled_state.get_ref(),
                canisters: &canisters,
                // TODO(EXC-750): Remove this field.
                cow_memory_manager_enabled: false,
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
                Err(e) => make_plaintext_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal error: {}", e),
                ),
            };

            Ok(res)
        })
    }
}
