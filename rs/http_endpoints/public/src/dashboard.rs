//! Module that serves the human-readable replica dashboard, which provide
//! information about the state of the replica.

use crate::state_reader_executor::StateReaderExecutor;
use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    Router,
};
use hyper::StatusCode;
use ic_config::http_handler::Config;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};

// See build.rs
include!(concat!(env!("OUT_DIR"), "/dashboard.rs"));

#[derive(Clone)]
pub(crate) struct DashboardService {
    config: Config,
    subnet_type: SubnetType,
    state_reader_executor: StateReaderExecutor,
}

impl DashboardService {
    pub(crate) fn route() -> &'static str {
        "/_/dashboard"
    }

    pub(crate) fn new_router(
        config: Config,
        subnet_type: SubnetType,
        state_reader_executor: StateReaderExecutor,
    ) -> Router {
        let state = DashboardService {
            config,
            subnet_type,
            state_reader_executor,
        };
        Router::new().route(
            DashboardService::route(),
            axum::routing::get(dashboard).with_state(state),
        )
    }
}

async fn dashboard(
    State(DashboardService {
        config,
        subnet_type,
        state_reader_executor,
    }): State<DashboardService>,
) -> impl IntoResponse {
    let labeled_state = match state_reader_executor.get_latest_state().await {
        Ok(ls) => ls,
        Err(e) => return (e.status, e.message).into_response(),
    };

    // See https://github.com/djc/askama/issues/333
    let canisters: Vec<&ic_replicated_state::CanisterState> =
        labeled_state.get_ref().canisters_iter().collect();

    let dashboard = Dashboard {
        subnet_type,
        http_config: &config,
        height: labeled_state.height(),
        replicated_state: labeled_state.get_ref(),
        canisters: &canisters,
        replica_version: ReplicaVersion::default(),
    };

    match dashboard.render() {
        Ok(content) => Html(content).into_response(),
        // If there was an internal error, the error description is text, not HTML, and
        // therefore we don't attach the header
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Internal error: {}", e),
        )
            .into_response(),
    }
}
