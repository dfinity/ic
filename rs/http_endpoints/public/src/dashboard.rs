//! Module that serves the human-readable replica dashboard, which provide
//! information about the state of the replica.

use std::sync::Arc;

use askama::Template;
use axum::{
    Router,
    extract::State,
    response::{Html, IntoResponse},
};
use hyper::StatusCode;
use ic_config::http_handler::Config;
use ic_interfaces_state_manager::StateReader;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{Height, ReplicaVersion};

#[derive(Template)]
#[template(path = "dashboard.html", escape = "html")]
struct Dashboard<'a> {
    subnet_type: ic_registry_subnet_type::SubnetType,
    http_config: &'a ic_config::http_handler::Config,

    height: Height,
    replicated_state: &'a ic_replicated_state::replicated_state::ReplicatedState,
    canisters: &'a Vec<(
        &'a ic_replicated_state::CanisterState,
        &'a ic_replicated_state::CanisterPriority,
    )>,
    replica_version: ic_types::ReplicaVersion,
}

#[derive(Clone)]
pub(crate) struct DashboardService {
    config: Config,
    subnet_type: SubnetType,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

impl DashboardService {
    pub(crate) fn route() -> &'static str {
        "/_/dashboard"
    }

    pub(crate) fn new_router(
        config: Config,
        subnet_type: SubnetType,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Router {
        let state = DashboardService {
            config,
            subnet_type,
            state_reader,
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
        state_reader,
    }): State<DashboardService>,
) -> impl IntoResponse {
    let labeled_state =
        match tokio::task::spawn_blocking(move || state_reader.get_latest_state()).await {
            Ok(labeled_state) => labeled_state,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal Error: {err}"),
                )
                    .into_response();
            }
        };

    // See https://github.com/djc/askama/issues/333
    let state = labeled_state.get_ref();
    let canisters: Vec<(
        &ic_replicated_state::CanisterState,
        &ic_replicated_state::CanisterPriority,
    )> = state
        .canister_states()
        .values()
        .map(|canister| (canister, state.canister_priority(&canister.canister_id())))
        .collect();

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
            format!("Internal error: {e}"),
        )
            .into_response(),
    }
}
