//! Module that serves the human-readable replica dashboard, which provide
//! information about the state of the replica.

use crate::common::CONTENT_TYPE_HTML;
use askama::Template;
use hyper::{Body, Response, StatusCode};
use ic_config::http_handler::Config;
use ic_interfaces::state_manager::StateReader;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{Height, ReplicaVersion};
use ic_utils::ic_features::cow_state_feature;

// See build.rs
include!(concat!(env!("OUT_DIR"), "/dashboard.rs"));

pub(crate) fn handle(
    config: &Config,
    state_reader: &dyn StateReader<State = ReplicatedState>,
    subnet_type: SubnetType,
) -> Response<Body> {
    use hyper::header;
    // get_latest_state returns a new struct, not a ref. We have to store it,
    // otherwise lifetime issues show up in the template.
    let labeled_state = state_reader.get_latest_state();

    // See https://github.com/djc/askama/issues/333
    let canisters: Vec<&ic_replicated_state::CanisterState> =
        labeled_state.get_ref().canisters_iter().collect();

    let cow_memory_manager_enabled = cow_state_feature::is_enabled(cow_state_feature::cow_state);

    let dashboard = Dashboard {
        subnet_type,
        http_config: &config,
        height: labeled_state.height(),
        replicated_state: labeled_state.get_ref(),
        canisters: &canisters,
        cow_memory_manager_enabled,
        replica_version: ReplicaVersion::default(),
    };

    match dashboard.render() {
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
        Err(e) => {
            let mut response = Response::new(Body::from(format!("Internal error: {}", e)));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}
