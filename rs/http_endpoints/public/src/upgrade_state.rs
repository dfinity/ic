//! Endpoint `/_/upgrade_state`: exposes the Phase-2 upgrade state for the
//! local node. The orchestrator polls this to know whether it should reboot.
//!
//! Response is CBOR-encoded [`UpgradeStateResponse`].

use crate::common::Cbor;

use axum::Router;
use axum::extract::State;
use ic_interfaces_state_manager::StateReader;
use ic_replicated_state::ReplicatedState;
use ic_types::consensus::upgrade::UpgradeStateResponse;
use ic_types::NodeId;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct UpgradeStateService {
    node_id: NodeId,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

impl UpgradeStateService {
    pub(crate) fn route() -> &'static str {
        "/_/upgrade_state"
    }

    pub(crate) fn new_router(
        node_id: NodeId,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    ) -> Router {
        let state = Self {
            node_id,
            state_reader,
        };
        Router::new().route_service(Self::route(), axum::routing::get(upgrade_state).with_state(state))
    }
}

pub(crate) async fn upgrade_state(
    State(state): State<UpgradeStateService>,
) -> Cbor<UpgradeStateResponse> {
    let upgrade_state = state
        .state_reader
        .get_latest_certified_state()
        .map(|s| {
            s.get_ref()
                .system_metadata()
                .upgrade_state
                .clone()
        })
        .unwrap_or_default();

    let has_permit = upgrade_state.authorized.contains_key(&state.node_id);

    Cbor(UpgradeStateResponse { has_permit })
}
