//! Endpoint `/_/upgrade_state`: exposes the Phase-2 upgrade state for the
//! local node. The orchestrator polls this to know whether it should reboot.
//!
//! Response is CBOR-encoded [`UpgradeStateResponse`].

use crate::common::{self, Cbor};

use axum::Router;
use axum::extract::State;
use ic_interfaces_state_manager::StateReader;
use ic_replicated_state::ReplicatedState;
use ic_types::consensus::upgrade::{UpgradeState, UpgradeStateResponse};
use ic_types::NodeId;
use std::sync::Arc;
use tower::BoxError;

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

    let permit = upgrade_state.issued_permits.get(&state.node_id).cloned();

    let target_guestos_version = permit
        .as_ref()
        .map(|p| p.target_version.clone());

    Cbor(UpgradeStateResponse {
        target_guestos_version,
        has_permit: permit.is_some(),
        permit,
    })
}
