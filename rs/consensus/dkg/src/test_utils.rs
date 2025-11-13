use ic_interfaces_state_manager::Labeled;
use ic_management_canister_types_private::{MasterPublicKeyId, VetKdKeyId};
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    ReshareChainKeyContext, SetupInitialDkgContext, SubnetCallContext,
};
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_types::{ids::node_test_id, messages::RequestBuilder};
use ic_types::{Height, RegistryVersion, crypto::threshold_sig::ni_dkg::NiDkgTargetId};
use std::sync::Arc;

pub(super) fn complement_state_manager_with_setup_initial_dkg_request(
    state_manager: Arc<RefMockStateManager>,
    registry_version: RegistryVersion,
    node_ids: Vec<u64>,
    times: Option<usize>,
    target: Option<NiDkgTargetId>,
) {
    let mut state = ic_test_utilities_state::get_initial_state(0, 0);

    // Add the context into state_manager.
    let nodes_in_target_subnet = node_ids.into_iter().map(node_test_id).collect();

    if let Some(target_id) = target {
        state.metadata.subnet_call_context_manager.push_context(
            SubnetCallContext::SetupInitialDKG(SetupInitialDkgContext {
                request: RequestBuilder::new().build(),
                nodes_in_target_subnet,
                target_id,
                registry_version,
                time: state.time(),
            }),
        );
    }

    let mut mock = state_manager.get_mut();
    let expectation = mock
        .expect_get_state_at()
        .return_const(Ok(Labeled::new(Height::new(0), Arc::new(state))));
    if let Some(times) = times {
        expectation.times(times);
    }
}

pub(super) fn complement_state_manager_with_reshare_chain_key_request(
    state_manager: Arc<RefMockStateManager>,
    registry_version: RegistryVersion,
    key_id: VetKdKeyId,
    node_ids: Vec<u64>,
    times: Option<usize>,
    target: Option<NiDkgTargetId>,
) {
    let mut state = ic_test_utilities_state::get_initial_state(0, 0);

    // Add the context into state_manager.
    let nodes_in_target_subnet = node_ids.into_iter().map(node_test_id).collect();

    if let Some(target_id) = target {
        state.metadata.subnet_call_context_manager.push_context(
            SubnetCallContext::ReshareChainKey(ReshareChainKeyContext {
                request: RequestBuilder::new().build(),
                key_id: MasterPublicKeyId::VetKd(key_id),
                nodes: nodes_in_target_subnet,
                registry_version,
                time: state.time(),
                target_id,
            }),
        );
    }

    let mut mock = state_manager.get_mut();
    let expectation = mock
        .expect_get_state_at()
        .return_const(Ok(Labeled::new(Height::new(0), Arc::new(state))));
    if let Some(times) = times {
        expectation.times(times);
    }
}
