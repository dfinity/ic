use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    SetupInitialDkgContext, SubnetCallContext,
};
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_types::{ids::node_test_id, messages::RequestBuilder};
use ic_types::{crypto::threshold_sig::ni_dkg::NiDkgTargetId, Height, RegistryVersion};
use std::sync::Arc;

pub(super) fn complement_state_manager_with_remote_dkg_requests(
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
    let expectation =
        mock.expect_get_state_at()
            .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                Height::new(0),
                Arc::new(state),
            )));
    if let Some(times) = times {
        expectation.times(times);
    }
}
