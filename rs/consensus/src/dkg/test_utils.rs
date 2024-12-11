use ic_interfaces::consensus_pool::ConsensusPool;
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    SetupInitialDkgContext, SubnetCallContext,
};
use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_types::{ids::node_test_id, messages::RequestBuilder};
use ic_types::{
    consensus::dkg::{DealingContent, DealingMessages},
    crypto::{
        threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId, NiDkgTargetId, NiDkgTranscript},
        BasicSig,
    },
    messages::CallbackId,
    signature::{BasicSignature, BasicSigned},
    Height, RegistryVersion, ReplicaVersion,
};
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

/// Create a dealing from the node `node_idx`
pub(super) fn create_dealing(node_idx: u64, dkg_id: NiDkgId) -> BasicSigned<DealingContent> {
    let node_id = node_test_id(node_idx);

    BasicSigned {
        content: DealingContent {
            version: ReplicaVersion::default(),
            dealing: NiDkgDealing::dummy_dealing_for_tests(node_idx as u8),
            dkg_id,
        },
        signature: BasicSignature {
            signature: BasicSig(vec![]).into(),
            signer: node_id,
        },
    }
}

/// Extract the remote dkg transcripts from the current highest validated block
pub(super) fn extract_remote_dkgs_from_highest_block(
    pool: &TestConsensusPool,
) -> Vec<(NiDkgId, CallbackId, Result<NiDkgTranscript, String>)> {
    let block: ic_types::consensus::Block = pool
        .validated()
        .block_proposal()
        .get_highest()
        .unwrap()
        .content
        .into_inner();

    if block.payload.as_ref().is_summary() {
        &block
            .payload
            .as_ref()
            .as_summary()
            .dkg
            .transcripts_for_remote_subnets
    } else {
        &block
            .payload
            .as_ref()
            .as_data()
            .dkg
            .transcripts_for_remote_subnets
    }
    .clone()
}

/// Extract the dealings from the current highest validated block
pub(super) fn extract_dealings_from_highest_block(pool: &TestConsensusPool) -> DealingMessages {
    let block: ic_types::consensus::Block = pool
        .validated()
        .block_proposal()
        .get_highest()
        .unwrap()
        .content
        .into_inner();

    if block.payload.as_ref().is_summary() {
        vec![]
    } else {
        block.payload.as_ref().as_data().dkg.messages.clone()
    }
}
