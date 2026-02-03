use ic_crypto_test_utils_ni_dkg::dummy_dealing;
use ic_interfaces::consensus_pool::ConsensusPool;
use ic_interfaces_state_manager::Labeled;
use ic_management_canister_types_private::{MasterPublicKeyId, VetKdKeyId};
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    ReshareChainKeyContext, SetupInitialDkgContext, SubnetCallContext,
};
use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_consensus::fake::FakeContentSigner;
use ic_test_utilities_types::{ids::node_test_id, messages::RequestBuilder};
use ic_types::{
    Height, RegistryVersion,
    consensus::dkg::{DealingContent, DealingMessages, Message},
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgTargetId, NiDkgTargetSubnet, NiDkgTranscript, config::NiDkgConfig,
    },
    messages::CallbackId,
};
use std::{collections::BTreeMap, sync::Arc};

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

/// Extract the remote dkg transcripts from the current highest validated block
pub(super) fn extract_remote_dkg_ids_from_highest_block(
    pool: &TestConsensusPool,
    target_id: NiDkgTargetId,
) -> Vec<NiDkgId> {
    extract_dkg_configs_from_highest_block(pool)
        .iter()
        .filter(|(id, _)| id.target_subnet == NiDkgTargetSubnet::Remote(target_id))
        .map(|(id, _)| id)
        .cloned()
        .collect()
}

/// Extract the DKG configs from the current highest validated block
pub(super) fn extract_dkg_configs_from_highest_block(
    pool: &TestConsensusPool,
) -> BTreeMap<NiDkgId, NiDkgConfig> {
    let block: ic_types::consensus::Block = pool
        .validated()
        .block_proposal()
        .get_highest()
        .unwrap()
        .content
        .into_inner();

    if block.payload.as_ref().is_summary() {
        block.payload.as_ref().as_summary().dkg.configs.clone()
    } else {
        BTreeMap::new()
    }
}

/// Create a dealing from the node `node_idx`
pub(super) fn create_dealing(node_idx: u64, dkg_id: NiDkgId) -> Message {
    let content = DealingContent::new(dummy_dealing(node_idx as u8), dkg_id);
    Message::fake(content, node_test_id(node_idx))
}
