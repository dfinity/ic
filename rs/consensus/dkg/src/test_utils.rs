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
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    Height, NumberOfNodes, RegistryVersion,
    consensus::{
        BlockPayload,
        dkg::{DealingContent, DealingMessages, Message},
    },
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet, NiDkgTranscript,
        config::{NiDkgConfig, NiDkgConfigData},
    },
    messages::CallbackId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub(super) fn make_setup_initial_dkg_context(
    registry_version: RegistryVersion,
    node_ids: Vec<u64>,
    target_id: NiDkgTargetId,
) -> SubnetCallContext {
    SubnetCallContext::SetupInitialDKG(SetupInitialDkgContext {
        request: RequestBuilder::new().build(),
        nodes_in_target_subnet: node_ids.into_iter().map(node_test_id).collect(),
        target_id,
        registry_version,
        time: ic_types::time::UNIX_EPOCH,
    })
}

pub(super) fn make_reshare_chain_key_context(
    registry_version: RegistryVersion,
    key_id: VetKdKeyId,
    node_ids: Vec<u64>,
    target_id: NiDkgTargetId,
) -> SubnetCallContext {
    SubnetCallContext::ReshareChainKey(ReshareChainKeyContext {
        request: RequestBuilder::new().build(),
        key_id: MasterPublicKeyId::VetKd(key_id),
        nodes: node_ids.into_iter().map(node_test_id).collect(),
        registry_version,
        time: ic_types::time::UNIX_EPOCH,
        target_id,
    })
}

/// Set up the state manager mock to return an initial state containing the
/// given subnet call contexts.
pub(super) fn complement_state_manager_with_dkg_contexts(
    state_manager: Arc<RefMockStateManager>,
    contexts: Vec<SubnetCallContext>,
    times: Option<usize>,
) {
    let mut state = ic_test_utilities_state::get_initial_state(0, 0);
    for context in contexts {
        state
            .metadata
            .subnet_call_context_manager
            .push_context(context);
    }
    let mut mock = state_manager.get_mut();
    let expectation = mock
        .expect_get_state_at()
        .return_const(Ok(Labeled::new(Height::new(0), Arc::new(state))));
    if let Some(times) = times {
        expectation.times(times);
    }
}

pub(super) fn complement_state_manager_with_setup_initial_dkg_request(
    state_manager: Arc<RefMockStateManager>,
    registry_version: RegistryVersion,
    node_ids: Vec<u64>,
    times: Option<usize>,
    target: Option<NiDkgTargetId>,
) {
    let contexts = target
        .into_iter()
        .map(|t| make_setup_initial_dkg_context(registry_version, node_ids.clone(), t))
        .collect();
    complement_state_manager_with_dkg_contexts(state_manager, contexts, times);
}

pub(super) fn complement_state_manager_with_reshare_chain_key_request(
    state_manager: Arc<RefMockStateManager>,
    registry_version: RegistryVersion,
    key_id: VetKdKeyId,
    node_ids: Vec<u64>,
    times: Option<usize>,
    target: Option<NiDkgTargetId>,
) {
    let contexts = target
        .into_iter()
        .map(|t| {
            make_reshare_chain_key_context(registry_version, key_id.clone(), node_ids.clone(), t)
        })
        .collect();
    complement_state_manager_with_dkg_contexts(state_manager, contexts, times);
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

    match block.payload.as_ref() {
        BlockPayload::Summary(summary) => summary.dkg.transcripts_for_remote_subnets.clone(),
        BlockPayload::Data(data) => data.dkg.transcripts_for_remote_subnets.clone(),
    }
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

    match block.payload.as_ref() {
        BlockPayload::Summary(_) => vec![],
        BlockPayload::Data(data) => data.dkg.messages.clone(),
    }
}

/// Extract the remote dkg IDs from the current highest validated block
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

    match block.payload.as_ref() {
        BlockPayload::Summary(summary) => summary.dkg.configs.clone(),
        BlockPayload::Data(_) => BTreeMap::new(),
    }
}

/// Create a dealing from the node `node_idx`
pub(super) fn create_dealing(node_idx: u64, dkg_id: NiDkgId) -> Message {
    let content = DealingContent::new(dummy_dealing(node_idx as u8), dkg_id);
    Message::fake(content, node_test_id(node_idx))
}

pub(super) fn make_test_config(dkg_id: NiDkgId, max_corrupt_dealers: u32) -> NiDkgConfig {
    let nodes: BTreeSet<_> = (0..10).map(node_test_id).collect();
    NiDkgConfig::new(NiDkgConfigData {
        dkg_id,
        max_corrupt_dealers: NumberOfNodes::from(max_corrupt_dealers),
        dealers: nodes.clone(),
        max_corrupt_receivers: NumberOfNodes::from(1),
        receivers: nodes,
        threshold: NumberOfNodes::from(2),
        registry_version: RegistryVersion::from(1),
        resharing_transcript: None,
    })
    .unwrap()
}

pub(super) fn local_dkg_id(tag: NiDkgTag) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(0),
        dealer_subnet: subnet_test_id(0),
        dkg_tag: tag,
        target_subnet: NiDkgTargetSubnet::Local,
    }
}

pub(super) fn remote_dkg_id(tag: NiDkgTag) -> NiDkgId {
    remote_dkg_id_with_target(tag, [0_u8; 32])
}

pub(super) fn remote_dkg_id_with_target(tag: NiDkgTag, target_id: [u8; 32]) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(0),
        dealer_subnet: subnet_test_id(0),
        dkg_tag: tag,
        target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new(target_id)),
    }
}
