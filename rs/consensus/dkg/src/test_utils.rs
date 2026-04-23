use ic_crypto_test_utils_ni_dkg::dummy_dealing;
use ic_interfaces_state_manager::Labeled;
use ic_management_canister_types_private::{MasterPublicKeyId, VetKdKeyId};
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    ReshareChainKeyContext, SetupInitialDkgContext, SubnetCallContext,
};
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_consensus::fake::FakeContentSigner;
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    Height, NumberOfNodes, RegistryVersion,
    consensus::dkg::{DealingContent, Message},
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        config::{NiDkgConfig, NiDkgConfigData},
    },
};
use std::{collections::BTreeSet, sync::Arc};

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
