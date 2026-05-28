use ic_management_canister_types_private::VetKdKeyId;
use ic_replicated_state::metadata_state::subnet_call_context_manager::SetupInitialDkgContext;
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    Height, RegistryVersion,
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
    },
    time::UNIX_EPOCH,
};
use std::collections::BTreeSet;

pub fn fake_setup_initial_dkg_context(registry_version: RegistryVersion) -> SetupInitialDkgContext {
    SetupInitialDkgContext {
        request: RequestBuilder::new().build(),
        nodes_in_target_subnet: BTreeSet::from([node_test_id(1)]),
        target_id: NiDkgTargetId::new([7_u8; NiDkgTargetId::SIZE]),
        registry_version,
        time: UNIX_EPOCH,
    }
}

pub fn fake_dkg_id(key_id: VetKdKeyId) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(0),
        dealer_subnet: subnet_test_id(0),
        dkg_tag: NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(key_id)),
        target_subnet: NiDkgTargetSubnet::Local,
    }
}
