#![allow(clippy::unwrap_used)]

use crate::common::test_utils::CryptoRegistryRecord;
use crate::sign::tests::{dealing_encryption_pk_record_with, REG_V1, REG_V2};
use ic_crypto_internal_types::curves::bls12_381::G1;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    FsEncryptionPublicKey, PublicCoefficientsBytes,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    ni_dkg_groth20_bls12_381, CspFsEncryptionPublicKey, CspNiDkgDealing, CspNiDkgTranscript,
};
use ic_test_utilities::crypto::basic_utilities::set_of;
use ic_test_utilities::crypto::ni_dkg_csp_dealing;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, SUBNET_1};
use ic_types::crypto::threshold_sig::ni_dkg::config::receivers::NiDkgReceivers;
use ic_types::crypto::threshold_sig::ni_dkg::config::{
    NiDkgConfig, NiDkgConfigData, NiDkgThreshold,
};
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript,
};
use ic_types::{Height, NodeId, NumberOfNodes, RegistryVersion};
use std::collections::{BTreeMap, BTreeSet};

// We use threshold 1 in these tests to get a valid DkgConfig in a simple way.
// Threshold 1 not a common value used in practice, but in these tests we only
// care that it is forwarded to the CSP correctly.
pub const THRESHOLD: NumberOfNodes = NumberOfNodes::new(1);
pub const RESHARING_TRANSCRIPT_THRESHOLD: NumberOfNodes = NumberOfNodes::new(1);
pub const REGISTRY_FS_ENC_PK_SIZE: usize = FsEncryptionPublicKey::SIZE;

pub const DKG_ID: NiDkgId = NiDkgId {
    start_block_height: Height::new(1),
    dealer_subnet: SUBNET_1,
    dkg_tag: NiDkgTag::LowThreshold,
    target_subnet: NiDkgTargetSubnet::Local,
};

pub const RESHARING_TRANSCRIPT_DKG_ID: NiDkgId = NiDkgId {
    start_block_height: Height::new(1),
    dealer_subnet: SUBNET_1,
    dkg_tag: NiDkgTag::LowThreshold,
    target_subnet: NiDkgTargetSubnet::Local,
};

pub fn minimal_dkg_config_data_without_resharing() -> NiDkgConfigData {
    NiDkgConfigData {
        dkg_id: DKG_ID,
        max_corrupt_dealers: NumberOfNodes::new(0),
        dealers: set_of(&[NODE_1]),
        max_corrupt_receivers: NumberOfNodes::new(0),
        receivers: set_of(&[NODE_1]),
        threshold: THRESHOLD,
        registry_version: REG_V2,
        resharing_transcript: None,
    }
}

pub fn minimal_dkg_config_data_with_resharing() -> NiDkgConfigData {
    NiDkgConfigData {
        dkg_id: DKG_ID,
        max_corrupt_dealers: NumberOfNodes::new(0),
        dealers: set_of(&[NODE_1]),
        max_corrupt_receivers: NumberOfNodes::new(0),
        receivers: set_of(&[NODE_1]),
        threshold: THRESHOLD,
        registry_version: REG_V2,
        resharing_transcript: Some(dummy_transcript()),
    }
}

pub fn dkg_config(data: NiDkgConfigData) -> NiDkgConfig {
    NiDkgConfig::new(data).expect("config invariant violated")
}

pub fn csp_dealing(data: u8) -> CspNiDkgDealing {
    ni_dkg_csp_dealing(data)
}

pub fn nodes(nodes: &[NodeId]) -> BTreeSet<NodeId> {
    nodes.iter().copied().collect()
}

pub fn transcript(
    committee: BTreeSet<NodeId>,
    reg_version: RegistryVersion,
    dkg_id: NiDkgId,
) -> NiDkgTranscript {
    NiDkgTranscript {
        dkg_id,
        threshold: NiDkgThreshold::new(RESHARING_TRANSCRIPT_THRESHOLD).unwrap(),
        committee: NiDkgReceivers::new(committee).expect("could not create committee"),
        registry_version: reg_version,
        internal_csp_transcript: CspNiDkgTranscript::Groth20_Bls12_381(
            ni_dkg_groth20_bls12_381::Transcript {
                public_coefficients: PublicCoefficientsBytes {
                    coefficients: vec![],
                },
                receiver_data: Default::default(),
            },
        ),
    }
}

pub fn dummy_transcript() -> NiDkgTranscript {
    transcript(
        set_of(&[NODE_3, NODE_1, NODE_2]),
        REG_V1,
        RESHARING_TRANSCRIPT_DKG_ID,
    )
}

pub fn dealing_enc_pk_record(
    node_id: NodeId,
    registry_version: RegistryVersion,
    data: u8,
) -> CryptoRegistryRecord {
    dealing_encryption_pk_record_with(
        node_id,
        vec![data; REGISTRY_FS_ENC_PK_SIZE],
        registry_version,
    )
}

pub fn csp_fs_enc_pk(data: u8) -> CspFsEncryptionPublicKey {
    CspFsEncryptionPublicKey::Groth20_Bls12_381(FsEncryptionPublicKey(G1([data; G1::SIZE])))
}

pub fn map_of<K: Ord, V>(entries: Vec<(K, V)>) -> BTreeMap<K, V> {
    let mut map = BTreeMap::new();
    for (key, value) in entries {
        assert!(map.insert(key, value).is_none());
    }
    map
}
