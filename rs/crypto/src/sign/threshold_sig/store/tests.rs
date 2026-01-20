use super::*;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_management_canister_types_private::{VetKdCurve, VetKdKeyId};
use ic_types::Height;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTargetId, NiDkgTargetSubnet};
use ic_types_test_utils::ids::{SUBNET_1, node_test_id};
use sign::tests::{REG_V1, REG_V2};
use strum::{EnumCount, IntoEnumIterator};

const NODE_1: u64 = 1;
const NODE_2: u64 = 2;
const NODE_1_INDEX: NodeIndex = 1;
const NODE_2_INDEX: NodeIndex = 2;

pub const NI_DKG_ID_HIGH_T: NiDkgId = NiDkgId {
    start_block_height: Height::new(3),
    dealer_subnet: SUBNET_1,
    dkg_tag: NiDkgTag::HighThreshold,
    target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new([42; 32])),
};

pub const NI_DKG_ID_LOW_T: NiDkgId = NiDkgId {
    start_block_height: Height::new(3),
    dealer_subnet: SUBNET_1,
    dkg_tag: NiDkgTag::LowThreshold,
    target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new([42; 32])),
};

pub const NI_DKG_ID_1: NiDkgId = NI_DKG_ID_HIGH_T;
pub const NI_DKG_ID_2: NiDkgId = NI_DKG_ID_LOW_T;

#[test]
fn should_contain_transcript_data_after_insertion_with_nidkg_id() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let indices = indices_with(vec![
            (node_test_id(NODE_1), NODE_1_INDEX),
            (node_test_id(NODE_2), NODE_2_INDEX),
        ]);
        let public_coeffs = public_coeffs();

        let dkg_id = ni_dkg_id_with_tag(tag.clone(), 42);

        store.insert_transcript_data(&dkg_id, public_coeffs.clone(), indices, REG_V1);

        let transcript_data = store.transcript_data(&dkg_id).unwrap();
        assert_eq!(transcript_data.public_coefficients(), &public_coeffs);
        assert_eq!(
            transcript_data.index(node_test_id(NODE_1)),
            Some(&NODE_1_INDEX)
        );
        assert_eq!(
            transcript_data.index(node_test_id(NODE_2)),
            Some(&NODE_2_INDEX)
        );
        assert_eq!(transcript_data.registry_version(), REG_V1);
    }
}

#[test]
fn should_not_contain_nonexistent_transcript_data() {
    for tag in all_tags() {
        let store = ThresholdSigDataStoreImpl::new();
        let dkg_id = ni_dkg_id_with_tag(tag, 1);

        assert!(store.transcript_data(&dkg_id).is_none());
    }
}

#[test]
fn should_contain_individual_public_keys_after_insertion_with_nidkg_id() {
    for tag in all_tags() {
        let dkg_id = ni_dkg_id_with_tag(tag.clone(), 1);
        let mut store = ThresholdSigDataStoreImpl::new();
        let csp_pubkey = csp_public_key();

        store.insert_individual_public_key(&dkg_id, node_test_id(NODE_1), csp_pubkey);

        assert_eq!(
            store.individual_public_key(&dkg_id, node_test_id(NODE_1)),
            Some(&csp_pubkey)
        );
    }
}

#[test]
fn should_insert_multiple_individual_public_keys() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let csp_pubkey_1 = csp_public_key();
        let csp_pubkey_2 = other_csp_public_key();
        let ni_dkg_id_1 = ni_dkg_id_with_tag(tag.clone(), 1);
        let ni_dkg_id_2 = ni_dkg_id_with_tag(tag.clone(), 2);

        assert_ne!(ni_dkg_id_1, NI_DKG_ID_2);
        store.insert_individual_public_key(&ni_dkg_id_1, node_test_id(NODE_1), csp_pubkey_1);
        store.insert_individual_public_key(&ni_dkg_id_1, node_test_id(NODE_2), csp_pubkey_2);
        store.insert_individual_public_key(&ni_dkg_id_2, node_test_id(NODE_1), csp_pubkey_2);

        assert_eq!(
            store.individual_public_key(&ni_dkg_id_1, node_test_id(NODE_1)),
            Some(&csp_pubkey_1)
        );
        assert_eq!(
            store.individual_public_key(&ni_dkg_id_1, node_test_id(NODE_2)),
            Some(&csp_pubkey_2)
        );
        assert_eq!(
            store.individual_public_key(&ni_dkg_id_2, node_test_id(NODE_1)),
            Some(&csp_pubkey_2)
        );
    }
}

#[test]
fn should_not_contain_nonexistent_individual_public_key() {
    for tag in all_tags() {
        let store = ThresholdSigDataStoreImpl::new();
        let dkg_id = ni_dkg_id_with_tag(tag, 1);

        assert_eq!(
            store.individual_public_key(&dkg_id, node_test_id(NODE_1)),
            None
        );
    }
}

#[test]
fn should_overwrite_existing_public_coefficients() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let (public_coeffs_1, public_coeffs_2) = (public_coeffs_1(), public_coeffs_2());
        assert_ne!(public_coeffs_1, public_coeffs_2);
        let ni_dkg_id = ni_dkg_id_with_tag(tag.clone(), 1);

        store.insert_transcript_data(&ni_dkg_id, public_coeffs_1, BTreeMap::new(), REG_V1);
        store.insert_transcript_data(&ni_dkg_id, public_coeffs_2.clone(), BTreeMap::new(), REG_V1);

        let transcript_data = store.transcript_data(&ni_dkg_id).unwrap();
        assert_eq!(transcript_data.public_coefficients(), &public_coeffs_2);
    }
}

#[test]
fn should_overwrite_existing_indices() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let indices_1 = indices_with(vec![(node_test_id(NODE_1), NODE_1_INDEX)]);
        let indices_2 = indices_with(vec![(node_test_id(NODE_2), NODE_2_INDEX)]);
        let public_coeffs = public_coeffs();
        let ni_dkg_id = ni_dkg_id_with_tag(tag.clone(), 1);

        store.insert_transcript_data(&ni_dkg_id, public_coeffs.clone(), indices_1, REG_V1);
        store.insert_transcript_data(&ni_dkg_id, public_coeffs, indices_2, REG_V1);

        let transcript_data = store.transcript_data(&ni_dkg_id).unwrap();
        assert_eq!(transcript_data.index(node_test_id(NODE_1)), None);
        assert_eq!(
            transcript_data.index(node_test_id(NODE_2)),
            Some(&NODE_2_INDEX)
        );
    }
}

#[test]
fn should_overwrite_existing_registry_version() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let (reg_v1, reg_v2) = (REG_V1, REG_V2);
        assert_ne!(reg_v1, reg_v2);
        let ni_dkg_id = ni_dkg_id_with_tag(tag.clone(), 1);

        store.insert_transcript_data(&ni_dkg_id, public_coeffs(), BTreeMap::new(), reg_v1);
        store.insert_transcript_data(&ni_dkg_id, public_coeffs(), BTreeMap::new(), reg_v2);

        let transcript_data = store.transcript_data(&ni_dkg_id).unwrap();
        assert_eq!(transcript_data.registry_version(), reg_v2);
    }
}

#[test]
fn should_overwrite_existing_individual_public_keys() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let csp_pubkey_1 = csp_public_key();
        let csp_pubkey_2 = other_csp_public_key();
        assert_ne!(csp_pubkey_1, csp_pubkey_2);
        let ni_dkg_id = ni_dkg_id_with_tag(tag.clone(), 1);

        store.insert_individual_public_key(&ni_dkg_id, node_test_id(NODE_1), csp_pubkey_1);
        store.insert_individual_public_key(&ni_dkg_id, node_test_id(NODE_1), csp_pubkey_2);

        assert_eq!(
            store.individual_public_key(&ni_dkg_id, node_test_id(NODE_1)),
            Some(&csp_pubkey_2)
        );
    }
}

#[test]
fn should_not_purge_data_on_inserting_transcript_data_if_capacity_not_exceeded() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();

        for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY {
            store.insert_transcript_data(
                &ni_dkg_id_with_tag(tag.clone(), i),
                public_coeffs(),
                BTreeMap::new(),
                REG_V1,
            );
        }

        assert_eq!(
            store.store.len(),
            ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY
        );
    }
}

#[test]
fn should_not_purge_data_on_inserting_pubkeys_if_capacity_not_exceeded() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();

        for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY {
            store.insert_individual_public_key(
                &ni_dkg_id_with_tag(tag.clone(), i),
                node_test_id(NODE_1),
                csp_public_key(),
            );
        }

        assert_eq!(
            store.store.len(),
            ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY
        );
    }
}

#[test]
fn should_purge_data_on_inserting_transcript_data_if_capacity_exceeded() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let pub_coeffs = public_coeffs();
        let registry_version = REG_V1;

        for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1 {
            store.insert_transcript_data(
                &ni_dkg_id_with_tag(tag.clone(), i),
                pub_coeffs.clone(),
                BTreeMap::new(),
                registry_version,
            );
        }

        assert_eq!(
            store.store.len(),
            ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY
        );
        assert!(
            store
                .transcript_data(&ni_dkg_id_with_tag(tag.clone(), 1))
                .is_none()
        );
        for i in 2..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1 {
            assert_eq!(
                pub_coeffs_from_store(&store, ni_dkg_id_with_tag(tag.clone(), i)),
                pub_coeffs
            );
        }
    }
}

#[test]
fn should_purge_data_in_insertion_order_on_inserting_transcript_data_if_capacity_exceeded() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let pub_coeffs = public_coeffs();
        let registry_version = REG_V1;

        for i in (1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1).rev() {
            store.insert_transcript_data(
                &ni_dkg_id_with_tag(tag.clone(), i),
                pub_coeffs.clone(),
                BTreeMap::new(),
                registry_version,
            );
        }

        assert_eq!(
            store.store.len(),
            ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY
        );
        for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY {
            assert_eq!(
                pub_coeffs_from_store(&store, ni_dkg_id_with_tag(tag.clone(), i)),
                pub_coeffs
            );
        }
        assert!(
            store
                .transcript_data(&ni_dkg_id_with_tag(
                    tag.clone(),
                    ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1
                ))
                .is_none()
        );
    }
}

fn should_not_purge_all_transcripts_of_certain_threshold_if_capacity_exceeded(
    single_transcript_threshold: NiDkgTag,
    other_transcripts_threshold: NiDkgTag,
) {
    let mut store = ThresholdSigDataStoreImpl::new();
    let pub_coeffs = public_coeffs();
    let registry_version = REG_V1;

    store.insert_transcript_data(
        &ni_dkg_id_with_tag(single_transcript_threshold.clone(), 1),
        pub_coeffs.clone(),
        BTreeMap::new(),
        registry_version,
    );
    for i in 0..ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1 {
        store.insert_transcript_data(
            &ni_dkg_id_with_tag(other_transcripts_threshold.clone(), i),
            pub_coeffs.clone(),
            BTreeMap::new(),
            registry_version,
        );
    }

    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1
    );
    assert_store_length_invariant(&store);

    // verify there is at least one high threshold transcript and at least one low threshold transcript
    let mut found_single_threshold = false;
    let mut found_other_threshold = false;
    for (ni_dkg_id, _value) in store.store.iter() {
        if ni_dkg_id.dkg_tag == single_transcript_threshold {
            found_single_threshold = true;
        } else if ni_dkg_id.dkg_tag == other_transcripts_threshold {
            found_other_threshold = true;
        }
        if found_single_threshold && found_other_threshold {
            break;
        }
    }
    assert!(found_other_threshold);
    assert!(found_single_threshold);
}

#[test]
fn should_not_purge_only_transcripts_for_some_tag_if_capacity_exceeded() {
    for tag in all_tags() {
        for other_tag in all_tags() {
            if tag != other_tag {
                should_not_purge_all_transcripts_of_certain_threshold_if_capacity_exceeded(
                    tag.clone(),
                    other_tag,
                )
            }
        }
    }
}

#[test]
fn should_purge_data_on_inserting_pubkeys_if_capacity_exceeded() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let csp_pubkey = csp_public_key();
        let node_id = node_test_id(NODE_1);

        for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1 {
            store.insert_individual_public_key(
                &ni_dkg_id_with_tag(tag.clone(), i),
                node_id,
                csp_pubkey,
            );
        }

        assert_eq!(
            store.store.len(),
            ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY
        );
        for i in 2..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1 {
            assert_eq!(
                store.individual_public_key(&ni_dkg_id_with_tag(tag.clone(), i), node_id),
                Some(&csp_pubkey)
            );
        }
        assert_eq!(
            store.individual_public_key(&ni_dkg_id_with_tag(tag.clone(), 1), node_id),
            None
        );
    }
}

#[test]
fn should_purge_data_in_insertion_order_on_inserting_pubkeys_if_max_size_exceeded() {
    for tag in all_tags() {
        let mut store = ThresholdSigDataStoreImpl::new();
        let csp_pubkey = csp_public_key();
        let node_id = node_test_id(NODE_1);

        for i in (1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1).rev() {
            store.insert_individual_public_key(
                &ni_dkg_id_with_tag(tag.clone(), i),
                node_id,
                csp_pubkey,
            );
        }

        assert_eq!(
            store.store.len(),
            ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY
        );
        for i in 1..=ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY {
            assert_eq!(
                store.individual_public_key(&ni_dkg_id_with_tag(tag.clone(), i), node_id),
                Some(&csp_pubkey)
            );
        }
        assert_eq!(
            store.individual_public_key(
                &ni_dkg_id_with_tag(
                    tag.clone(),
                    ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY + 1
                ),
                node_id
            ),
            None
        );
    }
}

#[test]
fn should_store_up_to_capacity_per_tag_for_all_tags() {
    let mut store = ThresholdSigDataStoreImpl::new();
    let pub_coeffs = public_coeffs();
    let registry_version = REG_V1;

    for i in 0..ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY {
        for tag in all_tags() {
            store.insert_transcript_data(
                &ni_dkg_id_with_tag(tag.clone(), i),
                pub_coeffs.clone(),
                BTreeMap::new(),
                registry_version,
            );
        }
    }

    // Verify we have exactly the max capacity stored
    assert_max_store_capacity(&store);
    assert_store_length_invariant(&store);

    // Insert one more transcript per tag
    for tag in all_tags() {
        store.insert_transcript_data(
            &ni_dkg_id_with_tag(tag, ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY),
            pub_coeffs.clone(),
            BTreeMap::new(),
            registry_version,
        );
    }

    // Verify that we still have exactly the max capacity stored (since one of each tag was purged)
    assert_max_store_capacity(&store);
    assert_store_length_invariant(&store);
}

fn indices_with(mappings: Vec<(NodeId, NodeIndex)>) -> BTreeMap<NodeId, NodeIndex> {
    let mut indices = BTreeMap::new();
    for (node_id, index) in mappings {
        indices.insert(node_id, index);
    }
    indices
}

fn csp_public_key() -> CspThresholdSigPublicKey {
    CspThresholdSigPublicKey::ThresBls12_381(PublicKeyBytes([42; PublicKeyBytes::SIZE]))
}

fn other_csp_public_key() -> CspThresholdSigPublicKey {
    CspThresholdSigPublicKey::ThresBls12_381(PublicKeyBytes([43; PublicKeyBytes::SIZE]))
}

fn public_coeffs() -> CspPublicCoefficients {
    public_coeffs_1()
}

fn public_coeffs_1() -> CspPublicCoefficients {
    CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([1; PublicKeyBytes::SIZE])],
    })
}

fn public_coeffs_2() -> CspPublicCoefficients {
    CspPublicCoefficients::Bls12_381(PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([2; PublicKeyBytes::SIZE])],
    })
}

fn pub_coeffs_from_store(
    store: &ThresholdSigDataStoreImpl,
    dkg_id: NiDkgId,
) -> CspPublicCoefficients {
    store
        .transcript_data(&dkg_id)
        .expect("Expecting transcript data to be present for dkg id")
        .public_coefficients()
        .clone()
}

fn ni_dkg_id(i: usize) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::new(i as u64),
        dealer_subnet: SUBNET_1,
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NI_DKG_ID_1.target_subnet,
    }
}

fn ni_dkg_id_with_tag(ni_dkg_tag: NiDkgTag, height: usize) -> NiDkgId {
    NiDkgId {
        dkg_tag: ni_dkg_tag,
        ..ni_dkg_id(height)
    }
}

fn all_tags() -> Vec<NiDkgTag> {
    assert_eq!(NiDkgMasterPublicKeyId::COUNT, 1);
    assert_eq!(VetKdCurve::iter().count(), 1);
    vec![
        NiDkgTag::LowThreshold,
        NiDkgTag::HighThreshold,
        NiDkgTag::HighThresholdForKey(vetkd_master_public_key_id()),
    ]
}

fn vetkd_master_public_key_id() -> NiDkgMasterPublicKeyId {
    NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: "vetkd_bls12_381_g2_key".to_string(),
    })
}

fn assert_max_store_capacity(store: &ThresholdSigDataStoreImpl) {
    assert_eq!(
        store.store.len(),
        ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY * 2
            + ThresholdSigDataStoreImpl::CAPACITY_PER_TAG_OR_KEY * (all_tags().len() - 2)
    );
}

fn assert_store_length_invariant(store: &ThresholdSigDataStoreImpl) {
    let high_threshold_for_key_id_dkg_id_insertion_order_len: usize = store
        .high_threshold_for_key_dkg_id_insertion_order
        .values()
        .map(|v| v.len())
        .sum();
    assert_eq!(
        store.store.len(),
        store.low_threshold_dkg_id_insertion_order.len()
            + store.high_threshold_dkg_id_insertion_order.len()
            + high_threshold_for_key_id_dkg_id_insertion_order_len,
        "ThresholdSigDataStore length invariant violated"
    );
}
