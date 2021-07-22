use super::*;
use crate::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetSubnet};
use crate::{Height, PrincipalId, SubnetId};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;

pub const NODE_1: u64 = 1;
pub const NODE_2: u64 = 2;
pub const NODE_3: u64 = 3;
pub const NODE_4: u64 = 4;

pub const REG_V1: RegistryVersion = RegistryVersion::new(1);
pub const REG_V2: RegistryVersion = RegistryVersion::new(2);

#[test]
fn should_succeed_creating_valid_config() {
    assert!(NiDkgConfig::new(valid_dkg_config_data()).is_ok());
}

#[test]
fn should_succeed_creating_valid_config_for_single_node() {
    let resharing_transcript = NiDkgTranscript {
        dkg_id: dkg_id(2),
        threshold: dkg_threshold(1),
        committee: NiDkgReceivers::new(set_of(&[node_id(NODE_1)])).unwrap(),
        registry_version: REG_V1,
        internal_csp_transcript: CspNiDkgTranscript::placeholder_to_delete(),
    };
    let config_data = NiDkgConfigData {
        dkg_id: dkg_id(1),
        max_corrupt_dealers: NumberOfNodes::new(0),
        dealers: set_of(&[node_id(NODE_1)]),
        max_corrupt_receivers: NumberOfNodes::new(0),
        receivers: set_of(&[node_id(NODE_1)]),
        threshold: NumberOfNodes::new(1),
        registry_version: REG_V2,
        resharing_transcript: Some(resharing_transcript),
    };
    assert!(NiDkgConfig::new(config_data).is_ok());
}

#[test]
fn should_fail_if_threshold_zero() {
    let threshold = NumberOfNodes::new(0);
    let config_data = NiDkgConfigData {
        threshold,
        ..valid_dkg_config_data()
    };

    let result = NiDkgConfig::new(config_data);

    assert_eq!(
        result.unwrap_err(),
        NiDkgConfigValidationError::ThresholdZero
    );
}

#[test]
fn should_fail_if_insufficient_threshold() {
    for (threshold, max_corrupt_receivers) in &[(1, 1), (1, 2), (2, 2), (4, 5), (7, 7)] {
        let threshold = NumberOfNodes::new(*threshold);
        let max_corrupt_receivers = NumberOfNodes::new(*max_corrupt_receivers);
        let config_data = NiDkgConfigData {
            max_corrupt_receivers,
            threshold,
            ..valid_dkg_config_data()
        };

        let result = NiDkgConfig::new(config_data);

        assert_eq!(
            result.unwrap_err(),
            NiDkgConfigValidationError::InsufficientThreshold {
                threshold: dkg_threshold(threshold.get()),
                max_corrupt_receivers,
            }
        );
    }
}

#[test]
fn should_fail_if_insufficient_dealers() {
    let max_corrupt_dealers = NumberOfNodes::new(1);
    let dealers = set_of(&[node_id(NODE_1)]);
    let config_data = NiDkgConfigData {
        max_corrupt_dealers,
        dealers,
        ..valid_dkg_config_data()
    };

    let result = NiDkgConfig::new(config_data);

    assert_eq!(
        result.unwrap_err(),
        NiDkgConfigValidationError::InsufficientDealers {
            dealer_count: NumberOfNodes::new(1),
            max_corrupt_dealers,
        }
    );
}

#[test]
fn should_fail_if_insufficient_receivers() {
    let max_corrupt_receivers = NumberOfNodes::new(1);
    let receivers = set_of(&[node_id(NODE_1), node_id(NODE_2)]);
    let threshold = 2;
    let config_data = NiDkgConfigData {
        max_corrupt_receivers,
        receivers,
        threshold: NumberOfNodes::new(threshold),
        ..valid_dkg_config_data()
    };

    let result = NiDkgConfig::new(config_data);

    assert_eq!(
        result.unwrap_err(),
        NiDkgConfigValidationError::InsufficientReceivers {
            receiver_count: NumberOfNodes::new(2),
            max_corrupt_receivers,
            threshold: dkg_threshold(threshold),
        }
    );
}

#[test]
fn should_not_overflow_when_ensuring_sufficient_receivers() {
    let max_corrupt_receivers = NumberOfNodes::new(NodeIndex::MAX - 1);
    let receivers = set_of(&[node_id(NODE_1), node_id(NODE_2)]);
    let threshold = NodeIndex::MAX;
    let config_data = NiDkgConfigData {
        max_corrupt_receivers,
        receivers,
        threshold: NumberOfNodes::new(threshold),
        ..valid_dkg_config_data()
    };

    let result = NiDkgConfig::new(config_data);

    assert_eq!(
        result.unwrap_err(),
        NiDkgConfigValidationError::InsufficientReceivers {
            receiver_count: NumberOfNodes::new(2),
            max_corrupt_receivers,
            threshold: dkg_threshold(threshold),
        }
    );
}

#[test]
fn should_fail_if_dealers_not_in_resharing_committee() {
    let dealers =
        NiDkgDealers::new(set_of(&[node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)])).unwrap();
    let resharing_transcript =
        transcript_with_committee(set_of(&[node_id(NODE_1), node_id(NODE_2), node_id(NODE_4)]));
    let config_data = NiDkgConfigData {
        dealers: dealers.get().clone(),
        resharing_transcript: Some(resharing_transcript.clone()),
        ..valid_dkg_config_data()
    };

    let result = NiDkgConfig::new(config_data);

    assert_eq!(
        result.unwrap_err(),
        NiDkgConfigValidationError::DealersNotInResharingCommittee {
            dealers_missing: set_of(&[node_id(NODE_3)]),
            dealers_existing: set_of(&[node_id(NODE_1), node_id(NODE_2)]),
            resharing_committee: resharing_transcript.committee.get().clone(),
        }
    );
}

#[test]
fn should_fail_if_insufficient_dealers_for_resharing_threshold() {
    let dealers = set_of(&[node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)]);
    let resharing_threshold = dkg_threshold(4);
    let config_data = NiDkgConfigData {
        dealers,
        resharing_transcript: Some(transcript_with_threshold(resharing_threshold)),
        ..valid_dkg_config_data()
    };

    let result = NiDkgConfig::new(config_data);

    assert_eq!(
        result.unwrap_err(),
        NiDkgConfigValidationError::InsufficientDealersForResharingThreshold {
            dealer_count: NumberOfNodes::new(3),
            resharing_threshold,
        }
    );
}

#[test]
fn should_return_correct_config_values() {
    let dkg_id = dkg_id(1);
    let max_corrupt_dealers = NumberOfNodes::new(1);
    let dealers = set_of(&[node_id(NODE_1), node_id(NODE_2)]);
    let max_corrupt_receivers = NumberOfNodes::new(1);
    let receivers = set_of(&[node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)]);
    let threshold = 2;
    let registry_version = REG_V1;
    let resharing_transcript = Some(transcript());

    let config_data = NiDkgConfigData {
        dkg_id,
        max_corrupt_dealers,
        dealers: dealers.clone(),
        max_corrupt_receivers,
        receivers: receivers.clone(),
        threshold: NumberOfNodes::new(threshold),
        registry_version,
        resharing_transcript: resharing_transcript.clone(),
    };

    let config = NiDkgConfig::new(config_data).unwrap();

    assert_eq!(config.dkg_id(), dkg_id);
    assert_eq!(config.max_corrupt_dealers(), max_corrupt_dealers);
    assert_eq!(config.dealers().get(), &dealers);
    assert_eq!(config.max_corrupt_receivers(), max_corrupt_receivers);
    assert_eq!(config.receivers().get(), &receivers);
    assert_eq!(config.threshold(), dkg_threshold(threshold));
    assert_eq!(config.registry_version(), registry_version);
    assert_eq!(config.resharing_transcript(), &resharing_transcript);
}

#[test]
// This is explicitly tested since this appears in debug log messages. The
// message should be well readable and in particular contain hex encodings where
// applicable.
//
// The format of the subnet ids is specified in the interface spec:
// https://sdk.dfinity.org/docs/interface-spec/index.html#textual-ids
fn should_correctly_format_config_display_message() {
    let config = NiDkgConfig::new(valid_dkg_config_data());

    let display_text = format!("{}", config.unwrap());

    assert_eq!(display_text,
               "NiDkgConfig { \
                    dkg_id: NiDkgId { \
                        start_block_height: 1, \
                        dealer_subnet: yndj2-3ybaa-aaaaa-aaaap-yai, \
                        dkg_tag: HighThreshold, \
                        target_subnet: Local \
                        }, \
                    max_corrupt_dealers: 1, \
                    dealers: NiDkgDealers { dealers: {3jo2y-lqbaa-aaaaa-aaaap-2ai, gfvbo-licaa-aaaaa-aaaap-2ai, 32uhy-eydaa-aaaaa-aaaap-2ai}, count: 3 }, \
                    max_corrupt_receivers: 1, \
                    receivers: NiDkgReceivers { receivers: {3jo2y-lqbaa-aaaaa-aaaap-2ai, gfvbo-licaa-aaaaa-aaaap-2ai, 32uhy-eydaa-aaaaa-aaaap-2ai}, count: 3 }, \
                    threshold: NiDkgThreshold { threshold: 2 }, \
                    registry_version: 1, \
                    resharing_transcript: Some(NiDkgTranscript { \
                        dkg_id: NiDkgId { \
                            start_block_height: 2, \
                            dealer_subnet: fbysm-3acaa-aaaaa-aaaap-yai, \
                            dkg_tag: HighThreshold, \
                            target_subnet: Local \
                            }, \
                        threshold: NiDkgThreshold { threshold: 2 }, \
                        committee: NiDkgReceivers { receivers: {3jo2y-lqbaa-aaaaa-aaaap-2ai, gfvbo-licaa-aaaaa-aaaap-2ai, 32uhy-eydaa-aaaaa-aaaap-2ai}, count: 3 }, \
                        registry_version: 2, \
                        internal_csp_transcript: Groth20_Bls12_381(Transcript { public_coefficients: PublicCoefficientsBytes { coefficients: [0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000] }, receiver_data: {} }) }) \
                        }"
    );
}

fn dkg_id(i: u64) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::new(i),
        dealer_subnet: SubnetId::from(PrincipalId::new_subnet_test_id(i)),
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NiDkgTargetSubnet::Local,
    }
}

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

fn set_of<T: Ord + Clone>(items: &[T]) -> BTreeSet<T> {
    let mut set = BTreeSet::new();
    for item in items {
        assert!(set.insert(item.clone()));
    }
    set
}

fn valid_dkg_config_data() -> NiDkgConfigData {
    NiDkgConfigData {
        dkg_id: dkg_id(1),
        max_corrupt_dealers: NumberOfNodes::new(1),
        dealers: set_of(&[node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)]),
        max_corrupt_receivers: NumberOfNodes::new(1),
        receivers: set_of(&[node_id(NODE_1), node_id(NODE_2), node_id(NODE_3)]),
        threshold: NumberOfNodes::new(2),
        registry_version: REG_V1,
        resharing_transcript: Some(transcript()),
    }
}

fn transcript() -> NiDkgTranscript {
    NiDkgTranscript {
        dkg_id: dkg_id(2),
        threshold: dkg_threshold(2),
        committee: NiDkgReceivers::new(set_of(&[
            node_id(NODE_1),
            node_id(NODE_2),
            node_id(NODE_3),
        ]))
        .unwrap(),
        registry_version: REG_V2,
        internal_csp_transcript: CspNiDkgTranscript::placeholder_to_delete(),
    }
}

fn transcript_with_committee(committee: BTreeSet<NodeId>) -> NiDkgTranscript {
    NiDkgTranscript {
        committee: NiDkgReceivers::new(committee).expect("could not create committee"),
        ..transcript()
    }
}

fn transcript_with_threshold(threshold: NiDkgThreshold) -> NiDkgTranscript {
    NiDkgTranscript {
        threshold,
        ..transcript()
    }
}

fn dkg_threshold(threshold: u32) -> NiDkgThreshold {
    NiDkgThreshold::new(NumberOfNodes::new(threshold)).unwrap()
}

mod threshold {
    use super::*;

    #[test]
    fn should_create_nonzero_threshold() {
        let threshold = NumberOfNodes::from(42);
        let result = NiDkgThreshold::new(threshold);

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_correct_threshold() {
        let threshold = NumberOfNodes::from(42);
        let result = NiDkgThreshold::new(threshold);

        assert_eq!(result.unwrap().get(), threshold);
    }

    #[test]
    fn should_fail_if_threshold_is_zero() {
        let threshold = NumberOfNodes::from(0);
        let result = NiDkgThreshold::new(threshold);

        assert_eq!(result, Err(NiDkgThresholdZeroError {}));
    }
}

// We test this private method here since testing it when used in `NiDkgDealers`
// and `NiDkgReceivers` is too expensive as very long vectors would have to be
// created.
mod number_of_nodes_from_usize {
    use super::*;

    #[test]
    fn should_fail_if_usize_too_large_for_number_of_nodes() {
        let usize_too_large_for_number_of_nodes = NodeIndex::try_from(usize::MAX).is_err();

        assert_eq!(
            usize_too_large_for_number_of_nodes,
            number_of_nodes_from_usize(usize::MAX).is_err()
        );
    }

    #[test]
    fn should_succeed_if_usize_fits_into_number_of_nodes() {
        let usize_fits_into_number_of_nodes = NodeIndex::try_from(usize::MAX).is_ok();

        assert_eq!(
            usize_fits_into_number_of_nodes,
            number_of_nodes_from_usize(usize::MAX).is_ok()
        );
    }
}
