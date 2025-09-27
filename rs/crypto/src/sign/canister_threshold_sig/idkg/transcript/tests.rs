use super::*;
use assert_matches::assert_matches;
use ic_types::crypto::AlgorithmId;

mod ensure_sufficient_openings {
    use super::*;
    use crate::sign::canister_threshold_sig::idkg::transcript::tests::ensure_matching_transcript_ids_and_dealer_ids::{Setup, TRANSCRIPT_ID, DEALER_ID, DEALER_INDEX, OpeningIds};
    use crate::sign::canister_threshold_sig::idkg::transcript::ensure_sufficient_openings;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
    use ic_types_test_utils::ids::NODE_3;
    use ic_types_test_utils::ids::NODE_4;

    #[test]
    fn should_return_error_if_not_enough_openings() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![OpeningIds {
                    node_id: NODE_3,
                    ..Default::default()
                }],
            )
            .build();
        assert_eq!(setup.transcript.reconstruction_threshold().get(), 2);

        let result = ensure_sufficient_openings(&setup.openings, &setup.transcript);

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::InsufficientOpenings { internal_error })
            if internal_error == "insufficient number of openings: got 1, but required 2"
        );
    }

    #[test]
    fn should_return_ok_if_enough_openings() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![
                    OpeningIds {
                        node_id: NODE_3,
                        ..Default::default()
                    },
                    OpeningIds {
                        node_id: NODE_4,
                        ..Default::default()
                    },
                ],
            )
            .build();
        assert_eq!(setup.transcript.reconstruction_threshold().get(), 2);

        let result = ensure_sufficient_openings(&setup.openings, &setup.transcript);

        assert_matches!(result, Ok(()));
    }
}

mod ensure_matching_transcript_ids_and_dealer_ids {
    use super::*;
    use crate::sign::canister_threshold_sig::idkg::IDkgComplaint;
    use crate::sign::canister_threshold_sig::idkg::IDkgOpening;
    use crate::sign::canister_threshold_sig::idkg::transcript::IDkgTranscript;
    use crate::sign::canister_threshold_sig::idkg::transcript::IDkgTranscriptType;
    use crate::sign::canister_threshold_sig::idkg::transcript::ensure_matching_transcript_ids_and_dealer_ids;
    use crate::sign::canister_threshold_sig::test_utils::batch_signed_dealing_with;
    use crate::sign::canister_threshold_sig::test_utils::node_set;
    use crate::sign::tests::REG_V1;
    use ic_base_types::NodeId;
    use ic_crypto_test_utils::map_of;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_transcript_id_for_tests;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgMaskedTranscriptOrigin;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgReceivers;
    use ic_types_test_utils::ids::NODE_1;
    use ic_types_test_utils::ids::NODE_2;
    use ic_types_test_utils::ids::NODE_3;
    use ic_types_test_utils::ids::NODE_4;
    use std::collections::BTreeMap;

    pub(crate) const DEALER_ID: NodeId = NODE_2;
    pub(crate) const DEALER_INDEX: NodeIndex = 2;
    pub(crate) const TRANSCRIPT_ID: u64 = 42;

    #[test]
    fn should_return_ok_if_openings_empty() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID).build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(result, Ok(()));
    }

    #[test]
    fn should_return_ok_for_single_complaint_with_two_openings() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![
                    OpeningIds::default(),
                    OpeningIds {
                        node_id: NODE_2,
                        ..Default::default()
                    },
                ],
            )
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(result, Ok(()));
    }

    #[test]
    fn should_return_ok_for_two_complaints_each_with_two_openings() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![
                    OpeningIds::default(),
                    OpeningIds {
                        node_id: NODE_2,
                        ..Default::default()
                    },
                ],
            )
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![
                    OpeningIds::default(),
                    OpeningIds {
                        node_id: NODE_2,
                        ..Default::default()
                    },
                ],
            )
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(result, Ok(()));
    }

    #[test]
    fn should_return_error_for_two_complaints_each_with_two_openings_but_one_has_wrong_dealer_id() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![
                    OpeningIds::default(),
                    OpeningIds {
                        node_id: NODE_2,
                        ..Default::default()
                    },
                ],
            )
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![
                    OpeningIds::default(),
                    OpeningIds {
                        node_id: NODE_2,
                        dealer_id: NODE_3,
                        ..Default::default()
                    },
                ],
            )
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
            if internal_error.contains("mismatching dealer IDs in opening")
        );
    }

    #[test]
    fn should_return_error_for_two_complaints_each_with_two_openings_but_one_has_wrong_transcript_id()
     {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![
                    OpeningIds::default(),
                    OpeningIds {
                        node_id: NODE_2,
                        ..Default::default()
                    },
                ],
            )
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![
                    OpeningIds::default(),
                    OpeningIds {
                        node_id: NODE_2,
                        transcript_id: TRANSCRIPT_ID + 1,
                        ..Default::default()
                    },
                ],
            )
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
            if internal_error.contains("mismatching transcript IDs in opening")
        );
    }

    #[test]
    fn should_return_ok_for_single_complaint_with_one_opening() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![OpeningIds::default()],
            )
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(result, Ok(()));
    }

    #[test]
    fn should_return_ok_for_single_complaint_and_no_openings() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(TRANSCRIPT_ID, vec![])
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(result, Ok(()));
    }

    #[test]
    fn should_return_error_if_transcript_id_mismatch_between_single_complaint_and_transcript() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(TRANSCRIPT_ID + 1, vec![])
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
            if internal_error.contains("mismatching transcript IDs in complaint")
        );
    }

    #[test]
    fn should_return_error_for_single_complaint_and_transcript_id_mismatch_in_opening() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![OpeningIds {
                    transcript_id: TRANSCRIPT_ID + 1,
                    ..Default::default()
                }],
            )
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
            if internal_error.contains("mismatching transcript IDs in opening")
        );
    }

    #[test]
    fn should_return_error_for_single_complaint_and_dealer_id_mismatch_in_opening() {
        let setup = Setup::builder(DEALER_ID, DEALER_INDEX, TRANSCRIPT_ID)
            .with_complaint_transcript_id_and_opening_ids(
                TRANSCRIPT_ID,
                vec![OpeningIds {
                    dealer_id: NODE_1,
                    ..Default::default()
                }],
            )
            .build();

        let result =
            ensure_matching_transcript_ids_and_dealer_ids(&setup.openings, &setup.transcript);

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::InvalidArguments { internal_error })
            if internal_error.contains("mismatching dealer IDs in opening")
        );
    }

    pub(crate) struct OpeningIds {
        pub(crate) node_id: NodeId,
        pub(crate) transcript_id: u64,
        pub(crate) dealer_id: NodeId,
    }

    impl Default for OpeningIds {
        fn default() -> Self {
            OpeningIds {
                node_id: NODE_1,
                transcript_id: TRANSCRIPT_ID,
                dealer_id: DEALER_ID,
            }
        }
    }

    pub(crate) struct Setup {
        pub(crate) openings: BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
        pub(crate) transcript: IDkgTranscript,
    }

    impl Setup {
        pub(crate) fn builder(
            dealer_id: NodeId,
            dealer_index: NodeIndex,
            transcript_id: u64,
        ) -> SetupBuilder {
            SetupBuilder {
                dealer_id,
                dealer_index,
                transcript_id,
                complaint_transcript_ids: BTreeMap::new(),
            }
        }
    }

    pub(crate) struct SetupBuilder {
        dealer_id: NodeId,
        dealer_index: NodeIndex,
        transcript_id: u64,
        complaint_transcript_ids: BTreeMap<u64, Vec<OpeningIds>>,
    }

    impl SetupBuilder {
        pub(crate) fn with_complaint_transcript_id_and_opening_ids(
            mut self,
            complaint_transcript_id: u64,
            opening_ids: Vec<OpeningIds>,
        ) -> Self {
            self.complaint_transcript_ids
                .insert(complaint_transcript_id, opening_ids);
            self
        }

        pub(crate) fn build(self) -> Setup {
            let transcript_id = dummy_idkg_transcript_id_for_tests(self.transcript_id);
            let verified_dealings = map_of(vec![(
                self.dealer_index,
                batch_signed_dealing_with(vec![], self.dealer_id),
            )]);
            let transcript = IDkgTranscript {
                transcript_id,
                receivers: IDkgReceivers::new(node_set(&[NODE_1, NODE_2, NODE_3, NODE_4]))
                    .expect("creation of receivers should succeed"),
                registry_version: REG_V1,
                verified_dealings: Arc::new(verified_dealings),
                transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
                algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                internal_transcript_raw: vec![],
            };
            let mut openings = BTreeMap::new();
            for (complaint_transcript_id, opening_ids) in self.complaint_transcript_ids {
                let complaint = IDkgComplaint {
                    transcript_id: dummy_idkg_transcript_id_for_tests(complaint_transcript_id),
                    dealer_id: self.dealer_id,
                    internal_complaint_raw: vec![],
                };
                let mut openings_map = BTreeMap::new();
                for opening_id in opening_ids {
                    let opening = IDkgOpening {
                        transcript_id: dummy_idkg_transcript_id_for_tests(opening_id.transcript_id),
                        dealer_id: opening_id.dealer_id,
                        internal_opening_raw: vec![],
                    };
                    openings_map.insert(opening_id.node_id, opening);
                }
                openings.insert(complaint, openings_map);
            }
            Setup {
                openings,
                transcript,
            }
        }
    }
}

mod load_transcript_serialization_error {
    use super::*;
    use crate::sign::canister_threshold_sig::idkg::transcript::load_transcript;
    use crate::sign::canister_threshold_sig::test_utils::batch_signed_dealing_with;
    use crate::sign::canister_threshold_sig::test_utils::node_set;
    use crate::sign::tests::REG_V1;
    use ic_base_types::NodeId;
    use ic_crypto_test_utils::map_of;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_transcript_id_for_tests;
    use ic_crypto_test_utils_keys::public_keys::valid_idkg_dealing_encryption_public_key;
    use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_registry_keys::make_crypto_node_key;
    use ic_types::crypto::canister_threshold_sig::error::IDkgLoadTranscriptError;
    use ic_types::crypto::canister_threshold_sig::idkg::{
        IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscriptType,
    };
    use ic_types::crypto::{AlgorithmId, KeyPurpose};
    use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4};
    use prost::Message;
    use std::sync::Arc;

    const DEALER_ID: NodeId = NODE_2;
    const DEALER_INDEX: NodeIndex = 2;

    #[test]
    fn should_fail_with_serialization_error_when_internal_dealing_raw_is_invalid() {
        // Create a BatchSignedIDkgDealing with invalid (empty) internal_dealing_raw
        let invalid_dealing = batch_signed_dealing_with(vec![], DEALER_ID);
        let invalid_verified_dealings = map_of(vec![(DEALER_INDEX, invalid_dealing)]);

        let transcript = IDkgTranscript {
            transcript_id: dummy_idkg_transcript_id_for_tests(42),
            receivers: IDkgReceivers::new(node_set(&[NODE_1, NODE_2, NODE_3, NODE_4]))
                .expect("creation of receivers should succeed"),
            registry_version: REG_V1,
            verified_dealings: Arc::new(invalid_verified_dealings),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };

        let result = load_transcript(
            &(Arc::new(MockLocalCspVault::new()) as _),
            &NODE_1,
            &mock_registry_with_valid_mega_pubkey_for_node(NODE_1),
            &transcript,
        );

        assert_matches!(
            result,
            Err(IDkgLoadTranscriptError::SerializationError { internal_error })
            if internal_error.contains("failed to deserialize internal dealing")
        );
    }

    fn mock_registry_with_valid_mega_pubkey_for_node(node_id: NodeId) -> MockRegistryClient {
        // Set up MockRegistryClient to return a valid mega public key for NODE_1
        let mut registry = MockRegistryClient::new();
        let registry_key = make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption);
        let mut idkg_dealing_encryption_public_key_bytes = Vec::new();
        valid_idkg_dealing_encryption_public_key()
            .encode(&mut idkg_dealing_encryption_public_key_bytes)
            .expect("encoding public key should succeed");
        let registry_key_clone = registry_key.clone();
        registry
            .expect_get_value()
            .withf(move |key, version| key == registry_key_clone.as_str() && version == &REG_V1)
            .return_const(Ok(Some(idkg_dealing_encryption_public_key_bytes)));
        registry
    }
}
