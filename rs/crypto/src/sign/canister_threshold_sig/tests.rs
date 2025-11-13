mod get_master_public_key_from_transcript {
    use crate::get_master_public_key_from_transcript;
    use crate::sign::canister_threshold_sig::MasterPublicKeyExtractionError;
    use crate::sign::tests::REG_V1;
    use assert_matches::assert_matches;
    use ic_base_types::SubnetId;
    use ic_crypto_internal_threshold_sig_canister_threshold_sig::IDkgTranscriptInternal;
    use ic_crypto_test_utils::set_of;
    use ic_types::Height;
    use ic_types::PrincipalId;
    use ic_types::crypto::AlgorithmId;
    use ic_types::crypto::canister_threshold_sig::MasterPublicKey;
    use ic_types::crypto::canister_threshold_sig::idkg::{
        IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
        IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
    };
    use ic_types_test_utils::ids::NODE_1;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use strum::IntoEnumIterator;

    #[test]
    fn should_return_error_if_transcript_type_is_masked() {
        for alg in all_canister_threshold_algorithms() {
            let transcript = dummy_transcript(
                IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
                alg,
                vec![],
            );

            assert_matches!(
                get_master_public_key_from_transcript(&transcript),
                Err(MasterPublicKeyExtractionError::CannotExtractFromMasked)
            );
        }
    }

    #[test]
    fn should_return_error_if_internal_transcript_cannot_be_deserialized() {
        for alg in all_canister_threshold_algorithms() {
            let transcript = dummy_transcript(
                IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(
                    dummy_transcript_id(),
                )),
                alg,
                vec![],
            );

            assert_matches!(
                get_master_public_key_from_transcript(&transcript),
                Err(MasterPublicKeyExtractionError::SerializationError( error ))
                    if error.contains("SerializationError")
            );
        }
    }

    #[test]
    fn should_return_error_if_algorithm_id_is_invalid() {
        AlgorithmId::iter()
            .filter(|algorithm_id| {
                !algorithm_id.is_threshold_ecdsa() && !algorithm_id.is_threshold_schnorr()
            })
            .for_each(|wrong_algorithm_id| {
                let transcript = dummy_transcript(
                    IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(
                        dummy_transcript_id(),
                    )),
                    wrong_algorithm_id,
                    valid_internal_transcript_raw(AlgorithmId::ThresholdEcdsaSecp256k1)
                        .serialize()
                        .expect("serialization of internal transcript raw should succeed"),
                );

                assert_matches!(
                    get_master_public_key_from_transcript(&transcript),
                    Err(MasterPublicKeyExtractionError::UnsupportedAlgorithm(_))
                );
            });
    }

    #[test]
    fn should_return_master_threshold_public_key() {
        for alg in all_canister_threshold_algorithms() {
            let transcript = dummy_transcript(
                IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(
                    dummy_transcript_id(),
                )),
                alg,
                valid_internal_transcript_raw(alg)
                    .serialize()
                    .expect("serialization of internal transcript raw should succeed"),
            );
            let expected_valid_master_public_key = valid_master_public_key(alg);

            assert_matches!(
                get_master_public_key_from_transcript(&transcript),
                Ok(master_public_key)
                    if master_public_key == expected_valid_master_public_key
            );
        }
    }

    /// Retrieved from a successful execution of
    /// `ic_crypto_internal_threshold_sig_canister_threshold_sig::transcript::new`.
    const VALID_SECP256K1_INTERNAL_TRANSCRIPT_RAW: &str = "a173636f6d62696e65645f636f6d6d69746d656e74a16b427953756d6d6174696f\
        6ea168506564657273656ea166706f696e7473825822010252a937b4c129d822412\
        d79f39d3626f32e7a1cf85ba1dfb01c9671d7d434003f582201025b168f9f47284b\
        ed02b26197840033de1668d53ef8f4d6928b61cc7efec2a838";

    const VALID_SECP256R1_INTERNAL_TRANSCRIPT_RAW: &str = "a173636f6d62696e65645f636f6d6d69746d656e74a16b427953756d6d6174696f\
         6ea168506564657273656ea166706f696e7473825822020279474d9bb87dce85dc\
         fc0786c9b4a4ddcb662e36fd716c42a0781fa05d208afb58220203915ca5584abf\
         0abd9e71fb68561d607a96c61bf621c8092d7ea00677f5324829";

    const VALID_ED25519_INTERNAL_TRANSCRIPT_RAW: &str = "a173636f6d62696e65645f636f6d6d69746d656e74a16b427953756d6d6174696f\
        6ea168506564657273656ea166706f696e747381582103f9f047c9125b490f118c7\
        281a2091593d47f83197542e2fd956bf979ec97d26d";

    fn valid_internal_transcript_raw(alg: AlgorithmId) -> IDkgTranscriptInternal {
        match alg {
            AlgorithmId::ThresholdEcdsaSecp256k1 | AlgorithmId::ThresholdSchnorrBip340 => {
                IDkgTranscriptInternal::deserialize(
                    &hex::decode(VALID_SECP256K1_INTERNAL_TRANSCRIPT_RAW)
                        .expect("hex decoding of valid internal transcript raw should succeed"),
                )
                .expect("deserialization of valid internal transcript raw bytes should succeed")
            }
            AlgorithmId::ThresholdEcdsaSecp256r1 => IDkgTranscriptInternal::deserialize(
                &hex::decode(VALID_SECP256R1_INTERNAL_TRANSCRIPT_RAW)
                    .expect("hex decoding of valid internal transcript raw should succeed"),
            )
            .expect("deserialization of valid internal transcript raw bytes should succeed"),
            AlgorithmId::ThresholdEd25519 => IDkgTranscriptInternal::deserialize(
                &hex::decode(VALID_ED25519_INTERNAL_TRANSCRIPT_RAW)
                    .expect("hex decoding of valid internal transcript raw should succeed"),
            )
            .expect("deserialization of valid internal transcript raw bytes should succeed"),
            unexpected => {
                panic!("Unexpected canister threshold algorithm {unexpected}");
            }
        }
    }

    fn valid_master_public_key(alg: AlgorithmId) -> MasterPublicKey {
        match alg {
            AlgorithmId::ThresholdEcdsaSecp256k1 => MasterPublicKey {
                algorithm_id: AlgorithmId::EcdsaSecp256k1,
                public_key: hex::decode(
                    "0252a937b4c129d822412d79f39d3626f32e7a1cf85ba1dfb01c9671d7d434003f",
                )
                .expect("hex decoding of public key bytes should succeed"),
            },
            AlgorithmId::ThresholdEcdsaSecp256r1 => MasterPublicKey {
                algorithm_id: AlgorithmId::EcdsaP256,
                public_key: hex::decode(
                    "0279474d9bb87dce85dcfc0786c9b4a4ddcb662e36fd716c42a0781fa05d208afb",
                )
                .expect("hex decoding of public key bytes should succeed"),
            },
            AlgorithmId::ThresholdSchnorrBip340 => MasterPublicKey {
                algorithm_id: AlgorithmId::SchnorrSecp256k1,
                public_key: hex::decode(
                    "0252a937b4c129d822412d79f39d3626f32e7a1cf85ba1dfb01c9671d7d434003f",
                )
                .expect("hex decoding of public key bytes should succeed"),
            },
            AlgorithmId::ThresholdEd25519 => MasterPublicKey {
                algorithm_id: AlgorithmId::Ed25519,
                public_key: hex::decode(
                    "f9f047c9125b490f118c7281a2091593d47f83197542e2fd956bf979ec97d26d",
                )
                .expect("hex decoding of public key bytes should succeed"),
            },
            unexpected => {
                panic!("Unexpected threshold ECDSA algorithm {unexpected}");
            }
        }
    }

    fn dummy_transcript_id() -> IDkgTranscriptId {
        IDkgTranscriptId::new(
            SubnetId::from(PrincipalId::new_subnet_test_id(42)),
            0,
            Height::new(0),
        )
    }

    fn dummy_transcript(
        transcript_type: IDkgTranscriptType,
        algorithm_id: AlgorithmId,
        internal_transcript_raw: Vec<u8>,
    ) -> IDkgTranscript {
        IDkgTranscript {
            verified_dealings: Arc::new(BTreeMap::new()),
            transcript_id: dummy_transcript_id(),
            receivers: IDkgReceivers::new(set_of(&[NODE_1])).expect("failed to create receivers"),
            registry_version: REG_V1,
            transcript_type,
            algorithm_id,
            internal_transcript_raw,
        }
    }

    fn all_canister_threshold_algorithms() -> Vec<AlgorithmId> {
        AlgorithmId::all_threshold_ecdsa_algorithms()
            .into_iter()
            .chain(AlgorithmId::all_threshold_schnorr_algorithms())
            .collect()
    }
}
