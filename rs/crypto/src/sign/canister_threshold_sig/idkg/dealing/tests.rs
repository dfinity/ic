mod verify_dealing_public {
    use crate::sign::BasicSig;
    use crate::sign::BasicSigOf;
    use crate::sign::canister_threshold_sig::idkg::SignedIDkgDealing;
    use crate::sign::canister_threshold_sig::idkg::dealing::BasicSignature;
    use crate::sign::canister_threshold_sig::idkg::dealing::IDkgDealing;
    use crate::sign::canister_threshold_sig::idkg::dealing::verify_dealing_public;
    use crate::sign::canister_threshold_sig::test_utils::valid_internal_dealing_raw;
    use assert_matches::assert_matches;
    use ic_base_types::NodeId;
    use ic_base_types::RegistryVersion;
    use ic_crypto_internal_csp::types::CspPublicKey;
    use ic_crypto_internal_csp::types::SigConverter;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_initial_idkg_dealing_for_tests;
    use ic_crypto_test_utils_canister_threshold_sigs::node_id;
    use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
    use ic_crypto_test_utils_keys::public_keys::valid_node_signing_public_key;
    use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_interfaces::crypto::ErrorReproducibility;
    use ic_interfaces_registry::RegistryValue;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_registry_keys::make_crypto_node_key;
    use ic_types::crypto::KeyPurpose::NodeSigning;
    use ic_types::crypto::canister_threshold_sig::error::IDkgVerifyDealingPublicError;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation;
    use ic_types::crypto::canister_threshold_sig::idkg::InitialIDkgDealings;
    use ic_types::crypto::{AlgorithmId, CryptoError, Signable};
    use ic_types::registry::RegistryClientError;
    use rand::Rng;

    #[test]
    fn should_fail_on_reproducible_registry_error() {
        let rng = &mut reproducible_rng();

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let registry_client_error = RegistryClientError::DecodeError {
                error: "decode error".to_string(),
            };

            let setup = Setup::new_with_registry_client_get_value_error(
                alg,
                registry_client_error.clone(),
                rng,
            );

            assert_matches!(
                verify_dealing_public(
                    &setup.csp,
                    &setup.registry_client,
                    setup.idkg_dealings.params(),
                    setup.idkg_dealings
                        .dealings()
                        .first()
                        .expect("should contain a dealing"),
                ),
                Err(IDkgVerifyDealingPublicError::InvalidSignature {
                    error,
                    crypto_error
                })
                    if error.contains("Invalid basic signature on signed iDKG dealing")
                    && crypto_error == CryptoError::RegistryClient(registry_client_error)
                    && crypto_error.is_reproducible()
            );
        }
    }

    #[test]
    fn should_fail_on_not_necessarily_reproducible_registry_error() {
        let rng = &mut reproducible_rng();

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let registry_client_error = RegistryClientError::VersionNotAvailable {
                version: RegistryVersion::from(rng.r#gen::<u32>() as u64),
            };

            let setup = Setup::new_with_registry_client_get_value_error(
                alg,
                registry_client_error.clone(),
                rng,
            );

            assert_matches!(
                verify_dealing_public(
                    &setup.csp,
                    &setup.registry_client,
                    setup.idkg_dealings.params(),
                    setup.idkg_dealings
                        .dealings()
                        .first()
                        .expect("should contain a dealing"),
                ),
                Err(IDkgVerifyDealingPublicError::InvalidSignature {
                    error,
                    crypto_error
                })
                    if error.contains("Invalid basic signature on signed iDKG dealing")
                    && crypto_error == CryptoError::RegistryClient(registry_client_error)
                    && !crypto_error.is_reproducible()
            );
        }
    }

    #[test]
    fn should_fail_if_deserializing_operation_fails() {
        let rng = &mut reproducible_rng();

        for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
            let setup =
                Setup::new_with_dealer(alg, node_id(37), valid_node_signing_public_key(), rng);

            // The deserialization of the operation fails if `internal_transcript_raw` is empty
            assert_matches!(
                setup.idkg_dealings.params().operation_type(),
                IDkgTranscriptOperation::ReshareOfUnmasked(idkg_transcript)
                    if idkg_transcript.internal_transcript_raw.is_empty()
            );

            // The error returned if the deserialization of the operation fails is `InvalidDealing`
            assert_matches!(
                verify_dealing_public(
                    &setup.csp,
                    &setup.registry_client,
                    setup.idkg_dealings.params(),
                    &setup.signed_dealing.expect("should have a signed dealing")
                ),
                Err(IDkgVerifyDealingPublicError::InvalidDealing { reason })
                    if reason.contains("EOF while parsing a value")
            );
        }
    }

    struct Setup {
        registry_client: MockRegistryClient,
        idkg_dealings: InitialIDkgDealings,
        csp: MockAllCryptoServiceProvider,
        signed_dealing: Option<SignedIDkgDealing>,
    }

    impl Setup {
        fn new_with_registry_client_get_value_error(
            alg: AlgorithmId,
            registry_client_error: RegistryClientError,
            rng: &mut ReproducibleRng,
        ) -> Self {
            let mut registry_client = MockRegistryClient::new();
            registry_client
                .expect_get_value()
                .return_const(Err(registry_client_error.clone()));
            let mut csp = MockAllCryptoServiceProvider::new();
            csp.expect_verify().never();
            Setup {
                registry_client,
                idkg_dealings: dummy_initial_idkg_dealing_for_tests(alg, rng),
                csp,
                signed_dealing: None,
            }
        }

        fn new_with_dealer(
            alg: AlgorithmId,
            dealer_id: NodeId,
            dealer_node_signing_public_key_proto: PublicKey,
            rng: &mut ReproducibleRng,
        ) -> Self {
            let idkg_dealings = dummy_initial_idkg_dealing_for_tests(alg, rng);
            let mut node_signing_public_key_bytes = Vec::new();
            dealer_node_signing_public_key_proto
                .encode(&mut node_signing_public_key_bytes)
                .expect("the public key should encode successfully");
            let registry_client = registry_client_returning_get_value_result(
                dealer_id,
                node_signing_public_key_bytes,
                idkg_dealings.params().registry_version(),
            );

            let params = idkg_dealings.params();
            let signed_dealing = SignedIDkgDealing {
                content: IDkgDealing {
                    transcript_id: params.transcript_id(),
                    internal_dealing_raw: valid_internal_dealing_raw(),
                },
                signature: BasicSignature {
                    signature: BasicSigOf::new(BasicSig(vec![
                        0u8;
                        ic_crypto_internal_basic_sig_ed25519::types::SignatureBytes::SIZE
                    ])),
                    signer: dealer_id,
                },
            };
            let idkg_dealing = signed_dealing.idkg_dealing().clone();
            let csp_public_key = CspPublicKey::try_from(dealer_node_signing_public_key_proto)
                .expect("should convert PublicKeyProto to CspPublicKey");
            let csp_signature = SigConverter::for_target(ic_types::crypto::AlgorithmId::Ed25519)
                .try_from_basic(&signed_dealing.signature.signature)
                .expect("should convert signature to CspSignature");
            let mut csp = MockAllCryptoServiceProvider::new();
            csp.expect_verify()
                .withf(move |sig, msg, alg, pk| {
                    sig == &csp_signature
                        && msg == idkg_dealing.as_signed_bytes()
                        && alg == &ic_types::crypto::AlgorithmId::Ed25519
                        && pk == &csp_public_key
                })
                .return_const(Ok(()));
            Setup {
                registry_client,
                idkg_dealings,
                csp,
                signed_dealing: Some(signed_dealing),
            }
        }
    }

    fn registry_client_returning_get_value_result(
        node_id: NodeId,
        node_signing_public_key_bytes: Vec<u8>,
        registry_version: RegistryVersion,
    ) -> MockRegistryClient {
        let mut registry_client = MockRegistryClient::new();
        let registry_key = make_crypto_node_key(node_id, NodeSigning);
        registry_client
            .expect_get_value()
            .withf(move |key, version| key == registry_key.as_str() && version == &registry_version)
            .return_const(Ok(Some(node_signing_public_key_bytes)));
        registry_client
    }
}
