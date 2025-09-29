use crate::sign::canister_threshold_sig::idkg::retain_active_keys::oldest_public_key;
use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_base_types::SubnetId;
use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_internal_csp::keygen::utils::idkg_dealing_encryption_pk_to_proto;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::MEGaPublicKey;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{EccCurveType, EccPoint, EccScalar};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::Height;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::KeyPurpose;
use ic_types::crypto::canister_threshold_sig::error::IDkgRetainKeysError;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscriptType,
};
use ic_types::registry::RegistryClientError;
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

mod retain_keys_for_transcripts {
    use super::*;
    use crate::sign::canister_threshold_sig::idkg::retain_active_keys::IDkgTranscriptInternal;
    use crate::sign::canister_threshold_sig::idkg::retain_active_keys::retain_keys_for_transcripts;
    use ic_crypto_internal_csp::key_id::KeyId;
    use ic_crypto_internal_test_vectors::unhex::hex_to_byte_vec;
    use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
    use maplit::btreeset;

    #[test]
    fn should_succeed_when_key_in_registry_and_node_in_receivers() {
        let rng = &mut reproducible_rng();
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = FakeRegistryClient::new(data_provider.clone());
        let registry_version = RegistryVersion::new(2);
        let metrics = Arc::new(CryptoMetrics::none());

        let transcript = idkg_transcript_with_internal_transcript_and_registry_version(
            node_id(),
            registry_version,
            rng,
        );
        let mut transcripts = HashSet::new();
        transcripts.insert(
            idkg_transcript_with_internal_transcript_and_registry_version(
                another_node_id(),
                RegistryVersion::new(1),
                rng,
            ),
        );
        transcripts.insert(
            idkg_transcript_with_internal_transcript_and_registry_version(
                node_id(),
                RegistryVersion::new(3),
                rng,
            ),
        );
        transcripts.insert(transcript.clone());
        transcripts.insert(
            idkg_transcript_with_internal_transcript_and_registry_version(
                node_id(),
                RegistryVersion::new(4),
                rng,
            ),
        );
        let idkg_public_key = idkg_unique_public_key_per_registry_version(&registry_version);
        register_idkg_public_key(
            node_id(),
            idkg_dealing_encryption_pk_to_proto(idkg_public_key.clone()),
            registry_version,
            data_provider,
        );
        registry_client.update_to_latest_version();
        let internal_transcript = IDkgTranscriptInternal::try_from(&transcript)
            .expect("converting valid random transcript to internal script should succeed");

        let expected_key_ids = btreeset! {
            KeyId::from(internal_transcript.combined_commitment.commitment())
        };

        let mut mock_vault = MockLocalCspVault::new();
        mock_vault
            .expect_idkg_retain_active_keys()
            .withf(move |key_ids, oldest_public_key| {
                key_ids == &expected_key_ids && oldest_public_key == &idkg_public_key
            })
            .times(1)
            .return_const(Ok(()));
        let mock_vault = Arc::new(mock_vault);

        assert_eq!(
            retain_keys_for_transcripts(
                &(mock_vault as _),
                &node_id(),
                &registry_client,
                &metrics,
                &transcripts
            ),
            Ok(())
        );
    }

    #[test]
    fn should_be_noop_when_node_not_in_receivers() {
        let rng = &mut reproducible_rng();
        let registry_client = MockRegistryClient::new();
        let registry_version = RegistryVersion::new(1);
        let mut transcripts = HashSet::new();
        let transcript = idkg_transcript_with_internal_transcript_and_registry_version(
            another_node_id(),
            registry_version,
            rng,
        );
        transcripts.insert(transcript);
        let metrics = Arc::new(CryptoMetrics::none());
        let mock_vault = Arc::new(MockLocalCspVault::new());

        assert_eq!(
            retain_keys_for_transcripts(
                &(mock_vault as _),
                &node_id(),
                &registry_client,
                &metrics,
                &transcripts
            ),
            Ok(())
        );
    }

    #[test]
    fn should_fail_with_public_key_not_found_when_node_in_receivers_but_key_not_in_registry() {
        let rng = &mut reproducible_rng();
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = FakeRegistryClient::new(data_provider.clone());
        let registry_version = RegistryVersion::new(1);
        let mut transcripts = HashSet::new();
        let transcript = idkg_transcript_with_internal_transcript_and_registry_version(
            node_id(),
            registry_version,
            rng,
        );
        transcripts.insert(transcript);
        let idkg_public_key = idkg_unique_public_key_per_registry_version(&registry_version);
        register_idkg_public_key(
            another_node_id(),
            idkg_dealing_encryption_pk_to_proto(idkg_public_key),
            registry_version,
            data_provider,
        );
        registry_client.update_to_latest_version();
        let metrics = Arc::new(CryptoMetrics::none());
        let mock_vault = Arc::new(MockLocalCspVault::new());

        let result = retain_keys_for_transcripts(
            &(mock_vault as _),
            &node_id(),
            &registry_client,
            &metrics,
            &transcripts,
        );

        assert_matches!(
            result,
            Err(IDkgRetainKeysError::InternalError { internal_error })
            if internal_error.contains("Internal error while searching for iDKG public key: PublicKeyNotFound")
        );
    }

    fn idkg_transcript_with_internal_transcript_and_registry_version<R: Rng + CryptoRng>(
        receiver: NodeId,
        version: RegistryVersion,
        rng: &mut R,
    ) -> IDkgTranscript {
        let mut receivers = BTreeSet::new();
        receivers.insert(receiver);
        IDkgTranscript {
            transcript_id: random_transcript_id(rng),
            receivers: IDkgReceivers::new(receivers).expect("error creating IDKG receivers"),
            registry_version: version,
            verified_dealings: Arc::new(BTreeMap::new()),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            // from rs/crypto/internal/crypto_lib/threshold_sig/tecdsa/tests/data/transcript_random.hex:
            internal_transcript_raw: hex_to_byte_vec(
                "a173636f6d62696e65645f636f6d6d69746d656e74a16b427953756d6d6174696f6ea168506564657273656ea166706f696e747383582201024be7c27cb1efce8378bc1d8385c409bfc620ddc702aac1664e6c71680a1b0e2858220102ec466b3c1ae94746014ff54624efb1773689b1f615752164208e77dd13b8308158220102d4c87220329fe8165d678c5556d29f067e1694af40585cb70e1b565c0895a5ed",
            ),
        }
    }
}

mod oldest_public_key {
    use ic_crypto_test_utils_metrics::assertions::MetricsObservationsAssert;
    use ic_metrics::MetricsRegistry;

    use super::*;

    #[test]
    fn should_return_public_key_not_found_when_node_a_receiver_but_no_key_in_registry() {
        let rng = &mut reproducible_rng();
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = FakeRegistryClient::new(data_provider.clone());
        let mut transcripts = HashSet::new();
        let registry_version = RegistryVersion::new(1);
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            registry_version,
            rng,
        ));
        let idkg_public_key = idkg_unique_public_key_per_registry_version(&registry_version);
        register_idkg_public_key(
            another_node_id(),
            idkg_dealing_encryption_pk_to_proto(idkg_public_key),
            registry_version,
            data_provider,
        );
        registry_client.update_to_latest_version();
        let metrics = Arc::new(CryptoMetrics::none());

        let result = oldest_public_key(&node_id(), &registry_client, &metrics, &transcripts);

        assert_matches!(
            result,
            Some(Err(
                IDkgRetainKeysError::InternalError { internal_error }
            )) if internal_error.contains("Internal error while searching for iDKG public key: PublicKeyNotFound")
        );
    }

    #[test]
    fn should_return_none_when_node_not_receiver_in_any_transcript() {
        let rng = &mut reproducible_rng();
        let registry_client = registry_returning_transient_error();
        let registry_versions = vec![1, 2, 3];
        let mut transcripts = HashSet::new();
        for registry_version in registry_versions {
            transcripts.insert(idkg_transcript_with_registry_version(
                another_node_id(),
                RegistryVersion::new(registry_version),
                rng,
            ));
        }
        let metrics = Arc::new(CryptoMetrics::none());

        let result = oldest_public_key(&node_id(), &registry_client, &metrics, &transcripts);

        assert_eq!(result, None);
    }

    #[test]
    fn should_return_oldest_public_key_where_node_in_receivers() {
        let rng = &mut reproducible_rng();
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = FakeRegistryClient::new(data_provider.clone());
        let mut transcripts = HashSet::new();
        transcripts.insert(idkg_transcript_with_registry_version(
            another_node_id(),
            RegistryVersion::new(1),
            rng,
        ));
        let old_registry_version = RegistryVersion::new(2);
        let old_idkg_public_key = generate_and_register_idkg_public_key(
            node_id(),
            old_registry_version,
            data_provider.clone(),
            &mut transcripts,
            rng,
        );
        let new_registry_version = RegistryVersion::new(3);
        let _new_idkg_public_key = generate_and_register_idkg_public_key(
            node_id(),
            new_registry_version,
            data_provider,
            &mut transcripts,
            rng,
        );
        registry_client.update_to_latest_version();
        let metrics = Arc::new(CryptoMetrics::none());

        assert_matches!(
            oldest_public_key(&node_id(), &registry_client, &metrics, &transcripts),
            Some(Ok(idkg_public_key)) if idkg_public_key == old_idkg_public_key
        );
    }

    #[test]
    fn should_be_none_when_no_transcripts_and_should_not_query_registry() {
        let registry = registry_returning_transient_error();
        let metrics = Arc::new(CryptoMetrics::none());
        let result = oldest_public_key(&node_id(), &registry, &metrics, &HashSet::new());
        assert_eq!(result, None);
    }

    #[test]
    fn should_return_transient_error_when_registry_transient_error() {
        let rng = &mut reproducible_rng();
        let mut transcripts = HashSet::new();
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            RegistryVersion::new(2),
            rng,
        ));
        let registry = registry_returning_transient_error();
        let metrics = Arc::new(CryptoMetrics::none());

        let result = oldest_public_key(&node_id(), &registry, &metrics, &transcripts);

        assert_matches!(
            result,
            Some(Err(
                IDkgRetainKeysError::TransientInternalError { internal_error }
            )) if internal_error.contains("Transient error")
        );
    }
    #[test]
    fn should_return_internal_error_when_registry_reproducible_error() {
        let rng = &mut reproducible_rng();
        let mut transcripts = HashSet::new();
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            RegistryVersion::new(2),
            rng,
        ));
        let registry = registry_returning_reproducible_error();
        let metrics = Arc::new(CryptoMetrics::none());

        let result = oldest_public_key(&node_id(), &registry, &metrics, &transcripts);

        assert_matches!(
            result,
            Some(Err(
                IDkgRetainKeysError::InternalError { internal_error }
            )) if internal_error.contains("Internal error")
        );
    }

    #[test]
    fn should_return_internal_error_when_public_key_malformed() {
        let rng = &mut reproducible_rng();
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = FakeRegistryClient::new(data_provider.clone());
        let registry_version = RegistryVersion::new(1);
        let mut transcripts = HashSet::new();
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            registry_version,
            rng,
        ));
        register_idkg_public_key(
            node_id(),
            malformed_idkg_public_key(),
            registry_version,
            data_provider,
        );
        registry_client.update_to_latest_version();
        let metrics = Arc::new(CryptoMetrics::none());

        let result = oldest_public_key(&node_id(), &registry_client, &metrics, &transcripts);

        assert_matches!(
            result,
            Some(Err(
                IDkgRetainKeysError::InternalError { internal_error }
            )) if internal_error.contains("MalformedPublicKey")
        );
    }

    #[test]
    fn should_return_oldest_public_key_with_transcript_versions_out_of_order() {
        let rng = &mut reproducible_rng();
        let registry_versions = vec![2, 4, 1, 10];
        let oldest_registry_version =
            RegistryVersion::new(*registry_versions.iter().min().expect("empty versions"));
        let idkg_public_keys = generate_unique_idkg_public_keys(&registry_versions);
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = FakeRegistryClient::new(data_provider.clone());
        let mut transcripts = HashSet::new();
        for (version, idkg_public_key) in &idkg_public_keys {
            transcripts.insert(idkg_transcript_with_registry_version(
                node_id(),
                *version,
                rng,
            ));
            register_idkg_public_key(
                node_id(),
                idkg_dealing_encryption_pk_to_proto(idkg_public_key.clone()),
                *version,
                data_provider.clone(),
            );
        }
        registry_client.update_to_latest_version();
        let metrics = Arc::new(CryptoMetrics::none());

        let result = oldest_public_key(&node_id(), &registry_client, &metrics, &transcripts)
            .expect("missing result")
            .expect("missing IDKG public key");

        assert_eq!(
            result,
            idkg_public_keys
                .get(&oldest_registry_version)
                .expect("missing oldest public key")
                .clone()
        );
    }

    #[test]
    fn should_observe_metrics_when_computing_oldest_idkg_dealing_encryption_key() {
        let rng = &mut reproducible_rng();
        let registry_versions = vec![2, 4, 1, 10];
        let oldest_registry_version =
            RegistryVersion::new(*registry_versions.iter().min().expect("empty versions"));
        let idkg_public_keys = generate_unique_idkg_public_keys(&registry_versions);
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = FakeRegistryClient::new(data_provider.clone());
        let mut transcripts = HashSet::new();
        for (version, idkg_public_key) in &idkg_public_keys {
            transcripts.insert(idkg_transcript_with_registry_version(
                node_id(),
                *version,
                rng,
            ));
            register_idkg_public_key(
                node_id(),
                idkg_dealing_encryption_pk_to_proto(idkg_public_key.clone()),
                *version,
                data_provider.clone(),
            );
        }
        registry_client.update_to_latest_version();

        let metrics_registry = MetricsRegistry::new();
        let metrics = Arc::new(CryptoMetrics::new(Some(&metrics_registry)));

        let _result = oldest_public_key(&node_id(), &registry_client, &metrics, &transcripts)
            .expect("missing result")
            .expect("missing IDKG public key");

        MetricsObservationsAssert::assert_that(metrics_registry)
            .contains_minimum_registry_version_in_active_idkg_transcripts(
                oldest_registry_version.get(),
            );
    }
}

mod minimum_registry_version {
    use super::*;
    use crate::sign::canister_threshold_sig::idkg::retain_active_keys::minimum_registry_version_for_node;

    #[test]
    fn should_return_none_for_no_transcripts() {
        let transcripts = HashSet::new();

        assert_eq!(
            minimum_registry_version_for_node(&transcripts, node_id()),
            None
        );
    }

    #[test]
    fn should_return_minimum_registry_version_for_single_transcript() {
        let rng = &mut reproducible_rng();
        let registry_versions: Vec<u64> = vec![2];
        let mut transcripts = HashSet::new();
        for version in registry_versions {
            transcripts.insert(idkg_transcript_with_registry_version(
                node_id(),
                RegistryVersion::new(version),
                rng,
            ));
        }

        assert_eq!(
            minimum_registry_version_for_node(&transcripts, node_id()),
            Some(RegistryVersion::new(2))
        );
    }

    #[test]
    fn should_return_minimum_registry_version_for_multiple_transcripts() {
        let rng = &mut reproducible_rng();
        let registry_versions: Vec<u64> = vec![2, 4, 1, 10];
        let mut transcripts = HashSet::new();
        for version in registry_versions {
            transcripts.insert(idkg_transcript_with_registry_version(
                node_id(),
                RegistryVersion::new(version),
                rng,
            ));
        }

        assert_eq!(
            minimum_registry_version_for_node(&transcripts, node_id()),
            Some(RegistryVersion::new(1))
        );
    }

    #[test]
    fn should_return_minimum_registry_version_for_multiple_transcripts_and_different_receivers() {
        let rng = &mut reproducible_rng();
        let mut transcripts = HashSet::new();
        transcripts.insert(idkg_transcript_with_registry_version(
            another_node_id(),
            RegistryVersion::new(1),
            rng,
        ));
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            RegistryVersion::new(2),
            rng,
        ));
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            RegistryVersion::new(3),
            rng,
        ));

        assert_eq!(
            minimum_registry_version_for_node(&transcripts, node_id()),
            Some(RegistryVersion::new(2))
        );
    }
}

fn idkg_transcript_with_registry_version<R: Rng + CryptoRng>(
    receiver: NodeId,
    version: RegistryVersion,
    rng: &mut R,
) -> IDkgTranscript {
    let mut receivers = BTreeSet::new();
    receivers.insert(receiver);
    IDkgTranscript {
        transcript_id: random_transcript_id(rng),
        receivers: IDkgReceivers::new(receivers).expect("error creating IDKG receivers"),
        registry_version: version,
        verified_dealings: Arc::new(BTreeMap::new()),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}

fn random_transcript_id<R: Rng + CryptoRng>(rng: &mut R) -> IDkgTranscriptId {
    let id = rng.r#gen();
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(rng.r#gen::<u64>()));
    let height = Height::from(rng.r#gen::<u64>());

    IDkgTranscriptId::new(subnet, id, height)
}

fn node_id() -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(42))
}

fn another_node_id() -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(187))
}

fn generate_and_register_idkg_public_key<R: Rng + CryptoRng>(
    node_id: NodeId,
    registry_version: RegistryVersion,
    data_provider: Arc<ProtoRegistryDataProvider>,
    transcripts: &mut HashSet<IDkgTranscript>,
    rng: &mut R,
) -> MEGaPublicKey {
    transcripts.insert(idkg_transcript_with_registry_version(
        node_id,
        registry_version,
        rng,
    ));
    let idkg_public_key = idkg_unique_public_key_per_registry_version(&registry_version);
    register_idkg_public_key(
        node_id,
        idkg_dealing_encryption_pk_to_proto(idkg_public_key.clone()),
        registry_version,
        data_provider,
    );
    idkg_public_key
}

fn registry_returning_transient_error() -> impl RegistryClient {
    let mut registry = MockRegistryClient::new();
    registry
        .expect_get_value()
        .return_const(Err(RegistryClientError::PollLockFailed {
            error: "oh no!".to_string(),
        }));
    registry
}

fn registry_returning_reproducible_error() -> impl RegistryClient {
    let mut registry = MockRegistryClient::new();
    registry
        .expect_get_value()
        .return_const(Err(RegistryClientError::DecodeError {
            error: "oh no!".to_string(),
        }));
    registry
}

fn register_idkg_public_key(
    node_id: NodeId,
    idkg_public_key: PublicKey,
    registry_version: RegistryVersion,
    data_provider: Arc<ProtoRegistryDataProvider>,
) {
    data_provider
        .add(
            &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
            registry_version,
            Some(idkg_public_key),
        )
        .expect("Could not add public key to registry");
}

fn malformed_idkg_public_key() -> PublicKey {
    PublicKey {
        version: 0,
        algorithm: AlgorithmIdProto::MegaSecp256k1 as i32,
        key_value: Vec::new(),
        proof_data: None,
        timestamp: None,
    }
}

fn generate_unique_idkg_public_keys(
    registry_versions: &[u64],
) -> HashMap<RegistryVersion, MEGaPublicKey> {
    let mut public_keys_in_registry: HashMap<RegistryVersion, MEGaPublicKey> = HashMap::new();
    for registry_version in registry_versions {
        let version = RegistryVersion::new(*registry_version);
        let idkg_public_key = idkg_unique_public_key_per_registry_version(&version);
        public_keys_in_registry.insert(version, idkg_public_key);
    }
    assert_eq!(
        public_keys_in_registry
            .values()
            .map(|public_key| public_key.serialize()) //MEGaPublicKey does not implement Hash
            .collect::<HashSet<_>>()
            .len(),
        registry_versions.len()
    );
    public_keys_in_registry
}

fn idkg_unique_public_key_per_registry_version(version: &RegistryVersion) -> MEGaPublicKey {
    let unique_scalar_per_version = EccScalar::hash_to_scalar(
        EccCurveType::K256,
        "dummy input".as_bytes(),
        &version.get().to_be_bytes(),
    )
    .expect("error hashing to scalar");
    MEGaPublicKey::new(
        EccPoint::generator_g(EccCurveType::K256)
            .scalar_mul(&unique_scalar_per_version)
            .expect("error with multiplication by scalar"),
    )
}
