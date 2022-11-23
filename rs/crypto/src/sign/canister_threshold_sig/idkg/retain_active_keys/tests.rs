use crate::sign::canister_threshold_sig::idkg::retain_active_keys::oldest_public_key;
use ic_base_types::{NodeId, RegistryVersion};
use ic_crypto_internal_threshold_sig_ecdsa::MEGaPublicKey;
use ic_interfaces_registry::RegistryClient;
use ic_types::crypto::canister_threshold_sig::error::IDkgRetainThresholdKeysError;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

mod oldest_public_key {
    use super::*;
    use ic_base_types::PrincipalId;
    use ic_base_types::SubnetId;
    use ic_crypto_internal_csp::keygen::utils::idkg_dealing_encryption_pk_to_proto;
    use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, EccPoint, EccScalar};
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
    use ic_protobuf::registry::crypto::v1::PublicKey;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_crypto_node_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
    use ic_types::crypto::canister_threshold_sig::idkg::{
        IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscriptType,
    };
    use ic_types::crypto::{AlgorithmId, KeyPurpose};
    use ic_types::registry::RegistryClientError;
    use ic_types::Height;
    use rand::Rng;
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn should_be_none_when_no_transcripts_and_should_not_query_registry() {
        let registry = Arc::new(registry_returning_transient_error()) as Arc<_>;
        let result = oldest_public_key(&node_id(), &registry, &HashSet::new());
        assert!(result.is_none());
    }

    #[test]
    fn should_return_transient_error_when_registry_transient_error() {
        let mut transcripts = HashSet::new();
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            RegistryVersion::new(2),
        ));
        let registry = Arc::new(registry_returning_transient_error()) as Arc<_>;

        let result = oldest_public_key(&node_id(), &registry, &transcripts);

        assert!(matches!(
            result,
            Some(Err(
                IDkgRetainThresholdKeysError::TransientInternalError { internal_error }
            )) if internal_error.contains("Transient error")
        ))
    }
    #[test]
    fn should_return_internal_error_when_registry_reproducible_error() {
        let mut transcripts = HashSet::new();
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            RegistryVersion::new(2),
        ));
        let registry = Arc::new(registry_returning_reproducible_error()) as Arc<_>;

        let result = oldest_public_key(&node_id(), &registry, &transcripts);

        assert!(matches!(
            result,
            Some(Err(
                IDkgRetainThresholdKeysError::InternalError { internal_error }
            )) if internal_error.contains("Internal error")
        ))
    }

    #[test]
    fn should_return_internal_error_when_public_key_malformed() {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));
        let registry_version = RegistryVersion::new(1);
        let mut transcripts = HashSet::new();
        transcripts.insert(idkg_transcript_with_registry_version(
            node_id(),
            registry_version,
        ));
        register_idkg_public_key(
            node_id(),
            malformed_idkg_public_key(),
            registry_version,
            data_provider,
        );
        registry_client.update_to_latest_version();

        let result = oldest_public_key(&node_id(), &(registry_client as Arc<_>), &transcripts);

        assert!(matches!(
            result,
            Some(Err(
                IDkgRetainThresholdKeysError::InternalError { internal_error }
            )) if internal_error.contains("MalformedPublicKey")
        ))
    }

    #[test]
    fn should_return_oldest_public_key() {
        let registry_versions = vec![2, 4, 1, 10];
        let oldest_registry_version =
            RegistryVersion::new(*registry_versions.iter().min().expect("empty versions"));
        let idkg_public_keys = generate_unique_idkg_public_keys(&registry_versions);
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));
        let mut transcripts = HashSet::new();
        for (version, idkg_public_key) in &idkg_public_keys {
            transcripts.insert(idkg_transcript_with_registry_version(node_id(), *version));
            register_idkg_public_key(
                node_id(),
                idkg_dealing_encryption_pk_to_proto(idkg_public_key.clone()),
                *version,
                data_provider.clone(),
            );
        }
        registry_client.update_to_latest_version();

        let result = oldest_public_key(&node_id(), &(registry_client as Arc<_>), &transcripts)
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

    fn idkg_transcript_with_registry_version(
        receiver: NodeId,
        version: RegistryVersion,
    ) -> IDkgTranscript {
        let mut receivers = BTreeSet::new();
        receivers.insert(receiver);
        IDkgTranscript {
            transcript_id: random_transcript_id(),
            receivers: IDkgReceivers::new(receivers).expect("error creating IDKG receivers"),
            registry_version: version,
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        }
    }

    fn random_transcript_id() -> IDkgTranscriptId {
        let rng = &mut rand::thread_rng();

        let id = rng.gen();
        let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(rng.gen::<u64>()));
        let height = Height::from(rng.gen::<u64>());

        IDkgTranscriptId::new(subnet, id, height)
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
                .expect("generator wrong")
                .scalar_mul(&unique_scalar_per_version)
                .expect("error with multiplication by scalar"),
        )
    }

    fn node_id() -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(42))
    }
}
