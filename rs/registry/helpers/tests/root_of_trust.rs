use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_base_types::RegistryVersion;
use ic_base_types::SubnetId;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::types::v1::PrincipalId as PrincipalIdProto;
use ic_protobuf::types::v1::SubnetId as SubnetIdProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::crypto::root_of_trust::{
    RegistryRootOfTrustProvider, RegistryRootOfTrustProviderError,
};
use ic_registry_keys::ROOT_SUBNET_ID_KEY;
use ic_registry_keys::make_crypto_threshold_signing_pubkey_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::threshold_sig::{IcRootOfTrust, RootOfTrustProvider};
use std::sync::Arc;

const REGISTRY_VERSION_1: RegistryVersion = RegistryVersion::new(1);

#[test]
fn should_fail_when_root_subnet_missing() {
    let (registry, expected_registry_version) = RegistryBuilder::new().build();
    let provider = RegistryRootOfTrustProvider::new(registry, expected_registry_version);

    let result = provider.root_of_trust();

    assert_matches!(
        result,
        Err(RegistryRootOfTrustProviderError::RootSubnetNotFound { registry_version })
        if registry_version == expected_registry_version
    );
}

#[test]
fn should_fail_when_root_subnet_public_key_missing() {
    let (registry, expected_registry_version) = RegistryBuilder::new()
        .with_root_subnet_id(root_subnet_id())
        .build();
    let provider = RegistryRootOfTrustProvider::new(registry, expected_registry_version);

    let result = provider.root_of_trust();

    assert_matches!(
        result,
        Err(RegistryRootOfTrustProviderError::RootSubnetPublicKeyNotFound { registry_version })
        if registry_version == expected_registry_version
    );
}

#[test]
#[should_panic(expected = "Failed to convert registry data to threshold signing public key")]
fn should_panic_when_root_subnet_public_key_from_registry_is_invalid() {
    let (registry, registry_version) = RegistryBuilder::new()
        .with_root_subnet_id(root_subnet_id())
        .with_root_subnet_public_key(
            root_subnet_id(),
            PublicKey {
                algorithm: AlgorithmIdProto::RsaSha256 as i32,
                ..PublicKey::from(root_subnet_public_key())
            },
        )
        .build();
    let provider = RegistryRootOfTrustProvider::new(registry, registry_version);

    let _panic = provider.root_of_trust();
}

#[test]
fn should_retrieve_root_of_trust() {
    let root_subnet_public_key = root_subnet_public_key();
    let (registry, registry_version) = RegistryBuilder::new()
        .with_root_subnet_id(root_subnet_id())
        .with_root_subnet_public_key(root_subnet_id(), root_subnet_public_key)
        .build();
    let provider = RegistryRootOfTrustProvider::new(registry, registry_version);

    let result = provider.root_of_trust();

    assert_eq!(result, Ok(root_subnet_public_key));
}

fn root_subnet_public_key() -> IcRootOfTrust {
    IcRootOfTrust::from([0; 96])
}

struct RegistryBuilder {
    registry_data: Arc<ProtoRegistryDataProvider>,
    registry_client: Arc<FakeRegistryClient>,
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client =
            Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
        Self {
            registry_data,
            registry_client,
        }
    }
}

impl RegistryBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn with_root_subnet_id(self, root_subnet_id: SubnetId) -> Self {
        let root_subnet_id = SubnetIdProto {
            principal_id: Some(PrincipalIdProto {
                raw: root_subnet_id.get_ref().to_vec(),
            }),
        };
        self.registry_data
            .add(ROOT_SUBNET_ID_KEY, REGISTRY_VERSION_1, Some(root_subnet_id))
            .expect("failed to add root subnet ID to registry");
        self
    }

    fn with_root_subnet_public_key<K: Into<PublicKey>>(
        self,
        root_subnet_id: SubnetId,
        root_subnet_public_key: K,
    ) -> Self {
        self.registry_data
            .add(
                &make_crypto_threshold_signing_pubkey_key(root_subnet_id),
                REGISTRY_VERSION_1,
                Some(root_subnet_public_key.into()),
            )
            .expect("failed to add root subnet public key to registry");
        self
    }

    fn build(self) -> (Arc<dyn RegistryClient>, RegistryVersion) {
        self.registry_client.update_to_latest_version();
        let registry_version = self.registry_client.get_latest_version();
        (self.registry_client, registry_version)
    }
}

fn root_subnet_id() -> SubnetId {
    SubnetId::new(PrincipalId::new_subnet_test_id(1))
}
