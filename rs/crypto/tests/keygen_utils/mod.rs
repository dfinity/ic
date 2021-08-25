use ic_crypto::utils::{NodeKeysToGenerate, TempCryptoComponent};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key};
use ic_test_utilities::types::ids::node_test_id;
use ic_types::crypto::KeyPurpose;
use ic_types::{NodeId, RegistryVersion};
use std::sync::Arc;

pub struct TestKeygenCryptoBuilder {
    node_keys_to_generate: NodeKeysToGenerate,
    add_node_signing_key_to_registry: bool,
    node_signing_key: Option<PublicKey>,
    add_committee_signing_key_to_registry: bool,
    committee_signing_key: Option<PublicKey>,
    add_dkg_dealing_enc_key_to_registry: bool,
    dkg_dealing_enc_key: Option<PublicKey>,
    add_tls_cert_to_registry: bool,
    tls_cert: Option<X509PublicKeyCert>,
}

impl TestKeygenCryptoBuilder {
    pub fn with_node_keys_to_generate(mut self, node_keys_to_generate: NodeKeysToGenerate) -> Self {
        self.node_keys_to_generate = node_keys_to_generate;
        self
    }

    pub fn add_generated_node_signing_key_to_registry(mut self) -> Self {
        self.add_node_signing_key_to_registry = true;
        self
    }

    pub fn with_node_signing_key_in_registry(mut self, key: PublicKey) -> Self {
        self.node_signing_key = Some(key);
        self
    }

    pub fn add_generated_committee_signing_key_to_registry(mut self) -> Self {
        self.add_committee_signing_key_to_registry = true;
        self
    }

    pub fn with_committee_signing_key_in_registry(mut self, key: PublicKey) -> Self {
        self.committee_signing_key = Some(key);
        self
    }

    pub fn add_generated_dkg_dealing_enc_key_to_registry(mut self) -> Self {
        self.add_dkg_dealing_enc_key_to_registry = true;
        self
    }

    pub fn with_dkg_dealing_enc_key_in_registry(mut self, key: PublicKey) -> Self {
        self.dkg_dealing_enc_key = Some(key);
        self
    }

    pub fn add_generated_tls_cert_to_registry(mut self) -> Self {
        self.add_tls_cert_to_registry = true;
        self
    }

    pub fn with_tls_cert_in_registry(mut self, cert: X509PublicKeyCert) -> Self {
        self.tls_cert = Some(cert);
        self
    }

    pub fn build(self, node_id: u64, registry_version: RegistryVersion) -> TestKeygenCrypto {
        let node_id = node_test_id(node_id);
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));
        let (temp_crypto, node_pubkeys) = TempCryptoComponent::new_with_node_keys_generation(
            Arc::clone(&registry_client) as Arc<_>,
            node_id,
            self.node_keys_to_generate.clone(),
        );
        self.add_node_signing_key_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            &node_pubkeys.node_signing_pk,
        )
        .add_committee_signing_key_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            &node_pubkeys.committee_signing_pk,
        )
        .add_dkg_dealing_enc_key_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            &node_pubkeys.dkg_dealing_encryption_pk,
        )
        .add_tls_cert_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            node_pubkeys.tls_certificate,
        );
        registry_client.update_to_latest_version();
        TestKeygenCrypto { temp_crypto }
    }

    fn add_node_signing_key_to_registry_if_present(
        self,
        registry_version: RegistryVersion,
        node_id: NodeId,
        data_provider: &Arc<ProtoRegistryDataProvider>,
        public_key: &Option<PublicKey>,
    ) -> Self {
        if self.add_node_signing_key_to_registry && self.node_signing_key.is_some() {
            panic!("invalid use of builder: cannot add default and custom node signing key!")
        }
        if self.add_node_signing_key_to_registry {
            add_public_key_to_registry(
                public_key
                    .as_ref()
                    .expect("invalid use of builder: node signing key was not generated.")
                    .clone(),
                node_id,
                KeyPurpose::NodeSigning,
                Arc::clone(&data_provider),
                registry_version,
            );
        }
        if let Some(pub_key) = self.node_signing_key.as_ref() {
            add_public_key_to_registry(
                pub_key.clone(),
                node_id,
                KeyPurpose::NodeSigning,
                Arc::clone(&data_provider),
                registry_version,
            );
        }
        self
    }

    fn add_committee_signing_key_to_registry_if_present(
        self,
        registry_version: RegistryVersion,
        node_id: NodeId,
        data_provider: &Arc<ProtoRegistryDataProvider>,
        public_key: &Option<PublicKey>,
    ) -> Self {
        if self.add_committee_signing_key_to_registry && self.committee_signing_key.is_some() {
            panic!("invalid use of builder: cannot add default and custom committee signing key!")
        }
        if self.add_committee_signing_key_to_registry {
            add_public_key_to_registry(
                public_key
                    .as_ref()
                    .expect("invalid use of builder: committee member key was not generated.")
                    .clone(),
                node_id,
                KeyPurpose::CommitteeSigning,
                Arc::clone(&data_provider),
                registry_version,
            );
        }
        if let Some(pub_key) = self.committee_signing_key.as_ref() {
            add_public_key_to_registry(
                pub_key.clone(),
                node_id,
                KeyPurpose::CommitteeSigning,
                Arc::clone(&data_provider),
                registry_version,
            );
        }
        self
    }

    fn add_dkg_dealing_enc_key_to_registry_if_present(
        self,
        registry_version: RegistryVersion,
        node_id: NodeId,
        data_provider: &Arc<ProtoRegistryDataProvider>,
        public_key: &Option<PublicKey>,
    ) -> Self {
        if self.add_dkg_dealing_enc_key_to_registry && self.dkg_dealing_enc_key.is_some() {
            panic!("invalid use of builder: cannot add default and custom dkg dealing enc key!")
        }
        if self.add_dkg_dealing_enc_key_to_registry {
            add_public_key_to_registry(
                public_key
                    .as_ref()
                    .expect("invalid use of builder: dealing encryption key was not generated.")
                    .clone(),
                node_id,
                KeyPurpose::DkgDealingEncryption,
                Arc::clone(&data_provider),
                registry_version,
            );
        }
        if let Some(pub_key) = self.dkg_dealing_enc_key.as_ref() {
            add_public_key_to_registry(
                pub_key.clone(),
                node_id,
                KeyPurpose::DkgDealingEncryption,
                Arc::clone(&data_provider),
                registry_version,
            );
        }
        self
    }

    fn add_tls_cert_to_registry_if_present(
        self,
        registry_version: RegistryVersion,
        node_id: NodeId,
        data_provider: &Arc<ProtoRegistryDataProvider>,
        tls_certificate: Option<X509PublicKeyCert>,
    ) -> Self {
        if self.add_node_signing_key_to_registry && self.node_signing_key.is_some() {
            panic!("invalid use of builder: cannot add default and custom cert!")
        }
        if self.add_tls_cert_to_registry {
            add_tls_cert_to_registry(
                tls_certificate.expect("invalid use of builder: tls cert was not generated."),
                node_id,
                Arc::clone(&data_provider),
                registry_version,
            );
        }
        if let Some(cert) = self.tls_cert.as_ref() {
            add_tls_cert_to_registry(
                cert.clone(),
                node_id,
                Arc::clone(&data_provider),
                registry_version,
            );
        }
        self
    }
}

pub struct TestKeygenCrypto {
    temp_crypto: TempCryptoComponent,
}

impl TestKeygenCrypto {
    pub fn builder() -> TestKeygenCryptoBuilder {
        TestKeygenCryptoBuilder {
            node_keys_to_generate: NodeKeysToGenerate::none(),
            add_node_signing_key_to_registry: false,
            node_signing_key: None,
            add_committee_signing_key_to_registry: false,
            add_dkg_dealing_enc_key_to_registry: false,
            dkg_dealing_enc_key: None,
            committee_signing_key: None,
            add_tls_cert_to_registry: false,
            tls_cert: None,
        }
    }

    pub fn get(&self) -> &TempCryptoComponent {
        &self.temp_crypto
    }
}

fn add_tls_cert_to_registry(
    cert: X509PublicKeyCert,
    node_id: NodeId,
    registry: Arc<ProtoRegistryDataProvider>,
    registry_version: RegistryVersion,
) {
    registry
        .add(
            &make_crypto_tls_cert_key(node_id),
            registry_version,
            Some(cert),
        )
        .expect("Could not add TLS cert key to registry");
}

fn add_public_key_to_registry(
    public_key: PublicKey,
    node_id: NodeId,
    key_purpose: KeyPurpose,
    registry: Arc<ProtoRegistryDataProvider>,
    registry_version: RegistryVersion,
) {
    registry
        .add(
            &make_crypto_node_key(node_id, key_purpose),
            registry_version,
            Some(public_key),
        )
        .expect("Could not add public key to registry");
}
