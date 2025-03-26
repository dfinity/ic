use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_interfaces::crypto::KeyManager;
use ic_interfaces_registry::RegistryDataProvider;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::KeyPurpose;
use ic_types::{NodeId, RegistryVersion};
use ic_types_test_utils::ids::node_test_id;
use std::sync::Arc;

pub struct TestKeygenCryptoBuilder {
    node_keys_to_generate: NodeKeysToGenerate,
    add_node_signing_key_to_registry: bool,
    node_signing_key: Option<PublicKey>,
    add_committee_signing_key_to_registry: bool,
    committee_signing_key: Option<PublicKey>,
    add_dkg_dealing_enc_key_to_registry: bool,
    dkg_dealing_enc_key: Option<PublicKey>,
    add_idkg_dealing_enc_key_to_registry: bool,
    idkg_dealing_enc_key: Option<PublicKey>,
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

    pub fn add_generated_idkg_dealing_enc_key_to_registry(mut self) -> Self {
        self.add_idkg_dealing_enc_key_to_registry = true;
        self
    }

    pub fn with_idkg_dealing_enc_key_in_registry(mut self, key: PublicKey) -> Self {
        self.idkg_dealing_enc_key = Some(key);
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
        let temp_crypto = TempCryptoComponent::builder()
            .with_registry(Arc::clone(&registry_client) as Arc<_>)
            .with_node_id(node_id)
            .with_keys(self.node_keys_to_generate.clone())
            .build();
        let node_pubkeys = temp_crypto
            .current_node_public_keys()
            .expect("Failed to retrieve node public keys");
        self.add_node_signing_key_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            &node_pubkeys.node_signing_public_key,
        )
        .add_committee_signing_key_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            &node_pubkeys.committee_signing_public_key,
        )
        .add_dkg_dealing_enc_key_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            &node_pubkeys.dkg_dealing_encryption_public_key,
        )
        .add_idkg_dealing_enc_key_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            &node_pubkeys.idkg_dealing_encryption_public_key,
        )
        .add_tls_cert_to_registry_if_present(
            registry_version,
            node_id,
            &data_provider,
            node_pubkeys.tls_certificate,
        )
        .add_dummy_registry_entry_if_necessary_to_ensure_existence_of_registry_version(
            registry_version,
            &data_provider,
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
                Arc::clone(data_provider),
                registry_version,
            );
        }
        if let Some(pub_key) = self.node_signing_key.as_ref() {
            add_public_key_to_registry(
                pub_key.clone(),
                node_id,
                KeyPurpose::NodeSigning,
                Arc::clone(data_provider),
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
                Arc::clone(data_provider),
                registry_version,
            );
        }
        if let Some(pub_key) = self.committee_signing_key.as_ref() {
            add_public_key_to_registry(
                pub_key.clone(),
                node_id,
                KeyPurpose::CommitteeSigning,
                Arc::clone(data_provider),
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
                Arc::clone(data_provider),
                registry_version,
            );
        }
        if let Some(pub_key) = self.dkg_dealing_enc_key.as_ref() {
            add_public_key_to_registry(
                pub_key.clone(),
                node_id,
                KeyPurpose::DkgDealingEncryption,
                Arc::clone(data_provider),
                registry_version,
            );
        }
        self
    }

    fn add_idkg_dealing_enc_key_to_registry_if_present(
        self,
        registry_version: RegistryVersion,
        node_id: NodeId,
        data_provider: &Arc<ProtoRegistryDataProvider>,
        public_key: &Option<PublicKey>,
    ) -> Self {
        if self.add_idkg_dealing_enc_key_to_registry && self.idkg_dealing_enc_key.is_some() {
            panic!("invalid use of builder: cannot add default and custom I-DKG dealing enc key!")
        }
        if self.add_idkg_dealing_enc_key_to_registry {
            add_public_key_to_registry(
                public_key
                    .as_ref()
                    .expect(
                        "invalid use of builder: I-DKG dealing encryption key was not generated.",
                    )
                    .clone(),
                node_id,
                KeyPurpose::IDkgMEGaEncryption,
                Arc::clone(data_provider),
                registry_version,
            );
        }
        if let Some(pub_key) = self.idkg_dealing_enc_key.as_ref() {
            add_public_key_to_registry(
                pub_key.clone(),
                node_id,
                KeyPurpose::IDkgMEGaEncryption,
                Arc::clone(data_provider),
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
                Arc::clone(data_provider),
                registry_version,
            );
        }
        if let Some(cert) = self.tls_cert.as_ref() {
            add_tls_cert_to_registry(
                cert.clone(),
                node_id,
                Arc::clone(data_provider),
                registry_version,
            );
        }
        self
    }

    fn add_dummy_registry_entry_if_necessary_to_ensure_existence_of_registry_version(
        self,
        registry_version: RegistryVersion,
        data_provider: &Arc<ProtoRegistryDataProvider>,
    ) -> Self {
        if data_provider
            .get_updates_since(RegistryVersion::from(0))
            .expect("failed to get updates")
            .is_empty()
        {
            let dummy_registry_key = "dummy_registry_key";
            let dummy_registry_value = X509PublicKeyCert {
                certificate_der: vec![],
            };
            data_provider
                .add(
                    dummy_registry_key,
                    registry_version,
                    Some(dummy_registry_value),
                )
                .expect("Could not add dummy registry entry to registry");
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
            committee_signing_key: None,
            add_dkg_dealing_enc_key_to_registry: false,
            dkg_dealing_enc_key: None,
            add_idkg_dealing_enc_key_to_registry: false,
            idkg_dealing_enc_key: None,
            add_tls_cert_to_registry: false,
            tls_cert: None,
        }
    }

    pub fn get(&self) -> &TempCryptoComponent {
        &self.temp_crypto
    }
}

pub fn add_tls_cert_to_registry(
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

pub fn add_public_key_to_registry(
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
