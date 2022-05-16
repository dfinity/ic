use crate::common::utils::generate_tls_keys;
use crate::common::utils::{
    generate_committee_signing_keys, generate_dkg_dealing_encryption_keys,
    generate_idkg_dealing_encryption_keys, generate_node_signing_keys,
};
use crate::{derive_node_id, CryptoComponent, CryptoComponentFatClient};
use async_trait::async_trait;
use ic_base_types::PrincipalId;
use ic_config::crypto::{CryptoConfig, CspVaultType};
use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
use ic_crypto_internal_csp::secret_key_store::volatile_store::VolatileSecretKeyStore;
use ic_crypto_internal_csp::vault::remote_csp_vault::TarpcCspVaultServerImpl;
use ic_crypto_internal_csp::{public_key_store, CryptoServiceProvider, Csp};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, TlsClientHandshakeError, TlsHandshake,
    TlsServerHandshakeError, TlsStream,
};
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigVerifierByPublicKey, CanisterSigVerifier, IDkgProtocol, KeyManager,
    MultiSigVerifier, Signable, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
    ThresholdSigVerifier, ThresholdSigVerifierByPublicKey,
};
use ic_interfaces::registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgVerifyComplaintError, IDkgVerifyDealingPrivateError,
    IDkgVerifyDealingPublicError, IDkgVerifyOpeningError, IDkgVerifyTranscriptError,
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgMultiSignedDealing, IDkgOpening, IDkgTranscript,
    IDkgTranscriptParams,
};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
};
use ic_types::crypto::threshold_sig::ni_dkg::DkgId;
use ic_types::crypto::{
    BasicSigOf, CanisterSigOf, CombinedMultiSigOf, CombinedThresholdSigOf, CryptoResult,
    IndividualMultiSigOf, KeyPurpose, ThresholdSigShareOf, UserPublicKey,
};
use ic_types::{NodeId, Randomness, RegistryVersion, SubnetId};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::{TcpStream, UnixListener};

#[cfg(test)]
mod tests;

/// A crypto component set up in a temporary directory. The directory is
/// automatically deleted when this component goes out of scope.
pub type TempCryptoComponent =
    TempCryptoComponentGeneric<Csp<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore>>;

/// This struct combines the following two items:
/// * a crypto component whose state lives in a temporary directory
/// * a newly created temporary directory that contains the state
///
/// Combining these two items is useful for testing because the temporary
/// directory will exist for as long as the struct exists and is automatically
/// deleted once the struct goes out of scope.
pub struct TempCryptoComponentGeneric<C: CryptoServiceProvider> {
    crypto_component: CryptoComponentFatClient<C>,
    vault_server: Option<Arc<TempCspVaultServer>>,
    temp_dir: TempDir,
}

impl<C: CryptoServiceProvider> Deref for TempCryptoComponentGeneric<C> {
    type Target = CryptoComponentFatClient<C>;

    fn deref(&self) -> &Self::Target {
        &self.crypto_component
    }
}

pub struct TempCryptoBuilder {
    node_keys_to_generate: Option<NodeKeysToGenerate>,
    registry_client: Option<Arc<dyn RegistryClient>>,
    registry_version: Option<RegistryVersion>,
    node_id: Option<NodeId>,
    start_remote_vault: bool,
    connected_remote_vault: Option<Arc<TempCspVaultServer>>,
}

impl TempCryptoBuilder {
    const DEFAULT_NODE_ID: u64 = 1;
    const DEFAULT_REGISTRY_VERSION: u64 = 1;

    pub fn with_node_id(mut self, node_id: NodeId) -> Self {
        self.node_id = Some(node_id);
        self
    }

    pub fn with_registry(mut self, registry_client: Arc<dyn RegistryClient>) -> Self {
        self.registry_client = Some(registry_client);
        self
    }

    pub fn with_keys(mut self, keys: NodeKeysToGenerate) -> Self {
        self.node_keys_to_generate = Some(keys);
        self
    }

    pub fn with_keys_in_registry_version(
        mut self,
        keys: NodeKeysToGenerate,
        registry_version: RegistryVersion,
    ) -> Self {
        self.node_keys_to_generate = Some(keys);
        self.registry_version = Some(registry_version);
        self
    }

    pub fn with_remote_vault(mut self) -> Self {
        self.start_remote_vault = true;
        self.connected_remote_vault = None;
        self
    }

    pub fn with_existing_remote_vault(mut self, vault_server: Arc<TempCspVaultServer>) -> Self {
        self.connected_remote_vault = Some(vault_server);
        self.start_remote_vault = false;
        self
    }

    pub fn build(self) -> TempCryptoComponent {
        let (mut config, temp_dir) = CryptoConfig::new_in_temp_dir();

        let node_keys_to_generate = self
            .node_keys_to_generate
            .unwrap_or_else(|| NodeKeysToGenerate::none());
        let node_signing_pk = node_keys_to_generate
            .generate_node_signing_keys
            .then(|| generate_node_signing_keys(&config.crypto_root));
        let node_id = self.node_id.unwrap_or_else(|| {
            node_signing_pk.as_ref().map_or(
                NodeId::from(PrincipalId::new_node_test_id(Self::DEFAULT_NODE_ID)),
                |nspk| derive_node_id(nspk),
            )
        });
        let committee_signing_pk = node_keys_to_generate
            .generate_committee_signing_keys
            .then(|| generate_committee_signing_keys(&config.crypto_root));
        let dkg_dealing_encryption_pk = node_keys_to_generate
            .generate_dkg_dealing_encryption_keys
            .then(|| generate_dkg_dealing_encryption_keys(&config.crypto_root, node_id));
        let idkg_dealing_encryption_pk = node_keys_to_generate
            .generate_idkg_dealing_encryption_keys
            .then(|| generate_idkg_dealing_encryption_keys(&config.crypto_root));
        let tls_certificate = node_keys_to_generate
            .generate_tls_keys_and_certificate
            .then(|| generate_tls_keys(&config.crypto_root, node_id).to_proto());

        let registry_client = if let Some(registry_client) = self.registry_client {
            registry_client
        } else {
            let registry_version = self
                .registry_version
                .unwrap_or(RegistryVersion::new(Self::DEFAULT_REGISTRY_VERSION));
            let registry_data = Arc::new(ProtoRegistryDataProvider::new());

            if let Some(node_signing_pk) = &node_signing_pk {
                registry_data
                    .add(
                        &make_crypto_node_key(node_id, KeyPurpose::NodeSigning),
                        registry_version,
                        Some(node_signing_pk.to_owned()),
                    )
                    .expect("failed to add node signing key to registry");
            }
            if let Some(committee_signing_pk) = &committee_signing_pk {
                registry_data
                    .add(
                        &make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning),
                        registry_version,
                        Some(committee_signing_pk.to_owned()),
                    )
                    .expect("failed to add committee signing key to registry");
            }
            if let Some(dkg_dealing_encryption_pk) = &dkg_dealing_encryption_pk {
                registry_data
                    .add(
                        &make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption),
                        registry_version,
                        Some(dkg_dealing_encryption_pk.to_owned()),
                    )
                    .expect("failed to add NI-DKG dealing encryption key to registry");
            }
            if let Some(idkg_dealing_encryption_pk) = &idkg_dealing_encryption_pk {
                registry_data
                    .add(
                        &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
                        registry_version,
                        Some(idkg_dealing_encryption_pk.to_owned()),
                    )
                    .expect("failed to add iDKG dealing encryption key to registry");
            }
            if let Some(tls_certificate) = &tls_certificate {
                registry_data
                    .add(
                        &make_crypto_tls_cert_key(node_id),
                        registry_version,
                        Some(tls_certificate.to_owned()),
                    )
                    .expect("failed to add TLS certificate to registry");
            }

            let registry_client =
                Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
            registry_client.reload();
            registry_client as Arc<dyn RegistryClient>
        };

        let node_pubkeys = NodePublicKeys {
            version: 1,
            node_signing_pk,
            committee_signing_pk,
            dkg_dealing_encryption_pk,
            idkg_dealing_encryption_pk,
            tls_certificate,
        };
        public_key_store::store_node_public_keys(&config.crypto_root, &node_pubkeys)
            .unwrap_or_else(|_| panic!("failed to store public key material"));

        let vault_server = if self.start_remote_vault {
            let vault_server = TempCspVaultServer::start(&config.crypto_root);
            config.csp_vault_type = CspVaultType::UnixSocket(vault_server.vault_socket_path());
            Some(Arc::new(vault_server))
        } else if let Some(vault_server) = self.connected_remote_vault {
            config.csp_vault_type = CspVaultType::UnixSocket(vault_server.vault_socket_path());
            Some(vault_server)
        } else {
            None
        };

        let crypto_component = CryptoComponent::new_with_fake_node_id(
            &config,
            registry_client,
            node_id,
            no_op_logger(),
        );

        TempCryptoComponent {
            crypto_component,
            vault_server,
            temp_dir,
        }
    }

    pub fn build_arc(self) -> Arc<TempCryptoComponent> {
        Arc::new(self.build())
    }
}

/// A struct combining a temporary directory with a CSP vault server that is
/// listening on a unix socket that lives in this temporary directory. The
/// directory is automatically deleted when this struct goes out of scope.
pub struct TempCspVaultServer {
    join_handle: tokio::task::JoinHandle<()>,
    temp_dir: TempDir,
}

impl Drop for TempCspVaultServer {
    fn drop(&mut self) {
        // Aborts the tokio task that runs the vault server. This drops
        // the server and thus the unix listener and thus the server-side
        // handle to the file acting as unix domain socket used for
        // communication with the server.
        // If also all client-side handles to the socket file are dropped,
        // then nothing should prevent the deletion (=cleanup) of the
        // directory behind `temp_dir` when `temp_dir` is dropped.
        // Note that [the fields of a struct are dropped in declaration order]
        // (https://doc.rust-lang.org/reference/destructors.html#destructors).
        self.join_handle.abort();
    }
}

impl TempCspVaultServer {
    pub fn start(crypto_root: &Path) -> Self {
        let temp_dir = tempfile::Builder::new()
            .prefix("ic_crypto_csp_vault_")
            .tempdir()
            .expect("failed to create temporary directory");
        let vault_socket_path = Self::vault_socket_path_in(temp_dir.path());
        let listener = UnixListener::bind(&vault_socket_path).expect("failed to bind");
        let server = TarpcCspVaultServerImpl::new(crypto_root, listener, no_op_logger());

        let join_handle = tokio::spawn(server.run());

        Self {
            join_handle,
            temp_dir,
        }
    }

    pub fn vault_socket_path(&self) -> PathBuf {
        Self::vault_socket_path_in(self.temp_dir.path())
    }

    fn vault_socket_path_in(directory: &Path) -> PathBuf {
        let mut path = directory.to_path_buf();
        path.push("ic-crypto-csp.socket");
        path
    }
}

impl TempCryptoComponent {
    pub fn builder() -> TempCryptoBuilder {
        TempCryptoBuilder {
            node_id: None,
            start_remote_vault: false,
            registry_client: None,
            node_keys_to_generate: None,
            registry_version: None,
            connected_remote_vault: None,
        }
    }

    pub fn new(registry_client: Arc<dyn RegistryClient>, node_id: NodeId) -> Self {
        TempCryptoComponent::builder()
            .with_registry(registry_client)
            .with_node_id(node_id)
            .build()
    }

    pub fn new_with_ni_dkg_dealing_encryption_key_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, PublicKeyProto) {
        let temp_crypto = TempCryptoComponent::builder()
            .with_registry(registry_client)
            .with_node_id(node_id)
            .with_keys(NodeKeysToGenerate::only_dkg_dealing_encryption_key())
            .build();
        let dkg_dealing_encryption_pubkey = temp_crypto
            .node_public_keys()
            .dkg_dealing_encryption_pk
            .expect("missing dkg_dealing_encryption_pk");
        (temp_crypto, dkg_dealing_encryption_pubkey)
    }

    // TODO (CRP-1275): Remove this once MEGa key is in NodePublicKeys
    pub fn new_with_idkg_dealing_encryption_and_multisigning_keys_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, IDkgMEGaAndMultisignPublicKeys) {
        let temp_crypto = TempCryptoComponent::builder()
            .with_registry(registry_client)
            .with_node_id(node_id)
            .with_keys(NodeKeysToGenerate {
                generate_committee_signing_keys: true,
                generate_idkg_dealing_encryption_keys: true,
                ..NodeKeysToGenerate::none()
            })
            .build();
        let node_public_keys = temp_crypto.node_public_keys();

        let committee_signing_pk = node_public_keys
            .committee_signing_pk
            .expect("missing committee_signing_pk");
        let idkg_dealing_encryption_pk = node_public_keys
            .idkg_dealing_encryption_pk
            .expect("missing idkg_dealing_encryption_pk");
        (
            temp_crypto,
            IDkgMEGaAndMultisignPublicKeys {
                mega_pubkey: idkg_dealing_encryption_pk,
                multisign_pubkey: committee_signing_pk,
            },
        )
    }

    pub fn new_with_tls_key_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, TlsPublicKeyCert) {
        let temp_crypto = TempCryptoComponent::builder()
            .with_registry(registry_client)
            .with_node_id(node_id)
            .with_keys(NodeKeysToGenerate::only_tls_key_and_cert())
            .build();
        let tls_certificate = temp_crypto
            .node_public_keys()
            .tls_certificate
            .expect("missing tls_certificate");
        let tls_pubkey = TlsPublicKeyCert::new_from_der(tls_certificate.certificate_der)
            .expect("failed to create X509 cert from DER");
        (temp_crypto, tls_pubkey)
    }

    pub fn new_with_node_keys_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
        selector: NodeKeysToGenerate,
    ) -> (Self, NodePublicKeys) {
        let temp_crypto = TempCryptoComponent::builder()
            .with_registry(registry_client)
            .with_node_id(node_id)
            .with_keys(selector)
            .build();
        let node_pubkeys = temp_crypto.node_public_keys();
        (temp_crypto, node_pubkeys)
    }

    pub fn new_with(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
        config: &CryptoConfig,
        temp_dir: TempDir,
    ) -> Self {
        let crypto_component = CryptoComponent::new_with_fake_node_id(
            config,
            registry_client,
            node_id,
            no_op_logger(),
        );

        TempCryptoComponent {
            crypto_component,
            vault_server: None,
            temp_dir,
        }
    }

    pub fn multiple_new(
        nodes: &[NodeId],
        registry: Arc<dyn RegistryClient>,
    ) -> BTreeMap<NodeId, TempCryptoComponent> {
        nodes
            .iter()
            .map(|node| {
                let temp_crypto = Self::new(Arc::clone(&registry), *node);
                (*node, temp_crypto)
            })
            .collect()
    }

    pub fn temp_dir_path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }

    pub fn vault_server(&self) -> Option<Arc<TempCspVaultServer>> {
        self.vault_server
            .as_ref()
            .map(|vault_server| Arc::clone(vault_server))
    }
}

/// Bundles the public keys needed for canister threshold signature protocol
// TODO (CRP-1275): Remove this once MEGa key is in NodePublicKeys
pub struct IDkgMEGaAndMultisignPublicKeys {
    pub mega_pubkey: PublicKeyProto,
    pub multisign_pubkey: PublicKeyProto,
}

/// Selects which keys should be generated for a `TempCryptoComponent`.
#[derive(Clone)]
pub struct NodeKeysToGenerate {
    pub generate_node_signing_keys: bool,
    pub generate_committee_signing_keys: bool,
    pub generate_dkg_dealing_encryption_keys: bool,
    pub generate_idkg_dealing_encryption_keys: bool,
    pub generate_tls_keys_and_certificate: bool,
}

impl NodeKeysToGenerate {
    pub fn all() -> Self {
        NodeKeysToGenerate {
            generate_node_signing_keys: true,
            generate_committee_signing_keys: true,
            generate_dkg_dealing_encryption_keys: true,
            generate_idkg_dealing_encryption_keys: true,
            generate_tls_keys_and_certificate: true,
        }
    }

    pub fn none() -> Self {
        NodeKeysToGenerate {
            generate_node_signing_keys: false,
            generate_committee_signing_keys: false,
            generate_dkg_dealing_encryption_keys: false,
            generate_idkg_dealing_encryption_keys: false,
            generate_tls_keys_and_certificate: false,
        }
    }

    pub fn all_except_dkg_dealing_encryption_key() -> Self {
        NodeKeysToGenerate {
            generate_dkg_dealing_encryption_keys: false,
            ..Self::all()
        }
    }

    pub fn all_except_idkg_dealing_encryption_key() -> Self {
        NodeKeysToGenerate {
            generate_idkg_dealing_encryption_keys: false,
            ..Self::all()
        }
    }

    pub fn only_node_signing_key() -> Self {
        NodeKeysToGenerate {
            generate_node_signing_keys: true,
            ..Self::none()
        }
    }

    pub fn only_committee_signing_key() -> Self {
        NodeKeysToGenerate {
            generate_committee_signing_keys: true,
            ..Self::none()
        }
    }

    pub fn only_dkg_dealing_encryption_key() -> Self {
        NodeKeysToGenerate {
            generate_dkg_dealing_encryption_keys: true,
            ..Self::none()
        }
    }

    pub fn only_idkg_dealing_encryption_key() -> Self {
        NodeKeysToGenerate {
            generate_idkg_dealing_encryption_keys: true,
            ..Self::none()
        }
    }

    pub fn only_tls_key_and_cert() -> Self {
        NodeKeysToGenerate {
            generate_tls_keys_and_certificate: true,
            ..Self::none()
        }
    }
}

impl TempCryptoComponentGeneric<Csp<ChaChaRng, ProtoSecretKeyStore, VolatileSecretKeyStore>> {
    pub fn new_from_seed(
        seed: Randomness,
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> Self {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let csprng = ChaChaRng::from_seed(seed.get());
        let crypto_component = CryptoComponentFatClient::new_with_rng_and_fake_node_id(
            csprng,
            &config,
            no_op_logger(),
            registry_client,
            node_id,
        );

        TempCryptoComponentGeneric {
            crypto_component,
            vault_server: None,
            temp_dir,
        }
    }
}

impl<C: CryptoServiceProvider, T: Signable> BasicSigVerifierByPublicKey<T>
    for TempCryptoComponentGeneric<C>
{
    fn verify_basic_sig_by_public_key(
        &self,
        signature: &BasicSigOf<T>,
        signed_bytes: &T,
        public_key: &UserPublicKey,
    ) -> CryptoResult<()> {
        self.crypto_component
            .verify_basic_sig_by_public_key(signature, signed_bytes, public_key)
    }
}

impl<C: CryptoServiceProvider, T: Signable> CanisterSigVerifier<T>
    for TempCryptoComponentGeneric<C>
{
    fn verify_canister_sig(
        &self,
        signature: &CanisterSigOf<T>,
        signed_bytes: &T,
        public_key: &UserPublicKey,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        self.crypto_component.verify_canister_sig(
            signature,
            signed_bytes,
            public_key,
            registry_version,
        )
    }
}

impl<C: CryptoServiceProvider> IDkgProtocol for TempCryptoComponentGeneric<C> {
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<IDkgDealing, IDkgCreateDealingError> {
        self.crypto_component.create_dealing(params)
    }

    fn verify_dealing_public(
        &self,
        params: &IDkgTranscriptParams,
        dealing_id: NodeId,
        dealing: &IDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPublicError> {
        self.crypto_component
            .verify_dealing_public(params, dealing_id, dealing)
    }

    fn verify_dealing_private(
        &self,
        params: &IDkgTranscriptParams,
        dealer_id: NodeId,
        dealing: &IDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        self.crypto_component
            .verify_dealing_private(params, dealer_id, dealing)
    }

    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
    ) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
        self.crypto_component.create_transcript(params, dealings)
    }

    fn verify_transcript(
        &self,
        params: &IDkgTranscriptParams,
        transcript: &IDkgTranscript,
    ) -> Result<(), IDkgVerifyTranscriptError> {
        self.crypto_component.verify_transcript(params, transcript)
    }

    fn load_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
        self.crypto_component.load_transcript(transcript)
    }

    fn verify_complaint(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyComplaintError> {
        self.crypto_component
            .verify_complaint(transcript, complainer_id, complaint)
    }

    fn open_transcript(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgOpenTranscriptError> {
        self.crypto_component
            .open_transcript(transcript, complainer_id, complaint)
    }

    fn verify_opening(
        &self,
        transcript: &IDkgTranscript,
        opener: NodeId,
        opening: &IDkgOpening,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyOpeningError> {
        self.crypto_component
            .verify_opening(transcript, opener, opening, complaint)
    }

    fn load_transcript_with_openings(
        &self,
        transcript: &IDkgTranscript,
        openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgLoadTranscriptError> {
        self.crypto_component
            .load_transcript_with_openings(transcript, openings)
    }

    fn retain_active_transcripts(&self, active_transcripts: &[IDkgTranscript]) {
        self.crypto_component
            .retain_active_transcripts(active_transcripts)
    }
}

impl<C: CryptoServiceProvider> ThresholdEcdsaSigner for TempCryptoComponentGeneric<C> {
    fn sign_share(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
    ) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaSignShareError> {
        self.crypto_component.sign_share(inputs)
    }
}

impl<C: CryptoServiceProvider> ThresholdEcdsaSigVerifier for TempCryptoComponentGeneric<C> {
    fn verify_sig_share(
        &self,
        signer: NodeId,
        inputs: &ThresholdEcdsaSigInputs,
        share: &ThresholdEcdsaSigShare,
    ) -> Result<(), ThresholdEcdsaVerifySigShareError> {
        self.crypto_component
            .verify_sig_share(signer, inputs, share)
    }

    fn combine_sig_shares(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
        shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
    ) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
        self.crypto_component.combine_sig_shares(inputs, shares)
    }

    fn verify_combined_sig(
        &self,
        inputs: &ThresholdEcdsaSigInputs,
        signature: &ThresholdEcdsaCombinedSignature,
    ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
        self.crypto_component.verify_combined_sig(inputs, signature)
    }
}

#[async_trait]
impl<C: CryptoServiceProvider + Send + Sync> TlsHandshake for TempCryptoComponentGeneric<C> {
    async fn perform_tls_server_handshake(
        &self,
        tcp_stream: TcpStream,
        allowed_clients: AllowedClients,
        registry_version: RegistryVersion,
    ) -> Result<(TlsStream, AuthenticatedPeer), TlsServerHandshakeError> {
        self.crypto_component
            .perform_tls_server_handshake(tcp_stream, allowed_clients, registry_version)
            .await
    }

    async fn perform_tls_server_handshake_with_rustls(
        &self,
        tcp_stream: TcpStream,
        allowed_clients: AllowedClients,
        registry_version: RegistryVersion,
    ) -> Result<(TlsStream, AuthenticatedPeer), TlsServerHandshakeError> {
        self.crypto_component
            .perform_tls_server_handshake_with_rustls(tcp_stream, allowed_clients, registry_version)
            .await
    }

    async fn perform_tls_server_handshake_without_client_auth(
        &self,
        tcp_stream: TcpStream,
        registry_version: RegistryVersion,
    ) -> Result<TlsStream, TlsServerHandshakeError> {
        self.crypto_component
            .perform_tls_server_handshake_without_client_auth(tcp_stream, registry_version)
            .await
    }

    async fn perform_tls_server_handshake_without_client_auth_with_rustls(
        &self,
        tcp_stream: TcpStream,
        registry_version: RegistryVersion,
    ) -> Result<TlsStream, TlsServerHandshakeError> {
        self.crypto_component
            .perform_tls_server_handshake_without_client_auth_with_rustls(
                tcp_stream,
                registry_version,
            )
            .await
    }

    async fn perform_tls_client_handshake(
        &self,
        tcp_stream: TcpStream,
        server: NodeId,
        registry_version: RegistryVersion,
    ) -> Result<TlsStream, TlsClientHandshakeError> {
        self.crypto_component
            .perform_tls_client_handshake(tcp_stream, server, registry_version)
            .await
    }

    async fn perform_tls_client_handshake_with_rustls(
        &self,
        tcp_stream: TcpStream,
        server: NodeId,
        registry_version: RegistryVersion,
    ) -> Result<TlsStream, TlsClientHandshakeError> {
        self.crypto_component
            .perform_tls_client_handshake_with_rustls(tcp_stream, server, registry_version)
            .await
    }
}

impl<C: CryptoServiceProvider, T: Signable> BasicSigVerifier<T> for TempCryptoComponentGeneric<C> {
    fn verify_basic_sig(
        &self,
        signature: &BasicSigOf<T>,
        message: &T,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        self.crypto_component
            .verify_basic_sig(signature, message, signer, registry_version)
    }
}

impl<C: CryptoServiceProvider, T: Signable> MultiSigVerifier<T> for TempCryptoComponentGeneric<C> {
    fn verify_multi_sig_individual(
        &self,
        signature: &IndividualMultiSigOf<T>,
        message: &T,
        signer: NodeId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        self.crypto_component.verify_multi_sig_individual(
            signature,
            message,
            signer,
            registry_version,
        )
    }

    fn combine_multi_sig_individuals(
        &self,
        signatures: BTreeMap<NodeId, IndividualMultiSigOf<T>>,
        registry_version: RegistryVersion,
    ) -> CryptoResult<CombinedMultiSigOf<T>> {
        self.crypto_component
            .combine_multi_sig_individuals(signatures, registry_version)
    }

    fn verify_multi_sig_combined(
        &self,
        signature: &CombinedMultiSigOf<T>,
        message: &T,
        signers: BTreeSet<NodeId>,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        self.crypto_component.verify_multi_sig_combined(
            signature,
            message,
            signers,
            registry_version,
        )
    }
}

impl<C: CryptoServiceProvider, T: Signable> ThresholdSigVerifier<T>
    for TempCryptoComponentGeneric<C>
{
    fn verify_threshold_sig_share(
        &self,
        signature: &ThresholdSigShareOf<T>,
        message: &T,
        dkg_id: DkgId,
        signer: NodeId,
    ) -> CryptoResult<()> {
        self.crypto_component
            .verify_threshold_sig_share(signature, message, dkg_id, signer)
    }

    fn combine_threshold_sig_shares(
        &self,
        shares: BTreeMap<NodeId, ThresholdSigShareOf<T>>,
        dkg_id: DkgId,
    ) -> CryptoResult<CombinedThresholdSigOf<T>> {
        self.crypto_component
            .combine_threshold_sig_shares(shares, dkg_id)
    }

    fn verify_threshold_sig_combined(
        &self,
        signature: &CombinedThresholdSigOf<T>,
        message: &T,
        dkg_id: DkgId,
    ) -> CryptoResult<()> {
        self.crypto_component
            .verify_threshold_sig_combined(signature, message, dkg_id)
    }
}

impl<C: CryptoServiceProvider, T: Signable> ThresholdSigVerifierByPublicKey<T>
    for TempCryptoComponentGeneric<C>
{
    fn verify_combined_threshold_sig_by_public_key(
        &self,
        signature: &CombinedThresholdSigOf<T>,
        message: &T,
        subnet_id: SubnetId,
        registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        self.crypto_component
            .verify_combined_threshold_sig_by_public_key(
                signature,
                message,
                subnet_id,
                registry_version,
            )
    }
}
