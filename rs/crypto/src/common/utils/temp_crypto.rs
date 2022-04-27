use crate::common::utils::generate_tls_keys;
use crate::common::utils::{
    generate_committee_signing_keys, generate_dkg_dealing_encryption_keys,
    generate_idkg_dealing_encryption_keys, generate_node_signing_keys,
};
use crate::{CryptoComponent, CryptoComponentFatClient};
use async_trait::async_trait;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
use ic_crypto_internal_csp::secret_key_store::volatile_store::VolatileSecretKeyStore;
use ic_crypto_internal_csp::{public_key_store, CryptoServiceProvider, Csp};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, TlsClientHandshakeError, TlsHandshake,
    TlsServerHandshakeError, TlsStream,
};
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigVerifierByPublicKey, CanisterSigVerifier, IDkgProtocol,
    MultiSigVerifier, Signable, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
    ThresholdSigVerifier, ThresholdSigVerifierByPublicKey,
};
use ic_interfaces::registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
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
    IndividualMultiSigOf, ThresholdSigShareOf, UserPublicKey,
};
use ic_types::{NodeId, Randomness, RegistryVersion, SubnetId};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpStream;

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
    // the temp_dir is required even though it is never read, so the directory exists as long as
    // TempCryptoComponent exists.
    #[allow(dead_code)]
    temp_dir: TempDir,
}

impl<C: CryptoServiceProvider> Deref for TempCryptoComponentGeneric<C> {
    type Target = CryptoComponentFatClient<C>;

    fn deref(&self) -> &Self::Target {
        &self.crypto_component
    }
}

impl TempCryptoComponent {
    pub fn new(registry_client: Arc<dyn RegistryClient>, node_id: NodeId) -> Self {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let crypto_component = CryptoComponent::new_with_fake_node_id(
            &config,
            registry_client,
            node_id,
            no_op_logger(),
        );

        TempCryptoComponent {
            crypto_component,
            temp_dir,
        }
    }

    // Note that in this method we cannot simply use Self::new and then
    // pass the path of the returned crypto component to the key generation
    // method. This is because the key generation method will create
    // its own CSP, which will lead to synchronization/consistency issues
    // in the secret key store.
    pub fn new_with_ni_dkg_dealing_encryption_key_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, PublicKeyProto) {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let crypto_root = temp_dir.path().to_path_buf();
        let dkg_dealing_encryption_pubkey =
            generate_dkg_dealing_encryption_keys(&crypto_root, node_id);
        let node_pks = NodePublicKeys {
            version: 0,
            dkg_dealing_encryption_pk: Some(dkg_dealing_encryption_pubkey.to_owned()),
            ..Default::default()
        };
        public_key_store::store_node_public_keys(&crypto_root, &node_pks)
            .expect("Could not store node public keys.");
        let temp_crypto =
            TempCryptoComponent::new_with(registry_client, node_id, &config, temp_dir);
        (temp_crypto, dkg_dealing_encryption_pubkey)
    }

    // Note that in this method we cannot simply use Self::new and then
    // pass the path of the returned crypto component to the key generation
    // method. This is because the key generation method will create
    // its own CSP, which will lead to synchronization/consistency issues
    // in the secret key store.
    pub fn new_with_idkg_dealing_encryption_key_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, PublicKeyProto) {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let crypto_root = temp_dir.path().to_path_buf();
        let idkg_dealing_encryption_pubkey = generate_idkg_dealing_encryption_keys(&crypto_root);
        let temp_crypto =
            TempCryptoComponent::new_with(registry_client, node_id, &config, temp_dir);
        (temp_crypto, idkg_dealing_encryption_pubkey)
    }

    // Note that in this method we cannot simply use Self::new and then
    // pass the path of the returned crypto component to the key generation
    // method. This is because the key generation method will create
    // its own CSP, which will lead to synchronization/consistency issues
    // in the secret key store.
    // TODO (CRP-1275): Remove this once MEGa key is in NodePublicKeys
    pub fn new_with_idkg_dealing_encryption_and_multisigning_keys_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, IDkgMEGaAndMultisignPublicKeys) {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let crypto_root = temp_dir.path().to_path_buf();

        let mega_pubkey = generate_idkg_dealing_encryption_keys(&crypto_root);
        let multisign_pubkey = generate_committee_signing_keys(&crypto_root);

        let temp_crypto =
            TempCryptoComponent::new_with(registry_client, node_id, &config, temp_dir);
        (
            temp_crypto,
            IDkgMEGaAndMultisignPublicKeys {
                mega_pubkey,
                multisign_pubkey,
            },
        )
    }

    // Note that in this method we cannot simply use Self::new and then
    // pass the path of the returned crypto component to the key generation
    // method. This is because the key generation method will create
    // its own CSP, which will lead to synchronization/consistency issues
    // in the secret key store.
    pub fn new_with_tls_key_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
    ) -> (Self, TlsPublicKeyCert) {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let tls_pubkey = generate_tls_keys(temp_dir.path(), node_id);

        let temp_crypto =
            TempCryptoComponent::new_with(registry_client, node_id, &config, temp_dir);
        (temp_crypto, tls_pubkey)
    }

    // Note that in this method we cannot simply use Self::new and then
    // pass the path of the returned crypto component to the key generation
    // method. This is because the key generation method will create
    // its own CSP, which will lead to synchronization/consistency issues
    // in the secret key store.
    pub fn new_with_node_keys_generation(
        registry_client: Arc<dyn RegistryClient>,
        node_id: NodeId,
        selector: NodeKeysToGenerate,
    ) -> (Self, NodePublicKeys) {
        let (config, temp_dir) = CryptoConfig::new_in_temp_dir();
        let temp_dir_path = std::path::PathBuf::from(
            temp_dir
                .path()
                .to_str()
                .expect("failed to convert path to string"),
        );

        let node_signing_pk = match selector.generate_node_signing_keys {
            true => Some(generate_node_signing_keys(&temp_dir_path)),
            false => None,
        };
        let committee_signing_pk = match selector.generate_committee_signing_keys {
            true => Some(generate_committee_signing_keys(&temp_dir_path)),
            false => None,
        };
        let dkg_dealing_encryption_pk = match selector.generate_dkg_dealing_encryption_keys {
            true => Some(generate_dkg_dealing_encryption_keys(
                &temp_dir_path,
                node_id,
            )),
            false => None,
        };
        let idkg_dealing_encryption_pk = match selector.generate_idkg_dealing_encryption_keys {
            true => Some(generate_idkg_dealing_encryption_keys(&temp_dir_path)),
            false => None,
        };
        let tls_certificate = match selector.generate_tls_keys_and_certificate {
            true => Some(generate_tls_keys(&temp_dir_path, node_id).to_proto()),
            false => None,
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
            .unwrap_or_else(|_| panic!("Failed to store public key material"));

        let temp_crypto =
            TempCryptoComponent::new_with(registry_client, node_id, &config, temp_dir);
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
