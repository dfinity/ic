use ic_crypto_internal_csp::Csp;
use ic_interfaces::time_source::SysTimeSource;
use ic_protobuf::registry::crypto::v1::{EcdsaCurve, EcdsaKeyId};
use ic_protobuf::registry::subnet::v1::{ChainKeyConfig, KeyConfig, SubnetRecord, SubnetType};
use ic_types::{NodeId, ReplicaVersion, SubnetId};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use std::time::Duration;

/// A crypto component set up in a temporary directory and using [`OsRng`]. The
/// directory is automatically deleted when this component goes out of scope.
pub type TempCryptoComponent = TempCryptoComponentGeneric<OsRng>;

/// A crypto component set up in a temporary directory. The directory is
/// automatically deleted when this component goes out of scope.
pub type TempCryptoComponentGeneric<R> = internal::TempCryptoComponentGeneric<Csp, R>;

/// A supertrait collecting traits required for an RNG used in the [`CryptoComponent`].
pub trait CryptoComponentRng: Rng + CryptoRng + 'static + Send + Sync {}
impl<T: Rng + CryptoRng + 'static + Send + Sync> CryptoComponentRng for T {}

pub mod internal {
    use super::*;
    use ic_base_types::PrincipalId;
    use ic_config::crypto::{CryptoConfig, CspVaultType};
    use ic_crypto::{CryptoComponent, CryptoComponentImpl};
    use ic_crypto_interfaces_sig_verification::{BasicSigVerifierByPublicKey, CanisterSigVerifier};
    use ic_crypto_internal_csp::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
    use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
    use ic_crypto_internal_csp::vault::local_csp_vault::ProdLocalCspVault;
    use ic_crypto_internal_csp::LocalCspVault;
    use ic_crypto_internal_csp::{CryptoServiceProvider, Csp};
    use ic_crypto_internal_logmon::metrics::CryptoMetrics;
    use ic_crypto_node_key_generation::{
        generate_committee_signing_keys, generate_dkg_dealing_encryption_keys,
        generate_idkg_dealing_encryption_keys, generate_node_signing_keys, generate_tls_keys,
    };
    use ic_crypto_temp_crypto_vault::{
        RemoteVaultEnvironment, TempCspVaultServer, TokioRuntimeOrHandle,
    };
    use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsConfig, TlsConfigError, TlsPublicKeyCert};
    use ic_crypto_utils_basic_sig::conversions::derive_node_id;
    use ic_interfaces::crypto::{
        BasicSigVerifier, BasicSigner, CheckKeysWithRegistryError, CurrentNodePublicKeysError,
        IDkgDealingEncryptionKeyRotationError, IDkgKeyRotationResult, IDkgProtocol, KeyManager,
        LoadTranscriptResult, MultiSigVerifier, MultiSigner, NiDkgAlgorithm,
        ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner, ThresholdSchnorrSigVerifier,
        ThresholdSchnorrSigner, ThresholdSigVerifier, ThresholdSigVerifierByPublicKey,
        ThresholdSigner,
    };
    use ic_interfaces::time_source::TimeSource;
    use ic_interfaces_registry::RegistryClient;
    use ic_logger::replica_logger::no_op_logger;
    use ic_logger::{new_logger, ReplicaLogger};
    use ic_protobuf::registry::subnet::v1::SubnetListRecord;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::{
        make_crypto_node_key, make_crypto_tls_cert_key, make_subnet_list_record_key,
        make_subnet_record_key,
    };
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types::crypto::canister_threshold_sig::error::{
        IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
        IDkgOpenTranscriptError, IDkgRetainKeysError, IDkgVerifyComplaintError,
        IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError,
        IDkgVerifyInitialDealingsError, IDkgVerifyOpeningError, IDkgVerifyTranscriptError,
        ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaCreateSigShareError,
        ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
        ThresholdSchnorrCombineSigSharesError, ThresholdSchnorrCreateSigShareError,
        ThresholdSchnorrVerifyCombinedSigError, ThresholdSchnorrVerifySigShareError,
    };
    use ic_types::crypto::canister_threshold_sig::idkg::{
        BatchSignedIDkgDealings, IDkgComplaint, IDkgOpening, IDkgTranscript, IDkgTranscriptParams,
        InitialIDkgDealings, SignedIDkgDealing,
    };
    use ic_types::crypto::canister_threshold_sig::{
        ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
        ThresholdSchnorrCombinedSignature, ThresholdSchnorrSigInputs, ThresholdSchnorrSigShare,
    };
    use ic_types::crypto::threshold_sig::ni_dkg::config::NiDkgConfig;
    use ic_types::crypto::threshold_sig::ni_dkg::errors::{
        create_dealing_error::DkgCreateDealingError,
        create_transcript_error::DkgCreateTranscriptError, key_removal_error::DkgKeyRemovalError,
        load_transcript_error::DkgLoadTranscriptError, verify_dealing_error::DkgVerifyDealingError,
    };
    use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId, NiDkgTranscript};
    use ic_types::crypto::threshold_sig::IcRootOfTrust;
    use ic_types::crypto::{
        BasicSigOf, CanisterSigOf, CombinedMultiSigOf, CombinedThresholdSigOf, CryptoResult,
        CurrentNodePublicKeys, IndividualMultiSigOf, KeyPurpose, Signable, ThresholdSigShareOf,
        UserPublicKey,
    };
    use ic_types::signature::BasicSignatureBatch;
    use ic_types::{NodeId, RegistryVersion, SubnetId};
    use rand::rngs::OsRng;
    use rustls::{ClientConfig, ServerConfig};
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::ops::Deref;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::TempDir;

    /// This struct combines the following two items:
    /// * a crypto component whose state lives in a temporary directory
    /// * a newly created temporary directory that contains the state
    ///
    /// Combining these two items is useful for testing because the temporary
    /// directory will exist for as long as the struct exists and is automatically
    /// deleted once the struct goes out of scope.
    pub struct TempCryptoComponentGeneric<C, R>
    where
        C: CryptoServiceProvider,
        R: CryptoComponentRng,
    {
        crypto_component: CryptoComponentImpl<C>,
        remote_vault_environment: Option<
            RemoteVaultEnvironment<
                LocalCspVault<R, ProtoSecretKeyStore, ProtoSecretKeyStore, ProtoPublicKeyStore>,
            >,
        >,
        temp_dir: TempDir,
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng> Deref for TempCryptoComponentGeneric<C, R> {
        type Target = CryptoComponentImpl<C>;

        fn deref(&self) -> &Self::Target {
            &self.crypto_component
        }
    }

    pub struct TempCryptoBuilder<R: CryptoComponentRng> {
        node_keys_to_generate: Option<NodeKeysToGenerate>,
        registry_client: Option<Arc<dyn RegistryClient>>,
        registry_data: Option<Arc<ProtoRegistryDataProvider>>,
        registry_version: Option<RegistryVersion>,
        node_id: Option<NodeId>,
        start_remote_vault: bool,
        vault_client_runtime_handle: Option<tokio::runtime::Handle>,
        temp_dir_source: Option<PathBuf>,
        logger: Option<ReplicaLogger>,
        metrics: Option<Arc<CryptoMetrics>>,
        time_source: Option<Arc<dyn TimeSource>>,
        ecdsa_subnet_config: Option<EcdsaSubnetConfig>,
        rng: R,
    }

    impl<R: CryptoComponentRng> TempCryptoBuilder<R> {
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

        /// If the `registry_client` is of type `FakeRegistryClient`, the caller may manually have to
        /// call `registry_client.reload()` after calling `build()`.
        pub fn with_registry_client_and_data(
            mut self,
            registry_client: Arc<dyn RegistryClient>,
            registry_data: Arc<ProtoRegistryDataProvider>,
        ) -> Self {
            self.registry_client = Some(registry_client);
            self.registry_data = Some(registry_data);
            self
        }

        pub fn with_logger(mut self, logger: ReplicaLogger) -> Self {
            self.logger = Some(logger);
            self
        }

        pub fn with_metrics(mut self, metrics: Arc<CryptoMetrics>) -> Self {
            self.metrics = Some(metrics);
            self
        }

        pub fn with_temp_dir_source(mut self, source: PathBuf) -> Self {
            self.temp_dir_source = Some(source);
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
            self
        }

        pub fn with_vault_client_runtime(mut self, rt_handle: tokio::runtime::Handle) -> Self {
            self.vault_client_runtime_handle = Some(rt_handle);
            self
        }

        pub fn with_time_source(mut self, time_source: Arc<dyn TimeSource>) -> Self {
            self.time_source = Some(time_source);
            self
        }

        pub fn with_ecdsa_subnet_config(mut self, ecdsa_subnet_config: EcdsaSubnetConfig) -> Self {
            self.ecdsa_subnet_config = Some(ecdsa_subnet_config);
            self
        }

        pub fn with_rng<OtherRng: CryptoComponentRng>(
            self,
            rng: OtherRng,
        ) -> TempCryptoBuilder<OtherRng> {
            TempCryptoBuilder {
                node_keys_to_generate: self.node_keys_to_generate,
                registry_client: self.registry_client,
                registry_data: self.registry_data,
                registry_version: self.registry_version,
                node_id: self.node_id,
                start_remote_vault: self.start_remote_vault,
                vault_client_runtime_handle: self.vault_client_runtime_handle,
                temp_dir_source: self.temp_dir_source,
                logger: self.logger,
                metrics: self.metrics,
                time_source: self.time_source,
                ecdsa_subnet_config: self.ecdsa_subnet_config,
                rng,
            }
        }

        pub fn build(self) -> TempCryptoComponentGeneric<Csp, R> {
            let logger = self.logger.unwrap_or_else(no_op_logger);
            let metrics = self
                .metrics
                .unwrap_or_else(|| Arc::new(CryptoMetrics::none()));
            let time_source = self
                .time_source
                .unwrap_or_else(|| Arc::new(SysTimeSource::new()));

            let (mut config, temp_dir) = CryptoConfig::new_in_temp_dir();
            if let Some(source) = self.temp_dir_source {
                copy_crypto_root(&source, temp_dir.path());
            }
            let local_vault = Arc::new(
                ProdLocalCspVault::builder_in_dir(
                    &config.crypto_root,
                    Arc::clone(&metrics),
                    new_logger!(logger),
                )
                .with_rng(self.rng)
                .with_time_source(Arc::clone(&time_source))
                .build(),
            );
            let opt_remote_vault_environment = self.start_remote_vault.then(|| {
                let vault_server =
                    TempCspVaultServer::start_with_local_csp_vault(Arc::clone(&local_vault));
                config.csp_vault_type = CspVaultType::UnixSocket {
                    logic: vault_server.vault_socket_path(),
                    metrics: None,
                };
                RemoteVaultEnvironment {
                    vault_server,
                    vault_client_runtime: TokioRuntimeOrHandle::new(
                        self.vault_client_runtime_handle,
                    ),
                }
            });

            let csp = if let Some(env) = &opt_remote_vault_environment {
                let vault_client = env
                    .new_vault_client_builder()
                    .with_logger(new_logger!(logger))
                    .with_metrics(Arc::clone(&metrics))
                    .build()
                    .expect("Failed to build a vault client");
                Csp::new_from_vault(
                    Arc::new(vault_client),
                    new_logger!(logger),
                    Arc::clone(&metrics),
                )
            } else {
                Csp::new_from_vault(
                    Arc::clone(&local_vault) as _,
                    new_logger!(logger),
                    Arc::clone(&metrics),
                )
            };

            let node_keys_to_generate = self
                .node_keys_to_generate
                .unwrap_or_else(NodeKeysToGenerate::none);
            let node_signing_pk = node_keys_to_generate
                .generate_node_signing_keys
                .then(|| generate_node_signing_keys(local_vault.as_ref()));
            let node_id = self
                .node_id
                .unwrap_or_else(|| match node_signing_pk.as_ref() {
                    None => NodeId::from(PrincipalId::new_node_test_id(Self::DEFAULT_NODE_ID)),
                    Some(node_signing_pk) => derive_node_id(node_signing_pk)
                        .expect("Node signing public key should be valid"),
                });
            let committee_signing_pk = node_keys_to_generate
                .generate_committee_signing_keys
                .then(|| generate_committee_signing_keys(local_vault.as_ref()));
            let dkg_dealing_encryption_pk = node_keys_to_generate
                .generate_dkg_dealing_encryption_keys
                .then(|| generate_dkg_dealing_encryption_keys(local_vault.as_ref(), node_id));
            let idkg_dealing_encryption_pk = node_keys_to_generate
                .generate_idkg_dealing_encryption_keys
                .then(|| {
                    generate_idkg_dealing_encryption_keys(local_vault.as_ref()).unwrap_or_else(
                        |e| panic!("Error generating I-DKG dealing encryption keys: {:?}", e),
                    )
                });
            let tls_certificate = node_keys_to_generate
                .generate_tls_keys_and_certificate
                .then(|| generate_tls_keys(local_vault.as_ref(), node_id).to_proto());

            let is_registry_data_provided = self.registry_data.is_some();
            let registry_data = self
                .registry_data
                .unwrap_or_else(|| Arc::new(ProtoRegistryDataProvider::new()));
            if is_registry_data_provided || self.registry_client.is_none() {
                // add data. if a registry_client is provided, the caller has to reload it themselves.
                let registry_version = self
                    .registry_version
                    .unwrap_or(RegistryVersion::new(Self::DEFAULT_REGISTRY_VERSION));
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
                if let Some(ecdsa_subnet_config) = self.ecdsa_subnet_config {
                    registry_data
                        .add(
                            &make_subnet_record_key(ecdsa_subnet_config.subnet_id),
                            registry_version,
                            Some(ecdsa_subnet_config.subnet_record),
                        )
                        .expect("Failed to add subnet record.");
                    let subnet_list_record = SubnetListRecord {
                        subnets: vec![ecdsa_subnet_config.subnet_id.get().into_vec()],
                    };
                    // Set subnetwork list
                    registry_data
                        .add(
                            make_subnet_list_record_key().as_str(),
                            registry_version,
                            Some(subnet_list_record),
                        )
                        .expect("Failed to add subnet list record key");
                }
            }
            let registry_client = self.registry_client.unwrap_or_else(|| {
                let fake_registry_client = Arc::new(FakeRegistryClient::new(registry_data));
                fake_registry_client.reload();
                fake_registry_client as Arc<dyn RegistryClient>
            });

            let crypto_component = CryptoComponent::new_for_test(
                csp,
                local_vault,
                logger,
                registry_client,
                node_id,
                metrics,
                Some(time_source),
            );

            TempCryptoComponentGeneric {
                crypto_component,
                remote_vault_environment: opt_remote_vault_environment,
                temp_dir,
            }
        }

        pub fn build_arc(self) -> Arc<TempCryptoComponentGeneric<Csp, R>> {
            Arc::new(self.build())
        }
    }

    impl<R: CryptoComponentRng> TempCryptoComponentGeneric<Csp, R> {
        pub fn builder() -> TempCryptoBuilder<OsRng> {
            TempCryptoBuilder {
                node_id: None,
                start_remote_vault: false,
                vault_client_runtime_handle: None,
                registry_client: None,
                registry_data: None,
                node_keys_to_generate: None,
                registry_version: None,
                temp_dir_source: None,
                logger: None,
                metrics: None,
                time_source: None,
                ecdsa_subnet_config: None,
                rng: OsRng,
            }
        }

        pub fn node_tls_public_key_certificate(&self) -> TlsPublicKeyCert {
            let tls_certificate = self
                .current_node_public_keys()
                .expect("Failed to retrieve node public keys")
                .tls_certificate
                .expect("missing tls_certificate");
            TlsPublicKeyCert::new_from_der(tls_certificate.certificate_der)
                .expect("failed to create X509 cert from DER")
        }

        pub fn temp_dir_path(&self) -> &Path {
            self.temp_dir.path()
        }

        pub fn vault_client_runtime(&self) -> Option<&tokio::runtime::Handle> {
            self.remote_vault_environment
                .as_ref()
                .map(|env| env.vault_client_runtime.handle())
        }

        pub fn copy_crypto_root_to(&self, target: &Path) {
            copy_crypto_root(self.temp_dir_path(), target);
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng, T: Signable> BasicSigner<T>
        for TempCryptoComponentGeneric<C, R>
    {
        fn sign_basic(
            &self,
            message: &T,
            signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSigOf<T>> {
            self.crypto_component
                .sign_basic(message, signer, registry_version)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng, T: Signable>
        BasicSigVerifierByPublicKey<T> for TempCryptoComponentGeneric<C, R>
    {
        fn verify_basic_sig_by_public_key(
            &self,
            signature: &BasicSigOf<T>,
            signed_bytes: &T,
            public_key: &UserPublicKey,
        ) -> CryptoResult<()> {
            self.crypto_component.verify_basic_sig_by_public_key(
                signature,
                signed_bytes,
                public_key,
            )
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng, T: Signable> CanisterSigVerifier<T>
        for TempCryptoComponentGeneric<C, R>
    {
        fn verify_canister_sig(
            &self,
            signature: &CanisterSigOf<T>,
            signed_bytes: &T,
            public_key: &UserPublicKey,
            root_of_trust: &IcRootOfTrust,
        ) -> CryptoResult<()> {
            self.crypto_component.verify_canister_sig(
                signature,
                signed_bytes,
                public_key,
                root_of_trust,
            )
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng> IDkgProtocol
        for TempCryptoComponentGeneric<C, R>
    {
        fn create_dealing(
            &self,
            params: &IDkgTranscriptParams,
        ) -> Result<SignedIDkgDealing, IDkgCreateDealingError> {
            IDkgProtocol::create_dealing(&self.crypto_component, params)
        }

        fn verify_dealing_public(
            &self,
            params: &IDkgTranscriptParams,
            signed_dealing: &SignedIDkgDealing,
        ) -> Result<(), IDkgVerifyDealingPublicError> {
            self.crypto_component
                .verify_dealing_public(params, signed_dealing)
        }

        fn verify_dealing_private(
            &self,
            params: &IDkgTranscriptParams,
            signed_dealing: &SignedIDkgDealing,
        ) -> Result<(), IDkgVerifyDealingPrivateError> {
            self.crypto_component
                .verify_dealing_private(params, signed_dealing)
        }

        fn verify_initial_dealings(
            &self,
            params: &IDkgTranscriptParams,
            initial_dealings: &InitialIDkgDealings,
        ) -> Result<(), IDkgVerifyInitialDealingsError> {
            self.crypto_component
                .verify_initial_dealings(params, initial_dealings)
        }

        fn create_transcript(
            &self,
            params: &IDkgTranscriptParams,
            dealings: &BatchSignedIDkgDealings,
        ) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
            IDkgProtocol::create_transcript(&self.crypto_component, params, dealings)
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
            IDkgProtocol::load_transcript(&self.crypto_component, transcript)
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

        fn retain_active_transcripts(
            &self,
            active_transcripts: &HashSet<IDkgTranscript>,
        ) -> Result<(), IDkgRetainKeysError> {
            self.crypto_component
                .retain_active_transcripts(active_transcripts)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng> ThresholdEcdsaSigner
        for TempCryptoComponentGeneric<C, R>
    {
        fn create_sig_share(
            &self,
            inputs: &ThresholdEcdsaSigInputs,
        ) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaCreateSigShareError> {
            ThresholdEcdsaSigner::create_sig_share(&self.crypto_component, inputs)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng> ThresholdEcdsaSigVerifier
        for TempCryptoComponentGeneric<C, R>
    {
        fn verify_sig_share(
            &self,
            signer: NodeId,
            inputs: &ThresholdEcdsaSigInputs,
            share: &ThresholdEcdsaSigShare,
        ) -> Result<(), ThresholdEcdsaVerifySigShareError> {
            ThresholdEcdsaSigVerifier::verify_sig_share(
                &self.crypto_component,
                signer,
                inputs,
                share,
            )
        }

        fn combine_sig_shares(
            &self,
            inputs: &ThresholdEcdsaSigInputs,
            shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
        ) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
            ThresholdEcdsaSigVerifier::combine_sig_shares(&self.crypto_component, inputs, shares)
        }

        fn verify_combined_sig(
            &self,
            inputs: &ThresholdEcdsaSigInputs,
            signature: &ThresholdEcdsaCombinedSignature,
        ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
            ThresholdEcdsaSigVerifier::verify_combined_sig(
                &self.crypto_component,
                inputs,
                signature,
            )
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng> ThresholdSchnorrSigner
        for TempCryptoComponentGeneric<C, R>
    {
        fn create_sig_share(
            &self,
            inputs: &ThresholdSchnorrSigInputs,
        ) -> Result<ThresholdSchnorrSigShare, ThresholdSchnorrCreateSigShareError> {
            ThresholdSchnorrSigner::create_sig_share(&self.crypto_component, inputs)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng> ThresholdSchnorrSigVerifier
        for TempCryptoComponentGeneric<C, R>
    {
        fn verify_sig_share(
            &self,
            signer: NodeId,
            inputs: &ThresholdSchnorrSigInputs,
            share: &ThresholdSchnorrSigShare,
        ) -> Result<(), ThresholdSchnorrVerifySigShareError> {
            ThresholdSchnorrSigVerifier::verify_sig_share(
                &self.crypto_component,
                signer,
                inputs,
                share,
            )
        }

        fn combine_sig_shares(
            &self,
            inputs: &ThresholdSchnorrSigInputs,
            shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
        ) -> Result<ThresholdSchnorrCombinedSignature, ThresholdSchnorrCombineSigSharesError>
        {
            ThresholdSchnorrSigVerifier::combine_sig_shares(&self.crypto_component, inputs, shares)
        }

        fn verify_combined_sig(
            &self,
            inputs: &ThresholdSchnorrSigInputs,
            signature: &ThresholdSchnorrCombinedSignature,
        ) -> Result<(), ThresholdSchnorrVerifyCombinedSigError> {
            ThresholdSchnorrSigVerifier::verify_combined_sig(
                &self.crypto_component,
                inputs,
                signature,
            )
        }
    }

    impl<C: CryptoServiceProvider + Send + Sync, R: CryptoComponentRng> TlsConfig
        for TempCryptoComponentGeneric<C, R>
    {
        fn server_config(
            &self,
            allowed_clients: SomeOrAllNodes,
            registry_version: RegistryVersion,
        ) -> Result<ServerConfig, TlsConfigError> {
            self.crypto_component
                .server_config(allowed_clients, registry_version)
        }

        fn server_config_without_client_auth(
            &self,
            registry_version: RegistryVersion,
        ) -> Result<ServerConfig, TlsConfigError> {
            self.crypto_component
                .server_config_without_client_auth(registry_version)
        }

        fn client_config(
            &self,
            server: NodeId,
            registry_version: RegistryVersion,
        ) -> Result<ClientConfig, TlsConfigError> {
            self.crypto_component
                .client_config(server, registry_version)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng, T: Signable> BasicSigVerifier<T>
        for TempCryptoComponentGeneric<C, R>
    {
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

        fn combine_basic_sig(
            &self,
            signatures: BTreeMap<NodeId, &BasicSigOf<T>>,
            registry_version: RegistryVersion,
        ) -> CryptoResult<BasicSignatureBatch<T>> {
            self.crypto_component
                .combine_basic_sig(signatures, registry_version)
        }

        fn verify_basic_sig_batch(
            &self,
            signature: &BasicSignatureBatch<T>,
            message: &T,
            registry_version: RegistryVersion,
        ) -> CryptoResult<()> {
            self.crypto_component
                .verify_basic_sig_batch(signature, message, registry_version)
        }
    }

    impl<C: CryptoServiceProvider, T: Signable, R: CryptoComponentRng> MultiSigVerifier<T>
        for TempCryptoComponentGeneric<C, R>
    {
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

    impl<C: CryptoServiceProvider, R: CryptoComponentRng, T: Signable> ThresholdSigVerifier<T>
        for TempCryptoComponentGeneric<C, R>
    {
        fn verify_threshold_sig_share(
            &self,
            signature: &ThresholdSigShareOf<T>,
            message: &T,
            dkg_id: NiDkgId,
            signer: NodeId,
        ) -> CryptoResult<()> {
            self.crypto_component
                .verify_threshold_sig_share(signature, message, dkg_id, signer)
        }

        fn combine_threshold_sig_shares(
            &self,
            shares: BTreeMap<NodeId, ThresholdSigShareOf<T>>,
            dkg_id: NiDkgId,
        ) -> CryptoResult<CombinedThresholdSigOf<T>> {
            self.crypto_component
                .combine_threshold_sig_shares(shares, dkg_id)
        }

        fn verify_threshold_sig_combined(
            &self,
            signature: &CombinedThresholdSigOf<T>,
            message: &T,
            dkg_id: NiDkgId,
        ) -> CryptoResult<()> {
            self.crypto_component
                .verify_threshold_sig_combined(signature, message, dkg_id)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng, T: Signable>
        ThresholdSigVerifierByPublicKey<T> for TempCryptoComponentGeneric<C, R>
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

    impl<C: CryptoServiceProvider, R: CryptoComponentRng> KeyManager
        for TempCryptoComponentGeneric<C, R>
    {
        fn check_keys_with_registry(
            &self,
            registry_version: RegistryVersion,
        ) -> Result<(), CheckKeysWithRegistryError> {
            self.crypto_component
                .check_keys_with_registry(registry_version)
        }

        fn current_node_public_keys(
            &self,
        ) -> Result<CurrentNodePublicKeys, CurrentNodePublicKeysError> {
            self.crypto_component.current_node_public_keys()
        }

        fn rotate_idkg_dealing_encryption_keys(
            &self,
            registry_version: RegistryVersion,
        ) -> Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError> {
            self.crypto_component
                .rotate_idkg_dealing_encryption_keys(registry_version)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng> NiDkgAlgorithm
        for TempCryptoComponentGeneric<C, R>
    {
        fn create_dealing(
            &self,
            config: &NiDkgConfig,
        ) -> Result<NiDkgDealing, DkgCreateDealingError> {
            NiDkgAlgorithm::create_dealing(&self.crypto_component, config)
        }

        fn verify_dealing(
            &self,
            config: &NiDkgConfig,
            dealer: NodeId,
            dealing: &NiDkgDealing,
        ) -> Result<(), DkgVerifyDealingError> {
            self.crypto_component
                .verify_dealing(config, dealer, dealing)
        }

        fn create_transcript(
            &self,
            config: &NiDkgConfig,
            verified_dealings: &BTreeMap<NodeId, NiDkgDealing>,
        ) -> Result<NiDkgTranscript, DkgCreateTranscriptError> {
            NiDkgAlgorithm::create_transcript(&self.crypto_component, config, verified_dealings)
        }

        fn load_transcript(
            &self,
            transcript: &NiDkgTranscript,
        ) -> Result<LoadTranscriptResult, DkgLoadTranscriptError> {
            NiDkgAlgorithm::load_transcript(&self.crypto_component, transcript)
        }

        fn retain_only_active_keys(
            &self,
            transcripts: HashSet<NiDkgTranscript>,
        ) -> Result<(), DkgKeyRemovalError> {
            self.crypto_component.retain_only_active_keys(transcripts)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng, T: Signable> ThresholdSigner<T>
        for TempCryptoComponentGeneric<C, R>
    {
        fn sign_threshold(
            &self,
            message: &T,
            dkg_id: NiDkgId,
        ) -> CryptoResult<ThresholdSigShareOf<T>> {
            self.crypto_component.sign_threshold(message, dkg_id)
        }
    }

    impl<C: CryptoServiceProvider, R: CryptoComponentRng, T: Signable> MultiSigner<T>
        for TempCryptoComponentGeneric<C, R>
    {
        fn sign_multi(
            &self,
            message: &T,
            signer: NodeId,
            registry_version: RegistryVersion,
        ) -> CryptoResult<IndividualMultiSigOf<T>> {
            self.crypto_component
                .sign_multi(message, signer, registry_version)
        }
    }

    /// Copies the given source directory into a newly-created directory.
    ///
    /// Note: The copy is only of files and only one level deep (all that's
    /// required for a CryptoComponent).
    fn copy_crypto_root(src: &Path, dest: &Path) {
        std::fs::create_dir_all(dest).unwrap_or_else(|err| {
            panic!(
                "Failed to create crypto root directory {}: {}",
                dest.display(),
                err
            )
        });
        for entry in std::fs::read_dir(src).expect("src directory doesn't exist") {
            let path = entry.expect("failed to get path in src dir").path();
            if path.is_file() {
                let filename = path.file_name().expect("failed to get src path");
                let dest_path = dest.join(filename);
                std::fs::copy(&path, dest_path).expect("failed to copy file");
            }
        }
    }
}

pub struct EcdsaSubnetConfig {
    pub subnet_id: SubnetId,
    pub subnet_record: SubnetRecord,
}

impl EcdsaSubnetConfig {
    pub fn new(
        subnet_id: SubnetId,
        node_id: Option<NodeId>,
        key_rotation_period: Option<Duration>,
    ) -> Self {
        EcdsaSubnetConfig {
            subnet_id,
            subnet_record: SubnetRecord {
                membership: if let Some(node_id) = node_id {
                    vec![node_id.get().to_vec()]
                } else {
                    vec![]
                },
                max_ingress_bytes_per_message: 60 * 1024 * 1024,
                max_ingress_messages_per_block: 1000,
                max_block_payload_size: 2 * 1024 * 1024,
                unit_delay_millis: 500,
                initial_notary_delay_millis: 1500,
                replica_version_id: ReplicaVersion::default().into(),
                dkg_interval_length: 59,
                dkg_dealings_per_block: 1,
                start_as_nns: false,
                subnet_type: SubnetType::Application.into(),
                is_halted: false,
                halt_at_cup_height: false,
                features: None,
                max_number_of_canisters: 0,
                ssh_readonly_access: vec![],
                ssh_backup_access: vec![],
                ecdsa_config: None,
                chain_key_config:  Some(ChainKeyConfig {
                    key_configs: vec![KeyConfig {
                        key_id: Some(ic_protobuf::registry::crypto::v1::MasterPublicKeyId {
                            key_id: Some(
                                ic_protobuf::registry::crypto::v1::master_public_key_id::KeyId::Ecdsa(
                                    EcdsaKeyId {
                                        curve: EcdsaCurve::Secp256k1.into(),
                                        name: "dummy_ecdsa_key_id".to_string(),
                                    },
                                ),
                            ),
                        }),
                        pre_signatures_to_create_in_advance: Some(1),
                        max_queue_size: Some(20),
                    }],
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: key_rotation_period
                        .map(|key_rotation_period| key_rotation_period.as_millis() as u64),
                }),
            },
        }
    }

    pub fn new_without_ecdsa_config(subnet_id: SubnetId, node_id: Option<NodeId>) -> Self {
        let mut subnet_config = Self::new(subnet_id, node_id, None);
        subnet_config.subnet_record.ecdsa_config = None;
        subnet_config
    }

    pub fn new_without_key_ids(
        subnet_id: SubnetId,
        node_id: Option<NodeId>,
        key_rotation_period: Option<Duration>,
    ) -> Self {
        let mut subnet_config = Self::new(subnet_id, node_id, key_rotation_period);
        subnet_config
            .subnet_record
            .chain_key_config
            .take()
            .expect("ECDSA config is None")
            .key_configs = vec![];
        subnet_config
    }
}

/// Selects which keys should be generated for a `TempCryptoComponent`.
#[derive(Clone, Eq, PartialEq)]
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
