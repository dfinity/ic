use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::key_id::KeyId;
use crate::types::{CspPop, CspPublicKey, CspSignature};
use crate::vault::api::{
    CspBasicSignatureError, CspBasicSignatureKeygenError, CspMultiSignatureError,
    CspMultiSignatureKeygenError, CspSecretKeyStoreContainsError, CspTlsKeygenError,
    CspTlsSignError, IDkgCreateDealingVaultError, PublicRandomSeedGeneratorError,
    ThresholdSchnorrSigShareBytes, ValidatePksAndSksError,
};
use crate::vault::api::{
    CspPublicKeyStoreError, CspVault, IDkgDealingInternalBytes, IDkgTranscriptInternalBytes,
};
use crate::vault::local_csp_vault::{LocalCspVault, ProdLocalCspVault};
use crate::vault::remote_csp_vault::ThresholdSchnorrCreateSigShareVaultError;
use crate::vault::remote_csp_vault::{remote_vault_codec_builder, TarpcCspVault};
use crate::vault::remote_csp_vault::{PksAndSksContainsErrors, FOUR_GIGA_BYTES};
use crate::ExternalPublicKeys;
use futures::StreamExt;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateFsKeyError, CspDkgCreateReshareDealingError, CspDkgLoadPrivateKeyError,
    CspDkgRetainThresholdKeysError, CspDkgUpdateFsEpochError,
};
use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, MEGaPublicKey, ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::NodeIndex;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_logger::replica_logger::no_op_logger;
use ic_logger::{info, new_logger, warn, ReplicaLogger};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgLoadTranscriptError, IDkgOpenTranscriptError, IDkgRetainKeysError,
    IDkgVerifyDealingPrivateError, ThresholdEcdsaCreateSigShareError,
};
use ic_types::crypto::canister_threshold_sig::{
    idkg::{BatchSignedIDkgDealing, IDkgTranscriptOperation},
    ExtendedDerivationPath,
};
use ic_types::crypto::{AlgorithmId, CurrentNodePublicKeys};
use ic_types::{NodeId, NumberOfNodes, Randomness};
use rayon::{ThreadPool, ThreadPoolBuilder};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use tarpc::server::BaseChannel;
#[allow(unused_imports)]
use tarpc::server::Serve;
use tarpc::{context, serde_transport, server::Channel};
use tokio::net::UnixListener;

use super::codec::{Bincode, CspVaultObserver, ObservableCodec};

/// Crypto service provider (CSP) vault server based on the tarpc RPC framework.
pub struct TarpcCspVaultServerImpl<C: CspVault> {
    local_csp_vault: Arc<C>,
    listener: UnixListener,
    thread_pool: Arc<ThreadPool>,
    max_frame_length: usize,
    metrics: Arc<CryptoMetrics>,
    #[allow(unused)]
    logger: ReplicaLogger,
}

/// A worker of the tarpc CSP vault server responsible for a single service request.
///
/// For each service request (i.e., remote procedure call), a new worker is
/// created through cloning (with `Clone`).
struct TarpcCspVaultServerWorker<C: CspVault> {
    local_csp_vault: Arc<C>,
    thread_pool: Arc<ThreadPool>,
}

async fn execute_on_thread_pool<F, T>(thread_pool: &ThreadPool, job: F) -> T
where
    F: FnOnce() -> T,
    F: Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    thread_pool.spawn(move || {
        if tx.is_closed() {
            // Do not start the job if the associated receiver handle was
            // dropped in the meanwhile (e.g., because the client closed
            // the connection or the client's RPC framework cancelled the
            // future due to a timeout).
            return;
        }
        let result = job();
        let _ = tx.send(result); // Errors occur if the associated receiver
                                 // handle was dropped and are considered
                                 // legitimate and are thus ignored.
    });
    rx.await.expect("the sender was dropped")
}

impl<C: CspVault> Clone for TarpcCspVaultServerWorker<C> {
    fn clone(&self) -> Self {
        Self {
            local_csp_vault: Arc::clone(&self.local_csp_vault),
            thread_pool: Arc::clone(&self.thread_pool),
        }
    }
}

impl<C: CspVault + 'static> TarpcCspVault for TarpcCspVaultServerWorker<C> {
    // `BasicSignatureCspVault`-methods.
    async fn sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        msg: ByteBuf,
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        let vault = self.local_csp_vault;
        let job = move || vault.sign(algorithm_id, msg.into_vec(), key_id);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn gen_node_signing_key_pair(
        self,
        _: context::Context,
    ) -> Result<CspPublicKey, CspBasicSignatureKeygenError> {
        let vault = self.local_csp_vault;
        let job = move || vault.gen_node_signing_key_pair();
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // `MultiSignatureCspVault`-methods.
    async fn multi_sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        message: ByteBuf,
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        let vault = self.local_csp_vault;
        let job = move || vault.multi_sign(algorithm_id, message.into_vec(), key_id);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn gen_committee_signing_key_pair(
        self,
        _: context::Context,
    ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        let vault = self.local_csp_vault;
        let job = move || vault.gen_committee_signing_key_pair();
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // `ThresholdSignatureCspVault`-methods.
    async fn threshold_sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        message: ByteBuf,
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        let vault = self.local_csp_vault;
        let job = move || vault.threshold_sign(algorithm_id, message.into_vec(), key_id);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // `NiDkgCspVault`-methods.
    async fn gen_dealing_encryption_key_pair(
        self,
        _: context::Context,
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        let vault = self.local_csp_vault;
        let job = move || vault.gen_dealing_encryption_key_pair(node_id);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn update_forward_secure_epoch(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch: Epoch,
    ) -> Result<(), CspDkgUpdateFsEpochError> {
        let vault = self.local_csp_vault;
        let job = move || vault.update_forward_secure_epoch(algorithm_id, key_id, epoch);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn create_dealing(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        maybe_resharing_secret: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, CspDkgCreateReshareDealingError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.create_dealing(
                algorithm_id,
                dealer_index,
                threshold,
                epoch,
                receiver_keys,
                maybe_resharing_secret,
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn load_threshold_signing_key(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        fs_key_id: KeyId,
        receiver_index: NodeIndex,
    ) -> Result<(), CspDkgLoadPrivateKeyError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.load_threshold_signing_key(
                algorithm_id,
                epoch,
                csp_transcript,
                fs_key_id,
                receiver_index,
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn retain_threshold_keys_if_present(
        self,
        _: context::Context,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), CspDkgRetainThresholdKeysError> {
        let vault = self.local_csp_vault;
        let job = move || vault.retain_threshold_keys_if_present(active_key_ids);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // SecretKeyStoreCspVault-methods.
    async fn sks_contains(
        self,
        _: context::Context,
        key_id: KeyId,
    ) -> Result<bool, CspSecretKeyStoreContainsError> {
        let vault = self.local_csp_vault;
        let job = move || vault.sks_contains(key_id);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // PublicKeyStoreCspVault-methods.
    async fn current_node_public_keys(
        self,
        _: context::Context,
    ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        let vault = self.local_csp_vault;
        let job = move || vault.current_node_public_keys();
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn current_node_public_keys_with_timestamps(
        self,
        _: context::Context,
    ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        let vault = self.local_csp_vault;
        let job = move || vault.current_node_public_keys_with_timestamps();
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn idkg_key_count(self, _: context::Context) -> Result<usize, CspPublicKeyStoreError> {
        let vault = self.local_csp_vault;
        let job = move || vault.idkg_dealing_encryption_pubkeys_count();
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // PublicAndSecretKeyStoreCspVault-methods.
    async fn pks_and_sks_contains(
        self,
        _: context::Context,
        external_public_keys: ExternalPublicKeys,
    ) -> Result<(), PksAndSksContainsErrors> {
        let vault = self.local_csp_vault;
        let job = move || vault.pks_and_sks_contains(external_public_keys);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn validate_pks_and_sks(
        self,
        _: context::Context,
    ) -> Result<ValidNodePublicKeys, ValidatePksAndSksError> {
        let vault = self.local_csp_vault;
        let job = move || vault.validate_pks_and_sks();
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // 'TlsHandshakeCspVault'-methods.
    async fn gen_tls_key_pair(
        self,
        _: context::Context,
        node: NodeId,
    ) -> Result<TlsPublicKeyCert, CspTlsKeygenError> {
        let vault = self.local_csp_vault;
        let job = move || vault.gen_tls_key_pair(node);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn tls_sign(
        self,
        _: context::Context,
        message: ByteBuf,
        key_id: KeyId,
    ) -> Result<CspSignature, CspTlsSignError> {
        let vault = self.local_csp_vault;
        let job = move || vault.tls_sign(message.into_vec(), key_id);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // `IDkgProtocolCspVault`-methods.
    async fn idkg_create_dealing(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        context_data: ByteBuf,
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: Vec<PublicKey>,
        transcript_operation: IDkgTranscriptOperation,
    ) -> Result<IDkgDealingInternalBytes, IDkgCreateDealingVaultError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_create_dealing(
                algorithm_id,
                context_data.into_vec(),
                dealer_index,
                reconstruction_threshold,
                receiver_keys,
                transcript_operation,
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn idkg_verify_dealing_private(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        dealing: IDkgDealingInternalBytes,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: ByteBuf,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_verify_dealing_private(
                algorithm_id,
                dealing,
                dealer_index,
                receiver_index,
                receiver_key_id,
                context_data.into_vec(),
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn idkg_load_transcript(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        context_data: ByteBuf,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_load_transcript(
                algorithm_id,
                dealings,
                context_data.into_vec(),
                receiver_index,
                key_id,
                transcript,
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn idkg_load_transcript_with_openings(
        self,
        _: context::Context,
        alg: AlgorithmId,
        dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        openings: BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: ByteBuf,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<(), IDkgLoadTranscriptError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_load_transcript_with_openings(
                alg,
                dealings,
                openings,
                context_data.into_vec(),
                receiver_index,
                key_id,
                transcript,
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn idkg_retain_active_keys(
        self,
        _: context::Context,
        active_key_ids: BTreeSet<KeyId>,
        oldest_public_key: MEGaPublicKey,
    ) -> Result<(), IDkgRetainKeysError> {
        let vault = self.local_csp_vault;
        let job = move || vault.idkg_retain_active_keys(active_key_ids, oldest_public_key);
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn idkg_gen_dealing_encryption_key_pair(
        self,
        _: context::Context,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        let vault = self.local_csp_vault;
        let job = move || vault.idkg_gen_dealing_encryption_key_pair();
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn idkg_open_dealing(
        self,
        _: context::Context,
        alg: AlgorithmId,
        dealing: BatchSignedIDkgDealing,
        dealer_index: NodeIndex,
        context_data: ByteBuf,
        opener_index: NodeIndex,
        opener_key_id: KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_open_dealing(
                alg,
                dealing,
                dealer_index,
                context_data.into_vec(),
                opener_index,
                opener_key_id,
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // `ThresholdEcdsaSignerCspVault`-methods
    async fn create_ecdsa_sig_share(
        self,
        _: context::Context,
        derivation_path: ExtendedDerivationPath,
        hashed_message: ByteBuf,
        nonce: Randomness,
        key_raw: IDkgTranscriptInternalBytes,
        kappa_unmasked_raw: IDkgTranscriptInternalBytes,
        lambda_masked_raw: IDkgTranscriptInternalBytes,
        kappa_times_lambda_raw: IDkgTranscriptInternalBytes,
        key_times_lambda_raw: IDkgTranscriptInternalBytes,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaCreateSigShareError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.create_ecdsa_sig_share(
                derivation_path,
                hashed_message.into_vec(),
                nonce,
                key_raw,
                kappa_unmasked_raw,
                lambda_masked_raw,
                kappa_times_lambda_raw,
                key_times_lambda_raw,
                algorithm_id,
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    // `ThresholdSchnorrSignerCspVault`-methods
    async fn create_schnorr_sig_share(
        self,
        _: context::Context,
        derivation_path: ExtendedDerivationPath,
        message: ByteBuf,
        nonce: Randomness,
        key_raw: IDkgTranscriptInternalBytes,
        presig_raw: IDkgTranscriptInternalBytes,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdSchnorrSigShareBytes, ThresholdSchnorrCreateSigShareVaultError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.create_schnorr_sig_share(
                derivation_path,
                message.into_vec(),
                nonce,
                key_raw,
                presig_raw,
                algorithm_id,
            )
        };
        execute_on_thread_pool(&self.thread_pool, job).await
    }

    async fn new_public_seed(
        self,
        _: context::Context,
    ) -> Result<Seed, PublicRandomSeedGeneratorError> {
        let vault = self.local_csp_vault;
        let job = move || vault.new_public_seed();
        execute_on_thread_pool(&self.thread_pool, job).await
    }
}

type VaultFactory<C> = dyn Fn(&ReplicaLogger, Arc<CryptoMetrics>) -> Arc<C> + Send + Sync;

pub struct TarpcCspVaultServerImplBuilder<C> {
    local_csp_vault_factory: Box<VaultFactory<C>>,
    max_frame_length: usize,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
}

impl TarpcCspVaultServerImplBuilder<ProdLocalCspVault> {
    pub fn new(key_store_dir: &Path) -> Self {
        let key_store_path = key_store_dir.to_path_buf();
        let local_csp_vault_factory = Box::new(move |logger: &ReplicaLogger, metrics| {
            Arc::new(LocalCspVault::new_in_dir(
                &key_store_path,
                metrics,
                new_logger!(logger),
            ))
        });
        Self::new_internal(local_csp_vault_factory)
    }
}

impl<C: 'static + Send + Sync> TarpcCspVaultServerImplBuilder<C> {
    pub fn new_with_local_csp_vault(local_csp_vault: Arc<C>) -> Self {
        let local_csp_vault_factory =
            Box::new(move |_logger: &ReplicaLogger, _metrics| Arc::clone(&local_csp_vault));
        Self::new_internal(local_csp_vault_factory)
    }
}

impl<C> TarpcCspVaultServerImplBuilder<C> {
    fn new_internal(local_csp_vault_factory: Box<VaultFactory<C>>) -> Self {
        TarpcCspVaultServerImplBuilder {
            local_csp_vault_factory,
            max_frame_length: FOUR_GIGA_BYTES,
            logger: no_op_logger(),
            metrics: Arc::new(CryptoMetrics::none()),
        }
    }

    pub fn with_logger(mut self, logger: ReplicaLogger) -> Self {
        self.logger = logger;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<CryptoMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn with_max_frame_length(mut self, max_frame_length: usize) -> Self {
        self.max_frame_length = max_frame_length;
        self
    }
}

impl<C: CspVault> TarpcCspVaultServerImplBuilder<C> {
    pub fn build(&self, listener: UnixListener) -> TarpcCspVaultServerImpl<C> {
        info!(&self.logger, "Starting new RPC CSP vault server");
        let local_csp_vault: Arc<C> =
            (self.local_csp_vault_factory)(&self.logger, Arc::clone(&self.metrics));
        TarpcCspVaultServerImpl {
            local_csp_vault,
            listener,
            // defaults the number of threads to the number of CPUs
            thread_pool: Arc::new(
                ThreadPoolBuilder::new()
                    .thread_name(|i| format!("ic-crypto-csp-{i}"))
                    .num_threads(
                        std::thread::available_parallelism()
                            .expect("obtaining the number of available cores should never fail")
                            .get(),
                    )
                    .build()
                    .expect("failed to instantiate a thread pool"),
            ),
            max_frame_length: self.max_frame_length,
            metrics: Arc::clone(&self.metrics),
            logger: new_logger!(&self.logger),
        }
    }
}

impl TarpcCspVaultServerImpl<ProdLocalCspVault> {
    pub fn builder(key_store_dir: &Path) -> TarpcCspVaultServerImplBuilder<ProdLocalCspVault> {
        TarpcCspVaultServerImplBuilder::new(key_store_dir)
    }
}

impl<C: CspVault + 'static> TarpcCspVaultServerImpl<C> {
    /// Creates a remote CSP vault server builder for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store is not guaranteed.
    pub fn builder_for_test(local_csp_vault: Arc<C>) -> TarpcCspVaultServerImplBuilder<C> {
        TarpcCspVaultServerImplBuilder::new_with_local_csp_vault(local_csp_vault)
    }
}

impl<C: CspVault + 'static> TarpcCspVaultServerImpl<C> {
    pub async fn run(self) {
        // Wrap data in telegrams with a length header.
        let mut codec_builder = remote_vault_codec_builder();
        codec_builder.max_frame_length(self.max_frame_length);

        // Listen for connections; spawns one `tokio` task per client.
        loop {
            let (conn, _addr) = self.listener.accept().await.unwrap_or_else(|e| {
                panic!(
                    "Error listening at socket {:?}: {}",
                    &self.listener.local_addr(),
                    e
                )
            });
            let local_csp_vault = Arc::clone(&self.local_csp_vault);
            let thread_pool = Arc::clone(&self.thread_pool);
            let codec = ObservableCodec::new(
                Bincode::default(),
                CspVaultObserver::new(new_logger!(&self.logger), Arc::clone(&self.metrics)),
            );
            tokio::spawn(async move {
                let framed = codec_builder.new_framed(conn);
                let transport = serde_transport::new(framed, codec);
                let worker = TarpcCspVaultServerWorker {
                    local_csp_vault,
                    thread_pool,
                };
                let channel = BaseChannel::with_defaults(transport);
                channel
                    .execute(worker.serve())
                    .for_each(|rpc| async {
                        tokio::spawn(rpc);
                    })
                    .await;
            });
        }
    }
}

impl<C: CspVault> Drop for TarpcCspVaultServerImpl<C> {
    fn drop(&mut self) {
        warn!(self.logger, "Dropping RPC CSP vault server")
    }
}
