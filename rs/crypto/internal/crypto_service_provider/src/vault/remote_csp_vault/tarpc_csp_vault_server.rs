use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::key_id::KeyId;
use crate::public_key_store::proto_pubkey_store::ProtoPublicKeyStore;
use crate::public_key_store::PublicKeyStore;
use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSignature};
use crate::vault::api::{
    BasicSignatureCspVault, CspPublicKeyStoreError, IDkgProtocolCspVault, MultiSignatureCspVault,
    NiDkgCspVault, PublicKeyStoreCspVault, PublicRandomSeedGenerator, SecretKeyStoreCspVault,
    ThresholdEcdsaSignerCspVault, ThresholdSignatureCspVault, TlsHandshakeCspVault,
};
use crate::vault::api::{
    CspBasicSignatureError, CspBasicSignatureKeygenError, CspMultiSignatureError,
    CspMultiSignatureKeygenError, CspSecretKeyStoreContainsError, CspThresholdSignatureKeygenError,
    CspTlsKeygenError, CspTlsSignError, PublicRandomSeedGeneratorError,
};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::remote_csp_vault::TarpcCspVault;
use crate::{
    SecretKeyStore, CANISTER_SKS_DATA_FILENAME, PUBLIC_KEY_STORE_DATA_FILENAME, SKS_DATA_FILENAME,
};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateFsKeyError, CspDkgCreateReshareDealingError, CspDkgLoadPrivateKeyError,
    CspDkgRetainThresholdKeysError, CspDkgUpdateFsEpochError,
};
use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::NodeIndex;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_logger::replica_logger::no_op_logger;
use ic_logger::{new_logger, ReplicaLogger};
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError,
    IDkgRetainThresholdKeysError, IDkgVerifyDealingPrivateError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::{AlgorithmId, CurrentNodePublicKeys};
use ic_types::{NodeId, NumberOfNodes, Randomness};
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use tarpc::server::BaseChannel;
#[allow(unused_imports)]
use tarpc::server::Serve;
use tarpc::tokio_serde::formats::Bincode;
use tarpc::{context, serde_transport, server::Channel};
use threadpool::ThreadPool;
use tokio::net::UnixListener;
use tokio_util::codec::length_delimited::LengthDelimitedCodec;

/// Crypto service provider (CSP) vault server based on the tarpc RPC framework.
pub struct TarpcCspVaultServerImpl<
    R: Rng + CryptoRng,
    S: SecretKeyStore,
    C: SecretKeyStore,
    P: PublicKeyStore,
> {
    local_csp_vault: Arc<LocalCspVault<R, S, C, P>>,
    listener: UnixListener,
    thread_pool: ThreadPool,
    #[allow(unused)]
    logger: ReplicaLogger,
}

/// A worker of the tarpc CSP vault server responsible for a single service request.
///
/// For each service request (i.e., remote procedure call), a new worker is
/// created through cloning (with `Clone`). Note that [cloning of a `ThreadPool`
/// creates a pool handle whose behavior is similar to `Arc`][1].
///
/// [1]: https://docs.rs/threadpool/1.8.1/threadpool/struct.ThreadPool.html#impl-Clone
struct TarpcCspVaultServerWorker<
    R: Rng + CryptoRng,
    S: SecretKeyStore,
    C: SecretKeyStore,
    P: PublicKeyStore,
> {
    local_csp_vault: Arc<LocalCspVault<R, S, C, P>>,
    thread_pool_handle: ThreadPool,
}

async fn execute_on_thread_pool<F, T>(thread_pool_handle: ThreadPool, job: F) -> T
where
    F: FnOnce() -> T,
    F: Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    thread_pool_handle.execute(move || {
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

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore> Clone
    for TarpcCspVaultServerWorker<R, S, C, P>
{
    fn clone(&self) -> Self {
        Self {
            local_csp_vault: Arc::clone(&self.local_csp_vault),
            thread_pool_handle: self.thread_pool_handle.clone(),
        }
    }
}

#[tarpc::server]
impl<
        R: Rng + CryptoRng + Send + Sync + 'static,
        S: SecretKeyStore + 'static,
        C: SecretKeyStore + 'static,
        P: PublicKeyStore + 'static,
    > TarpcCspVault for TarpcCspVaultServerWorker<R, S, C, P>
{
    // `BasicSignatureCspVault`-methods.
    async fn sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        msg: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        let vault = self.local_csp_vault;
        let job = move || vault.sign(algorithm_id, &*msg, key_id);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn gen_node_signing_key_pair(
        self,
        _: context::Context,
    ) -> Result<CspPublicKey, CspBasicSignatureKeygenError> {
        let vault = self.local_csp_vault;
        let job = move || vault.gen_node_signing_key_pair();
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    // `MultiSignatureCspVault`-methods.
    async fn multi_sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        let vault = self.local_csp_vault;
        let job = move || vault.multi_sign(algorithm_id, &*message, key_id);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn gen_committee_signing_key_pair(
        self,
        _: context::Context,
    ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        let vault = self.local_csp_vault;
        let job = move || vault.gen_committee_signing_key_pair();
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    // `ThresholdSignatureCspVault`-methods.
    async fn threshold_sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        let vault = self.local_csp_vault;
        let job = move || vault.threshold_sign(algorithm_id, &*message, key_id);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn threshold_keygen_for_test(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        signatory_eligibility: Vec<bool>,
    ) -> Result<(CspPublicCoefficients, Vec<Option<KeyId>>), CspThresholdSignatureKeygenError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.threshold_keygen_for_test(algorithm_id, threshold, &*signatory_eligibility)
        };
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    // `NiDkgCspVault`-methods.
    async fn gen_dealing_encryption_key_pair(
        self,
        _: context::Context,
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        let vault = self.local_csp_vault;
        let job = move || vault.gen_dealing_encryption_key_pair(node_id);
        execute_on_thread_pool(self.thread_pool_handle, job).await
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
        execute_on_thread_pool(self.thread_pool_handle, job).await
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
                &receiver_keys,
                maybe_resharing_secret,
            )
        };
        execute_on_thread_pool(self.thread_pool_handle, job).await
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
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn retain_threshold_keys_if_present(
        self,
        _: context::Context,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), CspDkgRetainThresholdKeysError> {
        let vault = self.local_csp_vault;
        let job = move || vault.retain_threshold_keys_if_present(active_key_ids);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    // SecretKeyStoreCspVault-methods.
    async fn sks_contains(
        self,
        _: context::Context,
        key_id: KeyId,
    ) -> Result<bool, CspSecretKeyStoreContainsError> {
        let vault = self.local_csp_vault;
        let job = move || vault.sks_contains(&key_id);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    // PublicKeyStoreCspVault-methods.
    async fn pks_contains(
        self,
        _: context::Context,
        public_keys: CurrentNodePublicKeys,
    ) -> Result<bool, CspPublicKeyStoreError> {
        let vault = self.local_csp_vault;
        let job = move || vault.pks_contains(public_keys);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn current_node_public_keys(
        self,
        _: context::Context,
    ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        let vault = self.local_csp_vault;
        let job = move || vault.current_node_public_keys();
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    // 'TlsHandshakeCspVault'-methods.
    async fn gen_tls_key_pair(
        self,
        _: context::Context,
        node: NodeId,
        not_after: String,
    ) -> Result<TlsPublicKeyCert, CspTlsKeygenError> {
        let vault = self.local_csp_vault;
        let job = move || vault.gen_tls_key_pair(node, &not_after);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn tls_sign(
        self,
        _: context::Context,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspTlsSignError> {
        let vault = self.local_csp_vault;
        let job = move || vault.tls_sign(&*message, &key_id);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    // `IDkgProtocolCspVault`-methods.
    async fn idkg_create_dealing(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        context_data: Vec<u8>,
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: Vec<MEGaPublicKey>,
        transcript_operation: IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_create_dealing(
                algorithm_id,
                &context_data,
                dealer_index,
                reconstruction_threshold,
                &receiver_keys,
                &transcript_operation,
            )
        };
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn idkg_verify_dealing_private(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: Vec<u8>,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_verify_dealing_private(
                algorithm_id,
                &dealing,
                dealer_index,
                receiver_index,
                receiver_key_id,
                &context_data,
            )
        };
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn idkg_load_transcript(
        self,
        _: context::Context,
        dealings: BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: Vec<u8>,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_load_transcript(
                &dealings,
                &context_data,
                receiver_index,
                &key_id,
                &transcript,
            )
        };
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn idkg_load_transcript_with_openings(
        self,
        _: context::Context,
        dealings: BTreeMap<NodeIndex, IDkgDealingInternal>,
        openings: BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: Vec<u8>,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternal,
    ) -> Result<(), IDkgLoadTranscriptError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_load_transcript_with_openings(
                &dealings,
                &openings,
                &context_data,
                receiver_index,
                &key_id,
                &transcript,
            )
        };
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn idkg_retain_threshold_keys_if_present(
        self,
        _: context::Context,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), IDkgRetainThresholdKeysError> {
        let vault = self.local_csp_vault;
        let job = move || vault.idkg_retain_threshold_keys_if_present(active_key_ids);
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn idkg_gen_dealing_encryption_key_pair(
        self,
        _: context::Context,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        let vault = self.local_csp_vault;
        let job = move || vault.idkg_gen_dealing_encryption_key_pair();
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn idkg_open_dealing(
        self,
        _: context::Context,
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: Vec<u8>,
        opener_index: NodeIndex,
        opener_key_id: KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.idkg_open_dealing(
                dealing,
                dealer_index,
                &context_data,
                opener_index,
                &opener_key_id,
            )
        };
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    // `ThresholdEcdsaSignerCspVault`-methods
    async fn ecdsa_sign_share(
        self,
        _: context::Context,
        derivation_path: ExtendedDerivationPath,
        hashed_message: Vec<u8>,
        nonce: Randomness,
        key: IDkgTranscriptInternal,
        kappa_unmasked: IDkgTranscriptInternal,
        lambda_masked: IDkgTranscriptInternal,
        kappa_times_lambda: IDkgTranscriptInternal,
        key_times_lambda: IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError> {
        let vault = self.local_csp_vault;
        let job = move || {
            vault.ecdsa_sign_share(
                &derivation_path,
                &hashed_message,
                &nonce,
                &key,
                &kappa_unmasked,
                &lambda_masked,
                &kappa_times_lambda,
                &key_times_lambda,
                algorithm_id,
            )
        };
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }

    async fn new_public_seed(
        self,
        _: context::Context,
    ) -> Result<Seed, PublicRandomSeedGeneratorError> {
        let vault = self.local_csp_vault;
        let job = move || vault.new_public_seed();
        execute_on_thread_pool(self.thread_pool_handle, job).await
    }
}

impl TarpcCspVaultServerImpl<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore, ProtoPublicKeyStore> {
    pub fn new(
        key_store_dir: &Path,
        listener: UnixListener,
        logger: ReplicaLogger,
        metrics: Arc<CryptoMetrics>,
    ) -> Self {
        let node_secret_key_store =
            ProtoSecretKeyStore::open(key_store_dir, SKS_DATA_FILENAME, Some(new_logger!(&logger)));
        let canister_secret_key_store = ProtoSecretKeyStore::open(
            key_store_dir,
            CANISTER_SKS_DATA_FILENAME,
            Some(new_logger!(&logger)),
        );
        let public_key_store =
            ProtoPublicKeyStore::open(key_store_dir, PUBLIC_KEY_STORE_DATA_FILENAME);
        let local_csp_server = Arc::new(LocalCspVault::new(
            node_secret_key_store,
            canister_secret_key_store,
            public_key_store,
            metrics,
            new_logger!(&logger),
        ));
        Self::new_with_local_csp_vault(local_csp_server, listener, logger)
    }
}

impl<R: Rng + CryptoRng, S: SecretKeyStore, C: SecretKeyStore, P: PublicKeyStore>
    TarpcCspVaultServerImpl<R, S, C, P>
{
    /// Creates a remote CSP vault server for testing.
    ///
    /// Note: This MUST NOT be used in production as the secrecy of the secret
    /// key store is not guaranteed.
    pub fn new_for_test(
        local_csp_vault: Arc<LocalCspVault<R, S, C, P>>,
        listener: UnixListener,
    ) -> Self {
        Self::new_with_local_csp_vault(local_csp_vault, listener, no_op_logger())
    }

    fn new_with_local_csp_vault(
        local_csp_vault: Arc<LocalCspVault<R, S, C, P>>,
        listener: UnixListener,
        logger: ReplicaLogger,
    ) -> Self {
        let thread_pool = threadpool::Builder::new()
            .thread_name("ic-crypto-csp".to_string())
            .build(); // defaults the number of threads to the number of CPUs
        Self {
            local_csp_vault,
            listener,
            thread_pool,
            logger,
        }
    }
}

impl<
        R: Rng + CryptoRng + Send + Sync + 'static,
        S: SecretKeyStore + Send + Sync + 'static,
        C: SecretKeyStore + Send + Sync + 'static,
        P: PublicKeyStore + 'static,
    > TarpcCspVaultServerImpl<R, S, C, P>
{
    pub async fn run(self) {
        // Wrap data in telegrams with a length header.
        let codec_builder = LengthDelimitedCodec::builder();

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
            let thread_pool_handle = self.thread_pool.clone(); // creates a pool handle similar to Arc
            tokio::spawn(async move {
                let framed = codec_builder.new_framed(conn);
                let transport = serde_transport::new(framed, Bincode::default());
                let worker = TarpcCspVaultServerWorker {
                    local_csp_vault,
                    thread_pool_handle,
                };
                let channel_executor =
                    BaseChannel::with_defaults(transport).execute(worker.serve());
                channel_executor.await;
            });
        }
    }
}
