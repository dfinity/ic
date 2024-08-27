use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::key_id::KeyId;
use crate::types::{CspPop, CspPublicKey, CspSignature};
use crate::vault::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspBasicSignatureKeygenError,
    CspMultiSignatureError, CspMultiSignatureKeygenError, CspPublicKeyStoreError,
    CspSecretKeyStoreContainsError, CspTlsKeygenError, CspTlsSignError,
    IDkgCreateDealingVaultError, IDkgDealingInternalBytes, IDkgProtocolCspVault,
    IDkgTranscriptInternalBytes, MultiSignatureCspVault, NiDkgCspVault, PksAndSksContainsErrors,
    PublicAndSecretKeyStoreCspVault, PublicKeyStoreCspVault, PublicRandomSeedGenerator,
    PublicRandomSeedGeneratorError, SecretKeyStoreCspVault, ThresholdEcdsaSignerCspVault,
    ThresholdSchnorrSigShareBytes, ThresholdSchnorrSignerCspVault, ThresholdSignatureCspVault,
    ValidatePksAndSksError,
};
use crate::vault::remote_csp_vault::codec::{Bincode, CspVaultObserver, ObservableCodec};
use crate::vault::remote_csp_vault::ThresholdSchnorrCreateSigShareVaultError;
use crate::vault::remote_csp_vault::{
    remote_vault_codec_builder, robust_unix_socket, TarpcCspVaultClient, FOUR_GIGA_BYTES,
};
use crate::{ExternalPublicKeys, TlsHandshakeCspVault};
use core::future::Future;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError;
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
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_logger::{debug, new_logger, ReplicaLogger};
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
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tarpc::serde_transport;
use tracing::instrument;

#[cfg(test)]
use ic_config::logger::Config as LoggerConfig;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
#[cfg(test)]
use ic_logger::new_replica_logger_from_config;
use ic_logger::replica_logger::no_op_logger;
#[cfg(test)]
use slog_async::AsyncGuard;

/// An implementation of `CspVault`-trait that talks to a remote CSP vault.
#[allow(dead_code)]
pub struct RemoteCspVault {
    tarpc_csp_client: TarpcCspVaultClient,
    // default timeout for RPC calls that can timeout.
    rpc_timeout: Duration,
    // special, long timeout for RPC calls that should not really timeout.
    long_rpc_timeout: Duration,
    tokio_runtime_handle: tokio::runtime::Handle,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
    #[cfg(test)]
    _logger_guard: Option<AsyncGuard>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteCspVaultError {
    TransportError {
        server_address: String,
        message: String,
    },
}

impl RemoteCspVault {
    fn tokio_block_on<T: Future>(&self, task: T) -> T::Output {
        self.tokio_runtime_handle.block_on(task)
    }
}

const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
const LONG_RPC_TIMEOUT: Duration = Duration::from_secs(3600 * 24 * 100); // 100 days

#[allow(dead_code)]
impl RemoteCspVault {
    /// Creates a new `RemoteCspVault`-object that communicates
    /// with a server via a Unix socket specified by `socket_path`.
    /// The socket must exist before this constructor is called,
    /// otherwise the constructor will fail.
    pub fn new(
        socket_path: &Path,
        rt_handle: tokio::runtime::Handle,
        logger: ReplicaLogger,
        metrics: Arc<CryptoMetrics>,
    ) -> Result<Self, RemoteCspVaultError> {
        RemoteCspVaultBuilder::new(socket_path.to_path_buf(), rt_handle)
            .with_logger(logger)
            .with_metrics(metrics)
            .build()
    }

    pub fn builder(
        socket_path: PathBuf,
        rt_handle: tokio::runtime::Handle,
    ) -> RemoteCspVaultBuilder {
        RemoteCspVaultBuilder::new(socket_path, rt_handle)
    }
}

pub struct RemoteCspVaultBuilder {
    socket_path: PathBuf,
    rt_handle: tokio::runtime::Handle,
    max_frame_length: usize,
    rpc_timeout: Duration,
    long_rpc_timeout: Duration,
    logger: ReplicaLogger,
    metrics: Arc<CryptoMetrics>,
    #[cfg(test)]
    _logger_guard: Option<AsyncGuard>,
}

impl RemoteCspVaultBuilder {
    pub fn new(socket_path: PathBuf, rt_handle: tokio::runtime::Handle) -> Self {
        RemoteCspVaultBuilder {
            socket_path,
            rt_handle,
            max_frame_length: FOUR_GIGA_BYTES,
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            long_rpc_timeout: LONG_RPC_TIMEOUT,
            logger: no_op_logger(),
            metrics: Arc::new(CryptoMetrics::none()),
            #[cfg(test)]
            _logger_guard: None,
        }
    }

    #[cfg(test)]
    pub fn new_for_test(socket_path: PathBuf, rt_handle: tokio::runtime::Handle) -> Self {
        let (logger, guard) = new_replica_logger_from_config(&LoggerConfig::default());
        let mut builder = Self::new(socket_path, rt_handle);
        builder.logger = logger;
        builder._logger_guard = Some(guard);
        builder
    }

    pub fn with_rpc_timeout(mut self, timeout: Duration) -> Self {
        self.rpc_timeout = timeout;
        self
    }

    pub fn with_long_rpc_timeout(mut self, timeout: Duration) -> Self {
        self.long_rpc_timeout = timeout;
        self
    }

    pub fn with_rpc_timeouts(mut self, timeout: Duration) -> Self {
        self.rpc_timeout = timeout;
        self.long_rpc_timeout = timeout;
        self
    }

    pub fn with_max_frame_length(mut self, new_length: usize) -> Self {
        self.max_frame_length = new_length;
        self
    }

    pub fn with_logger(mut self, logger: ReplicaLogger) -> Self {
        self.logger = logger;
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<CryptoMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn build(self) -> Result<RemoteCspVault, RemoteCspVaultError> {
        let conn = self
            .rt_handle
            .block_on(robust_unix_socket::connect(
                self.socket_path.clone(),
                new_logger!(&self.logger),
            ))
            .map_err(|e| RemoteCspVaultError::TransportError {
                server_address: self.socket_path.to_string_lossy().to_string(),
                message: e.to_string(),
            })?;
        let transport = serde_transport::new(
            remote_vault_codec_builder()
                .max_frame_length(self.max_frame_length)
                .new_framed(conn),
            ObservableCodec::new(
                Bincode::default(),
                CspVaultObserver::new(new_logger!(&self.logger), Arc::clone(&self.metrics)),
            ),
        );
        let client = {
            let _enter_guard = self.rt_handle.enter();
            TarpcCspVaultClient::new(Default::default(), transport).spawn()
        };
        debug!(self.logger, "Instantiated remote CSP vault client");
        Ok(RemoteCspVault {
            tarpc_csp_client: client,
            rpc_timeout: self.rpc_timeout,
            long_rpc_timeout: self.long_rpc_timeout,
            tokio_runtime_handle: self.rt_handle,
            logger: self.logger,
            metrics: self.metrics,
            #[cfg(test)]
            _logger_guard: self._logger_guard,
        })
    }

    pub fn build_expecting_ok(self) -> RemoteCspVault {
        self.build().expect("error building RemoteCspVault")
    }
}

fn deadline_from_now(timeout: Duration) -> SystemTime {
    SystemTime::now() + timeout
}

fn context_with_timeout(timeout: Duration) -> tarpc::context::Context {
    let mut context = tarpc::context::current();
    context.deadline = deadline_from_now(timeout);
    context
}

// Note: the implementation of the traits below blocks when calling
// the remote server, as the API used by `Csp` is synchronous, while the server
// API is async.
impl BasicSignatureCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        self.tokio_block_on(self.tarpc_csp_client.sign(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            ByteBuf::from(message),
            key_id,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspBasicSignatureError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }

    #[instrument(skip_all)]
    fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CspBasicSignatureKeygenError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .gen_node_signing_key_pair(context_with_timeout(self.rpc_timeout)),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspBasicSignatureKeygenError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }
}

impl MultiSignatureCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn multi_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        self.tokio_block_on(self.tarpc_csp_client.multi_sign(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            ByteBuf::from(message),
            key_id,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspMultiSignatureError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }

    #[instrument(skip_all)]
    fn gen_committee_signing_key_pair(
        &self,
    ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .gen_committee_signing_key_pair(context_with_timeout(self.rpc_timeout)),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspMultiSignatureKeygenError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }
}

impl ThresholdSignatureCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        self.tokio_block_on(self.tarpc_csp_client.threshold_sign(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            ByteBuf::from(message),
            key_id,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspThresholdSignError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }
}

impl SecretKeyStoreCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn sks_contains(&self, key_id: KeyId) -> Result<bool, CspSecretKeyStoreContainsError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .sks_contains(context_with_timeout(self.rpc_timeout), key_id),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspSecretKeyStoreContainsError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }
}

impl PublicKeyStoreCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .current_node_public_keys(context_with_timeout(self.rpc_timeout)),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspPublicKeyStoreError::TransientInternalError(
                rpc_error.to_string(),
            ))
        })
    }

    #[instrument(skip_all)]
    fn current_node_public_keys_with_timestamps(
        &self,
    ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .current_node_public_keys_with_timestamps(context_with_timeout(self.rpc_timeout)),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspPublicKeyStoreError::TransientInternalError(
                rpc_error.to_string(),
            ))
        })
    }

    #[instrument(skip_all)]
    fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, CspPublicKeyStoreError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .idkg_key_count(context_with_timeout(self.rpc_timeout)),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspPublicKeyStoreError::TransientInternalError(
                rpc_error.to_string(),
            ))
        })
    }
}

impl PublicAndSecretKeyStoreCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn pks_and_sks_contains(
        &self,
        external_public_keys: ExternalPublicKeys,
    ) -> Result<(), PksAndSksContainsErrors> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .pks_and_sks_contains(context_with_timeout(self.rpc_timeout), external_public_keys),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(PksAndSksContainsErrors::TransientInternalError(
                rpc_error.to_string(),
            ))
        })
    }

    #[instrument(skip_all)]
    fn validate_pks_and_sks(&self) -> Result<ValidNodePublicKeys, ValidatePksAndSksError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .validate_pks_and_sks(context_with_timeout(self.rpc_timeout)),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(ValidatePksAndSksError::TransientInternalError(
                rpc_error.to_string(),
            ))
        })
    }
}

impl NiDkgCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn gen_dealing_encryption_key_pair(
        &self,
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .gen_dealing_encryption_key_pair(context_with_timeout(self.rpc_timeout), node_id),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspDkgCreateFsKeyError::TransientInternalError(
                rpc_error.to_string(),
            ))
        })
    }

    #[instrument(skip_all)]
    fn update_forward_secure_epoch(
        &self,
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch: Epoch,
    ) -> Result<(), CspDkgUpdateFsEpochError> {
        self.tokio_block_on(self.tarpc_csp_client.update_forward_secure_epoch(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            key_id,
            epoch,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspDkgUpdateFsEpochError::TransientInternalError(
                InternalError {
                    internal_error: rpc_error.to_string(),
                },
            ))
        })
    }

    #[instrument(skip_all)]
    fn create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        maybe_resharing_secret: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, CspDkgCreateReshareDealingError> {
        self.tokio_block_on(self.tarpc_csp_client.create_dealing(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            dealer_index,
            threshold,
            epoch,
            receiver_keys,
            maybe_resharing_secret,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspDkgCreateReshareDealingError::TransientInternalError(
                InternalError {
                    internal_error: rpc_error.to_string(),
                },
            ))
        })
    }

    #[instrument(skip_all)]
    fn load_threshold_signing_key(
        &self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        fs_key_id: KeyId,
        receiver_index: NodeIndex,
    ) -> Result<(), CspDkgLoadPrivateKeyError> {
        self.tokio_block_on(self.tarpc_csp_client.load_threshold_signing_key(
            context_with_timeout(self.long_rpc_timeout),
            algorithm_id,
            epoch,
            csp_transcript,
            fs_key_id,
            receiver_index,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspDkgLoadPrivateKeyError::TransientInternalError(
                InternalError {
                    internal_error: rpc_error.to_string(),
                },
            ))
        })
    }

    #[instrument(skip_all)]
    fn retain_threshold_keys_if_present(
        &self,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), CspDkgRetainThresholdKeysError> {
        self.tokio_block_on(self.tarpc_csp_client.retain_threshold_keys_if_present(
            context_with_timeout(self.rpc_timeout),
            active_key_ids,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspDkgRetainThresholdKeysError::TransientInternalError(
                InternalError {
                    internal_error: rpc_error.to_string(),
                },
            ))
        })
    }
}

impl TlsHandshakeCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn gen_tls_key_pair(&self, node: NodeId) -> Result<TlsPublicKeyCert, CspTlsKeygenError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .gen_tls_key_pair(context_with_timeout(self.rpc_timeout), node),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspTlsKeygenError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }

    #[instrument(skip_all)]
    fn tls_sign(&self, message: Vec<u8>, key_id: KeyId) -> Result<CspSignature, CspTlsSignError> {
        // Here we cannot call `block_on` directly but have to wrap it in
        // `block_in_place` because this method here is called via a Rustls
        // callback (via our implementation of the `rustls::sign::Signer`
        // trait) from the async function `tokio_rustls::TlsAcceptor::accept`,
        // which in turn is called from our async function
        // `TlsHandshake::perform_tls_server_handshake`.
        #[allow(clippy::disallowed_methods)]
        tokio::task::block_in_place(|| {
            self.tokio_block_on(self.tarpc_csp_client.tls_sign(
                context_with_timeout(Duration::from_secs(5)),
                ByteBuf::from(message),
                key_id,
            ))
            .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
                Err(CspTlsSignError::TransientInternalError {
                    internal_error: rpc_error.to_string(),
                })
            })
        })
    }
}

impl IDkgProtocolCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    fn idkg_create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        context_data: Vec<u8>,
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: Vec<PublicKey>,
        transcript_operation: IDkgTranscriptOperation,
    ) -> Result<IDkgDealingInternalBytes, IDkgCreateDealingVaultError> {
        self.tokio_block_on(self.tarpc_csp_client.idkg_create_dealing(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            ByteBuf::from(context_data),
            dealer_index,
            reconstruction_threshold,
            receiver_keys,
            transcript_operation,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(IDkgCreateDealingVaultError::TransientInternalError(
                rpc_error.to_string(),
            ))
        })
    }

    #[instrument(skip_all)]
    fn idkg_verify_dealing_private(
        &self,
        algorithm_id: AlgorithmId,
        dealing: IDkgDealingInternalBytes,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: Vec<u8>,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        self.tokio_block_on(self.tarpc_csp_client.idkg_verify_dealing_private(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            dealing,
            dealer_index,
            receiver_index,
            receiver_key_id,
            ByteBuf::from(context_data),
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(IDkgVerifyDealingPrivateError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }

    #[instrument(skip_all)]
    fn idkg_load_transcript(
        &self,
        algorithm_id: AlgorithmId,
        dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        context_data: Vec<u8>,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        self.tokio_block_on(self.tarpc_csp_client.idkg_load_transcript(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            dealings,
            ByteBuf::from(context_data),
            receiver_index,
            key_id,
            transcript,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(IDkgLoadTranscriptError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }

    #[instrument(skip_all)]
    fn idkg_load_transcript_with_openings(
        &self,
        alg: AlgorithmId,
        dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        openings: BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: Vec<u8>,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<(), IDkgLoadTranscriptError> {
        self.tokio_block_on(self.tarpc_csp_client.idkg_load_transcript_with_openings(
            context_with_timeout(self.rpc_timeout),
            alg,
            dealings,
            openings,
            ByteBuf::from(context_data),
            receiver_index,
            key_id,
            transcript,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(IDkgLoadTranscriptError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }

    #[instrument(skip_all)]
    fn idkg_retain_active_keys(
        &self,
        active_key_ids: BTreeSet<KeyId>,
        oldest_public_key: MEGaPublicKey,
    ) -> Result<(), IDkgRetainKeysError> {
        self.tokio_block_on(self.tarpc_csp_client.idkg_retain_active_keys(
            context_with_timeout(self.rpc_timeout),
            active_key_ids,
            oldest_public_key,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(IDkgRetainKeysError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }

    #[instrument(skip_all)]
    fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .idkg_gen_dealing_encryption_key_pair(context_with_timeout(self.rpc_timeout)),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(CspCreateMEGaKeyError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }

    #[instrument(skip_all)]
    fn idkg_open_dealing(
        &self,
        alg: AlgorithmId,
        dealing: BatchSignedIDkgDealing,
        dealer_index: NodeIndex,
        context_data: Vec<u8>,
        opener_index: NodeIndex,
        opener_key_id: KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
        self.tokio_block_on(self.tarpc_csp_client.idkg_open_dealing(
            context_with_timeout(self.rpc_timeout),
            alg,
            dealing,
            dealer_index,
            ByteBuf::from(context_data),
            opener_index,
            opener_key_id,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(IDkgOpenTranscriptError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }
}

impl ThresholdEcdsaSignerCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    #[inline]
    fn create_ecdsa_sig_share(
        &self,
        derivation_path: ExtendedDerivationPath,
        hashed_message: Vec<u8>,
        nonce: Randomness,
        key_raw: IDkgTranscriptInternalBytes,
        kappa_unmasked_raw: IDkgTranscriptInternalBytes,
        lambda_masked_raw: IDkgTranscriptInternalBytes,
        kappa_times_lambda_raw: IDkgTranscriptInternalBytes,
        key_times_lambda_raw: IDkgTranscriptInternalBytes,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaCreateSigShareError> {
        self.tokio_block_on(self.tarpc_csp_client.create_ecdsa_sig_share(
            context_with_timeout(self.rpc_timeout),
            derivation_path,
            ByteBuf::from(hashed_message),
            nonce,
            key_raw,
            kappa_unmasked_raw,
            lambda_masked_raw,
            kappa_times_lambda_raw,
            key_times_lambda_raw,
            algorithm_id,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(ThresholdEcdsaCreateSigShareError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }
}

impl ThresholdSchnorrSignerCspVault for RemoteCspVault {
    #[instrument(skip_all)]
    #[inline]
    fn create_schnorr_sig_share(
        &self,
        derivation_path: ExtendedDerivationPath,
        message: Vec<u8>,
        nonce: Randomness,
        key_raw: IDkgTranscriptInternalBytes,
        presig_raw: IDkgTranscriptInternalBytes,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdSchnorrSigShareBytes, ThresholdSchnorrCreateSigShareVaultError> {
        self.tokio_block_on(self.tarpc_csp_client.create_schnorr_sig_share(
            context_with_timeout(self.rpc_timeout),
            derivation_path,
            ByteBuf::from(message),
            nonce,
            key_raw,
            presig_raw,
            algorithm_id,
        ))
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(
                ThresholdSchnorrCreateSigShareVaultError::TransientInternalError(
                    rpc_error.to_string(),
                ),
            )
        })
    }
}

impl PublicRandomSeedGenerator for RemoteCspVault {
    #[instrument(skip_all)]
    fn new_public_seed(&self) -> Result<Seed, PublicRandomSeedGeneratorError> {
        self.tokio_block_on(
            self.tarpc_csp_client
                .new_public_seed(context_with_timeout(self.rpc_timeout)),
        )
        .unwrap_or_else(|rpc_error: tarpc::client::RpcError| {
            Err(PublicRandomSeedGeneratorError::TransientInternalError {
                internal_error: rpc_error.to_string(),
            })
        })
    }
}
