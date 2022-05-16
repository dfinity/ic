use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::secret_key_store::{Scope, SecretKeyStoreError};
use crate::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSecretKey, CspSignature};
use crate::vault::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspBasicSignatureKeygenError,
    CspMultiSignatureError, CspMultiSignatureKeygenError, CspSecretKeyStoreContainsError,
    CspThresholdSignatureKeygenError, CspTlsKeygenError, CspTlsSignError, IDkgProtocolCspVault,
    MultiSignatureCspVault, NiDkgCspVault, SecretKeyStoreCspVault, ThresholdEcdsaSignerCspVault,
    ThresholdSignatureCspVault,
};
use crate::vault::remote_csp_vault::TarpcCspVaultClient;
use crate::TlsHandshakeCspVault;
use core::future::Future;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError;
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
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError,
    IDkgVerifyDealingPrivateError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeId, NumberOfNodes, Randomness};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, SystemTime};
use tarpc::serde_transport;
use tarpc::tokio_serde::formats::Bincode;
use tokio::net::UnixStream;
use tokio_util::codec::length_delimited::LengthDelimitedCodec;

/// An implementation of `CspVault`-trait that talks to a remote CSP vault.
#[allow(dead_code)]
pub struct RemoteCspVault {
    tarpc_csp_client: TarpcCspVaultClient,
    // default timeout for RPC calls that can timeout.
    rpc_timeout: Duration,
    // special, long timeout for RPC calls that should not really timeout.
    long_rpc_timeout: Duration,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteCspVaultError {
    TransportError {
        server_address: String,
        message: String,
    },
}

///  Executes async task in sync context without starving other independently
///  spawned tasks.
///  Works for both tokio-threads and for 'naked' std::threads.
///  TODO(CRP-1453): adapt this documentation once a final solution is ready.
pub(crate) fn thread_universal_block_on<T: Future>(task: T) -> T::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(task))
    } else {
        futures::executor::block_on(task)
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
    pub fn new(socket_path: &Path) -> Result<Self, RemoteCspVaultError> {
        let conn = thread_universal_block_on(UnixStream::connect(socket_path)).map_err(|e| {
            RemoteCspVaultError::TransportError {
                server_address: socket_path.to_string_lossy().to_string(),
                message: e.to_string(),
            }
        })?;
        let codec_builder = LengthDelimitedCodec::builder();
        let transport = serde_transport::new(codec_builder.new_framed(conn), Bincode::default());
        let client = TarpcCspVaultClient::new(Default::default(), transport).spawn();
        Ok(RemoteCspVault {
            tarpc_csp_client: client,
            rpc_timeout: DEFAULT_RPC_TIMEOUT,
            long_rpc_timeout: LONG_RPC_TIMEOUT,
        })
    }

    #[cfg(test)]
    pub fn new_for_test(
        socket_path: &Path,
        timeout: Duration,
    ) -> Result<Self, RemoteCspVaultError> {
        let mut csp_vault = Self::new(socket_path)?;
        csp_vault.rpc_timeout = timeout;
        csp_vault.long_rpc_timeout = timeout;
        Ok(csp_vault)
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
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        thread_universal_block_on(self.tarpc_csp_client.sign(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            message.to_vec(),
            key_id,
        ))?
    }

    fn gen_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey), CspBasicSignatureKeygenError> {
        thread_universal_block_on(
            self.tarpc_csp_client
                .gen_key_pair(context_with_timeout(self.rpc_timeout), algorithm_id),
        )?
    }
}

impl MultiSignatureCspVault for RemoteCspVault {
    fn multi_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        thread_universal_block_on(self.tarpc_csp_client.multi_sign(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            message.to_vec(),
            key_id,
        ))?
    }

    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        thread_universal_block_on(
            self.tarpc_csp_client
                .gen_key_pair_with_pop(context_with_timeout(self.rpc_timeout), algorithm_id),
        )?
    }
}

impl ThresholdSignatureCspVault for RemoteCspVault {
    fn threshold_keygen_for_test(
        &self,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        signatory_eligibility: &[bool],
    ) -> Result<(CspPublicCoefficients, Vec<Option<KeyId>>), CspThresholdSignatureKeygenError> {
        thread_universal_block_on(self.tarpc_csp_client.threshold_keygen_for_test(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            threshold,
            signatory_eligibility.to_vec(),
        ))?
    }

    fn threshold_sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        thread_universal_block_on(self.tarpc_csp_client.threshold_sign(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            message.to_vec(),
            key_id,
        ))?
    }
}

impl SecretKeyStoreCspVault for RemoteCspVault {
    fn sks_contains(&self, key_id: &KeyId) -> Result<bool, CspSecretKeyStoreContainsError> {
        thread_universal_block_on(
            self.tarpc_csp_client
                .sks_contains(context_with_timeout(self.rpc_timeout), *key_id),
        )
        .unwrap_or_else(|e| {
            Err(CspSecretKeyStoreContainsError::InternalError {
                internal_error: e.to_string(),
            })
        })
    }

    fn insert_secret_key(
        &self,
        _id: KeyId,
        _key: CspSecretKey,
        _scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError> {
        unimplemented!("RemoteCspVault does not support insertion of external secret keys")
    }

    fn get_secret_key(&self, _id: &KeyId) -> Option<CspSecretKey> {
        unimplemented!("RemoteCspVault does not support retrieval of secret keys")
    }
}

impl NiDkgCspVault for RemoteCspVault {
    fn gen_forward_secure_key_pair(
        &self,
        node_id: NodeId,
        algorithm_id: AlgorithmId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        thread_universal_block_on(self.tarpc_csp_client.gen_forward_secure_key_pair(
            context_with_timeout(self.rpc_timeout),
            node_id,
            algorithm_id,
        ))
        .unwrap_or_else(|e| {
            Err(CspDkgCreateFsKeyError::InternalError(InternalError {
                internal_error: e.to_string(),
            }))
        })
    }

    fn update_forward_secure_epoch(
        &self,
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch: Epoch,
    ) -> Result<(), CspDkgUpdateFsEpochError> {
        thread_universal_block_on(self.tarpc_csp_client.update_forward_secure_epoch(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            key_id,
            epoch,
        ))
        .unwrap_or_else(|e| {
            Err(CspDkgUpdateFsEpochError::InternalError(InternalError {
                internal_error: e.to_string(),
            }))
        })
    }

    fn create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: &BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        maybe_resharing_secret: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, CspDkgCreateReshareDealingError> {
        thread_universal_block_on(self.tarpc_csp_client.create_dealing(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            dealer_index,
            threshold,
            epoch,
            receiver_keys.clone(),
            maybe_resharing_secret,
        ))
        .unwrap_or_else(|e| {
            Err(CspDkgCreateReshareDealingError::InternalError(
                InternalError {
                    internal_error: e.to_string(),
                },
            ))
        })
    }

    fn load_threshold_signing_key(
        &self,
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        fs_key_id: KeyId,
        receiver_index: NodeIndex,
    ) -> Result<(), CspDkgLoadPrivateKeyError> {
        thread_universal_block_on(self.tarpc_csp_client.load_threshold_signing_key(
            context_with_timeout(self.long_rpc_timeout),
            algorithm_id,
            epoch,
            csp_transcript,
            fs_key_id,
            receiver_index,
        ))
        .unwrap_or_else(|e| {
            Err(CspDkgLoadPrivateKeyError::InternalError(InternalError {
                internal_error: e.to_string(),
            }))
        })
    }

    fn retain_threshold_keys_if_present(
        &self,
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), CspDkgRetainThresholdKeysError> {
        thread_universal_block_on(self.tarpc_csp_client.retain_threshold_keys_if_present(
            context_with_timeout(self.rpc_timeout),
            active_key_ids,
        ))
        .unwrap_or_else(|e| {
            Err(CspDkgRetainThresholdKeysError::InternalError(
                InternalError {
                    internal_error: e.to_string(),
                },
            ))
        })
    }
}

impl TlsHandshakeCspVault for RemoteCspVault {
    fn gen_tls_key_pair(
        &self,
        node: NodeId,
        not_after: &str,
    ) -> Result<(KeyId, TlsPublicKeyCert), CspTlsKeygenError> {
        thread_universal_block_on(self.tarpc_csp_client.gen_tls_key_pair(
            context_with_timeout(self.rpc_timeout),
            node,
            not_after.to_string(),
        ))?
    }

    fn tls_sign(&self, message: &[u8], key_id: &KeyId) -> Result<CspSignature, CspTlsSignError> {
        thread_universal_block_on(self.tarpc_csp_client.tls_sign(
            context_with_timeout(self.rpc_timeout),
            message.to_vec(),
            *key_id,
        ))?
    }
}

impl IDkgProtocolCspVault for RemoteCspVault {
    fn idkg_create_dealing(
        &self,
        algorithm_id: AlgorithmId,
        context_data: &[u8],
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: &[MEGaPublicKey],
        transcript_operation: &IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError> {
        thread_universal_block_on(self.tarpc_csp_client.idkg_create_dealing(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            context_data.to_vec(),
            dealer_index,
            reconstruction_threshold,
            receiver_keys.to_vec(),
            transcript_operation.clone(),
        ))
        .unwrap_or_else(|e| {
            Err(IDkgCreateDealingError::InternalError {
                internal_error: e.to_string(),
            })
        })
    }

    fn idkg_verify_dealing_private(
        &self,
        algorithm_id: AlgorithmId,
        dealing: &IDkgDealingInternal,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: &[u8],
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        thread_universal_block_on(self.tarpc_csp_client.idkg_verify_dealing_private(
            context_with_timeout(self.rpc_timeout),
            algorithm_id,
            dealing.clone(),
            dealer_index,
            receiver_index,
            receiver_key_id,
            context_data.to_vec(),
        ))
        .unwrap_or_else(|e| {
            Err(IDkgVerifyDealingPrivateError::CspVaultRpcError(
                e.to_string(),
            ))
        })
    }

    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        thread_universal_block_on(self.tarpc_csp_client.idkg_load_transcript(
            context_with_timeout(self.rpc_timeout),
            dealings.clone(),
            context_data.to_vec(),
            receiver_index,
            *key_id,
            transcript.clone(),
        ))
        .unwrap_or_else(|e| {
            Err(IDkgLoadTranscriptError::InternalError {
                internal_error: e.to_string(),
            })
        })
    }

    fn idkg_load_transcript_with_openings(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<(), IDkgLoadTranscriptError> {
        thread_universal_block_on(self.tarpc_csp_client.idkg_load_transcript_with_openings(
            context_with_timeout(self.rpc_timeout),
            dealings.clone(),
            openings.clone(),
            context_data.to_vec(),
            receiver_index,
            *key_id,
            transcript.clone(),
        ))
        .unwrap_or_else(|e| {
            Err(IDkgLoadTranscriptError::InternalError {
                internal_error: e.to_string(),
            })
        })
    }

    fn idkg_gen_mega_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        thread_universal_block_on(
            self.tarpc_csp_client
                .idkg_gen_mega_key_pair(context_with_timeout(self.rpc_timeout), algorithm_id),
        )
        .unwrap_or_else(|e| {
            Err(CspCreateMEGaKeyError::CspServerError {
                internal_error: e.to_string(),
            })
        })
    }

    fn idkg_open_dealing(
        &self,
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: &[u8],
        opener_index: NodeIndex,
        opener_key_id: &KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError> {
        thread_universal_block_on(self.tarpc_csp_client.idkg_open_dealing(
            context_with_timeout(self.rpc_timeout),
            dealing,
            dealer_index,
            context_data.to_vec(),
            opener_index,
            *opener_key_id,
        ))
        .unwrap_or_else(|e| {
            Err(IDkgOpenTranscriptError::InternalError {
                internal_error: e.to_string(),
            })
        })
    }
}

impl ThresholdEcdsaSignerCspVault for RemoteCspVault {
    fn ecdsa_sign_share(
        &self,
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: &Randomness,
        key: &IDkgTranscriptInternal,
        kappa_unmasked: &IDkgTranscriptInternal,
        lambda_masked: &IDkgTranscriptInternal,
        kappa_times_lambda: &IDkgTranscriptInternal,
        key_times_lambda: &IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError> {
        thread_universal_block_on(self.tarpc_csp_client.ecdsa_sign_share(
            context_with_timeout(self.rpc_timeout),
            derivation_path.clone(),
            hashed_message.to_vec(),
            *nonce,
            key.clone(),
            kappa_unmasked.clone(),
            lambda_masked.clone(),
            kappa_times_lambda.clone(),
            key_times_lambda.clone(),
            algorithm_id,
        ))
        .unwrap_or_else(|e| {
            Err(ThresholdEcdsaSignShareError::InternalError {
                internal_error: e.to_string(),
            })
        })
    }
}
