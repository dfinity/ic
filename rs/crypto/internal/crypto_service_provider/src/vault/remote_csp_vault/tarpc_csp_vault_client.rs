use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSignature};
use crate::vault::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspBasicSignatureKeygenError,
    CspMultiSignatureError, CspMultiSignatureKeygenError, CspThresholdSignatureKeygenError,
    IDkgProtocolCspVault, MultiSignatureCspVault, NiDkgCspVault, SecretKeyStoreCspVault,
    ThresholdSignatureCspVault,
};
use crate::vault::remote_csp_vault::TarpcCspVaultClient;
use futures::executor::block_on;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateFsKeyError, CspDkgCreateReshareDealingError, CspDkgLoadPrivateKeyError,
    CspDkgUpdateFsEpochError,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::NodeIndex;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError,
};
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeId, NumberOfNodes};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tarpc::serde_transport;
use tarpc::tokio_serde::formats::Bincode;
use tecdsa::{
    IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey,
};
use tokio::net::UnixStream;
use tokio_util::codec::length_delimited::LengthDelimitedCodec;

/// An implementation of `CspVault`-trait that talks to a remote CSP vault.
/// TOOD(CRP-1236): reconsider naming conventions.
#[allow(dead_code)]
pub struct RemoteCspVault {
    tarpc_csp_client: TarpcCspVaultClient,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteCspVaultError {
    TransportError {
        server_address: String,
        message: String,
    },
}

#[allow(dead_code)]
impl RemoteCspVault {
    /// Creates a new `RemoteCspVault`-object that communicates
    /// with a server via a Unix socket specified by `socket_path`.
    /// The socket must exist before this constructor is called,
    /// otherwise the constructor will fail.
    pub fn new(socket_path: &Path) -> Result<Self, RemoteCspVaultError> {
        let codec_builder = LengthDelimitedCodec::builder();

        let conn = block_on(UnixStream::connect(socket_path)).map_err(|e| {
            RemoteCspVaultError::TransportError {
                server_address: socket_path.to_string_lossy().to_string(),
                message: e.to_string(),
            }
        })?;
        let transport = serde_transport::new(codec_builder.new_framed(conn), Bincode::default());
        let client = TarpcCspVaultClient::new(Default::default(), transport).spawn();
        Ok(RemoteCspVault {
            tarpc_csp_client: client,
        })
    }
}

// Note: the implementation of the traits below does use `block_on` when calling
// the remote server, as the API used by `Csp` is synchronous, while the server
// API is async.
impl BasicSignatureCspVault for RemoteCspVault {
    fn sign(
        &self,
        algorithm_id: AlgorithmId,
        message: &[u8],
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        block_on(self.tarpc_csp_client.sign(
            tarpc::context::current(),
            algorithm_id,
            message.to_vec(),
            key_id,
        ))?
    }

    fn gen_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey), CspBasicSignatureKeygenError> {
        block_on(
            self.tarpc_csp_client
                .gen_key_pair(tarpc::context::current(), algorithm_id),
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
        block_on(self.tarpc_csp_client.multi_sign(
            tarpc::context::current(),
            algorithm_id,
            message.to_vec(),
            key_id,
        ))?
    }

    fn gen_key_pair_with_pop(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        block_on(
            self.tarpc_csp_client
                .gen_key_pair_with_pop(tarpc::context::current(), algorithm_id),
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
        block_on(self.tarpc_csp_client.threshold_keygen_for_test(
            tarpc::context::current(),
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
        block_on(self.tarpc_csp_client.threshold_sign(
            tarpc::context::current(),
            algorithm_id,
            message.to_vec(),
            key_id,
        ))?
    }
}

impl SecretKeyStoreCspVault for RemoteCspVault {
    fn sks_contains(&self, key_id: &KeyId) -> bool {
        block_on(
            self.tarpc_csp_client
                .sks_contains(tarpc::context::current(), *key_id),
        )
        .unwrap_or(false)
    }
}

impl NiDkgCspVault for RemoteCspVault {
    fn gen_forward_secure_key_pair(
        &self,
        node_id: NodeId,
        algorithm_id: AlgorithmId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        block_on(self.tarpc_csp_client.gen_forward_secure_key_pair(
            tarpc::context::current(),
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
        block_on(self.tarpc_csp_client.update_forward_secure_epoch(
            tarpc::context::current(),
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
        block_on(self.tarpc_csp_client.create_dealing(
            tarpc::context::current(),
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
        block_on(self.tarpc_csp_client.load_threshold_signing_key(
            tarpc::context::current(),
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

    fn retain_threshold_keys_if_present(&self, active_key_ids: BTreeSet<KeyId>) {
        block_on(
            self.tarpc_csp_client
                .retain_threshold_keys_if_present(tarpc::context::current(), active_key_ids),
        )
        .unwrap_or_else(|_| {});
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
        block_on(self.tarpc_csp_client.idkg_create_dealing(
            tarpc::context::current(),
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

    fn idkg_load_transcript(
        &self,
        dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: &[u8],
        receiver_index: NodeIndex,
        key_id: &KeyId,
        transcript: &IDkgTranscriptInternal,
    ) -> Result<Vec<IDkgComplaintInternal>, IDkgLoadTranscriptError> {
        block_on(self.tarpc_csp_client.idkg_load_transcript(
            tarpc::context::current(),
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

    fn idkg_gen_mega_key_pair(
        &self,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        block_on(
            self.tarpc_csp_client
                .idkg_gen_mega_key_pair(tarpc::context::current(), algorithm_id),
        )
        .unwrap_or_else(|e| {
            Err(CspCreateMEGaKeyError::CspServerError {
                internal_error: e.to_string(),
            })
        })
    }
}
