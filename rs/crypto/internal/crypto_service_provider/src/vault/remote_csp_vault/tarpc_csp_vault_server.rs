use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSignature};
use crate::vault::api::{
    BasicSignatureCspVault, CspBasicSignatureError, CspBasicSignatureKeygenError,
    CspMultiSignatureError, CspMultiSignatureKeygenError, CspThresholdSignatureKeygenError,
    CspTlsKeygenError, CspTlsSignError, IDkgProtocolCspVault, MultiSignatureCspVault,
    NiDkgCspVault, SecretKeyStoreCspVault, ThresholdEcdsaSignerCspVault,
    ThresholdSignatureCspVault,
};
use crate::vault::local_csp_vault::LocalCspVault;
use crate::vault::remote_csp_vault::TarpcCspVault;
use crate::{TlsHandshakeCspVault, CANISTER_SKS_DATA_FILENAME, SKS_DATA_FILENAME};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateFsKeyError, CspDkgCreateReshareDealingError, CspDkgLoadPrivateKeyError,
    CspDkgUpdateFsEpochError,
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
use ic_logger::new_logger;
use ic_logger::replica_logger::no_op_logger;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError,
    IDkgVerifyDealingPrivateError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeId, NumberOfNodes, Randomness};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use tarpc::server::BaseChannel;
#[allow(unused_imports)]
use tarpc::server::Serve;
use tarpc::tokio_serde::formats::Bincode;
use tarpc::{context, serde_transport, server::Channel};
use tokio::net::UnixListener;
use tokio_util::codec::length_delimited::LengthDelimitedCodec;

pub(crate) struct TarpcCspVaultServerImpl {
    local_csp_vault: Arc<LocalCspVault<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore>>,
    listener: UnixListener,
}

#[derive(Clone)]
struct TarpcCspVaultServerWorker {
    local_csp_vault: Arc<LocalCspVault<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore>>,
}

#[tarpc::server]
impl TarpcCspVault for TarpcCspVaultServerWorker {
    // `BasicSignatureCspVault`-methods.
    async fn sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        msg: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError> {
        self.local_csp_vault.sign(algorithm_id, &*msg, key_id)
    }

    async fn gen_key_pair(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey), CspBasicSignatureKeygenError> {
        self.local_csp_vault.gen_key_pair(algorithm_id)
    }

    // `MultiSignatureCspVault`-methods.
    async fn multi_sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError> {
        self.local_csp_vault
            .multi_sign(algorithm_id, &*message, key_id)
    }

    async fn gen_key_pair_with_pop(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CspMultiSignatureKeygenError> {
        self.local_csp_vault.gen_key_pair_with_pop(algorithm_id)
    }

    // `ThresholdSignatureCspVault`-methods.
    async fn threshold_sign(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        self.local_csp_vault
            .threshold_sign(algorithm_id, &*message, key_id)
    }

    async fn threshold_keygen_for_test(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        signatory_eligibility: Vec<bool>,
    ) -> Result<(CspPublicCoefficients, Vec<Option<KeyId>>), CspThresholdSignatureKeygenError> {
        self.local_csp_vault.threshold_keygen_for_test(
            algorithm_id,
            threshold,
            &*signatory_eligibility,
        )
    }

    // `NiDkgCspVault`-methods.
    async fn gen_forward_secure_key_pair(
        self,
        _: context::Context,
        node_id: NodeId,
        algorithm_id: AlgorithmId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        self.local_csp_vault
            .gen_forward_secure_key_pair(node_id, algorithm_id)
    }

    async fn update_forward_secure_epoch(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch: Epoch,
    ) -> Result<(), CspDkgUpdateFsEpochError> {
        self.local_csp_vault
            .update_forward_secure_epoch(algorithm_id, key_id, epoch)
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
        self.local_csp_vault.create_dealing(
            algorithm_id,
            dealer_index,
            threshold,
            epoch,
            &receiver_keys,
            maybe_resharing_secret,
        )
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
        self.local_csp_vault.load_threshold_signing_key(
            algorithm_id,
            epoch,
            csp_transcript,
            fs_key_id,
            receiver_index,
        )
    }

    async fn retain_threshold_keys_if_present(
        self,
        _: context::Context,
        active_key_ids: BTreeSet<KeyId>,
    ) {
        self.local_csp_vault
            .retain_threshold_keys_if_present(active_key_ids)
    }

    // SecretKeyStoreCspVault-methods.
    async fn sks_contains(self, _: context::Context, key_id: KeyId) -> bool {
        self.local_csp_vault.sks_contains(&key_id)
    }

    // 'TlsHandshakeCspVault'-methods.
    async fn gen_tls_key_pair(
        self,
        _: context::Context,
        node: NodeId,
        not_after: String,
    ) -> Result<(KeyId, TlsPublicKeyCert), CspTlsKeygenError> {
        self.local_csp_vault.gen_tls_key_pair(node, &not_after)
    }

    async fn tls_sign(
        self,
        _: context::Context,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspTlsSignError> {
        self.local_csp_vault.tls_sign(&*message, &key_id)
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
        self.local_csp_vault.idkg_create_dealing(
            algorithm_id,
            &context_data,
            dealer_index,
            reconstruction_threshold,
            &receiver_keys,
            &transcript_operation,
        )
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
        self.local_csp_vault.idkg_verify_dealing_private(
            algorithm_id,
            &dealing,
            dealer_index,
            receiver_index,
            receiver_key_id,
            &context_data,
        )
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
        self.local_csp_vault.idkg_load_transcript(
            &dealings,
            &context_data,
            receiver_index,
            &key_id,
            &transcript,
        )
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
        self.local_csp_vault.idkg_load_transcript_with_openings(
            &dealings,
            &openings,
            &context_data,
            receiver_index,
            &key_id,
            &transcript,
        )
    }

    async fn idkg_gen_mega_key_pair(
        self,
        _: context::Context,
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        self.local_csp_vault.idkg_gen_mega_key_pair(algorithm_id)
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
        self.local_csp_vault.idkg_open_dealing(
            dealing,
            dealer_index,
            &context_data,
            opener_index,
            &opener_key_id,
        )
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
        self.local_csp_vault.ecdsa_sign_share(
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
    }
}

impl TarpcCspVaultServerImpl {
    pub fn new(sks_dir: &Path, listener: UnixListener) -> Self {
        // TODO(CRP-1254: add a real logger.
        let logger = no_op_logger();
        let node_secret_key_store =
            ProtoSecretKeyStore::open(sks_dir, SKS_DATA_FILENAME, Some(new_logger!(&logger)));
        let canister_secret_key_store = ProtoSecretKeyStore::open(
            sks_dir,
            CANISTER_SKS_DATA_FILENAME,
            Some(new_logger!(&logger)),
        );
        let local_csp_server = Arc::new(LocalCspVault::new(
            node_secret_key_store,
            canister_secret_key_store,
            Arc::new(CryptoMetrics::none()),
            new_logger!(&logger),
        ));
        Self {
            local_csp_vault: local_csp_server,
            listener,
        }
    }

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
            let local_csp_server = Arc::clone(&self.local_csp_vault);
            tokio::spawn(async move {
                let framed = codec_builder.new_framed(conn);
                let transport = serde_transport::new(framed, Bincode::default());
                let worker = TarpcCspVaultServerWorker {
                    local_csp_vault: local_csp_server,
                };
                let channel_executor =
                    BaseChannel::with_defaults(transport).execute(worker.serve());
                channel_executor.await;
            });
        }
    }
}
