// Including this clippy allow to circumvent clippy errors spawned by MockAll
// internal expansion.  Should be removed when DFN-860 is resolved.
// Specifically relevant to the Vec<> parameter.
#![allow(clippy::ptr_arg)]
#![allow(clippy::too_many_arguments)]

use async_trait::async_trait;
use ic_crypto_internal_csp::api::tls_errors::{
    CspTlsClientHandshakeError, CspTlsServerHandshakeError,
};
use ic_crypto_internal_csp::api::{
    CspCreateMEGaKeyError, CspIDkgProtocol, CspKeyGenerator, CspSecretKeyStoreChecker, CspSigner,
    CspThresholdEcdsaSigVerifier, CspThresholdEcdsaSigner, CspThresholdSignError,
    CspTlsClientHandshake, CspTlsHandshakeSignerProvider, CspTlsServerHandshake,
    DistributedKeyGenerationCspClient, NiDkgCspClient, NodePublicKeyData,
    ThresholdSignatureCspClient,
};
use ic_crypto_internal_csp::tls_stub::cert_chain::CspCertificateChain;
use ic_crypto_internal_csp::types::{
    CspDealing, CspDkgTranscript, CspPop, CspPublicCoefficients, CspPublicKey, CspResponse,
    CspSignature,
};
use ic_crypto_internal_csp::TlsHandshakeCspVault;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateDealingError, CspDkgCreateFsKeyError, CspDkgCreateReshareDealingError,
    CspDkgCreateReshareTranscriptError, CspDkgCreateTranscriptError, CspDkgLoadPrivateKeyError,
    CspDkgUpdateFsEpochError, CspDkgVerifyDealingError, CspDkgVerifyReshareDealingError,
};
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey, CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_tls_interfaces::{TlsPublicKeyCert, TlsStream};
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::KeyId;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use ic_types::IDkgId;
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use mockall::predicate::*;
use mockall::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use tecdsa::{
    IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaCombinedSigInternal,
    ThresholdEcdsaSigShareInternal,
};
use tokio::net::TcpStream;

mock! {
    pub AllCryptoServiceProvider {}

    pub trait CspSigner {
        fn sign(
            &self,
            algorithm_id: AlgorithmId,
            msg: &[u8],
            key_id: KeyId,
        ) -> CryptoResult<CspSignature>;

        fn verify(
            &self,
            sig: &CspSignature,
            msg: &[u8],
            algorithm_id: AlgorithmId,
            signer: CspPublicKey,
        ) -> CryptoResult<()>;

        fn verify_pop(
            &self,
            pop: &CspPop,
            algorithm_id: AlgorithmId,
            public_key: CspPublicKey,
        ) -> CryptoResult<()>;

        fn combine_sigs(
            &self,
            signatures: Vec<(CspPublicKey, CspSignature)>,
            algorithm_id: AlgorithmId,
        ) -> CryptoResult<CspSignature>;

        fn verify_multisig(
            &self,
            signers: Vec<CspPublicKey>,
            signature: CspSignature,
            msg: &[u8],
            algorithm_id: AlgorithmId,
        ) -> CryptoResult<()>;
    }

    pub trait CspKeyGenerator {
        fn gen_key_pair(&self, alg_id: AlgorithmId) -> Result<(KeyId, CspPublicKey), CryptoError>;

        fn gen_key_pair_with_pop(
            &self,
            algorithm_id: AlgorithmId,
        ) -> Result<(KeyId, CspPublicKey, CspPop), CryptoError>;

        fn gen_tls_key_pair(
            &mut self,
            node: NodeId,
            not_after: &str,
        ) -> TlsPublicKeyCert;
    }

    pub trait ThresholdSignatureCspClient {

        fn threshold_sign(
            &self,
            _algorithm_id: AlgorithmId,
            _message: &[u8],
            _public_coefficients: CspPublicCoefficients,
        ) -> Result<CspSignature, CspThresholdSignError>;

        fn threshold_combine_signatures(
            &self,
            algorithm_id: AlgorithmId,
            signatures: &[Option<CspSignature>],
            public_coefficients: CspPublicCoefficients,
        ) -> CryptoResult<CspSignature>;

        fn threshold_individual_public_key(
            &self,
            algorithm_id: AlgorithmId,
            node_index: NodeIndex,
            public_coefficients: CspPublicCoefficients,
        ) -> CryptoResult<CspThresholdSigPublicKey>;

        fn threshold_verify_individual_signature(
            &self,
            algorithm_id: AlgorithmId,
            message: &[u8],
            signature: CspSignature,
            public_key: CspThresholdSigPublicKey,
        ) -> CryptoResult<()>;

        fn threshold_verify_combined_signature(
            &self,
            algorithm_id: AlgorithmId,
            message: &[u8],
            signature: CspSignature,
            public_coefficients: CspPublicCoefficients,
        ) -> CryptoResult<()>;
    }

    pub trait NiDkgCspClient {
    fn create_forward_secure_key_pair(
        &mut self,
        _algorithm_id: AlgorithmId,
        _node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError>;

    /// Erases forward secure secret keys at and before a given epoch
    fn update_forward_secure_epoch(
        &self,
        _algorithm_id: AlgorithmId,
        _epoch: Epoch,
    ) -> Result<(), CspDkgUpdateFsEpochError>;

        fn create_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            dealer_index: NodeIndex,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
        ) -> Result<CspNiDkgDealing, CspDkgCreateDealingError>;

        fn create_resharing_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            dealer_resharing_index: NodeIndex,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
            resharing_public_coefficients: CspPublicCoefficients,
        ) -> Result<CspNiDkgDealing, CspDkgCreateReshareDealingError>;

        fn verify_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            dealer_index: NodeIndex,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
            dealing: CspNiDkgDealing,
        ) -> Result<(), CspDkgVerifyDealingError>;

        fn verify_resharing_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            dealer_resharing_index: u32,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
            dealing: CspNiDkgDealing,
            resharing_public_coefficients: CspPublicCoefficients,
        ) -> Result<(), CspDkgVerifyReshareDealingError>;

        fn create_transcript(
            &self,
            algorithm_id: AlgorithmId,
            threshold: NumberOfNodes,
            number_of_receivers: NumberOfNodes,
            csp_dealings: BTreeMap<u32, CspNiDkgDealing>,
        ) -> Result<CspNiDkgTranscript, CspDkgCreateTranscriptError>;

        fn create_resharing_transcript(
            &self,
            algorithm_id: AlgorithmId,
            threshold: NumberOfNodes,
            number_of_receivers: NumberOfNodes,
            csp_dealings: BTreeMap<u32, CspNiDkgDealing>,
            resharing_public_coefficients: CspPublicCoefficients,
        ) -> Result<CspNiDkgTranscript, CspDkgCreateReshareTranscriptError>;

        fn load_threshold_signing_key(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            epoch: Epoch,
            csp_transcript: CspNiDkgTranscript,
            receiver_index: u32,
        ) -> Result<(), CspDkgLoadPrivateKeyError>;

        fn retain_threshold_keys_if_present(&self, active_keys: BTreeSet<CspPublicCoefficients>);
    }

    pub trait DistributedKeyGenerationCspClient {
         fn dkg_create_ephemeral(
        &self,
        dkg_id: IDkgId,
        node_id: &[u8],
    ) -> Result<(CspEncryptionPublicKey, CspPop), dkg_errors::DkgCreateEphemeralError>;

    fn dkg_verify_ephemeral(
        &self,
        dkg_id: IDkgId,
        node_id: &[u8],
        key: (CspEncryptionPublicKey, CspPop),
    ) -> Result<(), dkg_errors::DkgVerifyEphemeralError>;

    fn dkg_create_dealing(
        &self,
        dkg_id: IDkgId,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, dkg_errors::DkgCreateDealingError>;

    fn dkg_verify_dealing(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        csp_dealing: CspDealing,
    ) -> Result<(), dkg_errors::DkgVerifyDealingError>;

    fn dkg_create_response(
        &self,
        dkg_id: IDkgId,
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        my_index: NodeIndex,
    ) -> Result<CspResponse, dkg_errors::DkgCreateResponseError>;

    fn dkg_verify_response(
        &self,
        dkg_id: IDkgId,
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        receiver_index: NodeIndex,
        receiver_key: (CspEncryptionPublicKey, CspPop),
        response: CspResponse,
    ) -> Result<(), dkg_errors::DkgVerifyResponseError>;

    fn dkg_create_transcript(
        &self,
        threshold: NumberOfNodes,
        verified_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        verified_responses: &[Option<CspResponse>],
    ) -> Result<CspDkgTranscript, dkg_errors::DkgCreateTranscriptError>;

    fn dkg_load_private_key(
        &self,
        dkg_id: IDkgId,
        csp_transcript: CspDkgTranscript,
    ) -> Result<(), dkg_errors::DkgLoadPrivateKeyError>;

    fn dkg_create_resharing_dealing(
        &self,
        dkg_id: IDkgId,
        threshold: NumberOfNodes,
        resharing_public_coefficients: CspPublicCoefficients,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, dkg_errors::DkgCreateReshareDealingError>;

    fn dkg_verify_resharing_dealing(
        &self,
        threshold: NumberOfNodes,
        receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        csp_dealing: CspDealing,
        dealer_index: NodeIndex,
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), dkg_errors::DkgVerifyReshareDealingError>;

    fn dkg_create_resharing_transcript(
        &self,
        threshold: NumberOfNodes,
        verified_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        verified_responses: &[Option<CspResponse>],
        resharing_dealers: &[Option<(CspEncryptionPublicKey, CspPop)>],
        resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspDkgTranscript, dkg_errors::DkgCreateReshareTranscriptError>;
    }

    pub trait CspSecretKeyStoreChecker {
        fn sks_contains(&self, id: &KeyId) -> bool;
        fn sks_contains_tls_key(&self, cert: &TlsPublicKeyCert) -> bool;
    }

    #[async_trait]
    pub trait CspTlsServerHandshake {
        async fn perform_tls_server_handshake(
            &self,
            tcp_stream: TcpStream,
            self_cert: TlsPublicKeyCert,
            trusted_client_certs: HashSet<TlsPublicKeyCert>,
        ) -> Result<(TlsStream, Option<CspCertificateChain>), CspTlsServerHandshakeError>;

        async fn perform_tls_server_handshake_without_client_auth(
            &self,
            tcp_stream: TcpStream,
            self_cert: TlsPublicKeyCert,
        ) -> Result<TlsStream, CspTlsServerHandshakeError>;
    }

    #[async_trait]
    pub trait CspTlsClientHandshake {
        async fn perform_tls_client_handshake(
            &self,
            tcp_stream: TcpStream,
            self_cert: TlsPublicKeyCert,
            trusted_server_cert: TlsPublicKeyCert,
        ) -> Result<(TlsStream, TlsPublicKeyCert), CspTlsClientHandshakeError>;
    }

    pub trait NodePublicKeyData {
        fn node_public_keys(&self) -> NodePublicKeys;
        fn node_signing_key_id(&self) -> KeyId;
        fn dkg_dealing_encryption_key_id(&self) -> KeyId;
    }

    pub trait CspTlsHandshakeSignerProvider: Send + Sync {
        fn handshake_signer(&self) -> Arc<dyn TlsHandshakeCspVault>;
    }

    pub trait CspIDkgProtocol {
        fn idkg_create_dealing(
            &self,
            algorithm_id: AlgorithmId,
            context_data: &[u8],
            dealer_index: NodeIndex,
            reconstruction_threshold: NumberOfNodes,
            receiver_keys: &[MEGaPublicKey],
            transcript_operation: &IDkgTranscriptOperationInternal,
        ) -> Result<IDkgDealingInternal, IDkgCreateDealingError>;

        fn idkg_create_transcript(
            &self,
            algorithm_id: AlgorithmId,
            reconstruction_threshold: NumberOfNodes,
            verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            operation_mode: &IDkgTranscriptOperationInternal,
        ) -> Result<IDkgTranscriptInternal, IDkgCreateTranscriptError>;

        fn idkg_load_transcript(
            &self,
            dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            context_data: &[u8],
            receiver_index: NodeIndex,
            public_key: &MEGaPublicKey,
            transcript: &IDkgTranscriptInternal,
        ) -> Result<Vec<IDkgComplaintInternal>, IDkgLoadTranscriptError>;

        fn idkg_create_mega_key_pair(&mut self, algorithm_id: AlgorithmId) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;
    }

    pub trait CspThresholdEcdsaSigner {
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
        ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError>;
    }

    pub trait CspThresholdEcdsaSigVerifier {
        fn ecdsa_combine_sig_shares(
            &self,
            derivation_path: &ExtendedDerivationPath,
            nonce: &Randomness,
            key: &IDkgTranscriptInternal,
            kappa_unmasked: &IDkgTranscriptInternal,
            reconstruction_threshold: NumberOfNodes,
            sig_shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
            algorithm_id: AlgorithmId,
        ) -> Result<ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaCombineSigSharesError>;
    }
}
