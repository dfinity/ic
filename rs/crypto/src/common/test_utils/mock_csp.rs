use async_trait::async_trait;
use ic_crypto_internal_basic_sig_ed25519::types::SignatureBytes;
use ic_crypto_internal_csp::api::tls_errors::{
    CspTlsClientHandshakeError, CspTlsServerHandshakeError,
};
use ic_crypto_internal_csp::api::{
    CspKeyGenerator, CspSecretKeyInjector, CspSecretKeyStoreChecker, CspSigner,
    CspThresholdSignError, CspTlsClientHandshake, CspTlsServerHandshake,
    DistributedKeyGenerationCspClient, NiDkgCspClient, NodePublicKeyData,
    ThresholdSignatureCspClient,
};
use ic_crypto_internal_csp::tls_stub::cert_chain::CspCertificateChain;
use ic_crypto_internal_csp::types::{
    CspDealing, CspDkgTranscript, CspPop, CspPublicCoefficients, CspPublicKey, CspResponse,
    CspSecretKey, CspSignature,
};
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateDealingError, CspDkgCreateFsKeyError, CspDkgCreateReshareDealingError,
    CspDkgCreateReshareTranscriptError, CspDkgCreateTranscriptError, CspDkgLoadPrivateKeyError,
    CspDkgUpdateFsEpochError, CspDkgVerifyDealingError, CspDkgVerifyFsKeyError,
    CspDkgVerifyReshareDealingError,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_tls_interfaces::TlsStream;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::KeyId;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use ic_types::{IDkgId, NodeId, NodeIndex, NumberOfNodes};
use openssl::x509::X509;
use proptest::std_facade::BTreeMap;
use std::collections::BTreeSet;
use std::thread;
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Default)]
pub struct MockCryptoServiceProviderBuilder {
    params: MockCryptoServiceProviderParams,
}

impl MockCryptoServiceProviderBuilder {
    pub fn new() -> Self {
        // default() returns 'None' for all Option<T>
        Default::default()
    }

    pub fn with_sign_returning(
        &mut self,
        result: Result<CspSignature, CryptoError>,
    ) -> &mut MockCryptoServiceProviderBuilder {
        self.params.sign_result = Some(result);
        self
    }

    pub fn with_verify_returning(
        &mut self,
        result: Result<(), CryptoError>,
    ) -> &mut MockCryptoServiceProviderBuilder {
        self.params.verify_result = Some(result);
        self
    }

    pub fn with_combine_sigs_returning(
        &mut self,
        result: Result<CspSignature, CryptoError>,
    ) -> &mut MockCryptoServiceProviderBuilder {
        self.params.combine_sigs_result = Some(result);
        self
    }

    pub fn with_verify_multisig_returning(
        &mut self,
        result: Result<(), CryptoError>,
    ) -> &mut MockCryptoServiceProviderBuilder {
        self.params.verify_multisig_result = Some(result);
        self
    }

    pub fn with_sleep_duration_millis(
        &mut self,
        millis: u64,
    ) -> &mut MockCryptoServiceProviderBuilder {
        self.params.sleep_duration = Some(Duration::from_millis(millis));
        self
    }

    pub fn build(&mut self) -> MockCryptoServiceProvider {
        MockCryptoServiceProvider {
            params: self.params.to_owned(),
        }
    }
}

/// A mock implementation of the CryptoServiceProvider trait. This is not a
/// Mockall mock because it is used for testing the parallel execution in
/// multi-threading tests. Mockall does not allow for parallel execution of
/// stubbed methods.
pub struct MockCryptoServiceProvider {
    params: MockCryptoServiceProviderParams,
}

#[derive(Clone, Default)]
struct MockCryptoServiceProviderParams {
    sleep_duration: Option<Duration>,
    verify_result: Option<CryptoResult<()>>,
    combine_sigs_result: Option<CryptoResult<CspSignature>>,
    gen_key_pair_result: Option<(KeyId, CspPublicKey)>,
    sign_result: Option<CryptoResult<CspSignature>>,
    verify_multisig_result: Option<CryptoResult<()>>,
    gen_key_pair_with_pop_result: Option<Result<(KeyId, CspPublicKey, CspPop), CryptoError>>,
    node_public_keys: NodePublicKeys,
}

impl CspSigner for MockCryptoServiceProvider {
    fn sign(
        &self,
        _algorithm_id: AlgorithmId,
        _msg: &[u8],
        _key_id: KeyId,
    ) -> CryptoResult<CspSignature> {
        self.sleep_if_necessary();
        self.params.sign_result.to_owned().expect("unsupported")
    }

    fn verify(
        &self,
        _sig: &CspSignature,
        _msg: &[u8],
        _algorithm_id: AlgorithmId,
        _signer: CspPublicKey,
    ) -> CryptoResult<()> {
        self.sleep_if_necessary();
        self.params.verify_result.to_owned().expect("unsupported")
    }

    fn verify_pop(
        &self,
        _pop: &CspPop,
        _algorithm_id: AlgorithmId,
        _public_key: CspPublicKey,
    ) -> CryptoResult<()> {
        self.sleep_if_necessary();
        self.params.verify_result.to_owned().expect("unsupported")
    }

    fn combine_sigs(
        &self,
        _signatures: Vec<(CspPublicKey, CspSignature)>,
        _algorithm_id: AlgorithmId,
    ) -> CryptoResult<CspSignature> {
        self.sleep_if_necessary();
        self.params
            .combine_sigs_result
            .to_owned()
            .expect("unsupported")
    }

    fn verify_multisig(
        &self,
        _signers: Vec<CspPublicKey>,
        _signature: CspSignature,
        _msg: &[u8],
        _algorithm_id: AlgorithmId,
    ) -> CryptoResult<()> {
        self.sleep_if_necessary();
        self.params
            .verify_multisig_result
            .to_owned()
            .expect("unsupported")
    }
}

impl CspKeyGenerator for MockCryptoServiceProvider {
    fn gen_key_pair(&self, _alg_id: AlgorithmId) -> Result<(KeyId, CspPublicKey), CryptoError> {
        self.sleep_if_necessary();
        Ok(self
            .params
            .gen_key_pair_result
            .to_owned()
            .expect("unsupported"))
    }

    fn gen_key_pair_with_pop(
        &self,
        _algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CryptoError> {
        self.sleep_if_necessary();
        self.params
            .gen_key_pair_with_pop_result
            .to_owned()
            .expect("unsupported")
    }

    fn gen_tls_key_pair(&mut self, _node: NodeId, _not_after: &str) -> X509PublicKeyCert {
        unimplemented!()
    }
}

impl ThresholdSignatureCspClient for MockCryptoServiceProvider {
    fn threshold_sign_to_be_removed(
        &self,
        _algorithm_id: AlgorithmId,
        _message: &[u8],
        _key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError> {
        unimplemented!()
    }

    fn threshold_sign(
        &self,
        _algorithm_id: AlgorithmId,
        _message: &[u8],
        _public_coefficients: CspPublicCoefficients,
    ) -> Result<CspSignature, CspThresholdSignError> {
        unimplemented!()
    }

    fn threshold_combine_signatures(
        &self,
        _algorithm_id: AlgorithmId,
        _signatures: &[Option<CspSignature>],
        _public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<CspSignature> {
        unimplemented!()
    }

    fn threshold_individual_public_key(
        &self,
        _algorithm_id: AlgorithmId,
        _node_index: NodeIndex,
        _public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<CspThresholdSigPublicKey> {
        unimplemented!()
    }

    fn threshold_verify_individual_signature(
        &self,
        _algorithm_id: AlgorithmId,
        _message: &[u8],
        _signature: CspSignature,
        _public_key: CspThresholdSigPublicKey,
    ) -> CryptoResult<()> {
        unimplemented!()
    }

    fn threshold_verify_combined_signature(
        &self,
        _algorithm_id: AlgorithmId,
        _message: &[u8],
        _signature: CspSignature,
        _public_coefficients: CspPublicCoefficients,
    ) -> CryptoResult<()> {
        unimplemented!()
    }
}

impl NiDkgCspClient for MockCryptoServiceProvider {
    fn create_forward_secure_key_pair(
        &mut self,
        _algorithm_id: AlgorithmId,
        _node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError> {
        unimplemented!()
    }

    fn verify_forward_secure_key(
        &self,
        _algorithm_id: AlgorithmId,
        _public_key: CspFsEncryptionPublicKey,
        _pop: CspFsEncryptionPop,
        _node_id: NodeId,
    ) -> Result<(), CspDkgVerifyFsKeyError> {
        unimplemented!()
    }

    fn update_forward_secure_epoch(
        &self,
        _algorithm_id: AlgorithmId,
        _epoch: Epoch,
    ) -> Result<(), CspDkgUpdateFsEpochError> {
        unimplemented!()
    }

    fn create_dealing(
        &self,
        _algorithm_id: AlgorithmId,
        _dkg_id: NiDkgId,
        _dealer_index: NodeIndex,
        _threshold: NumberOfNodes,
        _epoch: Epoch,
        _receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
    ) -> Result<CspNiDkgDealing, CspDkgCreateDealingError> {
        unimplemented!()
    }

    fn create_resharing_dealing(
        &self,
        _algorithm_id: AlgorithmId,
        _dkg_id: NiDkgId,
        _dealer_index: NodeIndex,
        _threshold: NumberOfNodes,
        _epoch: Epoch,
        _receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
        _resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspNiDkgDealing, CspDkgCreateReshareDealingError> {
        unimplemented!()
    }

    fn verify_dealing(
        &self,
        _algorithm_id: AlgorithmId,
        _dkg_id: NiDkgId,
        _dealer_index: NodeIndex,
        _threshold: NumberOfNodes,
        _epoch: Epoch,
        _receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
        _dealing: CspNiDkgDealing,
    ) -> Result<(), CspDkgVerifyDealingError> {
        unimplemented!()
    }

    fn verify_resharing_dealing(
        &self,
        _algorithm_id: AlgorithmId,
        _dkg_id: NiDkgId,
        _dealer_resharing_index: NodeIndex,
        _threshold: NumberOfNodes,
        _epoch: Epoch,
        _receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
        _dealing: CspNiDkgDealing,
        _resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), CspDkgVerifyReshareDealingError> {
        unimplemented!()
    }

    fn create_transcript(
        &self,
        _algorithm_id: AlgorithmId,
        _threshold: NumberOfNodes,
        _number_of_receivers: NumberOfNodes,
        _csp_dealings: BTreeMap<u32, CspNiDkgDealing>,
    ) -> Result<CspNiDkgTranscript, CspDkgCreateTranscriptError> {
        unimplemented!()
    }

    fn create_resharing_transcript(
        &self,
        _algorithm_id: AlgorithmId,
        _threshold: NumberOfNodes,
        _number_of_receivers: NumberOfNodes,
        _csp_dealings: BTreeMap<u32, CspNiDkgDealing>,
        _resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspNiDkgTranscript, CspDkgCreateReshareTranscriptError> {
        unimplemented!()
    }

    fn load_threshold_signing_key(
        &self,
        _algorithm_id: AlgorithmId,
        _dkg_id: NiDkgId,
        _epoch: Epoch,
        _csp_transcript: CspNiDkgTranscript,
        _receiver_index: u32,
    ) -> Result<(), CspDkgLoadPrivateKeyError> {
        unimplemented!()
    }

    fn retain_threshold_keys_if_present(&self, _active_keys: BTreeSet<CspPublicCoefficients>) {
        unimplemented!()
    }
}

impl DistributedKeyGenerationCspClient for MockCryptoServiceProvider {
    fn dkg_create_ephemeral(
        &self,
        _dkg_id: IDkgId,
        _node_id: &[u8],
    ) -> Result<(CspEncryptionPublicKey, CspPop), dkg_errors::DkgCreateEphemeralError> {
        unimplemented!()
    }

    fn dkg_verify_ephemeral(
        &self,
        _dkg_id: IDkgId,
        _node_id: &[u8],
        _key: (CspEncryptionPublicKey, CspPop),
    ) -> Result<(), dkg_errors::DkgVerifyEphemeralError> {
        unimplemented!()
    }

    fn dkg_create_dealing(
        &self,
        _dkg_id: IDkgId,
        _threshold: NumberOfNodes,
        _receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, dkg_errors::DkgCreateDealingError> {
        unimplemented!()
    }

    fn dkg_verify_dealing(
        &self,
        _threshold: NumberOfNodes,
        _receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        _csp_dealing: CspDealing,
    ) -> Result<(), dkg_errors::DkgVerifyDealingError> {
        unimplemented!()
    }

    fn dkg_create_response(
        &self,
        _dkg_id: IDkgId,
        _verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        _my_index: NodeIndex,
    ) -> Result<CspResponse, dkg_errors::DkgCreateResponseError> {
        unimplemented!()
    }

    fn dkg_verify_response(
        &self,
        _dkg_id: IDkgId,
        _verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        _receiver_index: NodeIndex,
        _receiver_key: (CspEncryptionPublicKey, CspPop),
        _response: CspResponse,
    ) -> Result<(), dkg_errors::DkgVerifyResponseError> {
        unimplemented!()
    }

    fn dkg_create_transcript(
        &self,
        _threshold: NumberOfNodes,
        _verified_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        _verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        _verified_responses: &[Option<CspResponse>],
    ) -> Result<CspDkgTranscript, dkg_errors::DkgCreateTranscriptError> {
        unimplemented!()
    }

    fn dkg_load_private_key(
        &self,
        _dkg_id: IDkgId,
        _csp_transcript: CspDkgTranscript,
    ) -> Result<(), dkg_errors::DkgLoadPrivateKeyError> {
        unimplemented!()
    }

    fn dkg_create_resharing_dealing(
        &self,
        _dkg_id: IDkgId,
        _threshold: NumberOfNodes,
        _resharing_public_coefficients: CspPublicCoefficients,
        _receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
    ) -> Result<CspDealing, dkg_errors::DkgCreateReshareDealingError> {
        unimplemented!()
    }

    fn dkg_verify_resharing_dealing(
        &self,
        _threshold: NumberOfNodes,
        _receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        _csp_dealing: CspDealing,
        _dealer_index: NodeIndex,
        _resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<(), dkg_errors::DkgVerifyReshareDealingError> {
        unimplemented!()
    }

    fn dkg_create_resharing_transcript(
        &self,
        _threshold: NumberOfNodes,
        _verified_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
        _verified_csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
        _verified_responses: &[Option<CspResponse>],
        _resharing_dealers: &[Option<(CspEncryptionPublicKey, CspPop)>],
        _resharing_public_coefficients: CspPublicCoefficients,
    ) -> Result<CspDkgTranscript, dkg_errors::DkgCreateReshareTranscriptError> {
        unimplemented!()
    }
}

impl CspSecretKeyInjector for MockCryptoServiceProvider {
    fn insert_secret_key(&mut self, _key_id: KeyId, _sk: CspSecretKey) {
        unimplemented!()
    }
}

impl CspSecretKeyStoreChecker for MockCryptoServiceProvider {
    fn sks_contains(&self, _key_id: &KeyId) -> bool {
        unimplemented!()
    }

    fn sks_contains_tls_key(&self, _cert: &X509PublicKeyCert) -> bool {
        unimplemented!()
    }
}

#[async_trait]
impl CspTlsServerHandshake for MockCryptoServiceProvider {
    async fn perform_tls_server_handshake(
        &self,
        _tcp_stream: TcpStream,
        _self_cert: X509PublicKeyCert,
        _trusted_client_certs: Vec<X509PublicKeyCert>,
    ) -> Result<(TlsStream, Option<CspCertificateChain>), CspTlsServerHandshakeError> {
        unimplemented!()
    }
}

#[async_trait]
impl CspTlsClientHandshake for MockCryptoServiceProvider {
    async fn perform_tls_client_handshake(
        &self,
        _tcp_stream: TcpStream,
        _self_cert: X509PublicKeyCert,
        _trusted_server_cert: X509PublicKeyCert,
    ) -> Result<(TlsStream, X509), CspTlsClientHandshakeError> {
        unimplemented!()
    }
}

impl NodePublicKeyData for MockCryptoServiceProvider {
    fn node_public_keys(&self) -> NodePublicKeys {
        self.params.node_public_keys.clone()
    }

    fn node_signing_key_id(&self) -> KeyId {
        unimplemented!()
    }

    fn dkg_dealing_encryption_key_id(&self) -> KeyId {
        unimplemented!()
    }
}

pub fn dummy_signature() -> CspSignature {
    CspSignature::Ed25519(SignatureBytes([0; 64]))
}

impl MockCryptoServiceProvider {
    fn sleep_if_necessary(&self) {
        let duration = self.params.sleep_duration;
        if let Some(duration) = duration {
            thread::sleep(duration);
        }
    }
}
