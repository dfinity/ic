use ic_crypto_internal_csp::api::{
    CspSigner, CspThresholdSignError, NiDkgCspClient, ThresholdSignatureCspClient,
};
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSignature};
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateDealingError, CspDkgCreateReshareDealingError, CspDkgCreateReshareTranscriptError,
    CspDkgCreateTranscriptError, CspDkgLoadPrivateKeyError, CspDkgRetainThresholdKeysError,
    CspDkgUpdateFsEpochError, CspDkgVerifyDealingError, CspDkgVerifyReshareDealingError,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspFsEncryptionPublicKey, CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::{AlgorithmId, CryptoResult};
use ic_types::{NodeIndex, NumberOfNodes};
use mockall::predicate::*;
use mockall::*;
use std::collections::{BTreeMap, BTreeSet};

mock! {
    pub AllCryptoServiceProvider {}

    impl CspSigner for AllCryptoServiceProvider {
        fn sign(
            &self,
            algorithm_id: AlgorithmId,
            msg: Vec<u8>,
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

    impl ThresholdSignatureCspClient for AllCryptoServiceProvider {
        fn threshold_sign(
            &self,
            _algorithm_id: AlgorithmId,
            _message: Vec<u8>,
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

    impl NiDkgCspClient for AllCryptoServiceProvider {
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
            collection_threshold: NumberOfNodes,
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

        fn retain_threshold_keys_if_present(
            &self,
            active_keys: BTreeSet<CspPublicCoefficients>
        ) -> Result<(), CspDkgRetainThresholdKeysError>;

        fn observe_minimum_epoch_in_active_transcripts(&self, epoch: Epoch);

        fn observe_epoch_in_loaded_transcript(&self, epoch: Epoch);
    }
}
