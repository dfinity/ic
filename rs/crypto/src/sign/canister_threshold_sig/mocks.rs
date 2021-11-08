use ic_crypto_internal_types::sign::canister_threshold_sig::CspThresholdSignatureMsg;
use ic_types::crypto::canister_threshold_sig::error::{
    CombineSignatureError, EcdsaPublicKeyError, ThresholdSignatureGenerationError,
    ThresholdSignatureVerificationError,
};
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use ic_types::crypto::canister_threshold_sig::{
    EcdsaPublicKey, ThresholdSignatureInputs, ThresholdSignatureMsg,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, PrincipalId};

pub fn sign_threshold(
    _inputs: &ThresholdSignatureInputs,
) -> Result<ThresholdSignatureMsg, ThresholdSignatureGenerationError> {
    Ok(ThresholdSignatureMsg {
        internal_msg: CspThresholdSignatureMsg {},
    })
}

pub fn validate_threshold_sig_share(
    _signer: NodeId,
    _inputs: &ThresholdSignatureInputs,
    _output: &ThresholdSignatureMsg,
) -> Result<(), ThresholdSignatureVerificationError> {
    Ok(())
}

pub fn combine_threshold_sig_shares(
    _inputs: &ThresholdSignatureInputs,
    _outputs: &[ThresholdSignatureMsg],
) -> Result<Vec<u8>, CombineSignatureError> {
    Ok(vec![])
}

pub fn get_ecdsa_public_key(
    _canister_id: PrincipalId,
    _key_transcript: IDkgTranscript,
) -> Result<EcdsaPublicKey, EcdsaPublicKeyError> {
    Ok(EcdsaPublicKey {
        algorithm_id: AlgorithmId::EcdsaSecp256k1,
        public_key: vec![],
    })
}
