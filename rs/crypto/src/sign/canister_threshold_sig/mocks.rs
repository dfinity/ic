use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaGetPublicKeyError,
    ThresholdEcdsaSignShareError, ThresholdEcdsaVerifyCombinedSignatureError,
    ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use ic_types::crypto::canister_threshold_sig::{
    EcdsaPublicKey, ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs,
    ThresholdEcdsaSigShare,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, PrincipalId};

pub fn sign_share(
    _inputs: &ThresholdEcdsaSigInputs,
) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaSignShareError> {
    Ok(ThresholdEcdsaSigShare {
        sig_share_raw: vec![],
    })
}

pub fn verify_sig_share(
    _signer: NodeId,
    _inputs: &ThresholdEcdsaSigInputs,
    _share: &ThresholdEcdsaSigShare,
) -> Result<(), ThresholdEcdsaVerifySigShareError> {
    Ok(())
}

pub fn combine_sig_shares(
    _inputs: &ThresholdEcdsaSigInputs,
    _shares: &[ThresholdEcdsaSigShare],
) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
    Ok(ThresholdEcdsaCombinedSignature { signature: vec![] })
}

pub fn verify_combined_sig(
    _inputs: &ThresholdEcdsaSigInputs,
    _signature: &ThresholdEcdsaCombinedSignature,
) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
    Ok(())
}

pub fn get_public_key(
    _canister_id: PrincipalId,
    _key_transcript: IDkgTranscript,
) -> Result<EcdsaPublicKey, ThresholdEcdsaGetPublicKeyError> {
    Ok(EcdsaPublicKey {
        algorithm_id: AlgorithmId::EcdsaSecp256k1,
        public_key: vec![],
    })
}
