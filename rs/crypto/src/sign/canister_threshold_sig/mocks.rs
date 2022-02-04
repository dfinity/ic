use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
};
use ic_types::NodeId;
use std::collections::BTreeMap;

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn combine_sig_shares(
    _inputs: &ThresholdEcdsaSigInputs,
    _shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
    Ok(ThresholdEcdsaCombinedSignature { signature: vec![] })
}

pub fn verify_combined_sig(
    _inputs: &ThresholdEcdsaSigInputs,
    _signature: &ThresholdEcdsaCombinedSignature,
) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
    Ok(())
}
