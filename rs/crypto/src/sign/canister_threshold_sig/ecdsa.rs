//! Implementations of ThresholdEcdsaSigner
use super::MasterPublicKeyExtractionError;
use ic_crypto_internal_csp::vault::api::{CspVault, IDkgTranscriptInternalBytes};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    combine_ecdsa_signature_shares, verify_ecdsa_signature_share, verify_ecdsa_threshold_signature,
    CanisterThresholdSerializationError, DerivationPath, EccCurveType, IDkgTranscriptInternal,
    ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaSigShareInternal,
    ThresholdEcdsaVerifySigShareInternalError, ThresholdEcdsaVerifySignatureInternalError,
};
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaCreateSigShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::IDkgReceivers;
use ic_types::crypto::canister_threshold_sig::MasterPublicKey;
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, NodeIndex};
use std::collections::BTreeMap;
use std::convert::TryFrom;

/// Extracts the ECDSA master public key from the given `idkg_transcript`.
pub(crate) fn get_tecdsa_master_public_key_from_internal_transcript(
    idkg_transcript_internal: &IDkgTranscriptInternal,
) -> Result<MasterPublicKey, MasterPublicKeyExtractionError> {
    let pub_key = idkg_transcript_internal.constant_term();
    let algorithm_id = match pub_key.curve_type() {
        EccCurveType::K256 => AlgorithmId::EcdsaSecp256k1,
        EccCurveType::P256 => AlgorithmId::EcdsaP256,
        x => {
            return Err(MasterPublicKeyExtractionError::UnsupportedAlgorithm(
                format!("ECDSA does not support curve {:?}", x),
            ))
        }
    };

    Ok(MasterPublicKey {
        algorithm_id,
        public_key: pub_key.serialize(),
    })
}

pub fn sign_share(
    _vault: &dyn CspVault,
    self_node_id: &NodeId,
    inputs: &ThresholdEcdsaSigInputs,
) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaCreateSigShareError> {
    ensure_self_was_receiver(self_node_id, inputs.receivers())?;

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

pub fn verify_combined_signature(
    _inputs: &ThresholdEcdsaSigInputs,
    _signature: &ThresholdEcdsaCombinedSignature,
) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
    Ok(())
}

pub fn combine_sig_shares(
    inputs: &ThresholdEcdsaSigInputs,
    shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
    ensure_sufficient_sig_shares_collected(inputs, shares)?;

    Ok(ThresholdEcdsaCombinedSignature { signature: vec![] })
}

fn ensure_self_was_receiver(
    self_node_id: &NodeId,
    receivers: &IDkgReceivers,
) -> Result<(), ThresholdEcdsaCreateSigShareError> {
    if receivers.contains(*self_node_id) {
        Ok(())
    } else {
        Err(ThresholdEcdsaCreateSigShareError::NotAReceiver)
    }
}

fn ensure_sufficient_sig_shares_collected(
    inputs: &ThresholdEcdsaSigInputs,
    shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
) -> Result<(), ThresholdEcdsaCombineSigSharesError> {
    if shares.len() < inputs.reconstruction_threshold().get() as usize {
        Err(
            ThresholdEcdsaCombineSigSharesError::UnsatisfiedReconstructionThreshold {
                threshold: inputs.reconstruction_threshold().get(),
                share_count: shares.len(),
            },
        )
    } else {
        Ok(())
    }
}

/// Deserialize each raw signature share to the internal format,
/// and map them by signer index (rather than signer Id).
fn internal_sig_shares_by_index_from_sig_shares(
    shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
    inputs: &ThresholdEcdsaSigInputs,
) -> Result<BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>, ThresholdEcdsaCombineSigSharesError>
{
    shares
        .iter()
        .map(|(&id, share)| {
            let index = inputs
                .index_for_signer_id(id)
                .ok_or(ThresholdEcdsaCombineSigSharesError::SignerNotAllowed { node_id: id })?;
            let internal_share = ThresholdEcdsaSigShareInternal::deserialize(&share.sig_share_raw)
                .map_err(
                    |e| ThresholdEcdsaCombineSigSharesError::SerializationError {
                        internal_error: format!("failed to deserialize signature share: {}", e.0),
                    },
                )?;
            Ok((index, internal_share))
        })
        .collect()
}
