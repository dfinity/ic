//! Implementations of ThresholdEcdsaSigner
use super::MasterPublicKeyExtractionError;
use ic_crypto_internal_csp::api::{CspThresholdEcdsaSigVerifier, CspThresholdEcdsaSigner};
use ic_crypto_internal_threshold_sig_ecdsa::{
    EccCurveType, IDkgTranscriptInternal, ThresholdEcdsaCombinedSigInternal,
    ThresholdEcdsaSerializationError, ThresholdEcdsaSigShareInternal,
};
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
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

pub fn sign_share<C: CspThresholdEcdsaSigner>(
    csp_client: &C,
    self_node_id: &NodeId,
    inputs: &ThresholdEcdsaSigInputs,
) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaSignShareError> {
    ensure_self_was_receiver(self_node_id, inputs.receivers())?;

    let internal_sig_share = csp_client.ecdsa_sign_share(inputs)?;

    let sig_share_raw = internal_sig_share.serialize().map_err(|e| {
        ThresholdEcdsaSignShareError::SerializationError {
            internal_error: format!("{:?}", e),
        }
    })?;

    Ok(ThresholdEcdsaSigShare { sig_share_raw })
}

pub fn verify_sig_share<C: CspThresholdEcdsaSigVerifier>(
    csp_client: &C,
    signer: NodeId,
    inputs: &ThresholdEcdsaSigInputs,
    share: &ThresholdEcdsaSigShare,
) -> Result<(), ThresholdEcdsaVerifySigShareError> {
    fn conv_error(e: ThresholdEcdsaSerializationError) -> ThresholdEcdsaVerifySigShareError {
        ThresholdEcdsaVerifySigShareError::SerializationError {
            internal_error: e.0,
        }
    }

    let kappa_unmasked =
        IDkgTranscriptInternal::try_from(inputs.presig_quadruple().kappa_unmasked())
            .map_err(conv_error)?;
    let lambda_masked = IDkgTranscriptInternal::try_from(inputs.presig_quadruple().lambda_masked())
        .map_err(conv_error)?;
    let kappa_times_lambda =
        IDkgTranscriptInternal::try_from(inputs.presig_quadruple().kappa_times_lambda())
            .map_err(conv_error)?;
    let key_times_lambda =
        IDkgTranscriptInternal::try_from(inputs.presig_quadruple().key_times_lambda())
            .map_err(conv_error)?;
    let key = IDkgTranscriptInternal::try_from(inputs.key_transcript()).map_err(conv_error)?;

    let sig_share =
        ThresholdEcdsaSigShareInternal::deserialize(&share.sig_share_raw).map_err(|e| {
            ThresholdEcdsaVerifySigShareError::SerializationError {
                internal_error: format!("{:?}", e),
            }
        })?;
    let signer_index = inputs.key_transcript().index_for_signer_id(signer).ok_or(
        ThresholdEcdsaVerifySigShareError::InvalidArgumentMissingSignerInTranscript {
            signer_id: signer,
        },
    )?;

    csp_client.ecdsa_verify_sig_share(
        &sig_share,
        signer_index,
        inputs.derivation_path(),
        inputs.hashed_message(),
        inputs.nonce(),
        &key,
        &kappa_unmasked,
        &lambda_masked,
        &kappa_times_lambda,
        &key_times_lambda,
        inputs.algorithm_id(),
    )
}

pub fn verify_combined_signature<C: CspThresholdEcdsaSigVerifier>(
    csp_client: &C,
    inputs: &ThresholdEcdsaSigInputs,
    signature: &ThresholdEcdsaCombinedSignature,
) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
    fn conv_error(
        e: ThresholdEcdsaSerializationError,
    ) -> ThresholdEcdsaVerifyCombinedSignatureError {
        ThresholdEcdsaVerifyCombinedSignatureError::SerializationError {
            internal_error: e.0,
        }
    }

    let kappa_unmasked =
        IDkgTranscriptInternal::try_from(inputs.presig_quadruple().kappa_unmasked())
            .map_err(conv_error)?;
    let key = IDkgTranscriptInternal::try_from(inputs.key_transcript()).map_err(conv_error)?;

    let signature =
        ThresholdEcdsaCombinedSigInternal::deserialize(inputs.algorithm_id(), &signature.signature)
            .map_err(
                |e| ThresholdEcdsaVerifyCombinedSignatureError::SerializationError {
                    internal_error: format!("{:?}", e),
                },
            )?;

    csp_client.ecdsa_verify_combined_signature(
        &signature,
        inputs.derivation_path(),
        inputs.hashed_message(),
        inputs.nonce(),
        &key,
        &kappa_unmasked,
        inputs.algorithm_id(),
    )
}

pub fn combine_sig_shares<C: CspThresholdEcdsaSigVerifier>(
    csp_client: &C,
    inputs: &ThresholdEcdsaSigInputs,
    shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
    fn conv_error(e: ThresholdEcdsaSerializationError) -> ThresholdEcdsaCombineSigSharesError {
        ThresholdEcdsaCombineSigSharesError::SerializationError {
            internal_error: e.0,
        }
    }

    ensure_sufficient_sig_shares_collected(inputs, shares)?;

    let kappa_transcript = &inputs
        .presig_quadruple()
        .kappa_unmasked()
        .internal_transcript_raw;

    let kappa_unmasked =
        IDkgTranscriptInternal::deserialize(kappa_transcript).map_err(conv_error)?;

    let internal_shares = internal_sig_shares_by_index_from_sig_shares(shares, inputs)?;

    let key = IDkgTranscriptInternal::try_from(inputs.key_transcript()).map_err(conv_error)?;

    let internal_combined_sig = csp_client.ecdsa_combine_sig_shares(
        inputs.derivation_path(),
        inputs.hashed_message(),
        inputs.nonce(),
        &key,
        &kappa_unmasked,
        inputs.reconstruction_threshold(),
        &internal_shares,
        inputs.algorithm_id(),
    )?;

    Ok(ThresholdEcdsaCombinedSignature {
        signature: internal_combined_sig.serialize(),
    })
}

fn ensure_self_was_receiver(
    self_node_id: &NodeId,
    receivers: &IDkgReceivers,
) -> Result<(), ThresholdEcdsaSignShareError> {
    if receivers.contains(*self_node_id) {
        Ok(())
    } else {
        Err(ThresholdEcdsaSignShareError::NotAReceiver)
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
                        internal_error: format!("{:?}", e),
                    },
                )?;
            Ok((index, internal_share))
        })
        .collect()
}
