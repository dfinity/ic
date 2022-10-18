//! Implementations of ThresholdEcdsaSigner
use ic_crypto_internal_csp::api::{CspThresholdEcdsaSigVerifier, CspThresholdEcdsaSigner};
use ic_crypto_internal_threshold_sig_ecdsa::{
    IDkgTranscriptInternal, ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaSigShareInternal,
};
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptType::{Masked, Unmasked};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgReceivers, IDkgTranscript};
use ic_types::crypto::canister_threshold_sig::MasterEcdsaPublicKey;
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
};
use ic_types::crypto::AlgorithmId;
use ic_types::{NodeId, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

pub fn sign_share<C: CspThresholdEcdsaSigner>(
    csp_client: &C,
    self_node_id: &NodeId,
    inputs: &ThresholdEcdsaSigInputs,
) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaSignShareError> {
    ensure_self_was_receiver(self_node_id, inputs.receivers().get())?;

    let kappa_unmasked =
        internal_transcript_from_transcript(inputs.presig_quadruple().kappa_unmasked())?;
    let lambda_masked =
        internal_transcript_from_transcript(inputs.presig_quadruple().lambda_masked())?;
    let kappa_times_lambda =
        internal_transcript_from_transcript(inputs.presig_quadruple().kappa_times_lambda())?;
    let key_times_lambda =
        internal_transcript_from_transcript(inputs.presig_quadruple().key_times_lambda())?;
    let key = internal_transcript_from_transcript(inputs.key_transcript())?;

    let internal_sig_share = csp_client.ecdsa_sign_share(
        inputs.derivation_path(),
        inputs.hashed_message(),
        inputs.nonce(),
        &key,
        &kappa_unmasked,
        &lambda_masked,
        &kappa_times_lambda,
        &key_times_lambda,
        inputs.algorithm_id(),
    )?;

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
    let kappa_unmasked =
        internal_transcript_from_transcript(inputs.presig_quadruple().kappa_unmasked())?;
    let lambda_masked =
        internal_transcript_from_transcript(inputs.presig_quadruple().lambda_masked())?;
    let kappa_times_lambda =
        internal_transcript_from_transcript(inputs.presig_quadruple().kappa_times_lambda())?;
    let key_times_lambda =
        internal_transcript_from_transcript(inputs.presig_quadruple().key_times_lambda())?;
    let key = internal_transcript_from_transcript(inputs.key_transcript())?;

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
    let kappa_unmasked =
        internal_transcript_from_transcript(inputs.presig_quadruple().kappa_unmasked())?;
    let key = internal_transcript_from_transcript(inputs.key_transcript())?;

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
    ensure_sufficient_sig_shares_collected(inputs, shares)?;

    let kappa_unmasked = IDkgTranscriptInternal::deserialize(
        &inputs
            .presig_quadruple()
            .kappa_unmasked()
            .internal_transcript_raw,
    )
    .map_err(
        |e| ThresholdEcdsaCombineSigSharesError::SerializationError {
            internal_error: format!("{:?}", e),
        },
    )?;

    let internal_shares = internal_sig_shares_by_index_from_sig_shares(shares, inputs.receivers())?;

    let key = internal_transcript_from_transcript(inputs.key_transcript())?;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MasterPublicKeyExtractionError {
    UnsupportedAlgorithm(String),
    SerializationError(String),
    CannotExtractFromMasked,
}

/// Extracts the master public key from the given `idkg_transcript`.
#[allow(dead_code)]
pub fn get_tecdsa_master_public_key(
    idkg_transcript: &IDkgTranscript,
) -> Result<MasterEcdsaPublicKey, MasterPublicKeyExtractionError> {
    match idkg_transcript.transcript_type {
        Unmasked(_) => {
            let internal_transcript =
                IDkgTranscriptInternal::try_from(idkg_transcript).map_err(|e| {
                    MasterPublicKeyExtractionError::SerializationError(format!("{:?}", e))
                })?;
            let pub_key = internal_transcript.constant_term();
            let algorithm_id = match idkg_transcript.algorithm_id {
                AlgorithmId::ThresholdEcdsaSecp256k1 => AlgorithmId::EcdsaSecp256k1,
                _ => {
                    return Err(MasterPublicKeyExtractionError::UnsupportedAlgorithm(
                        format!("{:?}", idkg_transcript.algorithm_id),
                    ))
                }
            };
            Ok(MasterEcdsaPublicKey {
                algorithm_id,
                public_key: pub_key.serialize(),
            })
        }
        Masked(_) => Err(MasterPublicKeyExtractionError::CannotExtractFromMasked),
    }
}

fn ensure_self_was_receiver(
    self_node_id: &NodeId,
    receivers: &BTreeSet<NodeId>,
) -> Result<(), ThresholdEcdsaSignShareError> {
    if receivers.contains(self_node_id) {
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
    receivers: &IDkgReceivers,
) -> Result<BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>, ThresholdEcdsaCombineSigSharesError>
{
    shares
        .iter()
        .map(|(&id, share)| {
            let index = receivers
                .position(id)
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

fn internal_transcript_from_transcript(
    transcript: &IDkgTranscript,
) -> Result<IDkgTranscriptInternal, TranscriptDeserializationError> {
    IDkgTranscriptInternal::try_from(transcript)
        .map_err(|e| TranscriptDeserializationError(format!("{:?}", e)))
}

struct TranscriptDeserializationError(String);

impl From<TranscriptDeserializationError> for ThresholdEcdsaSignShareError {
    fn from(transcript_deserialization_error: TranscriptDeserializationError) -> Self {
        ThresholdEcdsaSignShareError::SerializationError {
            internal_error: transcript_deserialization_error.0,
        }
    }
}

impl From<TranscriptDeserializationError> for ThresholdEcdsaVerifySigShareError {
    fn from(transcript_deserialization_error: TranscriptDeserializationError) -> Self {
        ThresholdEcdsaVerifySigShareError::SerializationError {
            internal_error: transcript_deserialization_error.0,
        }
    }
}

impl From<TranscriptDeserializationError> for ThresholdEcdsaCombineSigSharesError {
    fn from(transcript_deserialization_error: TranscriptDeserializationError) -> Self {
        ThresholdEcdsaCombineSigSharesError::SerializationError {
            internal_error: transcript_deserialization_error.0,
        }
    }
}

impl From<TranscriptDeserializationError> for ThresholdEcdsaVerifyCombinedSignatureError {
    fn from(transcript_deserialization_error: TranscriptDeserializationError) -> Self {
        ThresholdEcdsaVerifyCombinedSignatureError::SerializationError {
            internal_error: transcript_deserialization_error.0,
        }
    }
}
