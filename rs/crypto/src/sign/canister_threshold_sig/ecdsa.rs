//! Implementations of ThresholdEcdsaSigner
use ic_crypto_internal_csp::api::{CspThresholdEcdsaSigVerifier, CspThresholdEcdsaSigner};
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgReceivers, IDkgTranscript};
use ic_types::crypto::canister_threshold_sig::{
    ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
};
use ic_types::{NodeId, NodeIndex};
use std::collections::{BTreeMap, BTreeSet};
use tecdsa::{IDkgTranscriptInternal, ThresholdEcdsaSigShareInternal};

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

    let key = internal_transcript_from_transcript(inputs.key_transcript()).map_err(|e| {
        ThresholdEcdsaCombineSigSharesError::SerializationError {
            internal_error: format!("{:?}", e),
        }
    })?;

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
    receivers: &BTreeSet<NodeId>,
) -> Result<(), ThresholdEcdsaSignShareError> {
    if receivers.contains(self_node_id) {
        Ok(())
    } else {
        Err(ThresholdEcdsaSignShareError::NotAReceiver)
    }
}

fn internal_transcript_from_transcript(
    transcript: &IDkgTranscript,
) -> Result<IDkgTranscriptInternal, ThresholdEcdsaSignShareError> {
    IDkgTranscriptInternal::deserialize(&transcript.internal_transcript_raw).map_err(|e| {
        ThresholdEcdsaSignShareError::SerializationError {
            internal_error: format!("{:?}", e),
        }
    })
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
