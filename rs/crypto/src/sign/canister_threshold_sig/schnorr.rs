//! Implementations of ThresholdSchnorrSigner and ThresholdSchnorrVerifier

use super::MasterPublicKeyExtractionError;
use ic_crypto_internal_csp::vault::api::{
    CspVault, IDkgTranscriptInternalBytes, ThresholdSchnorrCreateSigShareVaultError,
};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    DerivationPath, EccCurveType, IDkgTranscriptInternal,
    ThresholdBip340CombineSigSharesInternalError, ThresholdBip340CombinedSignatureInternal,
    ThresholdBip340SignatureShareInternal, ThresholdBip340VerifySigShareInternalError,
    ThresholdBip340VerifySignatureInternalError, ThresholdEd25519CombineSigSharesInternalError,
    ThresholdEd25519CombinedSignatureInternal, ThresholdEd25519SignatureShareInternal,
    ThresholdEd25519VerifySigShareInternalError, ThresholdEd25519VerifySignatureInternalError,
    combine_bip340_signature_shares, combine_ed25519_signature_shares,
    verify_bip340_signature_share, verify_ed25519_signature_share,
    verify_threshold_bip340_signature, verify_threshold_ed25519_signature,
};
use ic_types::{
    NodeId, NodeIndex, Randomness,
    crypto::canister_threshold_sig::{
        MasterPublicKey, ThresholdSchnorrCombinedSignature, ThresholdSchnorrSigInputs,
        ThresholdSchnorrSigShare,
        error::{
            ThresholdSchnorrCombineSigSharesError, ThresholdSchnorrCreateSigShareError,
            ThresholdSchnorrVerifyCombinedSigError, ThresholdSchnorrVerifySigShareError,
        },
        idkg::IDkgReceivers,
    },
    crypto::{AlgorithmId, ExtendedDerivationPath},
};
use std::collections::BTreeMap;

/// Extracts the Schnorr master public key from the given `idkg_transcript`.
pub(crate) fn get_tschnorr_master_public_key_from_internal_transcript(
    idkg_transcript_internal: &IDkgTranscriptInternal,
) -> Result<MasterPublicKey, MasterPublicKeyExtractionError> {
    let pub_key = idkg_transcript_internal.constant_term();
    let alg = match pub_key.curve_type() {
        EccCurveType::K256 => AlgorithmId::SchnorrSecp256k1,
        EccCurveType::Ed25519 => AlgorithmId::Ed25519,
        x => {
            return Err(MasterPublicKeyExtractionError::UnsupportedAlgorithm(
                format!("Schnorr does not support curve {x:?}"),
            ));
        }
    };
    Ok(MasterPublicKey {
        algorithm_id: alg,
        public_key: pub_key.serialize(),
    })
}

pub fn create_sig_share(
    vault: &dyn CspVault,
    self_node_id: &NodeId,
    inputs: &ThresholdSchnorrSigInputs,
) -> Result<ThresholdSchnorrSigShare, ThresholdSchnorrCreateSigShareError> {
    ensure_self_was_receiver(self_node_id, inputs.receivers())?;

    let key_raw = inputs.key_transcript().transcript_to_bytes();
    let presignature_raw = inputs
        .presig_transcript()
        .blinder_unmasked()
        .transcript_to_bytes();

    let sig_share_raw_typed = vault
        .create_schnorr_sig_share(
            ExtendedDerivationPath {
                caller: *inputs.caller(),
                derivation_path: inputs.derivation_path().to_vec(),
            },
            inputs.message().to_vec(),
            inputs.taproot_tree_root().map(Vec::from),
            Randomness::from(*inputs.nonce()),
            IDkgTranscriptInternalBytes::from(key_raw),
            IDkgTranscriptInternalBytes::from(presignature_raw),
            inputs.algorithm_id(),
        )
        .map_err(|e| {
            type F = ThresholdSchnorrCreateSigShareVaultError;
            type T = ThresholdSchnorrCreateSigShareError;
            match e {
                F::InvalidArguments(s) => T::InvalidArguments(s),
                F::InconsistentCommitments => T::InternalError(format!("{e:?}")),
                F::SerializationError(s) => T::SerializationError(s),
                F::SecretSharesNotFound { commitment_string } => {
                    T::SecretSharesNotFound { commitment_string }
                }
                F::InternalError(s) => T::InternalError(s),
                F::TransientInternalError(s) => T::TransientInternalError(s),
            }
        })?;
    let sig_share_raw = sig_share_raw_typed.into_vec();

    Ok(ThresholdSchnorrSigShare { sig_share_raw })
}

pub fn verify_sig_share(
    signer: NodeId,
    inputs: &ThresholdSchnorrSigInputs,
    share: &ThresholdSchnorrSigShare,
) -> Result<(), ThresholdSchnorrVerifySigShareError> {
    let presig = IDkgTranscriptInternal::try_from(inputs.presig_transcript().blinder_unmasked())
        .map_err(|e| {
            ThresholdSchnorrVerifySigShareError::SerializationError(format!(
                "failed to deserialize presignature transcript: {}",
                e.0
            ))
        })?;
    let key = IDkgTranscriptInternal::try_from(inputs.key_transcript()).map_err(|e| {
        ThresholdSchnorrVerifySigShareError::SerializationError(format!(
            "failed to deserialize key transcript: {}",
            e.0
        ))
    })?;

    let signer_index = inputs.key_transcript().index_for_signer_id(signer).ok_or(
        ThresholdSchnorrVerifySigShareError::InvalidArgumentMissingSignerInTranscript {
            signer_id: signer,
        },
    )?;

    match inputs.algorithm_id() {
        AlgorithmId::ThresholdSchnorrBip340 => {
            let internal_share =
                ThresholdBip340SignatureShareInternal::deserialize(&share.sig_share_raw).map_err(
                    |e| ThresholdSchnorrVerifySigShareError::SerializationError(format!("{e:?}")),
                )?;

            verify_bip340_signature_share(
                &internal_share,
                &DerivationPath::from(ExtendedDerivationPath {
                    caller: *inputs.caller(),
                    derivation_path: inputs.derivation_path().to_vec(),
                }),
                inputs.message(),
                inputs.taproot_tree_root(),
                Randomness::from(*inputs.nonce()),
                signer_index,
                &key,
                &presig,
            )
            .map_err(|e| {
                type F = ThresholdBip340VerifySigShareInternalError;
                type T = ThresholdSchnorrVerifySigShareError;
                match e {
                    F::InvalidArguments(s) => T::InvalidArguments(s),
                    F::InternalError(internal_error) => T::InternalError(internal_error),
                    F::InconsistentCommitments => T::InternalError(format!("{e:?}")),
                    F::InvalidSignatureShare => T::InvalidSignatureShare,
                }
            })
        }
        AlgorithmId::ThresholdEd25519 => {
            let internal_share = ThresholdEd25519SignatureShareInternal::deserialize(
                &share.sig_share_raw,
            )
            .map_err(|e| {
                ThresholdSchnorrVerifySigShareError::SerializationError(format!(
                    "failed to deserialize internal ed25519 signature share: {}",
                    e.0
                ))
            })?;

            verify_ed25519_signature_share(
                &internal_share,
                &DerivationPath::from(ExtendedDerivationPath {
                    caller: *inputs.caller(),
                    derivation_path: inputs.derivation_path().to_vec(),
                }),
                inputs.message(),
                Randomness::from(*inputs.nonce()),
                signer_index,
                &key,
                &presig,
            )
            .map_err(|e| {
                type F = ThresholdEd25519VerifySigShareInternalError;
                type T = ThresholdSchnorrVerifySigShareError;
                match e {
                    F::InvalidArguments(s) => T::InvalidArguments(s),
                    F::InternalError(internal_error) => T::InternalError(internal_error),
                    F::InconsistentCommitments => T::InternalError(format!("{e:?}")),
                    F::InvalidSignatureShare => T::InvalidSignatureShare,
                }
            })
        }
        algorithm_id => Err(ThresholdSchnorrVerifySigShareError::InvalidArguments(
            format!("invalid algorithm id for threshold Schnorr signature: {algorithm_id}"),
        )),
    }
}

pub fn combine_sig_shares(
    inputs: &ThresholdSchnorrSigInputs,
    shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
) -> Result<ThresholdSchnorrCombinedSignature, ThresholdSchnorrCombineSigSharesError> {
    ensure_sufficient_sig_shares_collected(inputs, shares)?;

    let presig = IDkgTranscriptInternal::try_from(inputs.presig_transcript().blinder_unmasked())
        .map_err(|e| {
            ThresholdSchnorrCombineSigSharesError::SerializationError(format!(
                "failed to deserialize presignature transcript : {}",
                e.0
            ))
        })?;
    let key = IDkgTranscriptInternal::try_from(inputs.key_transcript()).map_err(|e| {
        ThresholdSchnorrCombineSigSharesError::SerializationError(format!(
            "failed to deserialize key transcript: {}",
            e.0
        ))
    })?;

    match inputs.algorithm_id() {
        AlgorithmId::ThresholdSchnorrBip340 => {
            let internal_shares =
                internal_bip340_sig_shares_by_index_from_sig_shares(shares, inputs)?;

            let internal_combined_sig = combine_bip340_signature_shares(
                &DerivationPath::from(ExtendedDerivationPath {
                    caller: *inputs.caller(),
                    derivation_path: inputs.derivation_path().to_vec(),
                }),
                inputs.message(),
                inputs.taproot_tree_root(),
                Randomness::from(*inputs.nonce()),
                &key,
                &presig,
                inputs.reconstruction_threshold(),
                &internal_shares,
            )
            .map_err(|e| {
                type F = ThresholdBip340CombineSigSharesInternalError;
                type T = ThresholdSchnorrCombineSigSharesError;

                match e {
                    F::UnsupportedAlgorithm => {
                        T::InvalidArguments("unsupported algorithm".to_string())
                    }
                    F::InconsistentCommitments => {
                        T::InvalidArguments("inconsistent commitments".to_string())
                    }
                    F::InsufficientShares => T::InvalidArguments("insufficient shares".to_string()),
                    F::InternalError(s) => T::InternalError(s),
                }
            })?;

            Ok(ThresholdSchnorrCombinedSignature {
                signature: internal_combined_sig.serialize().map_err(|e| {
                    ThresholdSchnorrCombineSigSharesError::SerializationError(format!(
                        "failed to serialize combined BIP340 signature: {}",
                        e.0
                    ))
                })?,
            })
        }
        AlgorithmId::ThresholdEd25519 => {
            let internal_shares =
                internal_ed25519_sig_shares_by_index_from_sig_shares(shares, inputs)?;

            let internal_combined_sig = combine_ed25519_signature_shares(
                &DerivationPath::from(ExtendedDerivationPath {
                    caller: *inputs.caller(),
                    derivation_path: inputs.derivation_path().to_vec(),
                }),
                inputs.message(),
                Randomness::from(*inputs.nonce()),
                &key,
                &presig,
                inputs.reconstruction_threshold(),
                &internal_shares,
            )
            .map_err(|e| {
                type F = ThresholdEd25519CombineSigSharesInternalError;
                type T = ThresholdSchnorrCombineSigSharesError;

                match e {
                    F::UnsupportedAlgorithm => {
                        T::InvalidArguments("unsupported algorithm".to_string())
                    }
                    F::InconsistentCommitments => {
                        T::InvalidArguments("inconsistent commitments".to_string())
                    }
                    F::InsufficientShares => T::InvalidArguments("insufficient shares".to_string()),
                    F::InternalError(s) => T::InternalError(s),
                }
            })?;

            Ok(ThresholdSchnorrCombinedSignature {
                signature: internal_combined_sig.serialize(),
            })
        }
        algorithm_id => Err(ThresholdSchnorrCombineSigSharesError::InternalError(
            format!("invalid algorithm id for threshold Schnorr signature: {algorithm_id}"),
        )),
    }
}

fn ensure_sufficient_sig_shares_collected(
    inputs: &ThresholdSchnorrSigInputs,
    shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
) -> Result<(), ThresholdSchnorrCombineSigSharesError> {
    if shares.len() < inputs.reconstruction_threshold().get() as usize {
        Err(
            ThresholdSchnorrCombineSigSharesError::UnsatisfiedReconstructionThreshold {
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
fn internal_bip340_sig_shares_by_index_from_sig_shares(
    shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
    inputs: &ThresholdSchnorrSigInputs,
) -> Result<
    BTreeMap<NodeIndex, ThresholdBip340SignatureShareInternal>,
    ThresholdSchnorrCombineSigSharesError,
> {
    shares
        .iter()
        .map(|(&id, share)| {
            let index = inputs
                .index_for_signer_id(id)
                .ok_or(ThresholdSchnorrCombineSigSharesError::SignerNotAllowed { node_id: id })?;
            let internal_share =
                ThresholdBip340SignatureShareInternal::deserialize(&share.sig_share_raw).map_err(
                    |e| ThresholdSchnorrCombineSigSharesError::SerializationError(format!("{e:?}")),
                )?;
            Ok((index, internal_share))
        })
        .collect()
}

/// Deserialize each raw signature share to the internal format,
/// and map them by signer index (rather than signer Id).
fn internal_ed25519_sig_shares_by_index_from_sig_shares(
    shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
    inputs: &ThresholdSchnorrSigInputs,
) -> Result<
    BTreeMap<NodeIndex, ThresholdEd25519SignatureShareInternal>,
    ThresholdSchnorrCombineSigSharesError,
> {
    shares
        .iter()
        .map(|(&id, share)| {
            let index = inputs
                .index_for_signer_id(id)
                .ok_or(ThresholdSchnorrCombineSigSharesError::SignerNotAllowed { node_id: id })?;
            let internal_share = ThresholdEd25519SignatureShareInternal::deserialize(
                &share.sig_share_raw,
            )
            .map_err(|e| {
                ThresholdSchnorrCombineSigSharesError::SerializationError(format!(
                    "failed to deserialize internal ed25519 share: {}",
                    e.0
                ))
            })?;
            Ok((index, internal_share))
        })
        .collect()
}

pub fn verify_combined_sig(
    inputs: &ThresholdSchnorrSigInputs,
    signature: &ThresholdSchnorrCombinedSignature,
) -> Result<(), ThresholdSchnorrVerifyCombinedSigError> {
    let blinder_unmasked = IDkgTranscriptInternal::try_from(
        inputs.presig_transcript().blinder_unmasked(),
    )
    .map_err(|e| {
        ThresholdSchnorrVerifyCombinedSigError::SerializationError(format!(
            "failed to deserialize presignature transcript: {}",
            e.0
        ))
    })?;
    let key = IDkgTranscriptInternal::try_from(inputs.key_transcript()).map_err(|e| {
        ThresholdSchnorrVerifyCombinedSigError::SerializationError(format!(
            "failed to deserialize key transcript : {}",
            e.0
        ))
    })?;

    match inputs.algorithm_id() {
        AlgorithmId::ThresholdSchnorrBip340 => {
            let signature =
                ThresholdBip340CombinedSignatureInternal::deserialize(&signature.signature)
                    .map_err(|e| {
                        ThresholdSchnorrVerifyCombinedSigError::SerializationError(format!(
                            "failed to deserialize combined BIP340 signature: {}",
                            e.0
                        ))
                    })?;
            verify_threshold_bip340_signature(
                &signature,
                &DerivationPath::from(ExtendedDerivationPath {
                    caller: *inputs.caller(),
                    derivation_path: inputs.derivation_path().to_vec(),
                }),
                inputs.message(),
                inputs.taproot_tree_root(),
                Randomness::from(*inputs.nonce()),
                &blinder_unmasked,
                &key,
            )
            .map_err(|e| {
                type F = ThresholdBip340VerifySignatureInternalError;
                type T = ThresholdSchnorrVerifyCombinedSigError;
                match e {
                    F::UnexpectedCommitmentType => T::InvalidArguments(format!("{e:?}")),
                    F::InternalError(s) => T::InternalError(s),
                    F::InvalidSignature => T::InvalidSignature,
                }
            })
        }
        AlgorithmId::ThresholdEd25519 => {
            let signature =
                ThresholdEd25519CombinedSignatureInternal::deserialize(&signature.signature)
                    .map_err(|e| {
                        ThresholdSchnorrVerifyCombinedSigError::SerializationError(format!(
                            "failed to deserialize combined ed25519 signature: {}",
                            e.0
                        ))
                    })?;
            verify_threshold_ed25519_signature(
                &signature,
                &DerivationPath::from(ExtendedDerivationPath {
                    caller: *inputs.caller(),
                    derivation_path: inputs.derivation_path().to_vec(),
                }),
                inputs.message(),
                Randomness::from(*inputs.nonce()),
                &blinder_unmasked,
                &key,
            )
            .map_err(|e| {
                type F = ThresholdEd25519VerifySignatureInternalError;
                type T = ThresholdSchnorrVerifyCombinedSigError;
                match e {
                    F::UnexpectedCommitmentType => T::InvalidArguments(format!("{e:?}")),
                    F::InternalError(s) => T::InternalError(s),
                    F::InvalidSignature => T::InvalidSignature,
                }
            })
        }
        algorithm_id => Err(ThresholdSchnorrVerifyCombinedSigError::InvalidArguments(
            format!("invalid algorithm id for threshold Schnorr signature: {algorithm_id}"),
        )),
    }
}

fn ensure_self_was_receiver(
    self_node_id: &NodeId,
    receivers: &IDkgReceivers,
) -> Result<(), ThresholdSchnorrCreateSigShareError> {
    if receivers.contains(*self_node_id) {
        Ok(())
    } else {
        Err(ThresholdSchnorrCreateSigShareError::NotAReceiver)
    }
}
