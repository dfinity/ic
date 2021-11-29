//! Defines canister threshold signature types.
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgTranscript, IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
};
use crate::crypto::AlgorithmId;
use crate::Randomness;
use ic_base_types::PrincipalId;
use serde::{Deserialize, Serialize};

pub mod error;
pub mod idkg;

/// A threshold ECDSA public key.
///
/// The public key itself is stored as raw bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaPublicKey {
    pub algorithm_id: AlgorithmId,
    pub public_key: Vec<u8>,
}

/// A combined threshold ECDSA signature.
///
/// The signature itself is stored as raw bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdEcdsaCombinedSignature {
    pub signature: Vec<u8>,
}

/// Quadruple of signature-specific IDKG transcripts required to generate a
/// canister threshold signature (not including the secret key transcript).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PreSignatureQuadruple {
    kappa_unmasked: IDkgTranscript,
    lambda_masked: IDkgTranscript,
    kappa_times_lambda: IDkgTranscript,
    key_times_lambda: IDkgTranscript,
}

impl PreSignatureQuadruple {
    /// Constructs a `PreSignatureQuadruple` from the provided transcripts.
    ///
    /// # Arguments:
    /// - kappa_unmasked: An unmasked resharing of the masked random kappa
    /// - lambda_masked: A masked random sharing of lambda
    /// - kappa_times_lambda: The kappa_unmasked multiplied by lambda_masked
    ///   - Note that the order of the factors matters
    /// - key_times_lambda: The (unmasked, reshared) secret key multiplied by
    ///   lambda_masked
    ///   - Note that the order of the factors matters
    ///
    /// This checks that:
    /// - kappa is an Unmasked, from a Reshare of a Masked
    /// - lambda is a Masked, of type Random
    /// - kappa_times_lambda is a Masked, from a Multiplication of an Unmasked
    ///   times a Masked
    /// - key_times_lambda is a Masked, from a Multiplication of an Unmasked
    ///   times a Masked
    /// - The first factor of kappa_times_lambda matches kappa_unmasked
    /// - The second factors in both kappa_times_lambda and key_times_lambda
    ///   match lambda_masked
    pub fn new(
        kappa_unmasked: IDkgTranscript,
        lambda_masked: IDkgTranscript,
        kappa_times_lambda: IDkgTranscript,
        key_times_lambda: IDkgTranscript,
    ) -> Result<Self, error::PresignatureQuadrupleCreationError> {
        match (
            &kappa_unmasked.transcript_type,
            &lambda_masked.transcript_type,
            &kappa_times_lambda.transcript_type,
            &key_times_lambda.transcript_type,
        ) {
            (
                IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(_)),
                IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
                IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                    kappa_id_from_lambda_mult,
                    lambda_id_from_kappa_mult,
                )),
                IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                    _,
                    lambda_id_from_key_mult,
                )),
            ) if *kappa_id_from_lambda_mult == kappa_unmasked.transcript_id
                && *lambda_id_from_kappa_mult == lambda_masked.transcript_id
                && *lambda_id_from_key_mult == lambda_masked.transcript_id =>
            {
                Ok(Self {
                    kappa_unmasked,
                    lambda_masked,
                    kappa_times_lambda,
                    key_times_lambda,
                })
            }
            _ => Err(error::PresignatureQuadrupleCreationError::WrongTypes),
        }
    }
}

/// All inputs required to generate a canister threshold signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdEcdsaSigInputs {
    pub caller: PrincipalId,
    pub derivation_path: Vec<u32>,
    pub hashed_message: Vec<u8>,
    pub nonce: Randomness,
    pub presig_quadruple: PreSignatureQuadruple,
    pub key_transcript: IDkgTranscript,
}

impl ThresholdEcdsaSigInputs {
    /// Construct the inputs to Ecdsa signature generation.
    ///
    /// This checks that the first factor of presig_quadruple.key_times_lambda
    /// matches key_transcript.
    /// (We assume the presig_quadruple has already been checked during
    /// creation).
    pub fn new(
        caller: PrincipalId,
        derivation_path: &[u32],
        hashed_message: &[u8],
        nonce: Randomness,
        presig_quadruple: PreSignatureQuadruple,
        key_transcript: IDkgTranscript,
    ) -> Result<Self, error::ThresholdEcdsaSigInputsCreationError> {
        match &presig_quadruple.key_times_lambda.transcript_type {
            IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                key_id_from_mult,
                _,
            )) if *key_id_from_mult == key_transcript.transcript_id => Ok(Self {
                caller,
                derivation_path: derivation_path.to_vec(),
                hashed_message: hashed_message.to_vec(),
                nonce,
                presig_quadruple,
                key_transcript,
            }),
            _ => Err(error::ThresholdEcdsaSigInputsCreationError::NonmatchingTranscriptIds),
        }
    }
}

/// A single threshold ECDSA signature share.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdEcdsaSigShare {
    pub sig_share_raw: Vec<u8>,
}
