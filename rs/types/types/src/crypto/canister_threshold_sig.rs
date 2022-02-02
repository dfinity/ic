//! Defines canister threshold signature types.
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin,
};
use crate::crypto::AlgorithmId;
use crate::{NumberOfNodes, Randomness};
use ic_base_types::PrincipalId;
use serde::{Deserialize, Serialize};

pub mod error;
pub mod idkg;

/// A threshold ECDSA public key.
///
/// The public key itself is stored as raw bytes.
///
/// The chain key is included for BIP32-style key derivation
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EcdsaPublicKey {
    pub algorithm_id: AlgorithmId,
    pub public_key: Vec<u8>,
    pub chain_key: Vec<u8>,
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
    /// - All transcripts use the same AlgorithmId
    /// - All transcripts have the same receiver set (same receiver nodes, and
    ///   each node at the same index)
    pub fn new(
        kappa_unmasked: IDkgTranscript,
        lambda_masked: IDkgTranscript,
        kappa_times_lambda: IDkgTranscript,
        key_times_lambda: IDkgTranscript,
    ) -> Result<Self, error::PresignatureQuadrupleCreationError> {
        Self::check_algorithm_ids(
            &kappa_unmasked,
            &lambda_masked,
            &kappa_times_lambda,
            &key_times_lambda,
        )?;
        Self::check_receivers_are_equal(
            &kappa_unmasked,
            &lambda_masked,
            &kappa_times_lambda,
            &key_times_lambda,
        )?;
        Self::check_consistency_of_transcripts(
            &kappa_unmasked,
            &lambda_masked,
            &kappa_times_lambda,
            &key_times_lambda,
        )?;

        Ok(Self {
            kappa_unmasked,
            lambda_masked,
            kappa_times_lambda,
            key_times_lambda,
        })
    }

    pub fn kappa_unmasked(&self) -> &IDkgTranscript {
        &self.kappa_unmasked
    }

    pub fn lambda_masked(&self) -> &IDkgTranscript {
        &self.lambda_masked
    }

    pub fn kappa_times_lambda(&self) -> &IDkgTranscript {
        &self.kappa_times_lambda
    }

    pub fn key_times_lambda(&self) -> &IDkgTranscript {
        &self.key_times_lambda
    }

    fn check_algorithm_ids(
        kappa_unmasked: &IDkgTranscript,
        lambda_masked: &IDkgTranscript,
        kappa_times_lambda: &IDkgTranscript,
        key_times_lambda: &IDkgTranscript,
    ) -> Result<(), error::PresignatureQuadrupleCreationError> {
        if kappa_unmasked.algorithm_id == lambda_masked.algorithm_id
            && lambda_masked.algorithm_id == kappa_times_lambda.algorithm_id
            && kappa_times_lambda.algorithm_id == key_times_lambda.algorithm_id
        {
            Ok(())
        } else {
            Err(error::PresignatureQuadrupleCreationError::InconsistentAlgorithms)
        }
    }

    fn check_receivers_are_equal(
        kappa_unmasked: &IDkgTranscript,
        lambda_masked: &IDkgTranscript,
        kappa_times_lambda: &IDkgTranscript,
        key_times_lambda: &IDkgTranscript,
    ) -> Result<(), error::PresignatureQuadrupleCreationError> {
        if kappa_unmasked.receivers == lambda_masked.receivers
            && lambda_masked.receivers == kappa_times_lambda.receivers
            && kappa_times_lambda.receivers == key_times_lambda.receivers
        {
            Ok(())
        } else {
            Err(error::PresignatureQuadrupleCreationError::InconsistentReceivers)
        }
    }

    fn check_consistency_of_transcripts(
        kappa_unmasked: &IDkgTranscript,
        lambda_masked: &IDkgTranscript,
        kappa_times_lambda: &IDkgTranscript,
        key_times_lambda: &IDkgTranscript,
    ) -> Result<(), error::PresignatureQuadrupleCreationError> {
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
                Ok(())
            }
            _ => Err(error::PresignatureQuadrupleCreationError::WrongTypes),
        }
    }
}

/// Metadata used to derive a specific ECDSA keypair.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtendedDerivationPath {
    pub caller: PrincipalId,
    pub derivation_path: Vec<Vec<u8>>,
}

/// All inputs required to generate a canister threshold signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdEcdsaSigInputs {
    derivation_path: ExtendedDerivationPath,
    hashed_message: Vec<u8>,
    nonce: Randomness,
    presig_quadruple: PreSignatureQuadruple,
    key_transcript: IDkgTranscript,
}

impl ThresholdEcdsaSigInputs {
    /// Construct the inputs to Ecdsa signature generation.
    ///
    /// This checks that:
    /// - The first factor of presig_quadruple.key_times_lambda matches
    ///   key_transcript. (We assume the presig_quadruple has already been
    ///   checked during creation).
    /// - All transcripts use the same AlgorithmId
    /// - All transcripts have the same receiver set (same receiver nodes, and
    ///   each node at the same index)
    pub fn new(
        derivation_path: &ExtendedDerivationPath,
        hashed_message: &[u8],
        nonce: Randomness,
        presig_quadruple: PreSignatureQuadruple,
        key_transcript: IDkgTranscript,
    ) -> Result<Self, error::ThresholdEcdsaSigInputsCreationError> {
        Self::check_algorithm_ids(&presig_quadruple, &key_transcript)?;
        Self::check_receivers_are_equal(&presig_quadruple, &key_transcript)?;
        Self::check_consistency_of_transcripts(&presig_quadruple, &key_transcript)?;

        Ok(Self {
            derivation_path: derivation_path.clone(),
            hashed_message: hashed_message.to_vec(),
            nonce,
            presig_quadruple,
            key_transcript,
        })
    }

    pub fn derivation_path(&self) -> &ExtendedDerivationPath {
        &self.derivation_path
    }

    pub fn hashed_message(&self) -> &[u8] {
        &self.hashed_message
    }

    pub fn nonce(&self) -> &Randomness {
        &self.nonce
    }

    pub fn presig_quadruple(&self) -> &PreSignatureQuadruple {
        &self.presig_quadruple
    }

    pub fn key_transcript(&self) -> &IDkgTranscript {
        &self.key_transcript
    }

    /// Number of contributions needed to reconstruct a sharing.
    pub fn reconstruction_threshold(&self) -> NumberOfNodes {
        // We already checked that all receiver sets are equal
        self.key_transcript.reconstruction_threshold()
    }

    pub fn receivers(&self) -> &IDkgReceivers {
        // We already checked that all receiver sets are equal
        &self.key_transcript.receivers
    }

    pub fn algorithm_id(&self) -> AlgorithmId {
        // We already checked that all transcripts have the same alg_id
        self.key_transcript.algorithm_id
    }

    fn check_algorithm_ids(
        presig_quadruple: &PreSignatureQuadruple,
        key_transcript: &IDkgTranscript,
    ) -> Result<(), error::ThresholdEcdsaSigInputsCreationError> {
        // The quadruple was already checked to have a consistent AlgId
        if presig_quadruple.kappa_unmasked().algorithm_id == key_transcript.algorithm_id {
            Ok(())
        } else {
            Err(error::ThresholdEcdsaSigInputsCreationError::InconsistentAlgorithms)
        }
    }

    fn check_receivers_are_equal(
        presig_quadruple: &PreSignatureQuadruple,
        key_transcript: &IDkgTranscript,
    ) -> Result<(), error::ThresholdEcdsaSigInputsCreationError> {
        // The quadruple was already checked to have a consistent receiver set
        if presig_quadruple.kappa_unmasked().receivers == key_transcript.receivers {
            Ok(())
        } else {
            Err(error::ThresholdEcdsaSigInputsCreationError::InconsistentReceivers)
        }
    }

    fn check_consistency_of_transcripts(
        presig_quadruple: &PreSignatureQuadruple,
        key_transcript: &IDkgTranscript,
    ) -> Result<(), error::ThresholdEcdsaSigInputsCreationError> {
        match &presig_quadruple.key_times_lambda.transcript_type {
            IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                key_id_from_mult,
                _,
            )) if *key_id_from_mult == key_transcript.transcript_id => Ok(()),
            _ => Err(error::ThresholdEcdsaSigInputsCreationError::NonmatchingTranscriptIds),
        }
    }
}

/// A single threshold ECDSA signature share.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdEcdsaSigShare {
    pub sig_share_raw: Vec<u8>,
}
