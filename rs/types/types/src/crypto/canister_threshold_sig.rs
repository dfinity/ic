//! Defines canister threshold signature types.
use crate::NumberOfNodes;
use crate::crypto::AlgorithmId;
use crate::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin,
};
use crate::crypto::impl_display_using_debug;
use core::fmt;
use ic_base_types::NodeId;
use ic_base_types::PrincipalId;
use ic_crypto_internal_types::NodeIndex;
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;

pub mod error;
pub mod idkg;

#[cfg(test)]
mod tests;

/// A public key for canister threshold signatures.
///
/// The public key itself is stored as raw bytes.
///
/// The chain key is included for BIP32-style key derivation.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct PublicKey {
    pub algorithm_id: AlgorithmId,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub chain_key: Vec<u8>,
}

/// A master public key for canister threshold signatures.
///
/// The public key itself is stored as raw bytes.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct MasterPublicKey {
    pub algorithm_id: AlgorithmId,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

/// A combined threshold ECDSA signature.
///
/// The signature itself is stored as raw bytes.
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct ThresholdEcdsaCombinedSignature {
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl_display_using_debug!(ThresholdEcdsaCombinedSignature);

impl fmt::Debug for ThresholdEcdsaCombinedSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ThresholdEcdsaCombinedSignature {{ signature: 0x{} }}",
            hex::encode(&self.signature)
        )
    }
}

/// Quadruple of IDKG transcripts consumed by a canister-requested threshold ECDSA signature.
/// Each quadruple MUST be used *at most once* for a signature. Otherwise, the private key may be
/// leaked!
///
/// Each signature, in addition to the transcript for the sharing of the private key, requires the
/// following 4 transcripts that may be pre-computed (they are independent of the message to be
/// signed):
/// * an unmasked transcript for sharing of a random value `kappa`
/// * a masked transcript for sharing of another random value `lambda`
/// * a masked transcript for sharing the value `kappa * lambda`
/// * a masked transcript for sharing the value `private_key * lambda`
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct EcdsaPreSignatureQuadruple {
    kappa_unmasked: IDkgTranscript,
    lambda_masked: IDkgTranscript,
    kappa_times_lambda: IDkgTranscript,
    key_times_lambda: IDkgTranscript,
}

impl_display_using_debug!(EcdsaPreSignatureQuadruple);

impl fmt::Debug for EcdsaPreSignatureQuadruple {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PreSignatureQuadruple {{ ")?;
        write!(f, "kappa_unmasked: {:?}", self.kappa_unmasked.transcript_id)?;
        write!(f, ", lambda_masked: {:?}", self.lambda_masked.transcript_id)?;
        write!(
            f,
            ", kappa_times_lambda: {:?}",
            self.kappa_times_lambda.transcript_id
        )?;
        write!(
            f,
            ", key_times_lambda: {:?}",
            self.key_times_lambda.transcript_id
        )?;
        write!(f, " }}")?;
        Ok(())
    }
}

impl EcdsaPreSignatureQuadruple {
    /// Creates an `EcdsaPreSignatureQuadruple` which is a collection of four transcripts
    /// that can be used in the threshold ECDSA protocol.
    ///
    /// An `EcdsaPreSignatureQuadruple` can only be created if the following invariants hold:
    /// * All transcripts use the same algorithm ID (error: `InconsistentAlgorithms`)
    /// * All transcripts have the same receiver set (error: `InconsistentReceivers`)
    /// * The `kappa_unmasked` transcript is of type `Unmasked` with origin
    ///   `IDkgUnmaskedTranscriptOrigin::ReshareMasked` or
    ///   `IDkgUnmaskedTranscriptOrigin::Random` (error: `InvalidTranscriptOrigin`)
    /// * The `lambda_masked` transcript is of type `Masked` with origin
    ///   `Random` (error: `InvalidTranscriptOrigin`)
    /// * The `kappa_times_lambda` transcript is of type `Masked` with origin
    ///   `UnmaskedTimesMasked(left,right)`, where `left` and `right` are the
    ///   transcript IDs of `kappa_unmasked` and `lambda_masked`, respectively (error: `InvalidTranscriptOrigin`)
    /// * The `key_times_lambda` transcript is of type `Masked` with origin
    ///   `UnmaskedTimesMasked(left,right)`, where `right` is the
    ///   transcript ID of `lambda_masked` (error: `InvalidTranscriptOrigin`)
    pub fn new(
        kappa_unmasked: IDkgTranscript,
        lambda_masked: IDkgTranscript,
        kappa_times_lambda: IDkgTranscript,
        key_times_lambda: IDkgTranscript,
    ) -> Result<Self, error::EcdsaPresignatureQuadrupleCreationError> {
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
    ) -> Result<(), error::EcdsaPresignatureQuadrupleCreationError> {
        if kappa_unmasked.algorithm_id == lambda_masked.algorithm_id
            && lambda_masked.algorithm_id == kappa_times_lambda.algorithm_id
            && kappa_times_lambda.algorithm_id == key_times_lambda.algorithm_id
        {
            Ok(())
        } else {
            Err(error::EcdsaPresignatureQuadrupleCreationError::InconsistentAlgorithmIds)
        }
    }

    fn check_receivers_are_equal(
        kappa_unmasked: &IDkgTranscript,
        lambda_masked: &IDkgTranscript,
        kappa_times_lambda: &IDkgTranscript,
        key_times_lambda: &IDkgTranscript,
    ) -> Result<(), error::EcdsaPresignatureQuadrupleCreationError> {
        if kappa_unmasked.receivers == lambda_masked.receivers
            && lambda_masked.receivers == kappa_times_lambda.receivers
            && kappa_times_lambda.receivers == key_times_lambda.receivers
        {
            Ok(())
        } else {
            Err(error::EcdsaPresignatureQuadrupleCreationError::InconsistentReceivers)
        }
    }

    fn check_consistency_of_transcripts(
        kappa_unmasked: &IDkgTranscript,
        lambda_masked: &IDkgTranscript,
        kappa_times_lambda: &IDkgTranscript,
        key_times_lambda: &IDkgTranscript,
    ) -> Result<(), error::EcdsaPresignatureQuadrupleCreationError> {
        Self::check_kappa_unmasked_origin(kappa_unmasked)?;
        Self::check_lambda_masked_origin(lambda_masked)?;
        Self::check_kappa_times_lambda_origin(kappa_unmasked, lambda_masked, kappa_times_lambda)?;
        Self::check_key_times_lambda_origin(lambda_masked, key_times_lambda)?;
        Ok(())
    }

    fn check_kappa_unmasked_origin(
        kappa_unmasked: &IDkgTranscript,
    ) -> Result<(), error::EcdsaPresignatureQuadrupleCreationError> {
        match &kappa_unmasked.transcript_type {
            IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(_))
            | IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random) => Ok(()),
            _ => Err(
                error::EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(format!(
                    "`kappa_unmasked` transcript expected to have type `Unmasked` with `ReshareMasked` or `Random` origin, but found transcript of type {:?}",
                    kappa_unmasked.transcript_type
                )),
            ),
        }
    }

    fn check_lambda_masked_origin(
        lambda_masked: &IDkgTranscript,
    ) -> Result<(), error::EcdsaPresignatureQuadrupleCreationError> {
        match &lambda_masked.transcript_type {
            IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random) => Ok(()),
            _ => Err(
                error::EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(format!(
                    "`lambda_masked` transcript expected to have type `Masked` with `Random` origin, but found transcript of type {:?}",
                    lambda_masked.transcript_type
                )),
            ),
        }
    }

    fn check_kappa_times_lambda_origin(
        kappa_unmasked: &IDkgTranscript,
        lambda_masked: &IDkgTranscript,
        kappa_times_lambda: &IDkgTranscript,
    ) -> Result<(), error::EcdsaPresignatureQuadrupleCreationError> {
        match &kappa_times_lambda.transcript_type {
            IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                id_l,
                id_r,
            )) if *id_l == kappa_unmasked.transcript_id && *id_r == lambda_masked.transcript_id => {
                Ok(())
            }
            _ => Err(
                error::EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(format!(
                    "`kappa_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked({:?},{:?})`, but found transcript of type {:?}",
                    kappa_unmasked.transcript_id,
                    lambda_masked.transcript_id,
                    kappa_times_lambda.transcript_type
                )),
            ),
        }
    }

    fn check_key_times_lambda_origin(
        lambda_masked: &IDkgTranscript,
        key_times_lambda: &IDkgTranscript,
    ) -> Result<(), error::EcdsaPresignatureQuadrupleCreationError> {
        match &key_times_lambda.transcript_type {
            IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                _,
                id_r,
            )) if *id_r == lambda_masked.transcript_id => Ok(()),
            _ => Err(
                error::EcdsaPresignatureQuadrupleCreationError::InvalidTranscriptOrigin(format!(
                    "`key_times_lambda` transcript expected to have type `Masked` with origin of type `UnmaskedTimesMasked(_,{:?})`, but found transcript of type {:?}",
                    lambda_masked.transcript_id, key_times_lambda.transcript_type
                )),
            ),
        }
    }
}

/// All inputs required to generate a canister threshold signature.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ThresholdEcdsaSigInputs<'a> {
    caller: &'a PrincipalId,
    derivation_path: &'a [Vec<u8>],
    hashed_message: &'a [u8],
    nonce: &'a [u8; 32],
    presig_quadruple: &'a EcdsaPreSignatureQuadruple,
    key_transcript: &'a IDkgTranscript,
}

// The byte length of an hashed message for ECDSA signatures over the curve secp256k1.
pub const ECDSA_SECP256K1_HASH_BYTE_LENGTH: usize = 32;

// The byte length of an hashed message for ECDSA signatures over the curve secp256r1.
pub const ECDSA_SECP256R1_HASH_BYTE_LENGTH: usize = 32;

impl_display_using_debug!(ThresholdEcdsaSigInputs<'_>);

impl fmt::Debug for ThresholdEcdsaSigInputs<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ThresholdEcdsaSigInputs {{ ")?;
        write!(f, "derivation_path: {:?}", self.derivation_path)?;
        write!(
            f,
            ", hashed_message: 0x{}",
            hex::encode(self.hashed_message)
        )?;
        write!(f, ", nonce: 0x{}", hex::encode(self.nonce.as_ref()))?;
        write!(f, ", presig_quadruple: {}", self.presig_quadruple)?;
        write!(f, ", key_transcript: {}", self.key_transcript.transcript_id)?;
        write!(f, " }}")?;
        Ok(())
    }
}

impl AsRef<IDkgReceivers> for ThresholdEcdsaSigInputs<'_> {
    fn as_ref(&self) -> &IDkgReceivers {
        self.receivers()
    }
}

impl<'a> ThresholdEcdsaSigInputs<'a> {
    /// Creates the inputs to the threshold ECDSA signing protocol.
    ///
    /// A `ThresholdEcdsaSigInputs` can only be created if the following invariants hold:
    /// * The algorithm ID of the `key_transcript` is the same as the algorithm ID
    ///   of the transcripts in the `presig_quadruple` (error: `InconsistentAlgorithms`)
    /// * The algorithm ID of the `key_transcript` is supported for the creation
    ///   of threshold ECDSA signatures (error: `UnsupportedAlgorithm`)
    /// * The length of the `hashed_message` is correct for the algorithm ID
    ///   of the `key_transcript` (error: `InvalidHashLength`).
    /// * All transcripts have the same receiver set (error: `InconsistentReceivers`)
    /// * The `key_times_lambda` transcript of the `presig_quadruple` is the product
    ///   of the `key_transcript` and another masked transcript (error: `InvalidQuadrupleOrigin`)
    pub fn new(
        caller: &'a PrincipalId,
        derivation_path: &'a [Vec<u8>],
        hashed_message: &'a [u8],
        nonce: &'a [u8; 32],
        presig_quadruple: &'a EcdsaPreSignatureQuadruple,
        key_transcript: &'a IDkgTranscript,
    ) -> Result<Self, error::ThresholdEcdsaSigInputsCreationError> {
        Self::check_algorithm_ids(presig_quadruple, key_transcript)?;
        Self::check_hash_length(hashed_message, key_transcript.algorithm_id)?;
        Self::check_receivers_are_equal(presig_quadruple, key_transcript)?;
        Self::check_quadruple_origin(presig_quadruple, key_transcript)?;

        Ok(Self {
            caller,
            derivation_path,
            hashed_message,
            nonce,
            presig_quadruple,
            key_transcript,
        })
    }

    pub fn caller(&self) -> &PrincipalId {
        self.caller
    }

    pub fn derivation_path(&self) -> &[Vec<u8>] {
        self.derivation_path
    }

    pub fn hashed_message(&self) -> &[u8] {
        self.hashed_message
    }

    pub fn nonce(&self) -> &[u8; 32] {
        self.nonce
    }

    pub fn presig_quadruple(&self) -> &EcdsaPreSignatureQuadruple {
        self.presig_quadruple
    }

    pub fn key_transcript(&self) -> &IDkgTranscript {
        self.key_transcript
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

    pub fn index_for_signer_id(&self, node_id: NodeId) -> Option<NodeIndex> {
        self.key_transcript().index_for_signer_id(node_id)
    }

    fn check_algorithm_ids(
        presig_quadruple: &EcdsaPreSignatureQuadruple,
        key_transcript: &IDkgTranscript,
    ) -> Result<(), error::ThresholdEcdsaSigInputsCreationError> {
        // The quadruple was already checked to have a consistent algorithm ID
        if presig_quadruple.kappa_unmasked().algorithm_id == key_transcript.algorithm_id {
            Ok(())
        } else {
            Err(error::ThresholdEcdsaSigInputsCreationError::InconsistentAlgorithmIds)
        }
    }

    fn check_hash_length(
        hashed_message: &[u8],
        algorithm_id: AlgorithmId,
    ) -> Result<(), error::ThresholdEcdsaSigInputsCreationError> {
        match algorithm_id {
            AlgorithmId::ThresholdEcdsaSecp256k1 => {
                if hashed_message.len() != ECDSA_SECP256K1_HASH_BYTE_LENGTH {
                    return Err(error::ThresholdEcdsaSigInputsCreationError::InvalidHashLength);
                }
                Ok(())
            }
            AlgorithmId::ThresholdEcdsaSecp256r1 => {
                if hashed_message.len() != ECDSA_SECP256R1_HASH_BYTE_LENGTH {
                    return Err(error::ThresholdEcdsaSigInputsCreationError::InvalidHashLength);
                }
                Ok(())
            }
            _ => Err(error::ThresholdEcdsaSigInputsCreationError::UnsupportedAlgorithm),
        }
    }

    fn check_receivers_are_equal(
        presig_quadruple: &EcdsaPreSignatureQuadruple,
        key_transcript: &IDkgTranscript,
    ) -> Result<(), error::ThresholdEcdsaSigInputsCreationError> {
        // The quadruple was already checked to have a consistent receiver set
        if presig_quadruple.kappa_unmasked().receivers == key_transcript.receivers {
            Ok(())
        } else {
            Err(error::ThresholdEcdsaSigInputsCreationError::InconsistentReceivers)
        }
    }

    fn check_quadruple_origin(
        presig_quadruple: &EcdsaPreSignatureQuadruple,
        key_transcript: &IDkgTranscript,
    ) -> Result<(), error::ThresholdEcdsaSigInputsCreationError> {
        match &presig_quadruple.key_times_lambda.transcript_type {
            IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                key_id_from_mult,
                _,
            )) if *key_id_from_mult == key_transcript.transcript_id => Ok(()),
            _ => Err(
                error::ThresholdEcdsaSigInputsCreationError::InvalidQuadrupleOrigin(format!(
                    "Quadruple transcript `key_times_lambda` expected to have type `Masked` with origin of type `UnmaskedTimesMasked({:?},_)`, but found transcript of type {:?}",
                    key_transcript.transcript_id, presig_quadruple.key_times_lambda.transcript_type
                )),
            ),
        }
    }
}

/// A single threshold ECDSA signature share.
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct ThresholdEcdsaSigShare {
    #[serde(with = "serde_bytes")]
    pub sig_share_raw: Vec<u8>,
}

impl_display_using_debug!(ThresholdEcdsaSigShare);

impl fmt::Debug for ThresholdEcdsaSigShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ThresholdEcdsaSigShare {{ sig_share_raw: 0x{} }}",
            hex::encode(&self.sig_share_raw)
        )
    }
}

/// A combined threshold Schnorr signature.
///
/// The signature itself is stored as raw bytes.
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct ThresholdSchnorrCombinedSignature {
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

impl_display_using_debug!(ThresholdSchnorrCombinedSignature);

impl fmt::Debug for ThresholdSchnorrCombinedSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ThresholdSchnorrCombinedSignature {{ signature: {} }}",
            hex::encode(&self.signature)
        )
    }
}

/// All inputs required to generate a canister threshold signature.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ThresholdSchnorrSigInputs<'a> {
    caller: &'a PrincipalId,
    derivation_path: &'a [Vec<u8>],
    message: &'a [u8],
    taproot_tree_root: Option<&'a [u8]>,
    nonce: &'a [u8; 32],
    presig_transcript: &'a SchnorrPreSignatureTranscript,
    key_transcript: &'a IDkgTranscript,
}

impl_display_using_debug!(ThresholdSchnorrSigInputs<'_>);

impl fmt::Debug for ThresholdSchnorrSigInputs<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ThresholdSchnorrSigInputs {{ ")?;
        write!(f, "derivation_path: {:?}", self.derivation_path)?;
        write!(f, ", message: 0x{}", hex::encode(self.message))?;
        if let Some(ttr) = self.taproot_tree_root {
            write!(f, ", taproot_tree_root: 0x{}", hex::encode(ttr))?;
        }
        write!(f, ", nonce: 0x{}", hex::encode(self.nonce.as_ref()))?;
        write!(f, ", presig_transcript: {}", self.presig_transcript)?;
        write!(f, ", key_transcript: {}", self.key_transcript.transcript_id)?;
        write!(f, " }}")?;
        Ok(())
    }
}

impl AsRef<IDkgReceivers> for ThresholdSchnorrSigInputs<'_> {
    fn as_ref(&self) -> &IDkgReceivers {
        self.receivers()
    }
}

impl<'a> ThresholdSchnorrSigInputs<'a> {
    /// Creates the inputs to the threshold Schnorr signing protocol.
    ///
    /// A `ThresholdSchnorrSigInputs` can only be created if the following invariants hold:
    /// * The algorithm ID of the `key_transcript` is the same as the algorithm ID
    ///   of the transcripts in the `presig_quadruple` (error: `InconsistentAlgorithms`)
    /// * The algorithm ID of the `key_transcript` is supported for the creation
    ///   of threshold Schnorr signatures (error: `UnsupportedAlgorithm`)
    /// * All transcripts have the same receiver set (error: `InconsistentReceivers`)
    /// * The `blinder_unmasked` transcript of the `presig_transcript` is a random
    ///   unmasked transcript (error: `InvalidPreSignatureOrigin`)
    pub fn new(
        caller: &'a PrincipalId,
        derivation_path: &'a [Vec<u8>],
        message: &'a [u8],
        taproot_tree_root: Option<&'a [u8]>,
        nonce: &'a [u8; 32],
        presig_transcript: &'a SchnorrPreSignatureTranscript,
        key_transcript: &'a IDkgTranscript,
    ) -> Result<Self, error::ThresholdSchnorrSigInputsCreationError> {
        Self::check_algorithm_id_consistency(presig_transcript, key_transcript)?;
        Self::check_algorithm_id_validity(key_transcript.algorithm_id)?;
        Self::check_receivers_consistency(presig_transcript, key_transcript)?;
        Self::check_presig_transcript_origin(presig_transcript)?;
        Self::check_taproot_tree_root_argument(key_transcript.algorithm_id, taproot_tree_root)?;

        Ok(Self {
            caller,
            derivation_path,
            message,
            taproot_tree_root,
            nonce,
            presig_transcript,
            key_transcript,
        })
    }

    pub fn caller(&self) -> &PrincipalId {
        self.caller
    }

    pub fn derivation_path(&self) -> &[Vec<u8>] {
        self.derivation_path
    }

    pub fn message(&self) -> &[u8] {
        self.message
    }

    pub fn taproot_tree_root(&self) -> Option<&[u8]> {
        self.taproot_tree_root
    }

    pub fn nonce(&self) -> &[u8; 32] {
        self.nonce
    }

    pub fn presig_transcript(&self) -> &SchnorrPreSignatureTranscript {
        self.presig_transcript
    }

    pub fn key_transcript(&self) -> &IDkgTranscript {
        self.key_transcript
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

    pub fn index_for_signer_id(&self, node_id: NodeId) -> Option<NodeIndex> {
        self.key_transcript().index_for_signer_id(node_id)
    }

    fn check_algorithm_id_consistency(
        presig_transcript: &SchnorrPreSignatureTranscript,
        key_transcript: &IDkgTranscript,
    ) -> Result<(), error::ThresholdSchnorrSigInputsCreationError> {
        if presig_transcript.blinder_unmasked.algorithm_id != key_transcript.algorithm_id {
            return Err(
                error::ThresholdSchnorrSigInputsCreationError::InconsistentAlgorithmIds(
                    presig_transcript.blinder_unmasked.algorithm_id.to_string(),
                    key_transcript.algorithm_id.to_string(),
                ),
            );
        }
        Ok(())
    }

    fn check_receivers_consistency(
        presig_transcript: &SchnorrPreSignatureTranscript,
        key_transcript: &IDkgTranscript,
    ) -> Result<(), error::ThresholdSchnorrSigInputsCreationError> {
        if presig_transcript.blinder_unmasked.receivers != key_transcript.receivers {
            return Err(error::ThresholdSchnorrSigInputsCreationError::InconsistentReceivers);
        }
        Ok(())
    }

    fn check_algorithm_id_validity(
        algorithm_id: AlgorithmId,
    ) -> Result<(), error::ThresholdSchnorrSigInputsCreationError> {
        if algorithm_id.is_threshold_schnorr() {
            Ok(())
        } else {
            Err(
                error::ThresholdSchnorrSigInputsCreationError::UnsupportedAlgorithm(
                    algorithm_id.to_string(),
                ),
            )
        }
    }

    fn check_presig_transcript_origin(
        presig_transcript: &SchnorrPreSignatureTranscript,
    ) -> Result<(), error::ThresholdSchnorrSigInputsCreationError> {
        match &presig_transcript.blinder_unmasked.transcript_type {
            IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random) => Ok(()),
            origin => Err(
                error::ThresholdSchnorrSigInputsCreationError::InvalidPreSignatureOrigin(format!(
                    "Presignature transcript: {origin:?}",
                )),
            ),
        }
    }

    fn check_taproot_tree_root_argument(
        algorithm: AlgorithmId,
        taproot_tree_root: Option<&[u8]>,
    ) -> Result<(), error::ThresholdSchnorrSigInputsCreationError> {
        match taproot_tree_root {
            None => Ok(()),
            Some(ttr) => {
                if algorithm == AlgorithmId::ThresholdSchnorrBip340
                    && (ttr.is_empty() || ttr.len() == 32)
                {
                    Ok(())
                } else {
                    Err(error::ThresholdSchnorrSigInputsCreationError::InvalidUseOfTaprootHash)
                }
            }
        }
    }
}

/// Presignature containing a random unmasked IDKG transcript consumed by a
/// canister-requested threshold Schnorr signature. Each presignature MUST be
/// used *at most once* for a signature. Otherwise, the private key may be
/// leaked!
///
/// Each signature, in addition to the transcript for the sharing of the private
/// key, requires a presignature.
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SchnorrPreSignatureTranscript {
    blinder_unmasked: IDkgTranscript,
}

impl_display_using_debug!(SchnorrPreSignatureTranscript);

impl fmt::Debug for SchnorrPreSignatureTranscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PreSignatureTranscript {{ blinder_unmasked: {:?} }}",
            self.blinder_unmasked.transcript_id
        )?;
        Ok(())
    }
}

impl SchnorrPreSignatureTranscript {
    pub fn new(
        blinder_unmasked: IDkgTranscript,
    ) -> Result<Self, error::ThresholdSchnorrPresignatureTranscriptCreationError> {
        Self::check_algorithm_id(&blinder_unmasked)?;
        Self::check_transcript_origin(&blinder_unmasked)?;
        Ok(Self { blinder_unmasked })
    }

    pub fn blinder_unmasked(&self) -> &IDkgTranscript {
        &self.blinder_unmasked
    }

    fn check_algorithm_id(
        blinder_unmasked: &IDkgTranscript,
    ) -> Result<(), error::ThresholdSchnorrPresignatureTranscriptCreationError> {
        if !blinder_unmasked.algorithm_id.is_threshold_schnorr() {
            return Err(
                error::ThresholdSchnorrPresignatureTranscriptCreationError::UnsupportedAlgorithm(
                    blinder_unmasked.algorithm_id.to_string(),
                ),
            );
        }
        Ok(())
    }

    fn check_transcript_origin(
        blinder_unmasked: &IDkgTranscript,
    ) -> Result<(), error::ThresholdSchnorrPresignatureTranscriptCreationError> {
        if blinder_unmasked.transcript_type
            != IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random)
        {
            return Err(
                error::ThresholdSchnorrPresignatureTranscriptCreationError::InvalidTranscriptOrigin(
                    format!(
                        "Expected unmasked transcript with origin `Random`, but found transcript of type {:?}",
                        blinder_unmasked.transcript_type
                    ),
                ),
            );
        }
        Ok(())
    }
}

/// A single threshold Schnorr signature share.
#[derive(Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct ThresholdSchnorrSigShare {
    #[serde(with = "serde_bytes")]
    pub sig_share_raw: Vec<u8>,
}

impl_display_using_debug!(ThresholdSchnorrSigShare);

impl fmt::Debug for ThresholdSchnorrSigShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ThresholdSchnorrSigShare {{ sig_share_raw: 0x{} }}",
            hex::encode(&self.sig_share_raw)
        )
    }
}
