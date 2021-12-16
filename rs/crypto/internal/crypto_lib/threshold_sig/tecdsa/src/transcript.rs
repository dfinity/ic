use crate::*;
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgTranscript, IDkgTranscriptOperation};
use ic_types::NodeIndex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::TryFrom;

/// IDkg transcript information relevant for the internal Crypto operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDkgTranscriptInternal {
    pub combined_commitment: CombinedCommitment,
}

impl IDkgTranscriptInternal {
    pub fn serialize(&self) -> ThresholdEcdsaResult<Vec<u8>> {
        serde_cbor::to_vec(self)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }

    pub fn deserialize(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        serde_cbor::from_slice::<Self>(bytes)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }

    pub(crate) fn constant_term(&self) -> EccPoint {
        self.combined_commitment.commitment().constant_term()
    }

    pub(crate) fn evaluate_at(&self, eval_point: &EccScalar) -> ThresholdEcdsaResult<EccPoint> {
        self.combined_commitment
            .commitment()
            .evaluate_at(eval_point)
    }
}

impl TryFrom<&IDkgTranscript> for IDkgTranscriptInternal {
    type Error = ThresholdEcdsaError;

    fn try_from(idkm_transcript: &IDkgTranscript) -> Result<Self, ThresholdEcdsaError> {
        Self::deserialize(&idkm_transcript.internal_transcript_raw)
    }
}

/// Some type of commitment, specifying its combination strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CombinedCommitment {
    BySummation(PolynomialCommitment),
    ByInterpolation(PolynomialCommitment),
}

impl CombinedCommitment {
    pub fn commitment(&self) -> &PolynomialCommitment {
        match self {
            Self::BySummation(c) => c,
            Self::ByInterpolation(c) => c,
        }
    }

    pub fn serialize(&self) -> ThresholdEcdsaResult<Vec<u8>> {
        serde_cbor::to_vec(self)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }

    pub fn deserialize(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        serde_cbor::from_slice::<Self>(bytes)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }
}

/// IDkg transcript operation information relevant for internal Crypto
/// operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IDkgTranscriptOperationInternal {
    Random,
    ReshareOfMasked(PolynomialCommitment),
    ReshareOfUnmasked(PolynomialCommitment),
    UnmaskedTimesMasked(PolynomialCommitment, PolynomialCommitment),
}

impl TryFrom<&IDkgTranscriptOperation> for IDkgTranscriptOperationInternal {
    type Error = ThresholdEcdsaError;

    fn try_from(idkm_transcript_op: &IDkgTranscriptOperation) -> Result<Self, ThresholdEcdsaError> {
        match idkm_transcript_op {
            IDkgTranscriptOperation::Random => Ok(Self::Random),
            IDkgTranscriptOperation::ReshareOfMasked(idkm_transcript) => {
                let transcript = IDkgTranscriptInternal::try_from(idkm_transcript)?;
                Ok(Self::ReshareOfMasked(
                    transcript.combined_commitment.commitment().clone(),
                ))
            }
            IDkgTranscriptOperation::ReshareOfUnmasked(idkm_transcript) => {
                let transcript = IDkgTranscriptInternal::try_from(idkm_transcript)?;
                Ok(Self::ReshareOfUnmasked(
                    transcript.combined_commitment.commitment().clone(),
                ))
            }
            IDkgTranscriptOperation::UnmaskedTimesMasked(idkm_transcript_1, idkm_transcript_2) => {
                let transcript_1 = IDkgTranscriptInternal::try_from(idkm_transcript_1)?;
                let transcript_2 = IDkgTranscriptInternal::try_from(idkm_transcript_2)?;
                Ok(Self::UnmaskedTimesMasked(
                    transcript_1.combined_commitment.commitment().clone(),
                    transcript_2.combined_commitment.commitment().clone(),
                ))
            }
        }
    }
}

fn combine_commitments_via_interpolation(
    commitment_type: PolynomialCommitmentType,
    curve: EccCurveType,
    reconstruction_threshold: usize,
    verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
) -> ThresholdEcdsaResult<CombinedCommitment> {
    // First verify the dealings are of the expected type
    for dealing in verified_dealings.values() {
        if dealing.commitment.ctype() != commitment_type {
            return Err(ThresholdEcdsaError::InconsistentCommitments);
        }
    }

    let mut commitments = Vec::new();
    let mut indexes = Vec::new();
    let mut combined = Vec::new();

    for (index, dealing) in verified_dealings {
        indexes.push(EccScalar::from_node_index(curve, *index));
        commitments.push(dealing.commitment.clone());
    }

    for i in 0..reconstruction_threshold {
        let mut coeff = Vec::new();
        for commitment in &commitments {
            coeff.push(commitment.points()[i]);
        }
        let samples = indexes.iter().cloned().zip(coeff).collect::<Vec<_>>();
        combined.push(EccPoint::interpolation_at_zero(&samples)?)
    }

    let commitment = match commitment_type {
        PolynomialCommitmentType::Simple => SimpleCommitment::new(combined).into(),
        PolynomialCommitmentType::Pedersen => PedersenCommitment::new(combined).into(),
    };

    Ok(CombinedCommitment::ByInterpolation(commitment))
}

impl IDkgTranscriptInternal {
    pub fn new(
        curve: EccCurveType,
        reconstruction_threshold: usize,
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        operation_mode: &IDkgTranscriptOperationInternal,
    ) -> ThresholdEcdsaResult<IDkgTranscriptInternal> {
        // Check all dealings have correct length and are on the same curve
        for dealing in verified_dealings.values() {
            if dealing.commitment.points().len() != reconstruction_threshold {
                return Err(ThresholdEcdsaError::InconsistentCommitments);
            }

            for point in dealing.commitment.points() {
                if point.curve_type() != curve {
                    return Err(ThresholdEcdsaError::InconsistentCommitments);
                }
            }
        }

        // Combine the polynomials
        let combined_commitment = match operation_mode {
            IDkgTranscriptOperationInternal::Random => {
                // Combine commitments via sum
                let mut combined = vec![EccPoint::identity(curve); reconstruction_threshold];

                for dealing in verified_dealings.values() {
                    if dealing.commitment.ctype() != PolynomialCommitmentType::Pedersen {
                        return Err(ThresholdEcdsaError::InconsistentCommitments);
                    }

                    let c = dealing.commitment.points();
                    for i in 0..reconstruction_threshold {
                        combined[i] = combined[i].add_points(&c[i])?;
                    }
                }

                CombinedCommitment::BySummation(PedersenCommitment::new(combined).into())
            }

            IDkgTranscriptOperationInternal::ReshareOfMasked(reshared_commitment) => {
                // Verify that the old commitment is actually masked
                if reshared_commitment.ctype() != PolynomialCommitmentType::Pedersen {
                    return Err(ThresholdEcdsaError::InconsistentCommitments);
                }
                // Check the number of dealings is not smaller than the number of coefficients
                // of the opening of the `reshared_commitment`. This ensures that the
                // commitment combined via interpolation will open to a polynomial that has
                // the same constant term as the opening of `reshared_commitment`.
                if verified_dealings.len() < reshared_commitment.points().len() {
                    return Err(ThresholdEcdsaError::InsufficientDealings);
                }
                combine_commitments_via_interpolation(
                    PolynomialCommitmentType::Simple,
                    curve,
                    reconstruction_threshold,
                    verified_dealings,
                )?
            }

            IDkgTranscriptOperationInternal::ReshareOfUnmasked(reshared_commitment) => {
                // Verify that the old commitment is Unmasked
                if reshared_commitment.ctype() != PolynomialCommitmentType::Simple {
                    return Err(ThresholdEcdsaError::InconsistentCommitments);
                }
                // Check the number of dealings is not smaller than the number of coefficients
                // of the opening of the `reshared_commitment`. This ensures that the
                // commitment combined via interpolation will open to a polynomial that has
                // the same constant term as the opening of `reshared_commitment`.
                if verified_dealings.len() < reshared_commitment.points().len() {
                    return Err(ThresholdEcdsaError::InsufficientDealings);
                }
                let combined_commitment = combine_commitments_via_interpolation(
                    PolynomialCommitmentType::Simple,
                    curve,
                    reconstruction_threshold,
                    verified_dealings,
                )?;

                // Check the constant term of the combined commitment is
                // consistent with the reshared commitment
                if reshared_commitment.points()[0] != combined_commitment.commitment().points()[0] {
                    return Err(ThresholdEcdsaError::InconsistentCommitments);
                }

                combined_commitment
            }
            IDkgTranscriptOperationInternal::UnmaskedTimesMasked(
                left_commitment,
                right_commitment,
            ) => {
                if left_commitment.ctype() != PolynomialCommitmentType::Simple
                    || right_commitment.ctype() != PolynomialCommitmentType::Pedersen
                {
                    return Err(ThresholdEcdsaError::InconsistentCommitments);
                }
                // Check the number of dealings is not smaller than the number of coefficients
                // in the polynomial obtained by multiplying the opening of `left_commitment`
                // with the opening of `right_commitment`. This ensures that the commitment
                // combined via interpolation will open to a polynomial that has as constant
                // term the product of the constant terms of the openings of `left_commitment`
                // and `right_commitment`.
                if verified_dealings.len()
                    < left_commitment.points().len() + right_commitment.points().len() - 1
                {
                    return Err(ThresholdEcdsaError::InsufficientDealings);
                }

                combine_commitments_via_interpolation(
                    PolynomialCommitmentType::Pedersen,
                    curve,
                    reconstruction_threshold,
                    verified_dealings,
                )?
            }
        };

        Ok(IDkgTranscriptInternal {
            combined_commitment,
        })
    }
}

impl CommitmentOpening {
    pub(crate) fn from_dealings(
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        transcript: &IDkgTranscriptInternal,
        context_data: &[u8],
        receiver_index: NodeIndex,
        secret_key: &MEGaPrivateKey,
        public_key: &MEGaPublicKey,
    ) -> ThresholdEcdsaResult<Self> {
        let curve = secret_key.curve().curve_type();
        let mut openings = Vec::with_capacity(verified_dealings.len());

        for (dealer_index, dealing) in verified_dealings {
            // Decrypt each dealing and check consistency with the commitment in the dealing
            let opening = mega::decrypt_and_check(
                &dealing.ciphertext,
                &dealing.commitment,
                context_data,
                *dealer_index as usize,
                receiver_index as usize,
                secret_key,
                public_key,
            )?;

            let dealer_index = EccScalar::from_node_index(curve, *dealer_index);
            openings.push((dealer_index, opening));
        }

        let receiver_index = EccScalar::from_node_index(curve, receiver_index);

        // Recombine the openings according to the type of combined polynomial
        match &transcript.combined_commitment {
            CombinedCommitment::BySummation(commitment) => {
                // Recombine secret by summation
                let mut combined_value = EccScalar::zero(curve);
                let mut combined_mask = EccScalar::zero(curve);

                for (_dealer_index, opening) in openings {
                    if let Self::Pedersen(value, mask) = opening {
                        combined_value = combined_value.add(&value)?;
                        combined_mask = combined_mask.add(&mask)?;
                    } else {
                        return Err(ThresholdEcdsaError::InconsistentCommitments);
                    }
                }

                let combined_opening = Self::Pedersen(combined_value, combined_mask);

                // Check reconstructed opening matches the commitment
                if commitment.check_opening(&receiver_index, &combined_opening)? {
                    Ok(combined_opening)
                } else {
                    Err(ThresholdEcdsaError::InconsistentCommitments)
                }
            }

            CombinedCommitment::ByInterpolation(PolynomialCommitment::Pedersen(commitment)) => {
                let mut values = Vec::with_capacity(openings.len());
                let mut masks = Vec::with_capacity(openings.len());

                for (dealer_index, opening) in openings {
                    if let Self::Pedersen(value, mask) = opening {
                        values.push((dealer_index, value));
                        masks.push((dealer_index, mask));
                    } else {
                        return Err(ThresholdEcdsaError::InconsistentCommitments);
                    }
                }

                // Recombine secret by interpolation
                let combined_value = EccScalar::interpolation_at_zero(&values)?;
                let combined_mask = EccScalar::interpolation_at_zero(&masks)?;

                // Check reconstructed opening matches the commitment
                if commitment.check_opening(&receiver_index, &combined_value, &combined_mask)? {
                    Ok(Self::Pedersen(combined_value, combined_mask))
                } else {
                    Err(ThresholdEcdsaError::InconsistentCommitments)
                }
            }

            CombinedCommitment::ByInterpolation(PolynomialCommitment::Simple(commitment)) => {
                let mut values = Vec::with_capacity(openings.len());

                for (dealer_index, opening) in openings {
                    if let Self::Simple(value) = opening {
                        values.push((dealer_index, value))
                    } else {
                        return Err(ThresholdEcdsaError::InconsistentCommitments);
                    }
                }

                // Recombine secret by interpolation
                let combined_value = EccScalar::interpolation_at_zero(&values)?;

                // Check reconstructed opening matches the commitment
                if commitment.check_opening(&receiver_index, &combined_value)? {
                    Ok(Self::Simple(combined_value))
                } else {
                    Err(ThresholdEcdsaError::InconsistentCommitments)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDkgComplaintInternal {
    pub dealer_index: NodeIndex,
}

impl IDkgComplaintInternal {
    pub fn serialize(&self) -> ThresholdEcdsaResult<Vec<u8>> {
        serde_cbor::to_vec(self)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }

    pub fn deserialize(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        serde_cbor::from_slice::<Self>(bytes)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }
}
