use crate::*;
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgTranscript, IDkgTranscriptOperation};
use ic_types::NodeIndex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::TryFrom;

/// IDkg transcript information relevant for the internal Crypto operations
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
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

    pub fn constant_term(&self) -> EccPoint {
        self.combined_commitment.commitment().constant_term()
    }

    pub(crate) fn evaluate_at(&self, eval_point: NodeIndex) -> ThresholdEcdsaResult<EccPoint> {
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
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
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
            return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
        }
    }

    let mut commitments = Vec::with_capacity(verified_dealings.len());
    let mut indexes = Vec::with_capacity(verified_dealings.len());

    for (index, dealing) in verified_dealings {
        indexes.push(*index);
        commitments.push(dealing.commitment.clone());
    }

    let coefficients = LagrangeCoefficients::at_zero(curve, &indexes)?;
    let mut combined = Vec::with_capacity(reconstruction_threshold);

    for i in 0..reconstruction_threshold {
        let mut values = Vec::new();
        for commitment in &commitments {
            values.push(commitment.points()[i]);
        }
        combined.push(coefficients.interpolate_point(&values)?);
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
                return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
            }

            for point in dealing.commitment.points() {
                if point.curve_type() != curve {
                    return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
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
                        return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
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
                    return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
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
                    return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
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
                    return Err(ThresholdEcdsaError::InvalidCommitment);
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
                    return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
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

fn reconstruct_share_from_openings(
    dealing: &IDkgDealingInternal,
    openings: &BTreeMap<NodeIndex, CommitmentOpening>,
    share_index: NodeIndex,
) -> ThresholdEcdsaResult<CommitmentOpening> {
    let reconstruction_threshold = dealing.commitment.len();

    if openings.len() < reconstruction_threshold {
        return Err(ThresholdEcdsaError::InsufficientOpenings);
    }

    let curve = dealing.commitment.curve_type();
    let index = EccScalar::from_node_index(curve, share_index);

    match &dealing.commitment {
        PolynomialCommitment::Simple(_) => {
            let mut x_values = Vec::with_capacity(openings.len());
            let mut values = Vec::with_capacity(openings.len());

            for (receiver_index, opening) in openings {
                if let CommitmentOpening::Simple(value) = opening {
                    x_values.push(*receiver_index);
                    values.push(*value);
                } else {
                    return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
                }
            }

            let coefficients = LagrangeCoefficients::at_value(&index, &x_values)?;
            let combined_value = coefficients.interpolate_scalar(&values)?;
            let combined_opening = CommitmentOpening::Simple(combined_value);

            dealing
                .commitment
                .return_opening_if_consistent(share_index, &combined_opening)
        }
        PolynomialCommitment::Pedersen(_) => {
            let mut x_values = Vec::with_capacity(openings.len());
            let mut values = Vec::with_capacity(openings.len());
            let mut masks = Vec::with_capacity(openings.len());

            for (receiver_index, opening) in openings {
                if let CommitmentOpening::Pedersen(value, mask) = opening {
                    x_values.push(*receiver_index);
                    values.push(*value);
                    masks.push(*mask);
                } else {
                    return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
                }
            }

            let coefficients = LagrangeCoefficients::at_value(&index, &x_values)?;
            let combined_value = coefficients.interpolate_scalar(&values)?;
            let combined_mask = coefficients.interpolate_scalar(&masks)?;
            let combined_opening = CommitmentOpening::Pedersen(combined_value, combined_mask);

            dealing
                .commitment
                .return_opening_if_consistent(share_index, &combined_opening)
        }
    }
}

impl CommitmentOpening {
    /// Creates a commitment opening using dealings and openings
    ///
    /// The MEGa secret and public keys is our node's keypair. The
    /// `receiver_index` indicates our place within the dealings.
    ///
    /// # Preconditions
    /// * The dealings must have already been verified
    /// * The openings must have already been verified
    ///
    /// # Errors
    /// * `InsufficientOpenings` if we require openings for a corrupted dealing but
    ///   do not have sufficiently many openings for that dealing.
    /// * `InvalidCommitment` if the commitments are inconsistent. This
    ///   indicates that there is a corrupted dealing for which we have no openings
    ///   at all.
    pub(crate) fn from_dealings_and_openings(
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        provided_openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        transcript_commitment: &CombinedCommitment,
        context_data: &[u8],
        receiver_index: NodeIndex,
        secret_key: &MEGaPrivateKey,
        public_key: &MEGaPublicKey,
    ) -> ThresholdEcdsaResult<Self> {
        let curve = secret_key.curve_type();
        let mut openings = Vec::with_capacity(verified_dealings.len());

        for (dealer_index, dealing) in verified_dealings {
            // If provided_openings contains an entry for dealer_index,
            // reconstruct the share, otherwise attempt to decrypt the dealing
            let opening = if let Some(shares) = provided_openings.get(dealer_index) {
                reconstruct_share_from_openings(dealing, shares, receiver_index)?
            } else {
                dealing.ciphertext.decrypt_and_check(
                    &dealing.commitment,
                    context_data,
                    *dealer_index,
                    receiver_index,
                    secret_key,
                    public_key,
                )?
            };

            openings.push((*dealer_index, opening));
        }

        Self::combine_openings(&openings, transcript_commitment, receiver_index, curve)
    }

    /// Creates a commitment opening using dealings and openings
    ///
    /// The MEGa secret and public keys is our node's keypair. The
    /// `receiver_index` indicates our place within the dealings.
    ///
    /// # Preconditions
    /// * The dealings must have already been verified
    ///
    /// # Errors
    /// * `InvalidCommitment` if the commitments are inconsistent. This
    ///   indicates we should issue a complaint and collect openings.
    pub(crate) fn from_dealings(
        verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
        transcript_commitment: &CombinedCommitment,
        context_data: &[u8],
        receiver_index: NodeIndex,
        secret_key: &MEGaPrivateKey,
        public_key: &MEGaPublicKey,
    ) -> ThresholdEcdsaResult<Self> {
        let curve = secret_key.curve_type();
        let mut openings = Vec::with_capacity(verified_dealings.len());

        for (dealer_index, dealing) in verified_dealings {
            // Decrypt each dealing and check consistency with the commitment in the dealing
            let opening = dealing.ciphertext.decrypt_and_check(
                &dealing.commitment,
                context_data,
                *dealer_index,
                receiver_index,
                secret_key,
                public_key,
            )?;

            openings.push((*dealer_index, opening));
        }

        Self::combine_openings(&openings, transcript_commitment, receiver_index, curve)
    }

    fn combine_openings(
        openings: &[(NodeIndex, CommitmentOpening)],
        transcript_commitment: &CombinedCommitment,
        receiver_index: NodeIndex,
        curve: EccCurveType,
    ) -> ThresholdEcdsaResult<Self> {
        // Recombine the openings according to the type of combined polynomial
        match transcript_commitment {
            CombinedCommitment::BySummation(commitment) => {
                // Recombine secret by summation
                let mut combined_value = EccScalar::zero(curve);
                let mut combined_mask = EccScalar::zero(curve);

                for (_dealer_index, opening) in openings {
                    if let Self::Pedersen(value, mask) = opening {
                        combined_value = combined_value.add(value)?;
                        combined_mask = combined_mask.add(mask)?;
                    } else {
                        return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
                    }
                }

                let combined_opening = Self::Pedersen(combined_value, combined_mask);

                // Check reconstructed opening matches the commitment
                commitment.return_opening_if_consistent(receiver_index, &combined_opening)
            }

            CombinedCommitment::ByInterpolation(commitment) => {
                let opening = match commitment {
                    PolynomialCommitment::Simple(_) => {
                        let mut x_values = Vec::with_capacity(openings.len());
                        let mut values = Vec::with_capacity(openings.len());

                        for (dealer_index, opening) in openings {
                            if let Self::Simple(value) = opening {
                                x_values.push(*dealer_index);
                                values.push(*value);
                            } else {
                                return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
                            }
                        }

                        // Recombine secret by interpolation
                        let coefficients = LagrangeCoefficients::at_zero(curve, &x_values)?;
                        let combined_value = coefficients.interpolate_scalar(&values)?;
                        Self::Simple(combined_value)
                    }
                    PolynomialCommitment::Pedersen(_) => {
                        let mut x_values = Vec::with_capacity(openings.len());
                        let mut values = Vec::with_capacity(openings.len());
                        let mut masks = Vec::with_capacity(openings.len());

                        for (dealer_index, opening) in openings {
                            if let Self::Pedersen(value, mask) = opening {
                                x_values.push(*dealer_index);
                                values.push(*value);
                                masks.push(*mask);
                            } else {
                                return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
                            }
                        }

                        // Recombine secret by interpolation
                        let coefficients = LagrangeCoefficients::at_zero(curve, &x_values)?;
                        let combined_value = coefficients.interpolate_scalar(&values)?;
                        let combined_mask = coefficients.interpolate_scalar(&masks)?;
                        Self::Pedersen(combined_value, combined_mask)
                    }
                };

                // Check reconstructed opening matches the commitment
                commitment.return_opening_if_consistent(receiver_index, &opening)
            }
        }
    }
}
