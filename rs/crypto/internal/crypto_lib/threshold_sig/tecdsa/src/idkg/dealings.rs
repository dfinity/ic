use crate::*;
use core::fmt::{self, Debug};
use ic_types::crypto::canister_threshold_sig::idkg::BatchSignedIDkgDealing;
use ic_types::NumberOfNodes;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Clone)]
pub enum SecretShares {
    RandomUnmasked,
    Random,
    ReshareOfUnmasked(EccScalar),
    ReshareOfMasked(EccScalar, EccScalar),
    UnmaskedTimesMasked(EccScalar, (EccScalar, EccScalar)),
}

impl Debug for SecretShares {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Random => "Random",
            Self::RandomUnmasked => "RandomUnmasked",
            Self::ReshareOfUnmasked(_) => "ReshareOfUnmasked",
            Self::ReshareOfMasked(_, _) => "ReshareOfMasked",
            Self::UnmaskedTimesMasked(_, _) => "UnmaskedTimesMasked",
        };

        fn format_curve_id(curves: &[EccCurveType]) -> String {
            if curves.is_empty() {
                return "".to_string();
            }

            if curves.windows(2).all(|w| w[0] == w[1]) {
                format!("({:?})", curves[0])
            } else {
                format!(" unsupported curve combination {:?}", curves)
            }
        }

        let curve = match self {
            Self::Random => "".to_string(),
            Self::RandomUnmasked => "".to_string(),
            Self::ReshareOfUnmasked(s) => format_curve_id(&[s.curve_type()]),
            Self::ReshareOfMasked(s1, s2) => format_curve_id(&[s1.curve_type(), s2.curve_type()]),
            Self::UnmaskedTimesMasked(s1, (s2, s3)) => {
                format_curve_id(&[s1.curve_type(), s2.curve_type(), s3.curve_type()])
            }
        };

        let redacted = if curve.is_empty() { "" } else { " - REDACTED" };
        write!(f, "SecretShares::{}{}{}", name, curve, redacted)
    }
}

impl TryFrom<(&CommitmentOpeningBytes, Option<&CommitmentOpeningBytes>)> for SecretShares {
    type Error = CanisterThresholdSerializationError;

    fn try_from(
        commitments: (&CommitmentOpeningBytes, Option<&CommitmentOpeningBytes>),
    ) -> CanisterThresholdSerializationResult<Self> {
        match commitments {
            (CommitmentOpeningBytes::Simple(bytes), None) => {
                let scalar = EccScalar::try_from(bytes)?;
                Ok(SecretShares::ReshareOfUnmasked(scalar))
            }
            (CommitmentOpeningBytes::Pedersen(bytes1, bytes2), None) => {
                let scalar1 = EccScalar::try_from(bytes1)?;
                let scalar2 = EccScalar::try_from(bytes2)?;
                Ok(SecretShares::ReshareOfMasked(scalar1, scalar2))
            }
            (
                CommitmentOpeningBytes::Simple(simple_bytes),
                Some(CommitmentOpeningBytes::Pedersen(pedersen_bytes_1, pedersen_bytes_2)),
            ) => {
                let scalar_1 = EccScalar::try_from(simple_bytes)?;
                let scalar_2 = EccScalar::try_from(pedersen_bytes_1)?;
                let scalar_3 = EccScalar::try_from(pedersen_bytes_2)?;
                Ok(SecretShares::UnmaskedTimesMasked(
                    scalar_1,
                    (scalar_2, scalar_3),
                ))
            }
            _ => Err(CanisterThresholdSerializationError(
                "Unexpected commitment types".to_string(),
            )),
        }
    }
}

fn encrypt_and_commit_single_polynomial(
    alg: IdkgProtocolAlgorithm,
    poly: &Polynomial,
    num_coefficients: usize,
    recipients: &[MEGaPublicKey],
    dealer_index: NodeIndex,
    associated_data: &[u8],
    seed: Seed,
) -> CanisterThresholdResult<(MEGaCiphertext, PolynomialCommitment)> {
    let curve = poly.curve_type();

    let mut plaintexts = Vec::with_capacity(recipients.len());

    for (idx, _recipient) in recipients.iter().enumerate() {
        let scalar = EccScalar::from_node_index(curve, idx as NodeIndex);
        let v_s = poly.evaluate_at(&scalar)?;
        plaintexts.push(v_s)
    }

    let ciphertext = MEGaCiphertextSingle::encrypt(
        seed,
        alg,
        &plaintexts,
        recipients,
        dealer_index,
        associated_data,
    )?;

    let commitment = SimpleCommitment::create(poly, num_coefficients)?;

    Ok((ciphertext.into(), commitment.into()))
}

fn encrypt_and_commit_pair_of_polynomials(
    alg: IdkgProtocolAlgorithm,
    values: &Polynomial,
    mask: &Polynomial,
    num_coefficients: usize,
    recipients: &[MEGaPublicKey],
    dealer_index: NodeIndex,
    associated_data: &[u8],
    seed: Seed,
) -> CanisterThresholdResult<(MEGaCiphertext, PolynomialCommitment)> {
    let curve = values.curve_type();

    let mut plaintexts = Vec::with_capacity(recipients.len());

    for (idx, _recipient) in recipients.iter().enumerate() {
        let scalar = EccScalar::from_node_index(curve, idx as NodeIndex);
        let v_s = values.evaluate_at(&scalar)?;
        let m_s = mask.evaluate_at(&scalar)?;
        plaintexts.push((v_s, m_s))
    }

    let ciphertext = MEGaCiphertextPair::encrypt(
        seed,
        alg,
        &plaintexts,
        recipients,
        dealer_index,
        associated_data,
    )?;

    let commitment = PedersenCommitment::create(values, mask, num_coefficients)?;

    Ok((ciphertext.into(), commitment.into()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkProof {
    ProofOfMaskedResharing(zk::ProofOfEqualOpenings),
    ProofOfProduct(zk::ProofOfProduct),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IDkgDealingInternal {
    pub ciphertext: MEGaCiphertext,
    pub commitment: PolynomialCommitment,
    pub proof: Option<ZkProof>,
}

impl IDkgDealingInternal {
    pub fn new(
        shares: &SecretShares,
        alg: IdkgProtocolAlgorithm,
        seed: Seed,
        threshold: usize,
        recipients: &[MEGaPublicKey],
        dealer_index: NodeIndex,
        associated_data: &[u8],
    ) -> CanisterThresholdResult<Self> {
        if threshold == 0 || threshold > recipients.len() {
            return Err(CanisterThresholdError::InvalidThreshold(
                threshold,
                recipients.len(),
            ));
        }

        let signature_curve = alg.curve();
        let num_coefficients = threshold;

        let mut poly_rng = seed
            .derive(&DomainSep::SeedForDealingPolynomials(alg).to_string())
            .into_rng();

        let mega_seed = seed.derive(
            &DomainSep::SeedForDealingMega(alg, dealer_index, recipients.len()).to_string(),
        );

        let (commitment, ciphertext, proof) = match shares {
            SecretShares::Random => {
                let values = Polynomial::random(signature_curve, num_coefficients, &mut poly_rng); // omega in paper
                let mask = Polynomial::random(signature_curve, num_coefficients, &mut poly_rng); // omega' in paper

                let (ciphertext, commitment) = encrypt_and_commit_pair_of_polynomials(
                    alg,
                    &values,
                    &mask,
                    num_coefficients,
                    recipients,
                    dealer_index,
                    associated_data,
                    mega_seed,
                )?;

                (commitment, ciphertext, None)
            }
            SecretShares::RandomUnmasked => {
                let values = Polynomial::random(signature_curve, num_coefficients, &mut poly_rng);

                let (ciphertext, commitment) = encrypt_and_commit_single_polynomial(
                    alg,
                    &values,
                    num_coefficients,
                    recipients,
                    dealer_index,
                    associated_data,
                    mega_seed,
                )?;

                (commitment, ciphertext, None)
            }
            SecretShares::ReshareOfUnmasked(secret) => {
                if secret.curve_type() != signature_curve {
                    return Err(CanisterThresholdError::InvalidSecretShare);
                }

                let values =
                    Polynomial::random_with_constant(secret, num_coefficients, &mut poly_rng)?;

                let (ciphertext, commitment) = encrypt_and_commit_single_polynomial(
                    alg,
                    &values,
                    num_coefficients,
                    recipients,
                    dealer_index,
                    associated_data,
                    mega_seed,
                )?;

                // The commitment is unmasked so no ZK equivalence proof is required
                (commitment, ciphertext, None)
            }
            SecretShares::ReshareOfMasked(secret, masking) => {
                if secret.curve_type() != signature_curve || masking.curve_type() != signature_curve
                {
                    return Err(CanisterThresholdError::InvalidSecretShare);
                }

                let values =
                    Polynomial::random_with_constant(secret, num_coefficients, &mut poly_rng)?;

                let (ciphertext, commitment) = encrypt_and_commit_single_polynomial(
                    alg,
                    &values,
                    num_coefficients,
                    recipients,
                    dealer_index,
                    associated_data,
                    mega_seed,
                )?;

                let proof = ZkProof::ProofOfMaskedResharing(zk::ProofOfEqualOpenings::create(
                    seed.derive(&DomainSep::SeedForProofOfEqualOpenings(alg).to_string()),
                    alg,
                    secret,
                    masking,
                    associated_data,
                )?);

                (commitment, ciphertext, Some(proof))
            }
            SecretShares::UnmaskedTimesMasked(left_value, (right_value, right_masking)) => {
                if left_value.curve_type() != signature_curve
                    || right_value.curve_type() != signature_curve
                    || right_masking.curve_type() != signature_curve
                {
                    return Err(CanisterThresholdError::InvalidSecretShare);
                }

                // Generate secret polynomials
                let product = left_value.mul(right_value)?;

                let product_masking = EccScalar::random(signature_curve, &mut poly_rng);

                let values =
                    Polynomial::random_with_constant(&product, num_coefficients, &mut poly_rng)?;
                let mask = Polynomial::random_with_constant(
                    &product_masking,
                    num_coefficients,
                    &mut poly_rng,
                )?;

                let (ciphertext, commitment) = encrypt_and_commit_pair_of_polynomials(
                    alg,
                    &values,
                    &mask,
                    num_coefficients,
                    recipients,
                    dealer_index,
                    associated_data,
                    mega_seed,
                )?;

                let proof = ZkProof::ProofOfProduct(zk::ProofOfProduct::create(
                    seed.derive(&DomainSep::SeedForProofOfProduct(alg).to_string()),
                    alg,
                    left_value,
                    right_value,
                    right_masking,
                    &product,
                    &product_masking,
                    associated_data,
                )?);

                (commitment, ciphertext, Some(proof))
            }
        };

        Ok(Self {
            ciphertext,
            commitment,
            proof,
        })
    }

    pub fn publicly_verify(
        &self,
        key_curve: EccCurveType,
        alg: IdkgProtocolAlgorithm,
        transcript_type: &IDkgTranscriptOperationInternal,
        reconstruction_threshold: NumberOfNodes,
        dealer_index: NodeIndex,
        number_of_receivers: NumberOfNodes,
        associated_data: &[u8],
    ) -> CanisterThresholdResult<()> {
        if self.commitment.len() != reconstruction_threshold.get() as usize {
            return Err(CanisterThresholdError::InvalidCommitment);
        }

        let signature_curve = alg.curve();

        self.ciphertext.check_validity(
            alg,
            number_of_receivers.get() as usize,
            associated_data,
            dealer_index,
        )?;

        type Op = IDkgTranscriptOperationInternal;

        // Check that the proof type matches the transcript type, and verify the proof
        match (transcript_type, self.proof.as_ref()) {
            (Op::Random, None) => {
                self.commitment
                    .verify_is(PolynomialCommitmentType::Pedersen, signature_curve)?;
                self.ciphertext
                    .verify_is(MEGaCiphertextType::Pairs, key_curve, signature_curve)?;
                // no ZK proof for this transcript type
                Ok(())
            }
            (Op::RandomUnmasked, None) => {
                self.commitment
                    .verify_is(PolynomialCommitmentType::Simple, signature_curve)?;
                self.ciphertext.verify_is(
                    MEGaCiphertextType::Single,
                    key_curve,
                    signature_curve,
                )?;
                // no ZK proof for this transcript type
                Ok(())
            }
            (
                Op::ReshareOfMasked(previous_commitment),
                Some(ZkProof::ProofOfMaskedResharing(proof)),
            ) => {
                self.commitment
                    .verify_is(PolynomialCommitmentType::Simple, signature_curve)?;
                previous_commitment
                    .verify_is(PolynomialCommitmentType::Pedersen, signature_curve)?;
                self.ciphertext.verify_is(
                    MEGaCiphertextType::Single,
                    key_curve,
                    signature_curve,
                )?;

                proof.verify(
                    alg,
                    &previous_commitment.evaluate_at(dealer_index)?,
                    &self.commitment.constant_term(),
                    associated_data,
                )?;

                Ok(())
            }

            (Op::ReshareOfUnmasked(previous_commitment), None) => {
                self.commitment
                    .verify_is(PolynomialCommitmentType::Simple, signature_curve)?;
                previous_commitment.verify_is(PolynomialCommitmentType::Simple, signature_curve)?;
                self.ciphertext.verify_is(
                    MEGaCiphertextType::Single,
                    key_curve,
                    signature_curve,
                )?;

                match previous_commitment {
                    PolynomialCommitment::Pedersen(_) => {
                        return Err(CanisterThresholdError::UnexpectedCommitmentType)
                    }
                    PolynomialCommitment::Simple(c) => {
                        let constant_term = self.commitment.constant_term();

                        if c.evaluate_at(dealer_index)? != constant_term {
                            return Err(CanisterThresholdError::InvalidCommitment);
                        }
                    }
                }

                // no ZK proof for this transcript type
                Ok(())
            }
            (Op::UnmaskedTimesMasked(lhs, rhs), Some(ZkProof::ProofOfProduct(proof))) => {
                self.commitment
                    .verify_is(PolynomialCommitmentType::Pedersen, signature_curve)?;
                self.ciphertext
                    .verify_is(MEGaCiphertextType::Pairs, key_curve, signature_curve)?;
                lhs.verify_is(PolynomialCommitmentType::Simple, signature_curve)?;
                rhs.verify_is(PolynomialCommitmentType::Pedersen, signature_curve)?;

                proof.verify(
                    alg,
                    &lhs.evaluate_at(dealer_index)?,
                    &rhs.evaluate_at(dealer_index)?,
                    &self.commitment.constant_term(),
                    associated_data,
                )?;

                Ok(())
            }
            (_transcript_type, _proof) => Err(CanisterThresholdError::InvalidProof),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn privately_verify(
        &self,
        key_curve: EccCurveType,
        alg: IdkgProtocolAlgorithm,
        private_key: &MEGaPrivateKey,
        public_key: &MEGaPublicKey,
        associated_data: &[u8],
        dealer_index: NodeIndex,
        recipient_index: NodeIndex,
    ) -> CanisterThresholdResult<()> {
        let signature_curve = alg.curve();

        if private_key.curve_type() != key_curve || public_key.curve_type() != key_curve {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        if self.commitment.curve_type() != signature_curve {
            return Err(CanisterThresholdError::CurveMismatch);
        }

        let mega_type = match self.commitment.ctype() {
            PolynomialCommitmentType::Simple => MEGaCiphertextType::Single,
            PolynomialCommitmentType::Pedersen => MEGaCiphertextType::Pairs,
        };

        self.ciphertext
            .verify_is(mega_type, key_curve, signature_curve)?;

        let _opening = self.ciphertext.decrypt_and_check(
            alg,
            &self.commitment,
            associated_data,
            dealer_index,
            recipient_index,
            private_key,
            public_key,
        )?;

        Ok(())
    }

    pub fn serialize(&self) -> CanisterThresholdSerializationResult<Vec<u8>> {
        serde_cbor::to_vec(self).map_err(|e| {
            CanisterThresholdSerializationError(format!(
                "failed to serialize IDkgDealingInternal: {}",
                e
            ))
        })
    }

    pub fn deserialize(bytes: &[u8]) -> CanisterThresholdSerializationResult<Self> {
        serde_cbor::from_slice::<Self>(bytes).map_err(|e| {
            CanisterThresholdSerializationError(format!(
                "failed to deserialize IDkgDealingInternal: {}",
                e
            ))
        })
    }
}

impl TryFrom<&BatchSignedIDkgDealing> for IDkgDealingInternal {
    type Error = CanisterThresholdSerializationError;

    fn try_from(
        signed_dealing: &BatchSignedIDkgDealing,
    ) -> CanisterThresholdSerializationResult<Self> {
        Self::deserialize(&signed_dealing.idkg_dealing().internal_dealing_raw)
    }
}
