use crate::*;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgMultiSignedDealing;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkProof {}

#[derive(Debug, Clone)]
pub enum SecretShares {
    Random,
    ReshareOfUnmasked(EccScalar),
    ReshareOfMasked(EccScalar, EccScalar),
    UnmaskedTimesMasked(EccScalar, (EccScalar, EccScalar)),
}

impl TryFrom<(&CommitmentOpeningBytes, Option<&CommitmentOpeningBytes>)> for SecretShares {
    type Error = ThresholdEcdsaError;

    fn try_from(
        commitments: (&CommitmentOpeningBytes, Option<&CommitmentOpeningBytes>),
    ) -> ThresholdEcdsaResult<Self> {
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
            _ => Err(ThresholdEcdsaError::SerializationError(
                "inconsistent combination of commitment types".to_string(),
            )),
        }
    }
}

fn encrypt_and_commit_single_polynomial(
    poly: &Polynomial,
    num_coefficients: usize,
    recipients: &[MEGaPublicKey],
    dealer_index: usize,
    associated_data: &[u8],
    seed: Seed,
) -> ThresholdEcdsaResult<(MEGaCiphertext, PolynomialCommitment)> {
    let curve = poly.curve_type();

    let mut plaintexts = Vec::with_capacity(recipients.len());

    for (idx, _recipient) in recipients.iter().enumerate() {
        let scalar = EccScalar::from_u64(curve, (idx as u64) + 1);
        let v_s = poly.evaluate_at(&scalar)?;
        plaintexts.push(v_s)
    }

    let ciphertext =
        mega_encrypt_single(seed, &plaintexts, recipients, dealer_index, associated_data)?;

    let commitment = SimpleCommitment::create(poly, num_coefficients)?;

    Ok((ciphertext.into(), commitment.into()))
}

fn encrypt_and_commit_pair_of_polynomials(
    values: &Polynomial,
    mask: &Polynomial,
    num_coefficients: usize,
    recipients: &[MEGaPublicKey],
    dealer_index: usize,
    associated_data: &[u8],
    seed: Seed,
) -> ThresholdEcdsaResult<(MEGaCiphertext, PolynomialCommitment)> {
    let curve = values.curve_type();

    let mut plaintexts = Vec::with_capacity(recipients.len());

    for (idx, _recipient) in recipients.iter().enumerate() {
        let scalar = EccScalar::from_u64(curve, (idx as u64) + 1);
        let v_s = values.evaluate_at(&scalar)?;
        let m_s = mask.evaluate_at(&scalar)?;
        plaintexts.push((v_s, m_s))
    }

    let ciphertext =
        mega_encrypt_pair(seed, &plaintexts, recipients, dealer_index, associated_data)?;

    let commitment = PedersenCommitment::create(values, mask, num_coefficients)?;

    Ok((ciphertext.into(), commitment.into()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDkgDealingInternal {
    pub ciphertext: MEGaCiphertext,
    pub commitment: PolynomialCommitment,
    pub proof: Option<ZkProof>,
}

impl IDkgDealingInternal {
    pub fn new(
        shares: &SecretShares,
        curve: EccCurveType,
        seed: Seed,
        threshold: usize,
        recipients: &[MEGaPublicKey],
        dealer_index: usize,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<Self> {
        if threshold == 0 || threshold > recipients.len() {
            return Err(ThresholdEcdsaError::InvalidThreshold(
                threshold,
                recipients.len(),
            ));
        }

        for recipient in recipients {
            if recipient.curve_type() != curve {
                return Err(ThresholdEcdsaError::InvalidRecipients);
            }
        }

        let num_coefficients = threshold;

        let mut poly_rng = seed
            .derive("ic-crypto-tecdsa-create-dealing-polynomials")
            .into_rng();

        let mega_seed = seed.derive("ic-crypto-tecdsa-create-dealing-mega-encrypt");

        let (commitment, ciphertext, proof) = match shares {
            SecretShares::Random => {
                let values = Polynomial::random(curve, num_coefficients, &mut poly_rng)?; // omega in paper
                let mask = Polynomial::random(curve, num_coefficients, &mut poly_rng)?; // omega' in paper

                let (ciphertext, commitment) = encrypt_and_commit_pair_of_polynomials(
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
            SecretShares::ReshareOfUnmasked(secret) => {
                if secret.curve_type() != curve {
                    return Err(ThresholdEcdsaError::InvalidSecretShare);
                }

                let values =
                    Polynomial::random_with_constant(*secret, num_coefficients, &mut poly_rng)?;

                let (ciphertext, commitment) = encrypt_and_commit_single_polynomial(
                    &values,
                    num_coefficients,
                    recipients,
                    dealer_index,
                    associated_data,
                    mega_seed,
                )?;

                let proof = None; // TODO(CRP-1158)

                (commitment, ciphertext, proof)
            }
            SecretShares::ReshareOfMasked(secret, masking) => {
                if secret.curve_type() != curve || masking.curve_type() != curve {
                    return Err(ThresholdEcdsaError::InvalidSecretShare);
                }

                let values =
                    Polynomial::random_with_constant(*secret, num_coefficients, &mut poly_rng)?;

                let (ciphertext, commitment) = encrypt_and_commit_single_polynomial(
                    &values,
                    num_coefficients,
                    recipients,
                    dealer_index,
                    associated_data,
                    mega_seed,
                )?;

                // Compute zk proof
                // Note that `masking` will be used here as part of the witness
                let proof = None; // TODO(CRP-1158)

                (commitment, ciphertext, proof)
            }
            SecretShares::UnmaskedTimesMasked(left_value, (right_value, right_masking)) => {
                if left_value.curve_type() != curve
                    || right_value.curve_type() != curve
                    || right_masking.curve_type() != curve
                {
                    return Err(ThresholdEcdsaError::InvalidSecretShare);
                }

                // Generate secret polynomials
                let product = left_value.mul(right_value)?;
                let values =
                    Polynomial::random_with_constant(product, num_coefficients, &mut poly_rng)?;
                let mask = Polynomial::random(curve, num_coefficients, &mut poly_rng)?;

                let (ciphertext, commitment) = encrypt_and_commit_pair_of_polynomials(
                    &values,
                    &mask,
                    num_coefficients,
                    recipients,
                    dealer_index,
                    associated_data,
                    mega_seed,
                )?;

                // Compute zk proof
                // Note that `right_masking` will be used here as part of the witness
                let proof = None; // TODO(CRP-1158)

                (commitment, ciphertext, proof)
            }
        };

        Ok(Self {
            ciphertext,
            commitment,
            proof,
        })
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

impl TryFrom<&IDkgMultiSignedDealing> for IDkgDealingInternal {
    type Error = ThresholdEcdsaError;

    fn try_from(signed_dealing: &IDkgMultiSignedDealing) -> ThresholdEcdsaResult<Self> {
        Self::deserialize(&signed_dealing.dealing.dealing.internal_dealing_raw)
    }
}
