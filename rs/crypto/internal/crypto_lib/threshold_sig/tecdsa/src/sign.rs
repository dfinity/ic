use crate::DerivationPath;
use crate::*;

// This is the conversion function used by ECDSA which returns the
// x-coordinate of a point reduced modulo the modulus of the scalar
// field.
pub(crate) fn ecdsa_conversion_function(pt: &EccPoint) -> ThresholdEcdsaResult<EccScalar> {
    let x = pt.affine_x()?;
    let x_bytes = x.as_bytes();
    EccScalar::from_bytes_wide(pt.curve_type(), &x_bytes)
}

fn derive_rho(
    curve_type: EccCurveType,
    hashed_message: &[u8],
    randomness: &Randomness,
    derivation_path: &DerivationPath,
    key_transcript: &IDkgTranscriptInternal,
    presig_transcript: &IDkgTranscriptInternal,
) -> ThresholdEcdsaResult<(EccScalar, EccScalar, EccScalar)> {
    let pre_sig = match &presig_transcript.combined_commitment {
        CombinedCommitment::ByInterpolation(PolynomialCommitment::Simple(c)) => c.constant_term(),
        _ => return Err(ThresholdEcdsaError::InconsistentCommitments),
    };

    if pre_sig.curve_type() != curve_type {
        return Err(ThresholdEcdsaError::InconsistentCommitments);
    }

    let (key_tweak, _chain_key) = derivation_path.derive_tweak(&key_transcript.constant_term())?;

    let mut ro = ro::RandomOracle::new("ic-crypto-tecdsa-rerandomize-presig");
    ro.add_bytestring("randomness", &randomness.get())?;
    ro.add_bytestring("hashed_message", hashed_message)?;
    ro.add_point("pre_sig", &pre_sig)?;
    ro.add_scalar("key_tweak", &key_tweak)?;
    let randomizer = ro.output_scalar(curve_type)?;

    // Rerandomize presignature
    let randomized_pre_sig =
        pre_sig.add_points(&EccPoint::generator_g(curve_type)?.scalar_mul(&randomizer)?)?;

    let rho = ecdsa_conversion_function(&randomized_pre_sig)?;

    Ok((rho, key_tweak, randomizer))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdEcdsaSigShareInternal {
    sigma_numerator: CommitmentOpening,
    sigma_denominator: CommitmentOpening,
}

impl ThresholdEcdsaSigShareInternal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        derivation_path: &DerivationPath,
        hashed_message: &[u8],
        randomness: Randomness,
        key_transcript: &IDkgTranscriptInternal,
        presig_transcript: &IDkgTranscriptInternal,
        lambda: &CommitmentOpening,
        kappa_times_lambda: &CommitmentOpening,
        key_times_lambda: &CommitmentOpening,
        curve_type: EccCurveType,
    ) -> ThresholdEcdsaResult<Self> {
        let (rho, key_tweak, randomizer) = derive_rho(
            curve_type,
            hashed_message,
            &randomness,
            derivation_path,
            key_transcript,
            presig_transcript,
        )?;

        // Compute the message represenative from the hash, which may require
        // a reduction if int(hashed_message) >= group_order
        let e = EccScalar::from_bytes_wide(curve_type, hashed_message)?;

        let theta = e.add(&rho.mul(&key_tweak)?)?;

        let (lambda_value, lambda_mask) = match lambda {
            CommitmentOpening::Pedersen(lambda_value, lambda_mask) => (lambda_value, lambda_mask),
            _ => return Err(ThresholdEcdsaError::InconsistentCommitments),
        };

        // Compute shares of sigma's numerator, i.e. openings of
        // [nu] = theta*[lambda] + rho*[key_times_lambda]
        let nu = match key_times_lambda {
            CommitmentOpening::Pedersen(value, mask) => {
                let nu_value = theta.mul(lambda_value)?.add(&rho.mul(value)?)?;
                let nu_mask = theta.mul(lambda_mask)?.add(&rho.mul(mask)?)?;
                CommitmentOpening::Pedersen(nu_value, nu_mask)
            }
            _ => return Err(ThresholdEcdsaError::InconsistentCommitments),
        };

        // Compute shares of sigma's denominator, i.e. openings of
        // [mu] = randomizer*[lambda] + [kappa_times_lambda]
        let mu = match kappa_times_lambda {
            CommitmentOpening::Pedersen(value, mask) => {
                let mu_value = randomizer.mul(lambda_value)?.add(value)?;
                let mu_mask = randomizer.mul(lambda_mask)?.add(mask)?;
                CommitmentOpening::Pedersen(mu_value, mu_mask)
            }
            _ => return Err(ThresholdEcdsaError::InconsistentCommitments),
        };

        Ok(Self {
            sigma_numerator: nu,
            sigma_denominator: mu,
        })
    }

    /// Verify a signature share
    ///
    /// This function returns Ok(true) if the share seems completely valid,
    /// Ok(false) if the commitment values are incorrect, and some Err if the
    /// share is otherwise invalid, for instance because one of the values
    /// is a point for another elliptic curve, or if the wrong commitment
    /// type was included in a transcript.
    #[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    pub fn verify(
        &self,
        derivation_path: &DerivationPath,
        hashed_message: &[u8],
        randomness: Randomness,
        signer_index: NodeIndex,
        key_transcript: &IDkgTranscriptInternal,
        presig_transcript: &IDkgTranscriptInternal,
        lambda: &IDkgTranscriptInternal,
        kappa_times_lambda: &IDkgTranscriptInternal,
        key_times_lambda: &IDkgTranscriptInternal,
        curve_type: EccCurveType,
    ) -> ThresholdEcdsaResult<bool> {
        // Compute rho and tweak
        let (rho, key_tweak, randomizer) = derive_rho(
            curve_type,
            hashed_message,
            &randomness,
            derivation_path,
            key_transcript,
            presig_transcript,
        )?;

        // Compute theta
        let e = EccScalar::from_bytes_wide(curve_type, hashed_message)?;

        let theta = e.add(&rho.mul(&key_tweak)?)?;

        // Evaluate commitments at the receiver index
        let lambda_j = lambda.evaluate_at(signer_index)?;
        let kappa_times_lambda_j = kappa_times_lambda.evaluate_at(signer_index)?;
        let key_times_lambda_j = key_times_lambda.evaluate_at(signer_index)?;

        let sigma_num = lambda_j
            .scalar_mul(&theta)?
            .add_points(&key_times_lambda_j.scalar_mul(&rho)?)?;

        let sigma_den = lambda_j
            .scalar_mul(&randomizer)?
            .add_points(&kappa_times_lambda_j)?;

        match self.sigma_numerator {
            CommitmentOpening::Pedersen(v, m) => {
                if sigma_num != EccPoint::pedersen(&v, &m)? {
                    return Ok(false);
                }
            }
            _ => return Err(ThresholdEcdsaError::InconsistentCommitments),
        }

        match self.sigma_denominator {
            CommitmentOpening::Pedersen(v, m) => {
                if sigma_den != EccPoint::pedersen(&v, &m)? {
                    return Ok(false);
                }
            }
            _ => return Err(ThresholdEcdsaError::InconsistentCommitments),
        }

        Ok(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdEcdsaCombinedSigInternal {
    r: EccScalar,
    s: EccScalar,
}

impl ThresholdEcdsaCombinedSigInternal {
    pub fn serialize(&self) -> Vec<u8> {
        // EccScalar::serialize uses fixed length encoding
        let r_bytes = self.r.serialize();
        let s_bytes = self.s.serialize();

        let mut sig = Vec::with_capacity(r_bytes.len() + s_bytes.len());
        sig.extend_from_slice(&r_bytes);
        sig.extend_from_slice(&s_bytes);
        sig
    }
}

impl ThresholdEcdsaCombinedSigInternal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        derivation_path: &DerivationPath,
        hashed_message: &[u8],
        randomness: Randomness,
        key_transcript: &IDkgTranscriptInternal,
        presig_transcript: &IDkgTranscriptInternal,
        reconstruction_threshold: NumberOfNodes,
        sig_shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
        curve_type: EccCurveType,
    ) -> ThresholdEcdsaResult<Self> {
        let reconstruction_threshold = reconstruction_threshold.get() as usize;
        if sig_shares.len() < reconstruction_threshold {
            return Err(ThresholdEcdsaError::InsufficientDealings);
        }

        let (rho, _key_tweak, _randomizer) = derive_rho(
            curve_type,
            hashed_message,
            &randomness,
            derivation_path,
            key_transcript,
            presig_transcript,
        )?;

        // Compute sigma's numerator via interpolation
        let mut numerator_samples = Vec::with_capacity(reconstruction_threshold);
        let mut denominator_samples = Vec::with_capacity(reconstruction_threshold);

        for (index, sig_share) in sig_shares.iter().take(reconstruction_threshold) {
            let index = EccScalar::from_node_index(curve_type, *index);

            // Reconstruction of the signature share does not require recombining the
            // masking values.
            if let CommitmentOpening::Pedersen(c, _) = sig_share.sigma_numerator {
                numerator_samples.push((index, c));
            } else {
                return Err(ThresholdEcdsaError::InconsistentCommitments);
            }

            if let CommitmentOpening::Pedersen(c, _) = sig_share.sigma_denominator {
                denominator_samples.push((index, c));
            } else {
                return Err(ThresholdEcdsaError::InconsistentCommitments);
            }
        }

        let numerator = EccScalar::interpolation_at_zero(&numerator_samples)?;
        let denominator = EccScalar::interpolation_at_zero(&denominator_samples)?;

        let sigma = numerator.mul(&denominator.invert()?)?;

        // Always use the smaller value of s
        let norm_sigma = if sigma.is_high() {
            sigma.negate()
        } else {
            sigma
        };

        Ok(Self {
            r: rho,
            s: norm_sigma,
        })
    }

    /// Verify a threshold ECDSA signature
    ///
    /// This not only verifies the basic signature equation but also that
    /// it was generated with a particular presignature transcript.
    ///
    /// It also verifies that s is normalized to be in [0,n/2) following
    /// the malleability prevention approach of BTC/ETH.
    ///
    /// This function returns Ok(true) if the signature seems completely
    /// valid, Ok(false) if something was wrong the the signature itself
    /// (wrong rho, `s` too large, or the ECDSA equation fails to verify),
    /// or some Err if the signature or parameters are otherwise invalid,
    /// for instance because one of the values is on the wrong curve.
    pub fn verify(
        &self,
        derivation_path: &DerivationPath,
        hashed_message: &[u8],
        randomness: Randomness,
        presig_transcript: &IDkgTranscriptInternal,
        key_transcript: &IDkgTranscriptInternal,
        curve_type: EccCurveType,
    ) -> ThresholdEcdsaResult<bool> {
        let (rho, key_tweak, _) = derive_rho(
            curve_type,
            hashed_message,
            &randomness,
            derivation_path,
            key_transcript,
            presig_transcript,
        )?;

        if self.r != rho {
            return Ok(false);
        }

        // We require s normalization for all curves
        if self.s.is_high() {
            return Ok(false);
        }

        let master_public_key = key_transcript.constant_term();
        let tweak_g = EccPoint::mul_by_g(&key_tweak)?;
        let public_key = tweak_g.add_points(&master_public_key)?;

        ecdsa::verify_signature(&public_key, hashed_message, &self.r, &self.s)
    }
}

pub fn derive_public_key(
    key_transcript: &IDkgTranscriptInternal,
    derivation_path: &DerivationPath,
    algorithm_id: AlgorithmId,
) -> ThresholdEcdsaResult<EcdsaPublicKey> {
    // Compute tweak
    let (key_tweak, chain_key) = derivation_path.derive_tweak(&key_transcript.constant_term())?;

    let master_public_key = key_transcript.constant_term();
    let tweak_g = EccPoint::mul_by_g(&key_tweak)?;
    let public_key = tweak_g.add_points(&master_public_key)?;

    Ok(EcdsaPublicKey {
        algorithm_id,
        public_key: public_key.serialize(),
        chain_key,
    })
}
