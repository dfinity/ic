use ic_crypto_internal_threshold_sig_ecdsa::{
    EccCurveType, EccPoint, EccScalar, PedersenCommitment, PolynomialCommitment,
    PolynomialCommitmentType, SimpleCommitment,
};
use rand::{CryptoRng, Rng};

/// Generates a random [`PolynomialCommitment`] of type `type` containing `num_points` [`EccPoints`].
pub fn random_polynomial_commitment<R: Rng + CryptoRng>(
    num_points: usize,
    r#type: PolynomialCommitmentType,
    curve_type: EccCurveType,
    rng: &mut R,
) -> PolynomialCommitment {
    let points = (0..num_points)
        .map(|_| EccPoint::mul_by_g(&EccScalar::random(curve_type, rng)))
        .collect();
    match r#type {
        PolynomialCommitmentType::Simple => PolynomialCommitment::from(SimpleCommitment { points }),
        PolynomialCommitmentType::Pedersen => {
            PolynomialCommitment::from(PedersenCommitment { points })
        }
    }
}
