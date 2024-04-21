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

pub fn verify_bip340_signature_using_third_party(sec1_pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    use schnorr_fun::{
        fun::{marker::*, Point},
        Message, Schnorr, Signature,
    };
    use sha2::Sha256;

    let sig_array = <[u8; 64]>::try_from(sig).expect("signature is not 64 bytes");
    assert_eq!(sec1_pk.len(), 33);
    // The public key is a BIP-340 public key, which is a 32-byte
    // compressed public key ignoring the y coordinate in the first byte of the
    // SEC1 encoding.
    let bip340_pk_array = <[u8; 32]>::try_from(&sec1_pk[1..]).expect("public key is not 32 bytes");

    let schnorr = Schnorr::<Sha256>::verify_only();
    let public_key = Point::<EvenY, Public>::from_xonly_bytes(bip340_pk_array)
        .expect("failed to parse public key");
    let signature = Signature::<Public>::from_bytes(sig_array).unwrap();
    schnorr.verify(&public_key, Message::<Secret>::raw(msg), &signature)
}
