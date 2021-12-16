use crate::*;

/// ECDSA signature verification
///
/// Check the ECDSA verification equation, including that r,s != 0
///
/// This function assumes the message has already been hashed with
/// some appropriate hash function. It requires that the hash function
/// produce an output equal in length to the curve order, eg for
/// secp256 some 256-bit hash such as SHA-256 is required. If a hashed
/// message that is too large or too small for the curve is provided,
/// the signature is rejected.
pub fn verify_signature(
    public_key: &EccPoint,
    hashed_message: &[u8],
    r_sig: &EccScalar,
    s_sig: &EccScalar,
) -> ThresholdEcdsaResult<bool> {
    if r_sig.is_zero() || s_sig.is_zero() {
        return Ok(false);
    }

    let curve_type = public_key.curve_type();
    let curve = EccCurve::new(curve_type);

    // ECDSA has special rules for converting the hash to a scalar,
    // when the hash is larger than the curve order. If this check is
    // removed make sure these conversions are implemented, and not
    // just doing a reduction mod order using from_bytes_wide
    if hashed_message.len() != curve_type.scalar_bytes() {
        return Ok(false);
    }

    // Even though the same size, the integer represenatation of the
    // message might be larger than the order, requiring a reduction.
    let msg = EccScalar::from_bytes_wide(curve_type, hashed_message)?;

    let s_inv = s_sig.invert()?;

    let u1 = msg.mul(&s_inv)?;
    let u2 = r_sig.mul(&s_inv)?;

    let rp = curve.generator_g()?.mul_points(&u1, public_key, &u2)?;

    if rp.is_infinity()? {
        return Ok(false);
    }

    let v = sign::ecdsa_conversion_function(&rp)?;

    Ok(v == *r_sig)
}
