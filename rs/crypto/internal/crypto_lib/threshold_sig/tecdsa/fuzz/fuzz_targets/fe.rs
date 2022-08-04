#![no_main]
use libfuzzer_sys::fuzz_target;

use ic_crypto_internal_threshold_sig_ecdsa::*;
use num_bigint::BigUint;

/*
The fe-derive macro defines arithmetic types for operating in the fields defined
by the integers modulo the prime of P-256 and K-256. Compare their arithmetic
results against a generic biginteger implementation of the same operation.
*/

fn prime_for(curve: EccCurveType) -> BigUint {
    match curve {
        EccCurveType::P256 => BigUint::parse_bytes(
            b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap(),
        EccCurveType::K256 => BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        )
        .unwrap(),
    }
}

// Format a BigUint in the fixed-length SEC1 format
fn format_bn(bn: &BigUint) -> String {
    let field_bytes = 32;

    // Include leading zeros
    let bn_bytes = bn.to_bytes_be();

    assert!(bn_bytes.len() <= field_bytes);

    let padding_bytes = field_bytes - bn_bytes.len();

    hex::encode(vec![0u8; padding_bytes]) + &hex::encode(bn_bytes)
}

fn assert_fe_eq(fe: &EccFieldElement, bn: &BigUint) {
    assert_eq!(hex::encode(fe.as_bytes()), format_bn(bn));
}

/*
Test field element inversion and sqrt

If the element is not zero, invert it

Multiply the inverse by the original input - it must be equal to 1

Sqrt the element. If it exists, then verify that -element does not
have a valid square root. (This is specific for p == 3 mod 4 and may
need adjustment if other curves are added)
*/
fn check_field_inversion_and_sqrt(fe: &EccFieldElement) -> ThresholdEcdsaResult<()> {
    if !bool::from(fe.is_zero()) {
        let fe_inv = fe.invert();
        let maybe_one = fe_inv.mul(fe)?;
        assert_eq!(maybe_one, EccFieldElement::one(fe.curve_type()));

        let fe_sqrt = fe.sqrt();
        if bool::from(fe_sqrt.0) {
            assert!(!bool::from(fe.negate().unwrap().sqrt().0));
        }
    }
    Ok(())
}

fn fe_fuzz_run(curve_type: EccCurveType, data: &[u8]) -> Result<(), ThresholdEcdsaError> {
    let prime = prime_for(curve_type);

    let few = EccFieldElement::from_bytes_wide(curve_type, data).unwrap();
    let refw = BigUint::from_bytes_be(data) % &prime;

    assert_fe_eq(&few, &refw);

    let fe1_bits = &data[..32];
    let fe2_bits = &data[32..];

    let ref1 = BigUint::from_bytes_be(fe1_bits);
    let ref2 = BigUint::from_bytes_be(fe2_bits);

    let fe1 = EccFieldElement::from_bytes(curve_type, fe1_bits);
    let fe2 = EccFieldElement::from_bytes(curve_type, fe2_bits);

    let fe1w = EccFieldElement::from_bytes_wide(curve_type, fe1_bits).unwrap();
    let fe2w = EccFieldElement::from_bytes_wide(curve_type, fe2_bits).unwrap();

    match (fe1, fe2) {
        (Ok(fe1), Ok(fe2)) => {
            assert_eq!(hex::encode(fe1.as_bytes()), hex::encode(fe1_bits));
            assert_eq!(hex::encode(fe2.as_bytes()), hex::encode(fe2_bits));

            assert_eq!(hex::encode(fe1w.as_bytes()), hex::encode(fe1_bits));
            assert_eq!(hex::encode(fe2w.as_bytes()), hex::encode(fe2_bits));

            // Check field addition:
            let ref_sum = (&ref1 + &ref2) % &prime;
            assert_fe_eq(&fe1.add(&fe2)?, &ref_sum);

            // Check field subtraction:
            let ref_sub = ((&prime + &ref1) - &ref2) % &prime;
            assert_fe_eq(&fe1.sub(&fe2)?, &ref_sub);

            // Check field multiplication:
            let ref_mul = (&ref1 * &ref2) % &prime;
            assert_fe_eq(&fe1.mul(&fe2)?, &ref_mul);

            // Check field inversion and square root
            check_field_inversion_and_sqrt(&fe1)?;
            check_field_inversion_and_sqrt(&fe2)?;
        }

        (_, _) => {
            // If this failed one or both should be out of range
            assert!(ref1 >= prime || ref2 >= prime);
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    if data.len() != 64 {
        return;
    }

    let _ = fe_fuzz_run(EccCurveType::K256, data);
    let _ = fe_fuzz_run(EccCurveType::P256, data);
});
