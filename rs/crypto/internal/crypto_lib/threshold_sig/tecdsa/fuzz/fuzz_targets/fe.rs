#![no_main]
use libfuzzer_sys::fuzz_target;

use num_bigint::BigUint;
use tecdsa::*;

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

fn format_bn(bn: &BigUint) -> String {
    // Include leading zeros
    let bn_bytes = bn.to_bytes_be();

    assert!(bn_bytes.len() <= 32);

    let padding_bytes = 32 - bn_bytes.len();

    hex::encode(vec![0u8; padding_bytes]) + &hex::encode(bn_bytes)
}

fn fe_fuzz_run(curve_type: EccCurveType, data: &[u8]) -> Result<(), ThresholdEcdsaError> {
    let prime = prime_for(curve_type);

    let few = EccFieldElement::from_bytes_wide(curve_type, data).unwrap();
    let refw = BigUint::from_bytes_be(data) % &prime;

    assert_eq!(hex::encode(few.as_bytes()), format_bn(&refw));

    let one = EccFieldElement::one(curve_type);

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

            let fe_sum = fe1.add(&fe2)?;
            let ref_sum = (&ref1 + &ref2) % &prime;
            assert_eq!(hex::encode(fe_sum.as_bytes()), format_bn(&ref_sum));

            let fe_sub = fe1.sub(&fe2)?;
            let ref_sub = ((&prime + &ref1) - &ref2) % &prime;
            assert_eq!(hex::encode(fe_sub.as_bytes()), format_bn(&ref_sub));

            let fe_mul = fe1.mul(&fe2)?;
            let ref_mul = (&ref1 * &ref2) % &prime;
            assert_eq!(hex::encode(fe_mul.as_bytes()), format_bn(&ref_mul));

            if fe1.is_zero() == false {
                let fe1_inv = fe1.invert();
                let maybe_one = fe1_inv.mul(&fe1)?;
                assert_eq!(maybe_one, one);

                let fe1_sqrt = fe1.sqrt();
                if fe1_sqrt.is_zero() {
                    assert!(!fe1.negate().unwrap().sqrt().is_zero());
                }
            }

            if fe2.is_zero() == false {
                let fe2_inv = fe2.invert();
                let maybe_one = fe2_inv.mul(&fe2)?;
                assert_eq!(maybe_one, one);

                let fe2_sqrt = fe2.sqrt();
                if fe2_sqrt.is_zero() {
                    assert!(!fe2.negate().unwrap().sqrt().is_zero());
                }
            }
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
