use ic_crypto_internal_threshold_sig_ecdsa::*;
use rand::RngCore;

fn random_field_element(curve_type: EccCurveType) -> EccFieldElement {
    let mut rng = rand::thread_rng();

    let mut buf = vec![0u8; curve_type.field_bytes()];

    loop {
        rng.fill_bytes(&mut buf);
        if let Ok(fe) = EccFieldElement::from_bytes(curve_type, &buf) {
            return fe;
        }
    }
}

#[test]
fn test_one_minus_one_is_zero() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        let one = EccFieldElement::one(curve_type);
        let neg_one = one.negate()?;
        let zero = one.add(&neg_one).unwrap();
        assert!(bool::from(zero.is_zero()));
    }
    Ok(())
}

#[test]
fn test_one_from_bytes_eq_one() -> Result<(), ThresholdEcdsaError> {
    let ones = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];
    for curve_type in EccCurveType::all() {
        let one = EccFieldElement::one(curve_type);
        let one_from_bytes = EccFieldElement::from_bytes(curve_type, &ones)?;
        let one_from_bytes_wide = EccFieldElement::from_bytes_wide(curve_type, &ones)?;

        assert_eq!(one, one_from_bytes);
        assert_eq!(one, one_from_bytes_wide);
    }
    Ok(())
}

#[test]
fn test_x_minus_x_is_zero() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        for _trial in 0..100 {
            let val = random_field_element(curve_type);
            let neg_val = val.negate()?;
            let maybe_zero = val.add(&neg_val)?;
            assert!(bool::from(maybe_zero.is_zero()));

            let maybe_zero = neg_val.add(&val)?;
            assert!(bool::from(maybe_zero.is_zero()));

            let maybe_zero = val.sub(&val)?;
            assert!(bool::from(maybe_zero.is_zero()));
        }
    }
    Ok(())
}

#[test]
fn test_neg_one_x_neg_one_is_one() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        let one = EccFieldElement::one(curve_type);
        let neg_one = one.negate()?;
        let should_be_one = neg_one.mul(&neg_one).unwrap();
        assert_eq!(one, should_be_one);
    }
    Ok(())
}

#[test]
fn test_ct_assign_is_conditional() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        let fe1 = random_field_element(curve_type);
        let fe2 = random_field_element(curve_type);

        let mut dest = fe1;
        dest.ct_assign(&fe2, subtle::Choice::from(0u8))?;
        assert_eq!(dest, fe1);

        dest.ct_assign(&fe2, subtle::Choice::from(1u8))?;
        assert_eq!(dest, fe2);
    }
    Ok(())
}

#[test]
fn test_from_bytes_is_inverse_of_as_bytes() {
    let mut rng = rand::thread_rng();

    for curve_type in EccCurveType::all() {
        for _trial in 0..1000 {
            let mut buf = vec![0u8; curve_type.field_bytes()];
            rng.fill_bytes(&mut buf);
            if let Ok(fe) = EccFieldElement::from_bytes(curve_type, &buf) {
                assert_eq!(hex::encode(buf), hex::encode(fe.as_bytes()));
            }
        }
    }
}

#[test]
fn test_inverse_is_correct() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        let one = EccFieldElement::one(curve_type);

        for _trial in 0..100 {
            let fe = random_field_element(curve_type);
            let fe_inv = fe.invert();

            /*
            fe * fe^-1 should always be one unless fe is zero in which
            case fe^-1 is also zero
             */

            if bool::from(fe_inv.is_zero()) {
                assert!(bool::from(fe.is_zero()));
            } else {
                let fe_t_inv = fe.mul(&fe_inv)?;
                assert_eq!(fe_t_inv, one);
            }
        }
    }

    Ok(())
}

#[test]
fn test_inverse_of_zero_is_zero() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        let zero = EccFieldElement::zero(curve_type);
        assert!(bool::from(zero.invert().is_zero()));
    }

    Ok(())
}

#[test]
fn test_inverse_of_one_is_one() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        let one = EccFieldElement::one(curve_type);
        assert_eq!(one.invert(), one);
    }

    Ok(())
}

#[test]
fn test_sqrt_is_consistent_with_math() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        for _trial in 0..100 {
            let fe = random_field_element(curve_type);
            let (valid, fe_sqrt) = fe.sqrt();

            /*
             * For primes == 3 (mod 4) exactly one of x and -x has a square
             * root modulo p. All currently supported primes have this form,
             * so verify that this is true.
             *
             * This test would have to be ammended if support is later added
             * for a prime field == 1 (mod 4)
             */
            if !bool::from(valid) {
                let fe_neg = fe.negate()?;

                let (valid, _fe_neg_sqrt) = fe_neg.sqrt();
                assert!(bool::from(valid));
            } else {
                // sqrt*sqrt should equal the original element
                assert_eq!(fe_sqrt.mul(&fe_sqrt)?, fe);
            }
        }
    }

    Ok(())
}

#[test]
fn test_ab_values_are_correct() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        /*
        Test that a,b params are correct by choosing a random field element x
        then computing an affine point (x,y) using y = sqrt(x**3 + ax + b)
        and checking that the point decodes successfully.
         */

        let a = EccFieldElement::a(curve_type);
        let b = EccFieldElement::b(curve_type);

        loop {
            let x = random_field_element(curve_type);

            let x3 = x.mul(&x)?.mul(&x)?;
            let ax = x.mul(&a)?;

            let x3_ax_b = x3.add(&ax)?.add(&b)?;

            let (valid_y, y) = x3_ax_b.sqrt();

            if !bool::from(valid_y) {
                // turned out we picked an x that is not valid - retry
                continue;
            }

            let pt = EccPoint::from_field_elems(&x, &y);
            assert!(pt.is_ok());
            break;
        }
    }

    Ok(())
}

#[test]
fn test_sswu_z_values_are_correct() -> Result<(), ThresholdEcdsaError> {
    fn sswu_z_value(curve_type: EccCurveType) -> i32 {
        let one = EccFieldElement::one(curve_type);
        let mut z = EccFieldElement::sswu_z(curve_type);

        /*
        SSWU z value is always chosen to be the smallest acceptable value.
        This test assumes that z is negative, which is true for p256 and k256.
        It would have to be modified if support for a curve with positive Z
        is added.
         */

        let mut cnt = 0;

        while !bool::from(z.is_zero()) {
            z = z.add(&one).expect("Add failed");
            cnt += 1;
        }

        -cnt
    }

    assert_eq!(sswu_z_value(EccCurveType::P256), -10);
    assert_eq!(sswu_z_value(EccCurveType::K256), -11);

    Ok(())
}

#[test]
fn test_sswu_c2_values_are_correct() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        let z = EccFieldElement::sswu_z(curve_type);
        let c2 = EccFieldElement::sswu_c2(curve_type);
        let neg_z = z.negate()?;
        let (_, sqrt_neg_z) = neg_z.sqrt();
        assert_eq!(c2, sqrt_neg_z);
    }

    Ok(())
}

#[test]
fn test_from_bytes_of_max_integer_rejected() -> Result<(), ThresholdEcdsaError> {
    for curve_type in EccCurveType::all() {
        let field_len = (curve_type.field_bits() + 7) / 8;
        let too_large = vec![0xFF; field_len];
        assert!(EccFieldElement::from_bytes(curve_type, &too_large).is_err());
    }

    Ok(())
}
