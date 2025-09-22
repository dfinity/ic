use super::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;

fn to_i8_at_pos(naf: &Naf, i: usize) -> i8 {
    let get_bit = |bytes: &[u8]| {
        if i > (naf.positive_bits.len() * 8) {
            panic!(
                "Out of bounds: accessing bit {i} in a buffer containing {} bits",
                naf.positive_bits.len() * 8
            )
        }
        let target_byte = bytes[i / 8];
        let target_bit = (target_byte >> (i % 8)) & 1;
        target_bit == 1
    };
    let p = get_bit(&naf.positive_bits[..]);
    let n = get_bit(&naf.negative_bits[..]);

    match (p, n) {
        (false, true) => -1i8,
        (false, false) => 0i8,
        (true, false) => 1i8,
        (true, true) => panic!("NAF is true for both positive and negative bit at position {i}"),
    }
}

#[test]
fn test_range_to_i8_is_correct() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();
    for curve_type in EccCurveType::all() {
        let scalars: Vec<EccScalar> = (0..10)
            .map(|_| EccScalar::random(curve_type, rng))
            .collect();
        let nafs: Vec<Naf> = scalars.iter().map(Naf::from_scalar_vartime).collect();
        for naf in nafs {
            // tests 1000 ranges for each scalar
            for _iteration in 0..1000 {
                // generate a random position that is in bounds
                let pos = rng.gen_range(0..naf.bit_len());
                // generate a random length
                let len = rng.gen_range(1..std::cmp::min(8, naf.bit_len() - pos + 1));
                let computed_result = naf.range_as_i8(pos, len);
                // compute the expected result by pulling and aggregating single bits
                let mut expected_result = 0i8;
                for i in (pos..(pos + len)).rev() {
                    expected_result = expected_result * 2 + to_i8_at_pos(&naf, i);
                }
                assert_eq!(computed_result, expected_result);
            }
        }
    }
    Ok(())
}

/// Converts NAF to an instance of `R`, e.g., `i32`.
fn naf_reconstruction_helper<R: num_traits::int::PrimInt>(naf: &Naf) -> R {
    let bit_len = naf.positive_bits.len() * 8;
    let one: R = R::one();
    let mut result: R = R::zero();
    for i in 0..bit_len {
        // `value_j` is in [-1, 0, 1]
        let value_j = to_i8_at_pos(naf, i);
        match value_j {
            -1i8 => result = result - (one << i),
            0i8 => {}
            1i8 => result = result + (one << i),
            _ => panic!("this should never happen"),
        };
    }
    result
}

macro_rules! non_adjacent_form_transformation_is_correct_full_domain_test_factory {
    // $t is the input type
    // $r is the result type
    ($t:ty, $r:ty) => {
        ::paste::paste! {
            #[test]
                pub fn [<non_adjacent_form_transformation_is_correct_ $t _full_domain>]() -> CanisterThresholdResult<()> {
                let scalars: Vec<$t> = ($t::MIN..=$t::MAX).collect();
                let naf: Vec<Naf> = scalars
                    .iter()
                    .map(|x| Naf::from_be_bytes_vartime(&x.to_be_bytes()))
                    .collect();
                for i in 0..scalars.len() {
                    let result = naf_reconstruction_helper::<$r>(&naf[i]);
                    assert_eq!(result, scalars[i] as $r);
                }
                Ok(())
            }
        }
    };
}

// test NAF transformation for the full domatin of u8 and u16, respectively
non_adjacent_form_transformation_is_correct_full_domain_test_factory!(u8, i16);
non_adjacent_form_transformation_is_correct_full_domain_test_factory!(u16, i32);

#[test]
fn non_adjacent_form_transformation_is_correct_u64_random_samples() -> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();
    let scalars: Vec<u64> = (0..10000).map(|_| rng.next_u64()).collect();
    let naf: Vec<Naf> = scalars
        .iter()
        .map(|x| Naf::from_be_bytes_vartime(&x.to_be_bytes()))
        .collect();
    for i in 0..scalars.len() {
        let result = naf_reconstruction_helper::<i128>(&naf[i]);
        assert_eq!(result, scalars[i] as i128);
    }
    Ok(())
}

#[test]
fn non_adjacent_form_transformation_is_correct_ecc_scalar_random_samples()
-> CanisterThresholdResult<()> {
    let rng = &mut reproducible_rng();
    for curve_type in EccCurveType::all() {
        let scalars: Vec<EccScalar> = (0..1000)
            .map(|_| EccScalar::random(curve_type, rng))
            .collect();
        let naf: Vec<Naf> = scalars.iter().map(Naf::from_scalar_vartime).collect();
        let two = EccScalar::from_u64(curve_type, 2);
        for i in 0..scalars.len() {
            let mut term = EccScalar::one(curve_type);
            let bit_len = naf[i].positive_bits.len() * 8;
            let mut result = EccScalar::zero(curve_type);
            for j in 0..bit_len {
                // `value_j` is in [-1, 0, 1]
                let value_j = to_i8_at_pos(&naf[i], j);
                match value_j {
                    -1i8 => result = result.sub(&term)?,
                    0i8 => {}
                    1i8 => {
                        result = result.add(&term)?;
                    }
                    _ => panic!("this should never happen"),
                };
                term = term.mul(&two)?;
            }
            assert_eq!(result, scalars[i]);
        }
    }
    Ok(())
}

#[test]
fn bip340_k256_serialization_roundtrip_works_correctly() {
    let rng = &mut reproducible_rng();
    const K256: EccCurveType = EccCurveType::K256;
    let mut p = EccPoint::generator_g(K256)
        .scalar_mul(&EccScalar::random(K256, rng))
        .expect("failed to generate random point");
    if !p.is_y_even().expect("failed to check if point is even") {
        p = p.negate();
    }

    let raw = p.serialize_bip340().expect("failed to serialize");
    let deserialized = EccPoint::deserialize_bip340(K256, &raw).expect("failed to deserialize");

    assert_eq!(p, deserialized);
}
