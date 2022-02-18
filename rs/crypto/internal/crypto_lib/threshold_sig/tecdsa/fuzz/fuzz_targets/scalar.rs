#![no_main]
use libfuzzer_sys::fuzz_target;

use ic_crypto_internal_threshold_sig_ecdsa::*;
use num_bigint::BigUint;

fn prime_for(curve: EccCurveType) -> BigUint {
    match curve {
        EccCurveType::P256 => BigUint::parse_bytes(
            b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        .unwrap(),
        EccCurveType::K256 => BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
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

fn scalar_fuzz_run(curve_type: EccCurveType, data: &[u8]) -> Result<(), ThresholdEcdsaError> {
    let prime = prime_for(curve_type);

    let our_val = EccScalar::from_bytes_wide(curve_type, data).unwrap();
    let ref_val = BigUint::from_bytes_be(data) % &prime;
    assert_eq!(hex::encode(our_val.serialize()), format_bn(&ref_val));

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 {
        return;
    }
    let _ = scalar_fuzz_run(EccCurveType::K256, data);
    let _ = scalar_fuzz_run(EccCurveType::P256, data);
});
