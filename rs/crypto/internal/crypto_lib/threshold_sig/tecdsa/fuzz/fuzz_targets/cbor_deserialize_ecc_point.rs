#![no_main]
use libfuzzer_sys::fuzz_target;

use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, EccPoint};

// This fuzzer tries to find panics in CBOR deserialization of ECC points. We ignore errors
// returned by the decoding, as these do not lead to panics. You can run the fuzzer locally:
// bazel run --config=fuzzing //rs/crypto/internal/crypto_lib/threshold_sig/tecdsa/fuzz:cbor_deserialize_ecc_point
fuzz_target!(|data: &[u8]| {
    for curve_type in EccCurveType::all() {
        if let Ok(point) = EccPoint::deserialize(curve_type, data) {
            let re_ser = point.serialize();
            assert_eq!(re_ser, data);
        }
    }
});
