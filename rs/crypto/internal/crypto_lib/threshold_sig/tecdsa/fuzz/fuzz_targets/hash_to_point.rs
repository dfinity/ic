#![no_main]
use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, EccPoint};

// This fuzzer tries to find panics in CBOR deserialization of ECC points. We ignore errors
// returned by the decoding, as these do not lead to panics. You can run the fuzzer locally:
// bazel run --config=fuzzing //rs/crypto/internal/crypto_lib/threshold_sig/tecdsa/fuzz:cbor_deserialize_ecc_point
fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    if let Ok((input, dst)) = <(Vec<u8>, Vec<u8>)>::arbitrary(&mut unstructured) {
        for curve_type in EccCurveType::all() {
            EccPoint::hash_to_point(curve_type, &input, &dst).expect("hash_to_point failed");
        }
    }
});
