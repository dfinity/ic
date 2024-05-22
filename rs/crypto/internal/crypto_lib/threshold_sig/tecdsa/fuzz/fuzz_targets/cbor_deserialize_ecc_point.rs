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
            if re_ser != data && curve_type == EccCurveType::Ed25519 {
                // Fuzzer's input data and the serialization should normally be
                // equal, but in Ed25519 we currently allow the deserialization
                // of non-canonical points, i.e., points that have a second
                // possible, non-standard encoding (see
                // https://github.com/ZcashFoundation/ed25519-zebra/blob/8ffefcbc5dda8e6c30cbf7d33afb05ae7f1ff147/tests/util/mod.rs#L81-L155).
                //
                // TODO(CRP-2504): We might consider rejecting such points because
                // there doesn't seem to be a good reason to accept them.
                let re_deser = EccPoint::deserialize(curve_type, &re_ser);
                assert_eq!(re_deser, Ok(point));
            } else {
                assert_eq!(re_ser, data);
            }
        }
    }
});
