#![no_main]
use libfuzzer_sys::fuzz_target;

use ic_crypto_internal_threshold_sig_ecdsa::IDkgDealingInternal;

// This fuzzer tries to find panics in CBOR deserialization of dealings. We ignore errors
// returned by the decoding, as these do not lead to panics. You can run the fuzzer locally:
// bazel run --config=fuzzing //rs/crypto/internal/crypto_lib/threshold_sig/tecdsa/fuzz:cbor_deserialize_dealing
fuzz_target!(|data: &[u8]| {
    if let Ok(dealing) = IDkgDealingInternal::deserialize(data) {
        assert_eq!(
            dealing.serialize().expect("failed to serialize dealing"),
            data
        );
    }
});
