#![no_main]
use libfuzzer_sys::fuzz_target;

use ic_crypto_internal_threshold_sig_canister_threshold_sig::IDkgDealingInternal;

// This fuzzer tries to find panics in CBOR deserialization of dealings. We ignore errors
// returned by the decoding, as these do not lead to panics. You can run the fuzzer locally:
// bazel run --config=fuzzing //rs/crypto/internal/crypto_lib/threshold_sig/tecdsa/fuzz:cbor_deserialize_dealing
fuzz_target!(|data: &[u8]| {
    if let Ok(dealing) = IDkgDealingInternal::deserialize(data) {
        // A re-serialization could have a different format because
        // `IDkgDealingInternal::serialize()` is not compressed but CBOR
        // generally allows compression ("packed" CBOR). So it does not make
        // sense to compare both serializations.
        let re_ser = dealing.serialize().expect("failed to serialize dealing");
        // Since we know that's a valid dealing encoding, it's deserialization
        // should always succeed.
        let re_deser =
            IDkgDealingInternal::deserialize(&re_ser).expect("failed to deserialize dealing");
        // The re-deserialization should always produce a valid dealing that
        // equals the initially deserialized one.
        assert_eq!(dealing, re_deser);
    }
});
