use super::types;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};

// NOTE: both `new_keypair()` and `sign()` are exposed as public but
// are not used in production. They are exposed due to requirements on
// how the tests are structured. This should be resolved.
//
// For the same reason the majority of tests is using signature verification
// test vectors (addition of test vectors for signature creation is more
// involved as Rust OpenSSL API doesn't seem to provide a way for
// "de-randomization" of signing operation).

