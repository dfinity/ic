//! Algorithm identifiers for various signature algorithms
//!
//! This module defines the PKIX algorithm identifiers used to identify
//! different signature algorithms when parsing DER-encoded public keys.

use ic_crypto_internal_basic_sig_der_utils::PkixAlgorithmIdentifier;
use simple_asn1::oid;

/// The algorithm identifier for Ed25519 public keys
///
/// See [RFC 8410](https://tools.ietf.org/html/rfc8410).
pub fn ed25519_algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_empty_param(oid!(1, 3, 101, 112))
}

/// The algorithm identifier for ECDSA P-256 (secp256r1) public keys
pub fn ecdsa_p256_algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_oid_param(
        oid!(1, 2, 840, 10045, 2, 1),
        oid!(1, 2, 840, 10045, 3, 1, 7),
    )
}

/// The algorithm identifier for ECDSA secp256k1 public keys
pub fn ecdsa_secp256k1_algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_oid_param(
        oid!(1, 2, 840, 10045, 2, 1),
        oid!(1, 3, 132, 0, 10),
    )
}

/// The algorithm identifier for RSA public keys
///
/// See [RFC 8017](https://tools.ietf.org/html/rfc8017).
pub fn rsa_algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_null_param(oid!(1, 2, 840, 113549, 1, 1, 1))
}

/// The algorithm identifier for COSE-encoded public keys
pub fn cose_algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_empty_param(oid!(1, 3, 6, 1, 4, 1, 56387, 1, 1))
}

/// The algorithm identifier for ICCSA (Internet Computer Canister Signature Algorithm) public keys
pub fn iccsa_algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_empty_param(oid!(1, 3, 6, 1, 4, 1, 56387, 1, 2))
}
