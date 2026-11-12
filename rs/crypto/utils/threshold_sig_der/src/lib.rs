use ic_crypto_internal_basic_sig_der_utils::{
    PkixAlgorithmIdentifier, algo_id_and_public_key_bytes_from_der,
};
use simple_asn1::{ASN1Block, OID, oid};

/// Byte size of the public key, which is a G2 element.
pub const PUBLIC_KEY_SIZE: usize = 96;

/// Byte size of the DER encoding of a public key.
pub const PUBLIC_KEY_DER_SIZE: usize = 133;

/// Converts public key bytes into its DER-encoded form.
///
/// See [the Interface Spec](https://internetcomputer.org/docs/current/references/ic-interface-spec#certificate)
/// and [RFC 5480](https://tools.ietf.org/html/rfc5480).
pub fn public_key_to_der(key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != PUBLIC_KEY_SIZE {
        return Err(format!("key length is not {PUBLIC_KEY_SIZE} bytes"));
    }
    simple_asn1::to_der(&ASN1Block::Sequence(
        2,
        vec![
            ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(0, bls_algorithm_oid()),
                    ASN1Block::ObjectIdentifier(0, bls_curve_oid()),
                ],
            ),
            ASN1Block::BitString(0, key.len() * 8, key.to_vec()),
        ],
    ))
    .map_err(|e| e.to_string())
}

/// Parses a `PublicKeyBytes` from its DER-encoded form.
///
/// See [the Interface Spec](https://internetcomputer.org/docs/current/references/ic-interface-spec#certificate)
/// and [RFC 5480](https://tools.ietf.org/html/rfc5480).
///
/// # Errors
/// * Returns a string describing the error if the given `bytes` are not
///   [`PUBLIC_KEY_DER_SIZE`] long, are not valid ASN.1, or include unexpected
///   ASN.1 structures.
pub fn public_key_from_der(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_SIZE], String> {
    if bytes.len() != PUBLIC_KEY_DER_SIZE {
        return Err(format!(
            "unexpected DER length: {} bytes, expected {PUBLIC_KEY_DER_SIZE}",
            bytes.len()
        ));
    }

    let (algo_id, key) =
        algo_id_and_public_key_bytes_from_der(bytes).map_err(|e| e.internal_error)?;
    let bls_algo_id =
        PkixAlgorithmIdentifier::new_with_oid_param(bls_algorithm_oid(), bls_curve_oid());
    if algo_id != bls_algo_id {
        return Err(format!(
            "unsupported algorithm identifier: {algo_id:?}, expected {bls_algo_id:?}"
        ));
    }

    key.try_into()
        .map_err(|key: Vec<u8>| format!("unexpected key length: {} bytes", key.len()))
}

fn bls_algorithm_oid() -> OID {
    oid!(1, 3, 6, 1, 4, 1, 44668, 5, 3, 1, 2, 1)
}

fn bls_curve_oid() -> OID {
    oid!(1, 3, 6, 1, 4, 1, 44668, 5, 3, 2, 1)
}

mod conversions;
pub use conversions::*;
