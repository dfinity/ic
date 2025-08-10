//! Tests for generic traits on basic_sig Ed25519 types.

use super::*;

#[test]
fn signatures_should_have_a_nice_debug_representation() {
    let test_vectors = vec![
        (SignatureBytes([0u8;SignatureBytes::SIZE]), "SignatureBytes(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\")"),
    ];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{:?}", value), *formatted);
    }
}

#[test]
fn secret_keys_should_have_an_appropriate_debug_representation() {
    let test_vectors = vec![(
        SecretKeyBytes(SecretArray::new_and_dont_zeroize_argument(&[0u8; 32])),
        "SecretKeyBytes(REDACTED SecretArray<32>)",
    )];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{:?}", value), *formatted);
    }
}

#[test]
fn public_keys_should_have_a_nice_debug_representation() {
    let test_vectors = vec![(
        PublicKeyBytes([0u8; PublicKeyBytes::SIZE]),
        "PublicKeyBytes(\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\")",
    )];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{:?}", value), *formatted);
    }
}
