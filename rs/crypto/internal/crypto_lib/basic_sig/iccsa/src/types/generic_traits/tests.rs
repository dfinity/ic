//! Tests for generic trait implementations

use super::*;

#[test]
fn signature_bytes_should_have_a_nice_debug_representation() {
    let test_vectors = vec![(
        SignatureBytes(vec![1, 2, 3, 4]),
        "SignatureBytes(\"AQIDBA==\")",
    )];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{:?}", value), *formatted);
    }
}

#[test]
fn signatures_should_have_a_nice_debug_representation() {
    let test_vectors = vec![(
        Signature {
            certificate: Blob(vec![3, 1, 4, 2]),
            tree: MixedHashTree::Empty,
        },
        "Signature { certificate: Blob{4 bytes;03010402}, tree: Empty }",
    )];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{:?}", value), *formatted);
    }
}

#[test]
fn public_key_bytes_should_have_a_nice_debug_representation() {
    let test_vectors = vec![(
        PublicKeyBytes(vec![1, 2, 3, 4]),
        "PublicKeyBytes(\"AQIDBA==\")",
    )];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{:?}", value), *formatted);
    }
}

#[test]
fn public_keys_should_have_a_nice_debug_representation() {
    let test_vectors = vec![(
        PublicKey {
            signing_canister_id: CanisterId::from_u64(42),
            seed: vec![1, 2, 3, 4],
        },
        "PublicKey{ signing_canister_id: CanisterId(xbgkv-fyaaa-aaaaa-aaava-cai), seed: AQIDBA== }",
    )];
    for (value, formatted) in test_vectors {
        assert_eq!(format!("{:?}", value), *formatted);
    }
}
