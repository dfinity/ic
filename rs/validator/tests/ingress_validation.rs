use ic_crypto_sha256::Sha256;
use ic_interfaces::crypto::Signable;
use ic_test_utilities::types::ids::canister_test_id;
use ic_types::{messages::Delegation, time::UNIX_EPOCH};

// NOTE: Ideally, this test should be in the types crate where `Delegation` is
// defined, but the test is here to avoid circular dependencies between the
// "types" and "interfaces" crates.
#[test]
fn delegation_signed_bytes() {
    let d = Delegation::new(vec![1, 2, 3], UNIX_EPOCH);

    let mut expected_signed_bytes = Vec::new();
    expected_signed_bytes.extend_from_slice(b"\x1Aic-request-auth-delegation");

    // Representation-independent hash of the delegation.
    let mut pubkey_hash = Vec::new();
    pubkey_hash.extend_from_slice(&Sha256::hash(b"pubkey"));
    pubkey_hash.extend_from_slice(&Sha256::hash(&[1, 2, 3]));

    let mut expiration_hash = Vec::new();
    expiration_hash.extend_from_slice(&Sha256::hash(b"expiration"));
    expiration_hash.extend_from_slice(&Sha256::hash(&[0]));

    let mut hashes: Vec<Vec<u8>> = Vec::new();
    hashes.push(pubkey_hash);
    hashes.push(expiration_hash);
    hashes.sort();

    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.write(&hash);
    }

    // Concatenate domain with representation-independent hash.
    expected_signed_bytes.extend_from_slice(&hasher.finish());

    assert_eq!(d.as_signed_bytes(), expected_signed_bytes);
}

#[test]
fn delegation_with_targets_signed_bytes() {
    let d = Delegation::new_with_targets(vec![1, 2, 3], UNIX_EPOCH, vec![canister_test_id(1)]);

    let mut expected_signed_bytes = Vec::new();
    expected_signed_bytes.extend_from_slice(b"\x1Aic-request-auth-delegation");

    // Representation-independent hash of the delegation.
    let mut pubkey_hash = Vec::new();
    pubkey_hash.extend_from_slice(&Sha256::hash(b"pubkey"));
    pubkey_hash.extend_from_slice(&Sha256::hash(&[1, 2, 3]));

    let mut expiration_hash = Vec::new();
    expiration_hash.extend_from_slice(&Sha256::hash(b"expiration"));
    expiration_hash.extend_from_slice(&Sha256::hash(&[0]));

    let mut targets_hash = Vec::new();
    targets_hash.extend_from_slice(&Sha256::hash(b"targets"));
    targets_hash.extend_from_slice(&Sha256::hash(&Sha256::hash(
        canister_test_id(1).get().as_slice(),
    )));

    let mut hashes: Vec<Vec<u8>> = Vec::new();
    hashes.push(pubkey_hash);
    hashes.push(expiration_hash);
    hashes.push(targets_hash);
    hashes.sort();

    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.write(&hash);
    }

    // Concatenate domain with representation-independent hash.
    expected_signed_bytes.extend_from_slice(&hasher.finish());

    assert_eq!(d.as_signed_bytes(), expected_signed_bytes);
}
