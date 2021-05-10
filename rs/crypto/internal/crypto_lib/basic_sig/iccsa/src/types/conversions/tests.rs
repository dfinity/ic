#![allow(clippy::unwrap_used)]
use crate::types::conversions::PublicKeyFromBytesError;
use crate::types::{PublicKey, PublicKeyBytes};
use ic_types::CanisterId;
use std::convert::TryFrom;

#[test]
fn should_convert_valid_pubkey() {
    let canister_id = CanisterId::from_u64(42);
    let seed = b"seed";
    let public_key_bytes = public_key_bytes(canister_id, seed.to_vec());

    let public_key = PublicKey::try_from(&PublicKeyBytes(public_key_bytes)).unwrap();

    assert_eq!(public_key.signing_canister_id(), canister_id);
    assert_eq!(public_key.seed(), seed);
}

#[test]
fn should_convert_zero_length_pubkey() {
    let public_key_bytes = vec![0];

    let public_key = PublicKey::try_from(&PublicKeyBytes(public_key_bytes)).unwrap();

    assert_eq!(
        public_key.signing_canister_id(),
        CanisterId::try_from(vec![]).unwrap()
    );
    assert_eq!(public_key.seed(), &[0u8; 0][..]);
}

#[test]
fn should_fail_on_empty_pubkey() {
    let public_key_bytes = vec![];

    let public_key = PublicKey::try_from(&PublicKeyBytes(public_key_bytes));

    assert_eq!(
        public_key,
        Err(PublicKeyFromBytesError::MissingCanisterIdLengthByte)
    );
}

#[test]
fn should_fail_if_canister_bytes_too_short() {
    assert_eq!(
        PublicKey::try_from(&PublicKeyBytes(vec![1])),
        Err(PublicKeyFromBytesError::Malformed)
    );
    assert_eq!(
        PublicKey::try_from(&PublicKeyBytes(vec![3, 1, 2])),
        Err(PublicKeyFromBytesError::Malformed)
    );
}

fn public_key_bytes(canister_id: CanisterId, seed: Vec<u8>) -> Vec<u8> {
    PublicKey::new(canister_id, seed).to_bytes()
}
