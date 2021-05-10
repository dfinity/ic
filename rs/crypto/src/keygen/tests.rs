#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::test_utils::crypto_component::crypto_component_with;
use crate::common::test_utils::hex_to_32_bytes;
use ic_crypto_internal_csp::secret_key_store::volatile_store::VolatileSecretKeyStore;
use ic_crypto_internal_csp::secret_key_store::SecretKeyStore;
use ic_test_utilities::crypto::empty_fake_registry;

#[test]
fn should_correctly_generate_ed25519_user_keys() {
    let crypto = crypto_component_with(empty_fake_registry(), empty_secret_key_store());

    let (sk_id, pk) = crypto.generate_user_keys_ed25519().unwrap();

    assert_eq!(
        sk_id,
        KeyId::from(hex_to_32_bytes(
            "be652632635fa33651721671afa29c576396beaec8af0d8ba819605fc7dea8e4"
        ))
    );
    assert_eq!(
        pk,
        UserPublicKey {
            key: hex_decode("78eda21ba04a15e2000fe8810fe3e56741d23bb9ae44aa9d5bb21b76675ff34b"),
            algorithm_id: AlgorithmId::Ed25519,
        }
    );
}

#[test]
fn should_correctly_generate_committee_member_keys() {
    let crypto = crypto_component_with(empty_fake_registry(), empty_secret_key_store());

    let (sk_id, pk) = crypto.generate_committee_member_keys().unwrap();

    assert_eq!(
        sk_id,
        KeyId::from(hex_to_32_bytes(
            "f8782b0bc403eb23770b72bebe9f3efbedb98f7a2fdf2c2b7b312e894bd39a44"
        ))
    );
    assert_eq!(
        pk,
        CommitteeMemberPublicKey {
            key: hex_decode(
                 "986b177ef16c61c633e13769c42b079791cfa9702decd36eeb347be21bd98e8d1c4d9f2a1f16f2e09b995ae7ff856a830d382d0081c6ae253a7d2abf97de945f70a42e677ca30b129bcd08c91f78f8573fe2463a86afacf870e9fe4960f5c55f"
            ),
            proof_of_possession: hex_decode(
"8e1e3a79a9f0bf69b9e256041eedef82db44e7755d9920a17dd07ea9f039a0f0f79013c135678aa355e9695f36886b54"
            ),
        }
    );
}

fn empty_secret_key_store() -> impl SecretKeyStore {
    VolatileSecretKeyStore::new()
}

fn hex_decode(x: &str) -> Vec<u8> {
    hex::decode(x).unwrap()
}
