use ic_base_types::PrincipalId;
use ic_types::crypto::{AlgorithmId, UserPublicKey};
use lazy_static::lazy_static;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

lazy_static! {
    // A set of keys/principals to be used in tests.
    // Note that we use multiple rng's because declaring a single one an reusing it causes conflicts
    // about 2 different versions of rand_core being pulled.
    // -- The keypairs/pubkeys/principals of the owners of test neurons

    pub static ref TEST_NEURON_1_OWNER_KEYPAIR: ed25519_dalek::Keypair = {
        let mut rng = ChaChaRng::seed_from_u64(2000_u64);
        ed25519_dalek::Keypair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_1_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_1_OWNER_KEYPAIR.public.to_bytes().to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_NEURON_1_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_1_OWNER_PUBKEY.key.clone()));
    pub static ref TEST_NEURON_2_OWNER_KEYPAIR: ed25519_dalek::Keypair = {
        let mut rng = ChaChaRng::seed_from_u64(3000_u64);
        ed25519_dalek::Keypair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_2_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_2_OWNER_KEYPAIR.public.to_bytes().to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_NEURON_2_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_2_OWNER_PUBKEY.key.clone()));
    pub static ref TEST_NEURON_3_OWNER_KEYPAIR: ed25519_dalek::Keypair = {
        let mut rng = ChaChaRng::seed_from_u64(4000_u64);
        ed25519_dalek::Keypair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_3_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_3_OWNER_KEYPAIR.public.to_bytes().to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_NEURON_3_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_3_OWNER_PUBKEY.key.clone()));

    /// TEST_USER1 is a generic test identity that can be used for anything. It is not tied to any test neuron.
    pub static ref TEST_USER1_KEYPAIR: ed25519_dalek::Keypair = {
        let mut rng = ChaChaRng::seed_from_u64(5000_u64);
        ed25519_dalek::Keypair::generate(&mut rng)
    };
    pub static ref TEST_USER1_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER1_KEYPAIR.public.to_bytes().to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER1_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER1_PUBKEY.key.clone()));

}

/// This is copied from ic_canister_client::agent::ed25519_public_key_to_der to
/// avoid having to import that crate.
pub fn ed25519_public_key_to_der(mut key: Vec<u8>) -> Vec<u8> {
    let mut encoded: Vec<u8> = vec![
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    encoded.append(&mut key);
    encoded
}
