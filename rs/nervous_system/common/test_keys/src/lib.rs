use ic_base_types::PrincipalId;
use ic_types::crypto::{AlgorithmId, UserPublicKey};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

lazy_static! {
    // A set of keys/principals to be used in tests.
    // Note that we use multiple rng's because declaring a single one an reusing it causes conflicts
    // about 2 different versions of rand_core being pulled.
    // -- The keypairs/pubkeys/principals of the owners of test neurons

    pub static ref TEST_NEURON_1_OWNER_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(2000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_1_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_1_OWNER_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_NEURON_1_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_1_OWNER_PUBKEY.key.clone()));
    pub static ref TEST_NEURON_2_OWNER_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(3000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_2_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_2_OWNER_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_NEURON_2_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_2_OWNER_PUBKEY.key.clone()));
    pub static ref TEST_NEURON_3_OWNER_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(4000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_3_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_3_OWNER_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_NEURON_3_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_3_OWNER_PUBKEY.key.clone()));

    /// TEST_USER{1, 2, 3} are generic test identities that can be used for anything.
    /// They are not tied to any test neuron.
    pub static ref TEST_USER1_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(5000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER1_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER1_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER1_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER1_PUBKEY.key.clone()));

    pub static ref TEST_USER2_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(6000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER2_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER2_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER2_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER2_PUBKEY.key.clone()));

   pub static ref TEST_USER3_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(7000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER3_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER3_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER3_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER3_PUBKEY.key.clone()));

   pub static ref TEST_USER4_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(8000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER4_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER4_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER4_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER4_PUBKEY.key.clone()));

   pub static ref TEST_USER5_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(9000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER5_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER5_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER5_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER5_PUBKEY.key.clone()));

   pub static ref TEST_USER6_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(10000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER6_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER6_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER6_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER6_PUBKEY.key.clone()));

   pub static ref TEST_USER7_KEYPAIR: ic_canister_client_sender::Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(11000_u64);
        ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER7_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER7_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER7_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER7_PUBKEY.key.clone()));

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
