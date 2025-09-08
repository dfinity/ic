use ic_base_types::PrincipalId;
use ic_canister_client_sender::{Ed25519KeyPair, ed25519_public_key_to_der};
use ic_types::crypto::{AlgorithmId, UserPublicKey};
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub const TEST_NEURON_1_ID: u64 = 449479075714955186;
pub const TEST_NEURON_2_ID: u64 = 4368585614685248742;
pub const TEST_NEURON_3_ID: u64 = 4884056990215423907;

lazy_static! {
    // A set of keys/principals to be used in tests.
    // Note that we use multiple rng's because declaring a single one an reusing it causes conflicts
    // about 2 different versions of rand_core being pulled.
    // -- The keypairs/pubkeys/principals of the owners of test neurons

    pub static ref TEST_NEURON_1_OWNER_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(2000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_1_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_1_OWNER_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    // TEST_NEURON_1_OWNER_PRINCIPAL is b2ucp-4x6ou-zvxwi-niymn-pvllt-rdxqr-wi4zj-jat5l-ijt2s-vv4f5-4ae
    pub static ref TEST_NEURON_1_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_1_OWNER_PUBKEY.key.clone()));
    pub static ref TEST_NEURON_2_OWNER_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(3000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_2_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_2_OWNER_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    // TEST_NEURON_2_OWNER_PRINCIPAL is ivdtc-er3gy-5nsbt-epfob-ubilu-fi6yy-qluo4-ma6uc-ykmsl-y7q74-iae
    pub static ref TEST_NEURON_2_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_2_OWNER_PUBKEY.key.clone()));
    pub static ref TEST_NEURON_3_OWNER_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(4000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_NEURON_3_OWNER_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_NEURON_3_OWNER_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    // TEST_NEURON_3_OWNER_PRINCIPAL is 3nsx7-tzfj7-24piv-7mkdz-ifhz5-3ppgw-jcsig-coa6j-xms6b-iqsq5-oae
    pub static ref TEST_NEURON_3_OWNER_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_NEURON_3_OWNER_PUBKEY.key.clone()));

    /// TEST_USER{1, 2, 3} are generic test identities that can be used for anything.
    /// They are not tied to any test neuron.
    pub static ref TEST_USER1_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(5000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER1_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER1_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER1_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER1_PUBKEY.key.clone()));

    pub static ref TEST_USER2_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(6000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER2_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER2_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER2_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER2_PUBKEY.key.clone()));

    pub static ref TEST_USER3_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(7000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER3_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER3_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER3_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER3_PUBKEY.key.clone()));

    pub static ref TEST_USER4_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(8000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER4_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER4_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER4_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER4_PUBKEY.key.clone()));

    pub static ref TEST_USER5_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(9000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER5_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER5_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER5_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER5_PUBKEY.key.clone()));

    pub static ref TEST_USER6_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(10000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER6_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER6_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER6_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER6_PUBKEY.key.clone()));

    pub static ref TEST_USER7_KEYPAIR: Ed25519KeyPair = {
        let mut rng = ChaChaRng::seed_from_u64(11000_u64);
        Ed25519KeyPair::generate(&mut rng)
    };
    pub static ref TEST_USER7_PUBKEY : UserPublicKey = UserPublicKey {
         key: TEST_USER7_KEYPAIR.public_key.to_vec(),
         algorithm_id: AlgorithmId::Ed25519,
    };
    pub static ref TEST_USER7_PRINCIPAL: PrincipalId = PrincipalId::new_self_authenticating(
        &ed25519_public_key_to_der(TEST_USER7_PUBKEY.key.clone()));

}
