use ic_crypto_test_utils_vetkd::*;
use ic_vetkd_utils::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
use rand::Rng;
use rand_chacha::rand_core::SeedableRng;

#[test]
fn should_generate_valid_bls_signature() {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(42);

    let pk = PrivateKey::generate(&rng.gen::<[u8; 32]>());

    let canister_id = rng.gen::<[u8; 32]>();
    let context = rng.gen::<[u8; 32]>();
    let input = rng.gen::<[u8; 32]>();

    let tsk = TransportSecretKey::from_seed(rng.gen::<[u8; 32]>().to_vec()).unwrap();

    let ek_bytes = pk.vetkd_protocol(
        &canister_id,
        &context,
        &input,
        &tsk.public_key(),
        &rng.gen::<[u8; 32]>(),
    );

    let ek = EncryptedVetKey::deserialize(&ek_bytes).unwrap();

    let dpk = DerivedPublicKey::deserialize(&pk.public_key_bytes())
        .unwrap()
        .derive_sub_key(&canister_id)
        .derive_sub_key(&context);

    assert!(ek.decrypt_and_verify(&tsk, &dpk, &input).is_ok());
}
