//! Tests for the POP of the Encryption Key
use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::encryption_key_pop::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

fn setup_pop_instance_and_witness<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (EncryptionKeyInstance, Scalar) {
    let g1 = G1Affine::generator();
    let witness = Scalar::random(rng);
    let public_key = G1Affine::from(g1 * &witness);
    let associated_data = rng.r#gen::<[u8; 10]>().to_vec();

    let instance = EncryptionKeyInstance::new(&public_key, &associated_data);

    (instance, witness)
}

fn assert_expected_scalar(scalar: &Scalar, expected: &'static str) {
    assert_eq!(hex::encode(scalar.serialize()), expected);
}

#[test]
fn should_encryption_key_pop_be_stable() -> Result<(), EncryptionKeyPopError> {
    let rng = &mut rand_chacha::ChaCha20Rng::from_seed([74; 32]);
    let (instance, witness) = setup_pop_instance_and_witness(rng);

    assert_expected_scalar(
        &witness,
        "52443431e6d5c54a2ca4abde6bd8a04f6cf5a0472a16243a2ceb315d64624e69",
    );

    let pop = prove_pop(&instance, &witness, rng)?;
    verify_pop(&instance, &pop)?;

    let pop = pop.serialize();

    assert_eq!(
        hex::encode(pop.pop_key),
        "a915dacc6fdafdd3774d4906354c75c500ad13197852947a1cbe59617b07e450e89c2443b048ec1c52007e051a9eeeff"
    );
    assert_eq!(
        hex::encode(pop.challenge),
        "3432885d429c95abef62b00ff3d2cbce64d4563eb84bac2f5d4c1ed877e9cde0"
    );
    assert_eq!(
        hex::encode(pop.response),
        "24d9d6b15def4195194658df7d1e71e323a8d9463ab2caebcbcd7f43474171e0"
    );

    Ok(())
}

#[test]
fn should_verify_encryption_key_pop() {
    let rng = &mut reproducible_rng();
    let (instance, witness) = setup_pop_instance_and_witness(rng);

    let pop = prove_pop(&instance, &witness, rng);

    assert!(
        pop.is_ok(),
        "prove_pop failed to generate a PoP given a valid instance and witness."
    );

    assert_eq!(
        verify_pop(&instance, &pop.unwrap()),
        Ok(()),
        "verify_pop failed to verify a valid encryption key PoP."
    );
}

#[test]
fn prover_should_return_error_on_invalid_instance() {
    let rng = &mut reproducible_rng();
    let (instance, _witness) = setup_pop_instance_and_witness(rng);
    let (_other_instance, other_witness) = setup_pop_instance_and_witness(rng);

    let pop = prove_pop(&instance, &other_witness, rng);

    assert_eq!(
        pop.unwrap_err(),
        EncryptionKeyPopError::InvalidInstance,
        "prove_pop did not return an error on an invalid instance."
    );
}

#[test]
fn verifier_should_return_error_on_invalid_proof() {
    let rng = &mut reproducible_rng();
    let (instance, _witness) = setup_pop_instance_and_witness(rng);
    let (other_instance, other_witness) = setup_pop_instance_and_witness(rng);

    let wrong_pop = prove_pop(&other_instance, &other_witness, rng);

    assert!(
        wrong_pop.is_ok(),
        "prove_pop failed to generate a PoP given a valid instance and witness."
    );

    assert_eq!(
        verify_pop(&instance, &wrong_pop.unwrap()),
        Err(EncryptionKeyPopError::InvalidProof),
        "verify_pop did not return an error on an invalid proof."
    );
}
