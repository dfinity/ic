//! Tests for the POP of the Encryption Key
use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::fs_ni_dkg::encryption_key_pop::*;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

fn setup_pop_instance_and_witness<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (EncryptionKeyInstance, Scalar) {
    let g1 = G1Affine::generator();
    let witness = Scalar::random(rng);
    let public_key = G1Affine::from(g1 * witness);
    let associated_data = rng.gen::<[u8; 10]>().to_vec();

    let instance = EncryptionKeyInstance {
        g1_gen: *g1,
        public_key,
        associated_data,
    };

    (instance, witness)
}

fn assert_expected_g1(pt: &G1Affine, expected: &'static str) {
    assert_eq!(hex::encode(pt.serialize()), expected);
}

fn assert_expected_scalar(scalar: &Scalar, expected: &'static str) {
    assert_eq!(hex::encode(scalar.serialize()), expected);
}

fn assert_expected_bytestring(bytes: &[u8], expected: &'static str) {
    assert_eq!(hex::encode(bytes), expected);
}

#[test]
fn should_encryption_key_pop_be_stable() -> Result<(), EncryptionKeyPopError> {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([74; 32]);
    let (instance, witness) = setup_pop_instance_and_witness(&mut rng);

    assert_expected_scalar(
        &witness,
        "52443431e6d5c54a2ca4abde6bd8a04f6cf5a0472a16243a2ceb315d64624e69",
    );

    assert_expected_g1(&instance.g1_gen,
                       "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
    assert_expected_g1(&instance.public_key,
                       "a1765a77ff5c48777b06690f5d6ab175ca8561c8f74d80b181adba1ae7f96ff6ef01ee22bf9beddf99accb8fb8b58ea2");

    assert_expected_bytestring(&instance.associated_data, "b591e4441bc6cf4ca031");

    let pop = prove_pop(&instance, &witness, &mut rng)?;

    assert_expected_g1(&pop.pop_key,
                       "a915dacc6fdafdd3774d4906354c75c500ad13197852947a1cbe59617b07e450e89c2443b048ec1c52007e051a9eeeff");
    assert_expected_scalar(
        &pop.challenge,
        "3432885d429c95abef62b00ff3d2cbce64d4563eb84bac2f5d4c1ed877e9cde0",
    );
    assert_expected_scalar(
        &pop.response,
        "24d9d6b15def4195194658df7d1e71e323a8d9463ab2caebcbcd7f43474171e0",
    );

    verify_pop(&instance, &pop)?;
    Ok(())
}

#[test]
fn should_verify_encryption_key_pop() {
    let mut rng = rand::thread_rng();
    let (instance, witness) = setup_pop_instance_and_witness(&mut rng);

    let pop = prove_pop(&instance, &witness, &mut rng);

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
    let mut rng = rand::thread_rng();
    let (instance, _witness) = setup_pop_instance_and_witness(&mut rng);
    let (_other_instance, other_witness) = setup_pop_instance_and_witness(&mut rng);

    let pop = prove_pop(&instance, &other_witness, &mut rng);

    assert_eq!(
        pop.unwrap_err(),
        EncryptionKeyPopError::InvalidInstance,
        "prove_pop did not return an error on an invalid instance."
    );
}

#[test]
fn verifier_should_return_error_on_invalid_proof() {
    let mut rng = rand::thread_rng();
    let (instance, _witness) = setup_pop_instance_and_witness(&mut rng);
    let (other_instance, other_witness) = setup_pop_instance_and_witness(&mut rng);

    let wrong_pop = prove_pop(&other_instance, &other_witness, &mut rng);

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
