//! Tests for the POP of the Encryption Key
use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_internal_fs_ni_dkg::{encryption_key_pop::*, utils::RAND_ChaCha20};
use miracl_core::rand::RAND;

fn setup_pop_instance_and_witness(rng: &mut impl RAND) -> (EncryptionKeyInstance, Scalar) {
    let g1 = G1Affine::generator();
    let witness = Scalar::miracl_random_using_miracl_rand(rng);
    let public_key = G1Affine::from(g1 * witness);
    let associated_data = {
        let mut vec = vec![];
        for _i in 0..10 {
            vec.push(rng.getbyte());
        }
        vec
    };

    let instance = EncryptionKeyInstance {
        g1_gen: g1,
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
    let rng = &mut RAND_ChaCha20::new([74; 32]);
    let (instance, witness) = setup_pop_instance_and_witness(rng);

    assert_expected_scalar(
        &witness,
        "48cf7ef8def6f5e55f41a0b05a80011685f182fdeb87a3cc730633be27e9d0cc",
    );

    assert_expected_g1(&instance.g1_gen,
                       "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
    assert_expected_g1(&instance.public_key,
                       "afd98a416c76876bed65c80ae7967867532fada48ab842a6dfd002f0696219bc4f198816fdab9978d56c857f32667ea9");

    assert_expected_bytestring(&instance.associated_data, "96057d6b28e248fd8160");

    let pop = prove_pop(&instance, &witness, rng)?;

    assert_expected_g1(&pop.pop_key,
                       "86fd63a7502eb705e4dfe518cf4c412238cbfbb80835174b5415b6fecaae8db97a16b7e4a0bd5c6091e29f4a40e259e8");
    assert_expected_scalar(
        &pop.challenge,
        "5e1f9c08f910c30104e753d4e2fb91c8d5db9c1999b6281ddea6596d50a520eb",
    );
    assert_expected_scalar(
        &pop.response,
        "532a9892e9aeedda3c53c714a51340d26131a75fbd4e2b64fcd7304ccc8afdd7",
    );

    verify_pop(&instance, &pop)?;
    Ok(())
}

#[test]
fn should_verify_encryption_key_pop() {
    let rng = &mut RAND_ChaCha20::new([74; 32]);
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
    let rng = &mut RAND_ChaCha20::new([84; 32]);
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
    let rng = &mut RAND_ChaCha20::new([84; 32]);
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
