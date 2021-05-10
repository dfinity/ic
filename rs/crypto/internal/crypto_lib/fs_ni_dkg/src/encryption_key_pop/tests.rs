#![allow(clippy::unwrap_used)]
//! Tests for the POP of the Encryption Key
use super::*;

fn setup_pop_instance_and_witness(rng: &mut impl RAND) -> (EncryptionKeyInstance, BIG) {
    let g1 = ECP::generator();
    let witness = BIG::randomnum(&curve_order(), rng);
    let public_key = g1.mul(&witness);
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
