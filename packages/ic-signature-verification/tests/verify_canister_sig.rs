use assert_matches::assert_matches;
use ic_canister_sig_creation::CanisterSigPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
use ic_crypto_test_utils_canister_sigs::new_valid_sig_and_crypto_component;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_principal::Principal;
use ic_types::crypto::Signable;
use ic_types::crypto::threshold_sig::{IcRootOfTrust, ThresholdSigPublicKey};

fn get_root_pk_raw(root_of_trust: &IcRootOfTrust) -> Vec<u8> {
    let pk_raw: bls12_381::PublicKeyBytes =
        (*<IcRootOfTrust as AsRef<ThresholdSigPublicKey>>::as_ref(root_of_trust)).into();
    pk_raw.as_bytes().to_vec()
}

fn get_canister_sig_pk_der(pk_raw: &[u8]) -> Vec<u8> {
    CanisterSigPublicKey::try_from_raw(pk_raw)
        .expect("wrong raw canister sig pk")
        .to_der()
}

#[test]
fn should_verify_canister_sig() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_eq!(result, Ok(()));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_wrong_msg() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let wrong_msg = [1u8, 2, 3, 4];

        let result = ic_signature_verification::verify_canister_sig(
            &wrong_msg,
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("signature entry not found"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_invalid_sig() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let invalid_sig = {
            let mut sig_with_bit_flipped = sig_data.canister_sig.get_ref().0.clone();
            let len = sig_with_bit_flipped.len();
            sig_with_bit_flipped.as_mut_slice()[len - 5] ^= 0x01; // to be valid CBOR
            sig_with_bit_flipped
        };

        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &invalid_sig,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("doesn't match sig tree digest"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_sig_with_malformed_cbor_tag() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let sig_with_malformed_cbor_tag = {
            let mut corrupted_sig = sig_data.canister_sig.get_ref().0.clone();
            // position 1 in the sig corrupts the CBOR tag:
            corrupted_sig[1] ^= 0xFF;
            corrupted_sig
        };

        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_with_malformed_cbor_tag,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("CBOR doesn't have a self-describing tag"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_sig_with_malformed_cert() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let sig_with_malformed_cert = {
            let mut corrupted_sig_bytes = sig_data.canister_sig.get_ref().0.clone();
            // position 30 in the sig corrupts the certificate:
            corrupted_sig_bytes[30] ^= 0xFF;
            corrupted_sig_bytes
        };

        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_with_malformed_cert,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("failed to parse certificate"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_wrong_root_pk() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &[42; 96],
        );
        assert_matches!(result, Err(e) if e.contains("invalid BLS signature"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_invalid_root_pk() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &[42; 99], // invalid length
        );
        assert_matches!(result, Err(e) if e.contains("invalid BLS signature"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_invalid_canister_sig_pk() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let invalid_canister_sig_pk =
            CanisterSigPublicKey::new(Principal::from_slice(&[1, 2, 3, 4]), [7; 11].to_vec());
        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &invalid_canister_sig_pk.to_der(),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("certified_data entry not found"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_wrong_canister_sig_pk() {
    let rng = &mut ReproducibleRng::new();
    // A 2nd rng/sig_data to generate a different (yet well-formed) canister sig pk
    let rng_2 = &mut ReproducibleRng::new();
    let sig_data_2 = new_valid_sig_and_crypto_component(rng_2, false);

    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);

        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data_2.canister_pk.key), // use pk from 2nd sig
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("signature entry not found"));
    }
}
