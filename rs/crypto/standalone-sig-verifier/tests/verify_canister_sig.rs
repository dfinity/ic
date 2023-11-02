use assert_matches::assert_matches;
use ic_crypto_test_utils_canister_sigs::new_valid_sig_and_crypto_component;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_types::crypto::{CryptoError, Signable};

#[test]
fn should_validate_canister_signature_smoke_test() {
    let rng = &mut ReproducibleRng::new();
    let sig_data = new_valid_sig_and_crypto_component(rng, false);

    let result = ic_crypto_standalone_sig_verifier::verify_canister_sig(
        &sig_data.msg.as_signed_bytes(),
        &sig_data.canister_sig.get_ref().0,
        &sig_data.canister_pk.key,
        sig_data.root_of_trust,
    );

    assert_eq!(result, Ok(()));
}

#[test]
fn should_reject_invalid_canister_signature_smoke_test() {
    let rng = &mut ReproducibleRng::new();
    let sig_data = new_valid_sig_and_crypto_component(rng, false);
    let invalid_signature = {
        let mut sig_with_bit_flipped = sig_data.canister_sig.get_ref().0.clone();
        let len = sig_with_bit_flipped.len();
        sig_with_bit_flipped.as_mut_slice()[len - 5] ^= 0x01; //to be valid CBOR
        sig_with_bit_flipped
    };

    let result = ic_crypto_standalone_sig_verifier::verify_canister_sig(
        &sig_data.msg.as_signed_bytes(),
        &invalid_signature,
        &sig_data.canister_pk.key,
        sig_data.root_of_trust,
    );

    assert_matches!(result, Err(CryptoError::SignatureVerification { .. }));
}
