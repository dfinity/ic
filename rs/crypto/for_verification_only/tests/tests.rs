use ic_crypto_for_verification_only::new;
use ic_crypto_interfaces_sig_verification::BasicSigVerifierByPublicKey;
use ic_crypto_test_utils::ed25519_utils::ed25519_signature_and_public_key;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::messages::MessageId;
use std::sync::Arc;

#[test]
fn should_verify_valid_signature_using_crypto_for_verification() {
    let rng = &mut reproducible_rng();
    let message = MessageId::from([42; 32]);
    let dummy_registry = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    let (signature, public_key) = ed25519_signature_and_public_key(&message, rng);
    let crypto = new(Arc::new(dummy_registry));

    assert!(
        crypto
            .verify_basic_sig_by_public_key(&signature, &message, &public_key)
            .is_ok()
    );
}

/// This is a smoke test ensuring that `CryptoComponentForVerificationOnly`
/// actually checks signatures and does not simply return `Ok`.
#[test]
fn should_fail_verification_on_invalid_signature_using_crypto_for_verification() {
    let rng = &mut reproducible_rng();
    let message = MessageId::from([42; 32]);
    let dummy_registry = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    let (signature, public_key) = ed25519_signature_and_public_key(&message, rng);
    let crypto = new(Arc::new(dummy_registry));

    let different_message = MessageId::from([1; 32]);
    assert_ne!(message, different_message);
    assert!(
        crypto
            .verify_basic_sig_by_public_key(&signature, &different_message, &public_key)
            .unwrap_err()
            .is_signature_verification_error()
    );
}
