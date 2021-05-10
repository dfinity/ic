#![allow(clippy::unwrap_used)]
use ic_config::crypto::CryptoConfig;
use ic_crypto::{ecdsa_p256_signature_from_der_bytes, user_public_key_from_bytes, CryptoComponent};
use ic_crypto_internal_test_vectors::test_data;
use ic_interfaces::crypto::{BasicSigVerifierByPublicKey, SignableMock};
use ic_logger::replica_logger::no_op_logger;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities::types::ids::node_test_id;
use ic_types::crypto::{BasicSigOf, UserPublicKey};
use std::sync::Arc;

#[test]
fn should_verify_webauthn_signature_sample_1() {
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        let (pk, sig, webauthn_envelope) = verification_data(
            test_data::ECDSA_P256_PK_1_COSE_DER_WRAPPED_HEX.as_ref(),
            test_data::ECDSA_P256_SIG_1_DER_HEX.as_ref(),
            test_data::WEBAUTHN_MSG_1_HEX.as_bytes(),
        );
        assert!(crypto
            .verify_basic_sig_by_public_key(&sig, &webauthn_envelope, &pk)
            .is_ok());
    })
}

#[test]
fn should_verify_webauthn_signature_sample_2() {
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        let (pk, sig, webauthn_envelope) = verification_data(
            test_data::ECDSA_P256_PK_2_COSE_DER_WRAPPED_HEX.as_ref(),
            test_data::ECDSA_P256_SIG_2_DER_HEX.as_ref(),
            test_data::WEBAUTHN_MSG_2_HEX.as_bytes(),
        );
        assert!(crypto
            .verify_basic_sig_by_public_key(&sig, &webauthn_envelope, &pk)
            .is_ok());
    })
}

#[test]
fn should_fail_verifying_webauthn_signature_with_wrong_pk() {
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        let (pk, sig, webauthn_envelope) = verification_data(
            test_data::ECDSA_P256_PK_2_COSE_DER_WRAPPED_HEX.as_ref(), // wrong pk
            test_data::ECDSA_P256_SIG_1_DER_HEX.as_ref(),
            test_data::WEBAUTHN_MSG_1_HEX.as_bytes(),
        );
        let result = crypto.verify_basic_sig_by_public_key(&sig, &webauthn_envelope, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    })
}

#[test]
fn should_fail_verifying_webauthn_signature_with_wrong_signed_bytes() {
    CryptoConfig::run_with_temp_config(|config| {
        let crypto = crypto_component(&config);
        let (pk, sig, webauthn_envelope) = verification_data(
            test_data::ECDSA_P256_PK_1_COSE_DER_WRAPPED_HEX.as_ref(),
            test_data::ECDSA_P256_SIG_1_DER_HEX.as_ref(),
            test_data::WEBAUTHN_MSG_2_HEX.as_bytes(), // wrong signed bytes
        );
        let result = crypto.verify_basic_sig_by_public_key(&sig, &webauthn_envelope, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_signature_verification_error());
    })
}

#[test]
fn should_fail_parsing_corrupted_cose_pk() {
    let pk_cose = hex::decode(test_data::ECDSA_P256_PK_1_COSE_HEX).unwrap();
    let result = user_public_key_from_bytes(&pk_cose[1..]);
    assert!(result.is_err());
    assert!(result.unwrap_err().is_algorithm_not_supported());
}

#[test]
fn should_fail_parsing_corrupted_der_sig() {
    let sig_der = hex::decode(test_data::ECDSA_P256_SIG_1_DER_HEX).unwrap();
    let result = ecdsa_p256_signature_from_der_bytes(&sig_der[1..]);
    assert!(result.is_err());
    assert!(result.unwrap_err().is_malformed_signature());
}

fn verification_data(
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    signed_bytes: &[u8],
) -> (UserPublicKey, BasicSigOf<SignableMock>, SignableMock) {
    let (pk, _) = {
        let pk_cose = hex::decode(pk_bytes).unwrap();
        user_public_key_from_bytes(&pk_cose).unwrap()
    };
    let sig = {
        let sig_der = hex::decode(sig_bytes).unwrap();
        let basic_sig = ecdsa_p256_signature_from_der_bytes(&sig_der).unwrap();
        BasicSigOf::from(basic_sig)
    };
    let signable_mock = SignableMock {
        domain: vec![],
        signed_bytes_without_domain: hex::decode(signed_bytes).unwrap(),
    };
    (pk, sig, signable_mock)
}

fn crypto_component(config: &CryptoConfig) -> CryptoComponent {
    let dummy_registry = FakeRegistryClient::new(Arc::new(ProtoRegistryDataProvider::new()));
    CryptoComponent::new_with_fake_node_id(
        config,
        Arc::new(dummy_registry),
        node_test_id(42),
        no_op_logger(),
    )
}
