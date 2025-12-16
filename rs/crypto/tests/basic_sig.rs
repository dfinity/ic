use assert_matches::assert_matches;
use ic_crypto::CryptoComponentImpl;
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::vault::api::CspBasicSignatureError;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_temp_crypto::NodeKeysToGenerate;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
use ic_crypto_test_utils_local_csp_vault::MockLocalCspVault;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_interfaces::crypto::{BasicSigVerifier, BasicSigner};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_logger::no_op_logger;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::RegistryVersion;
use ic_types::crypto::BasicSig;
use ic_types::crypto::BasicSigOf;
use ic_types::crypto::CryptoError;
use ic_types::crypto::SignableMock;
use ic_types_test_utils::ids::NODE_1;
use std::sync::Arc;

pub const REG_V2: RegistryVersion = RegistryVersion::new(2);

#[test]
fn should_sign_and_verify() {
    let rng = ReproducibleRng::new();
    let crypto = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::only_node_signing_key())
        .with_rng(rng)
        .build();
    let msg = SignableMock::new(b"message".to_vec());
    let registry_version = crypto.registry_client().get_latest_version();

    let sign_result = crypto.sign_basic(&msg);
    assert_matches!(sign_result, Ok(_));

    let sig = sign_result.unwrap();
    assert_matches!(
        crypto.verify_basic_sig(&sig, &msg, crypto.get_node_id(), registry_version),
        Ok(())
    );
}

#[test]
fn should_fail_signing_with_secret_key_not_found_if_secret_key_not_found_in_key_store() {
    let mut vault = MockLocalCspVault::new();
    vault
        .expect_sign()
        .return_once(|_msg| Err(CspBasicSignatureError::SecretKeyNotFound(dummy_key_id())));
    let crypto = crypto_component_with_vault(vault, registry_panicking_on_usage());

    let result = crypto.sign_basic(&SignableMock::new(b"message".to_vec()));

    assert_matches!(result, Err(CryptoError::SecretKeyNotFound { .. }));
}

#[test]
fn should_fail_signing_with_public_key_not_found_if_public_key_not_found_in_key_store() {
    let mut vault = MockLocalCspVault::new();
    vault
        .expect_sign()
        .return_once(|_msg| Err(CspBasicSignatureError::PublicKeyNotFound));
    let crypto = crypto_component_with_vault(vault, registry_panicking_on_usage());

    let result = crypto.sign_basic(&SignableMock::new(b"message".to_vec()));

    assert_matches!(result, Err(CryptoError::InternalError { .. }));
}

#[test]
fn should_fail_signing_with_malformed_public_key_if_public_key_is_malformed() {
    let mut vault = MockLocalCspVault::new();
    vault.expect_sign().return_once(|_msg| {
        Err(CspBasicSignatureError::MalformedPublicKey(
            "invalid key format".to_string(),
        ))
    });
    let crypto = crypto_component_with_vault(vault, registry_panicking_on_usage());

    let result = crypto.sign_basic(&SignableMock::new(b"message".to_vec()));

    assert_matches!(result, Err(CryptoError::InternalError { .. }));
}

#[test]
fn should_fail_signing_with_wrong_secret_key_type_if_secret_key_type_is_wrong() {
    let mut vault = MockLocalCspVault::new();
    vault.expect_sign().return_once(|_msg| {
        Err(CspBasicSignatureError::WrongSecretKeyType {
            secret_key_variant: "EcdsaP256".to_string(),
        })
    });
    let crypto = crypto_component_with_vault(vault, registry_panicking_on_usage());

    let result = crypto.sign_basic(&SignableMock::new(b"message".to_vec()));

    assert_matches!(result, Err(CryptoError::InvalidArgument { .. }));
}

#[test]
fn should_fail_signing_with_transient_internal_error_if_vault_returns_transient_error() {
    let mut vault = MockLocalCspVault::new();
    vault.expect_sign().return_once(|_msg| {
        Err(CspBasicSignatureError::TransientInternalError {
            internal_error: "vault temporarily unavailable".to_string(),
        })
    });
    let crypto = crypto_component_with_vault(vault, registry_panicking_on_usage());

    let result = crypto.sign_basic(&SignableMock::new(b"message".to_vec()));

    assert_matches!(result, Err(CryptoError::TransientInternalError { .. }));
}

#[test]
fn should_fail_verifying_for_wrong_signature() {
    let rng = ReproducibleRng::new();
    let crypto = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::only_node_signing_key())
        .with_rng(rng)
        .build();
    let msg = SignableMock::new(b"message".to_vec());
    let registry_version = crypto.registry_client().get_latest_version();

    let wrong_sig = BasicSigOf::<SignableMock>::new(BasicSig([42; 64].to_vec()));

    assert_matches!(
        crypto.verify_basic_sig(&wrong_sig, &msg, crypto.get_node_id(), registry_version),
        Err(CryptoError::SignatureVerification { .. })
    );
}

#[test]
fn should_fail_verifying_for_wrong_message() {
    let rng = ReproducibleRng::new();
    let crypto = TempCryptoComponent::builder()
        .with_keys(NodeKeysToGenerate::only_node_signing_key())
        .with_rng(rng)
        .build();
    let registry_version = crypto.registry_client().get_latest_version();

    let msg = SignableMock::new(b"message".to_vec());
    let sig = crypto.sign_basic(&msg).unwrap();

    let wrong_msg = SignableMock::new(b"wrong message".to_vec());
    assert_matches!(
        crypto.verify_basic_sig(&sig, &wrong_msg, crypto.get_node_id(), registry_version),
        Err(CryptoError::SignatureVerification { .. })
    );
}

#[test]
fn should_fail_verifying_for_wrong_node_id() {
    let mut rng = ReproducibleRng::new();
    let registry_data = Arc::new(ProtoRegistryDataProvider::new());
    let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
    let crypto_1 = TempCryptoComponent::builder()
        .with_registry_client_and_data(Arc::clone(&registry) as _, Arc::clone(&registry_data))
        .with_keys(NodeKeysToGenerate::only_node_signing_key())
        .with_rng(rng.fork())
        .build();
    let crypto_2 = TempCryptoComponent::builder()
        .with_registry_client_and_data(Arc::clone(&registry) as _, registry_data)
        .with_keys(NodeKeysToGenerate::only_node_signing_key())
        .with_rng(rng)
        .build();
    registry.reload();
    let msg = SignableMock::new(b"test message".to_vec());

    let signature = crypto_1.sign_basic(&msg).unwrap();

    assert_matches!(
        crypto_2.verify_basic_sig(
            &signature,
            &msg,
            crypto_2.get_node_id(),
            registry.get_latest_version()
        ),
        Err(CryptoError::SignatureVerification { .. })
    );
}

pub fn crypto_component_with_vault(
    vault: MockLocalCspVault,
    registry_client: Arc<dyn RegistryClient>,
) -> CryptoComponentImpl<MockAllCryptoServiceProvider> {
    CryptoComponentImpl::new_for_test(
        MockAllCryptoServiceProvider::new(),
        Arc::new(vault),
        no_op_logger(),
        registry_client,
        NODE_1,
        Arc::new(CryptoMetrics::none()),
        None,
    )
}

pub fn registry_panicking_on_usage() -> Arc<dyn RegistryClient> {
    Arc::new(MockRegistryClient::new())
}

fn dummy_key_id() -> KeyId {
    KeyId::from([0; 32])
}
