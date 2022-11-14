use crate::secret_key_store::test_utils::MockSecretKeyStore;
use crate::secret_key_store::test_utils::TempSecretKeyStore;
use crate::secret_key_store::{SecretKeyStoreError, SecretKeyStorePersistenceError};
use crate::types::CspSecretKey;
use crate::vault::api::CspVault;
use crate::{KeyId, SecretKeyStore};
use ic_crypto_internal_tls::keygen::TlsEd25519SecretKeyDerBytes;
use ic_types_test_utils::ids::node_test_id;
use openssl::pkey::PKey;
use std::sync::Arc;

const NODE_1: u64 = 4241;
const NOT_AFTER: &str = "25670102030405Z";

/// Key should be present only after key generation.
///
/// Note:  Theoretically the invariant is: The key should be present only in the
/// CSP that generated it, and only after generation and before deletion, if
/// deletion is supported for that key type.  Thus ideally there should be a
/// test that generates many sequences of events and verifies that this
/// invariant holds, regardless of the sequence of events, the number or type of
/// keys in the CSP and so on.  Making such a test is hard, so this is just one
/// sequence of events.
pub fn sks_should_contain_keys_only_after_generation(
    csp_vault1: Arc<dyn CspVault>,
    csp_vault2: Arc<dyn CspVault>,
) {
    let public_key1 = csp_vault1
        .gen_node_signing_key_pair()
        .expect("Test setup failed: Failed to generate keys");
    let key_id1 = KeyId::from(&public_key1);
    assert!(
        csp_vault1.sks_contains(&key_id1).expect("SKS call failed"),
        "Key should be present after generation."
    );
    assert!(
        !csp_vault2.sks_contains(&key_id1).expect("SKS call failed"),
        "Key should be absent if not generated in the CSP."
    );

    let public_key2 = csp_vault2
        .gen_node_signing_key_pair()
        .expect("Test setup failed: Failed to generate keys");
    let key_id2 = KeyId::from(&public_key2);
    assert_ne!(
        key_id1, key_id2,
        "Test failure: Key IDs from different CSPs were the same.  Check random number generation."
    );
    assert!(
        csp_vault2.sks_contains(&key_id2).expect("SKS call failed"),
        "Key should be present in the CSP that generated it."
    );
    assert!(
        !csp_vault2.sks_contains(&key_id1).expect("SKS call failed"),
        "The second CSP should not contain the keys of the first."
    );
    assert!(
        !csp_vault1.sks_contains(&key_id2).expect("SKS call failed"),
        "Key first CSP should not contain the keys of the second."
    );
}

pub fn sks_should_contain_tls_keys_only_after_generation(
    csp_vault1: Arc<dyn CspVault>,
    csp_vault2: Arc<dyn CspVault>,
) {
    let public_key_cert1 = csp_vault1
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("error generating TLS key pair");
    let key_id1 = KeyId::from(&public_key_cert1);
    assert!(
        csp_vault1.sks_contains(&key_id1).expect("SKS call failed"),
        "TLS key should be present after generation."
    );
    assert!(
        !csp_vault2.sks_contains(&key_id1).expect("SKS call failed"),
        "TLS key should be absent if not generated in the CSP."
    );

    let public_key_cert2 = csp_vault2
        .gen_tls_key_pair(node_test_id(NODE_1), NOT_AFTER)
        .expect("error generating TLS key pair");
    let key_id2 = KeyId::from(&public_key_cert2);
    assert_ne!(
        key_id1, key_id2,
        "Test failure: Key IDs from different CSPs were the same.  Check random number generation."
    );
    assert!(
        csp_vault2.sks_contains(&key_id2).expect("SKS call failed"),
        "TLS key should be present in the CSP that generated it."
    );
    assert!(
        !csp_vault2.sks_contains(&key_id1).expect("SKS call failed"),
        "The second CSP should not contain the TLS keys of the first."
    );
    assert!(
        !csp_vault1.sks_contains(&key_id2).expect("SKS call failed"),
        "Key first CSP should not contain the TLS keys of the second."
    );
}

pub fn secret_key_store_with_duplicated_key_id_error_on_insert(
    duplicated_key_id: KeyId,
) -> impl SecretKeyStore {
    let mut sks_returning_duplicate_key_id_error_on_insert = MockSecretKeyStore::new();
    sks_returning_duplicate_key_id_error_on_insert
        .expect_insert()
        .times(1)
        .return_const(Err(SecretKeyStoreError::DuplicateKeyId(duplicated_key_id)));
    sks_returning_duplicate_key_id_error_on_insert
}

pub fn secret_key_store_with_serialization_error_on_insert() -> impl SecretKeyStore {
    let mut sks_returning_serialization_error_on_insert = MockSecretKeyStore::new();
    sks_returning_serialization_error_on_insert
        .expect_insert()
        .times(1)
        .return_const(Err(SecretKeyStoreError::PersistenceError(
            SecretKeyStorePersistenceError::SerializationError("error serializing key".to_string()),
        )));
    sks_returning_serialization_error_on_insert
}

pub fn secret_key_store_with_io_error_on_insert() -> impl SecretKeyStore {
    let mut sks_returning_io_error_on_insert = MockSecretKeyStore::new();
    sks_returning_io_error_on_insert
        .expect_insert()
        .times(1)
        .return_const(Err(SecretKeyStoreError::PersistenceError(
            SecretKeyStorePersistenceError::IoError(
                "io error persisting secret key store".to_string(),
            ),
        )));
    sks_returning_io_error_on_insert
}

pub fn secret_key_store_containing_key_with_invalid_encoding(key_id: KeyId) -> impl SecretKeyStore {
    let mut key_store = TempSecretKeyStore::new();
    let secret_key_with_invalid_der = CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes {
        bytes: b"invalid DER encoding".to_vec(),
    });
    assert!(key_store
        .insert(key_id, secret_key_with_invalid_der, None)
        .is_ok());
    key_store
}

pub fn secret_key_store_containing_key_with_invalid_length(key_id: KeyId) -> impl SecretKeyStore {
    let mut key_store = TempSecretKeyStore::new();
    let secret_key_with_invalid_length = CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes {
        bytes: PKey::generate_ed448()
            .expect("failed to create Ed2448 key pair")
            .private_key_to_der()
            .expect("failed to serialize Ed2448 key to DER"),
    });
    assert!(key_store
        .insert(key_id, secret_key_with_invalid_length, None)
        .is_ok());
    key_store
}
