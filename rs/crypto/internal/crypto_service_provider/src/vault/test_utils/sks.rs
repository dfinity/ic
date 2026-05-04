use crate::secret_key_store::SecretKeyStoreInsertionError;
use crate::secret_key_store::mock_secret_key_store::MockSecretKeyStore;
use crate::secret_key_store::temp_secret_key_store::TempSecretKeyStore;
use crate::types::CspSecretKey;
use crate::{KeyId, SecretKeyStore};
use ic_crypto_internal_tls::TlsEd25519SecretKeyDerBytes;

pub fn secret_key_store_with_duplicated_key_id_error_on_insert(
    duplicated_key_id: KeyId,
) -> impl SecretKeyStore {
    let mut sks_returning_duplicate_key_id_error_on_insert = MockSecretKeyStore::new();
    sks_returning_duplicate_key_id_error_on_insert
        .expect_insert()
        .times(1)
        .return_const(Err(SecretKeyStoreInsertionError::DuplicateKeyId(
            duplicated_key_id,
        )));
    sks_returning_duplicate_key_id_error_on_insert
}

pub fn secret_key_store_with_serialization_error_on_insert() -> impl SecretKeyStore {
    let mut sks_returning_serialization_error_on_insert = MockSecretKeyStore::new();
    sks_returning_serialization_error_on_insert
        .expect_insert()
        .times(1)
        .return_const(Err(SecretKeyStoreInsertionError::SerializationError(
            "error serializing key".to_string(),
        )));
    sks_returning_serialization_error_on_insert
}

pub fn secret_key_store_with_io_error_on_insert() -> impl SecretKeyStore {
    let mut sks_returning_io_error_on_insert = MockSecretKeyStore::new();
    sks_returning_io_error_on_insert
        .expect_insert()
        .times(1)
        .return_const(Err(SecretKeyStoreInsertionError::TransientError(
            "io error persisting secret key store".to_string(),
        )));
    sks_returning_io_error_on_insert
}

pub fn secret_key_store_containing_key_with_invalid_encoding(key_id: KeyId) -> impl SecretKeyStore {
    let mut key_store = TempSecretKeyStore::new();
    let secret_key_with_invalid_der = CspSecretKey::TlsEd25519(TlsEd25519SecretKeyDerBytes::new(
        b"invalid DER encoding".to_vec(),
    ));
    assert!(
        key_store
            .insert(key_id, secret_key_with_invalid_der, None)
            .is_ok()
    );
    key_store
}

pub fn secret_key_store_containing_key_with_invalid_length(key_id: KeyId) -> impl SecretKeyStore {
    let mut key_store = TempSecretKeyStore::new();

    let secret_key_with_invalid_length = CspSecretKey::TlsEd25519(
        TlsEd25519SecretKeyDerBytes::new(b"invalid_ed25519_key".to_vec()),
    );
    assert!(
        key_store
            .insert(key_id, secret_key_with_invalid_length, None)
            .is_ok()
    );
    key_store
}
