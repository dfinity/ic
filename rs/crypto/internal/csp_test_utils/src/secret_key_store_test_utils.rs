//! Testing utilities for the Secret Key Store

// Import Note:
// * The mock and temp secret key stores are used in the IDKM.
// * The tests use CSP-private methods on secret keys.

use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::secret_key_store;
use ic_crypto_internal_csp::secret_key_store::SecretKeyStorePersistenceError;
use ic_crypto_internal_csp::types::CspSecretKey;
use mockall::predicate::*;
use mockall::*;
use secret_key_store::{Scope, SecretKeyStore, SecretKeyStoreError};

mock! {
    /// Mock SecretKeyStore object for testing interactions
    pub SecretKeyStore {}

    pub trait SecretKeyStore {
        fn insert(&mut self, id: KeyId, key: CspSecretKey, scope: Option<Scope>) -> Result<(), SecretKeyStoreError>;
        fn get(&self, id: &KeyId) -> Option<CspSecretKey>;
        fn contains(&self, id: &KeyId) -> bool;
        fn remove(&mut self, id: &KeyId) -> Result<bool, SecretKeyStorePersistenceError>;
        fn retain<F>(&mut self, filter: F, scope: Scope) -> Result<(), SecretKeyStorePersistenceError>
            where F: Fn(&KeyId, &CspSecretKey) -> bool + 'static;
    }
}
