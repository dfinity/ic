use crate::key_id::KeyId;
use crate::secret_key_store::{
    Scope, SecretKeyStore, SecretKeyStoreError, SecretKeyStorePersistenceError,
};
use crate::types::CspSecretKey;
use mockall::predicate::*;
use mockall::*;

mock! {
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
