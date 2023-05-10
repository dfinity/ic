use crate::key_id::KeyId;
use crate::secret_key_store::{
    Scope, SecretKeyStore, SecretKeyStoreInsertionError, SecretKeyStoreWriteError,
};
use crate::types::CspSecretKey;
use mockall::predicate::*;
use mockall::*;

mock! {
    pub SecretKeyStore {}

    pub trait SecretKeyStore {
        fn insert(&mut self, id: KeyId, key: CspSecretKey, scope: Option<Scope>) -> Result<(), SecretKeyStoreInsertionError>;
        fn get(&self, id: &KeyId) -> Option<CspSecretKey>;
        fn contains(&self, id: &KeyId) -> bool;
        fn remove(&mut self, id: &KeyId) -> Result<bool, SecretKeyStoreWriteError>;
        fn retain<F>(&mut self, filter: F, scope: Scope) -> Result<(), SecretKeyStoreWriteError>
            where F: Fn(&KeyId, &CspSecretKey) -> bool + 'static;
    }
}
