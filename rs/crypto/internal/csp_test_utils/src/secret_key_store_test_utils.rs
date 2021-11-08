//! Testing utilities for the Secret Key Store

// Import Note:
// * The mock and temp secret key stores are used in the IDKM.
// * The tests use CSP-private methods on secret keys.

use crate::files::mk_temp_dir_with_permissions;
use ic_crypto_internal_csp::secret_key_store;
use ic_crypto_internal_csp::types::CspSecretKey;
use ic_types::crypto::KeyId;
use mockall::predicate::*;
use mockall::*;
use secret_key_store::proto_store::ProtoSecretKeyStore;
use secret_key_store::{Scope, SecretKeyStore, SecretKeyStoreError};
use tempfile::TempDir;

mock! {
    /// Mock SecretKeyStore object for testing interactions
    pub SecretKeyStore {}

    pub trait SecretKeyStore {
        fn insert(&mut self, id: KeyId, key: CspSecretKey, scope: Option<Scope>) -> Result<(), SecretKeyStoreError>;
        fn get(&self, id: &KeyId) -> Option<CspSecretKey>;
        fn contains(&self, id: &KeyId) -> bool;
        fn remove(&mut self, id: &KeyId) -> bool;
    }
}

/// This store is opened in a newly created temporary directory, which will
/// exist for as long as the object stays in scope. As soon as the object (or
/// rather, the contained tempdir field) goes out of scope, the created
/// temporary directory will automatically be deleted.
pub struct TempSecretKeyStore {
    store: ProtoSecretKeyStore,
    #[allow(dead_code)]
    tempdir: TempDir,
}

impl TempSecretKeyStore {
    /// Create a new TempSecretKeyStore in a newly created temporary directory.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let tempdir = mk_temp_dir_with_permissions(0o700);
        let temp_file = &"temp_sks_data.pb";
        let store = ProtoSecretKeyStore::open(tempdir.path(), temp_file, None);
        TempSecretKeyStore { store, tempdir }
    }
}

impl SecretKeyStore for TempSecretKeyStore {
    fn insert(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError> {
        self.store.insert(id, key, scope)
    }

    fn get(&self, id: &KeyId) -> Option<CspSecretKey> {
        self.store.get(id)
    }

    fn contains(&self, id: &KeyId) -> bool {
        self.store.contains(id)
    }

    fn remove(&mut self, id: &KeyId) -> bool {
        self.store.remove(id)
    }

    fn retain<F>(&mut self, _filter: F, _scope: Scope)
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool,
    {
        unimplemented!()
    }
}
