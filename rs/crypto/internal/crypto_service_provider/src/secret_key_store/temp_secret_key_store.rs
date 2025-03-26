use crate::key_id::KeyId;
use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::secret_key_store::{
    SecretKeyStore, SecretKeyStoreInsertionError, SecretKeyStoreWriteError,
};
use crate::types::CspSecretKey;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_internal_types::scope::Scope;
use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tempfile::TempDir;

/// This store is opened in a newly created temporary directory, which will
/// exist for as long as the object stays in scope. As soon as the object (or
/// rather, the contained tempdir field) goes out of scope, the created
/// temporary directory will automatically be deleted.
pub struct TempSecretKeyStore {
    store: ProtoSecretKeyStore,
    _temp_dir: TempDir,
}

impl TempSecretKeyStore {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let temp_dir = tempfile::Builder::new()
            .prefix("ic_crypto_")
            .tempdir()
            .expect("failed to create temporary crypto directory");
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o700)).unwrap_or_else(|_| {
            panic!(
                "failed to set permissions of crypto directory {}",
                temp_dir.path().display()
            )
        });
        let temp_file = "temp_sks_data.pb";
        let store = ProtoSecretKeyStore::open(
            temp_dir.path(),
            temp_file,
            None,
            Arc::new(CryptoMetrics::none()),
        );
        TempSecretKeyStore {
            store,
            _temp_dir: temp_dir,
        }
    }
}

impl SecretKeyStore for TempSecretKeyStore {
    fn insert(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreInsertionError> {
        self.store.insert(id, key, scope)
    }

    fn insert_or_replace(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreWriteError> {
        self.store.insert_or_replace(id, key, scope)
    }

    fn get(&self, id: &KeyId) -> Option<CspSecretKey> {
        self.store.get(id)
    }

    fn contains(&self, id: &KeyId) -> bool {
        self.store.contains(id)
    }

    fn remove(&mut self, id: &KeyId) -> Result<bool, SecretKeyStoreWriteError> {
        self.store.remove(id)
    }

    fn retain<F>(&mut self, filter: F, scope: Scope) -> Result<(), SecretKeyStoreWriteError>
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool + 'static,
    {
        self.store.retain(filter, scope)
    }

    fn retain_would_modify_keystore<F>(&self, filter: F, scope: Scope) -> bool
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool + 'static,
    {
        self.store.retain_would_modify_keystore(filter, scope)
    }
}
