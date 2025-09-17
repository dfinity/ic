use crate::key_id::KeyId;
use crate::secret_key_store::{
    SecretKeyStore, SecretKeyStoreInsertionError, SecretKeyStoreWriteError,
};
use crate::types::CspSecretKey;
use ic_crypto_internal_types::scope::Scope;
use ic_logger::{ReplicaLogger, debug, replica_logger::no_op_logger};
use std::collections::HashMap;

#[cfg(test)]
mod tests;

type SecretKeys = HashMap<KeyId, (CspSecretKey, Option<Scope>)>;

/// A secret key store that keeps data (only) in memory, without persisting to disk.
pub struct InMemorySecretKeyStore {
    keys: SecretKeys,
    logger: ReplicaLogger,
}

impl InMemorySecretKeyStore {
    #[allow(clippy::new_without_default)]
    pub fn new(logger: Option<ReplicaLogger>) -> Self {
        Self {
            keys: HashMap::new(),
            logger: logger.unwrap_or_else(no_op_logger),
        }
    }
}

impl SecretKeyStore for InMemorySecretKeyStore {
    fn insert(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreInsertionError> {
        match self.keys.get(&id) {
            Some(_) => Err(SecretKeyStoreInsertionError::DuplicateKeyId(id)),
            None => {
                self.keys.insert(id, (key, scope));
                debug!(self.logger, "Inserted new secret key {}", id);
                Ok(())
            }
        }
    }

    fn insert_or_replace(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreWriteError> {
        match self.keys.insert(id, (key, scope)) {
            None => debug!(self.logger, "Inserted new secret key {}", id),
            Some(_) => debug!(self.logger, "Replaced existing secret key {}", id),
        }
        Ok(())
    }

    fn get(&self, id: &KeyId) -> Option<CspSecretKey> {
        self.keys.get(id).map(|(csp_key, _)| csp_key.to_owned())
    }

    fn contains(&self, id: &KeyId) -> bool {
        self.keys.contains_key(id)
    }

    fn remove(&mut self, id: &KeyId) -> Result<bool, SecretKeyStoreWriteError> {
        match self.keys.remove(id) {
            Some(_) => {
                debug!(self.logger, "Removed secret key {}", id);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn retain<F>(&mut self, filter: F, scope: Scope) -> Result<(), SecretKeyStoreWriteError>
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool + 'static,
    {
        let mut all_keys = SecretKeys::new();
        core::mem::swap(&mut all_keys, &mut self.keys);
        for (key_id, (csp_key, maybe_scope)) in all_keys.drain() {
            if maybe_scope != Some(scope) || filter(&key_id, &csp_key) {
                self.keys.insert(key_id, (csp_key, maybe_scope));
            } else {
                debug!(
                    self.logger,
                    "Deleting key with ID {} with scope {}", key_id, scope
                );
            }
        }
        Ok(())
    }

    fn retain_would_modify_keystore<F>(&self, filter: F, scope: Scope) -> bool
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool + 'static,
    {
        for (key_id, (csp_key, maybe_scope)) in self.keys.iter() {
            if maybe_scope == &Some(scope) && !filter(key_id, csp_key) {
                // Key is to be deleted, i.e., the keystore will be modified.
                return true;
            }
        }
        false
    }
}
