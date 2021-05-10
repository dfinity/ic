//! In-memory secret key store (for testing)
use crate::secret_key_store::{Scope, SecretKeyStore, SecretKeyStoreError};
use crate::types::CspSecretKey;
use ic_types::crypto::KeyId;
use std::collections::HashMap;

/// An in-memory, non-thread-safe secret key store for testing purposes.
#[allow(unused)]
pub struct VolatileSecretKeyStore {
    keys: HashMap<KeyId, (CspSecretKey, Option<Scope>)>,
}

impl VolatileSecretKeyStore {
    #[allow(unused)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        VolatileSecretKeyStore {
            keys: HashMap::new(),
        }
    }
}

impl SecretKeyStore for VolatileSecretKeyStore {
    fn insert(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError> {
        if self.keys.contains_key(&id) {
            return Err(SecretKeyStoreError::DuplicateKeyId(id));
        }

        self.keys.insert(id, (key, scope));
        Ok(())
    }

    fn get(&self, id: &KeyId) -> Option<CspSecretKey> {
        self.keys
            .get(id)
            .map(|(secret_key, _scope)| secret_key)
            .cloned()
    }

    fn contains(&self, id: &KeyId) -> bool {
        self.keys.contains_key(id)
    }

    fn remove(&mut self, id: &KeyId) -> bool {
        self.keys.remove(id).is_some()
    }

    fn retain<F>(&mut self, filter: F, scope: Scope)
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool,
    {
        let mut keys = HashMap::new();
        core::mem::swap(&mut keys, &mut self.keys);
        self.keys = keys
            .into_iter()
            .filter(|(id, (key, key_scope))| {
                let keep = (*key_scope != Some(scope)) || filter(id, key);
                if !keep {
                    // Production code should use a logger.  The volatile key store has none so we
                    // print instead.
                    println!("WARNING: Deleting key ID {}", id);
                }
                keep
            })
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_utils;
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn should_retrieve_inserted_key(seed1: u64, seed2: u64) {
            test_utils::should_retrieve_inserted_key(seed1, seed2, volatile_key_store());
        }

        #[test]
        fn should_contain_existing_key(seed1: u64, seed2: u64) {
            test_utils::should_contain_existing_key(seed1, seed2, volatile_key_store());
        }

        #[test]
        fn should_not_contain_nonexisting_key(seed1: u64) {
            test_utils::should_not_contain_nonexisting_key(seed1, volatile_key_store());
        }

        #[test]
        fn should_remove_existing_key(seed1: u64, seed2: u64) {
            test_utils::should_remove_existing_key(seed1, seed2, volatile_key_store());
        }

        #[test]
        fn should_not_remove_nonexisting_key(seed1: u64) {
            test_utils::should_not_remove_nonexisting_key(seed1, volatile_key_store());
        }

        #[test]
        fn deleting_twice_should_return_false(seed1: u64, seed2: u64) {
            test_utils::deleting_twice_should_return_false(seed1, seed2, volatile_key_store());
        }

        #[test]
        fn no_overwrites(seed1: u64, seed2: u64, seed3: u64) {
            test_utils::no_overwrites(seed1, seed2, seed3, volatile_key_store());
        }

        ////////////////////////////////////////////////////////////////////////////////////////
        // If you add tests here, remember to also add them for the ProtoSecretKeyStore
        ////////////////////////////////////////////////////////////////////////////////////////
    }

    #[test]
    fn should_retain_expected_keys() {
        test_utils::should_retain_expected_keys(volatile_key_store());
    }

    fn volatile_key_store() -> VolatileSecretKeyStore {
        VolatileSecretKeyStore::new()
    }
}
