#![allow(clippy::unwrap_used)]
// Note: The mock and temp secret key stores are used in the IDKM.
// Weird compiler errors - can a mock from elsewhere not be used?
// Ok, let's duplicate the mock and see what happens.

use crate::secret_key_store::proto_store::ProtoSecretKeyStore;
use crate::secret_key_store::{scope::ConstScope, Scope, SecretKeyStore, SecretKeyStoreError};
use crate::types::CspSecretKey;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_csp_test_utils::files::mk_temp_dir_with_permissions;
use ic_crypto_secrets_containers::SecretArray;
use ic_types::crypto::KeyId;
use mockall::predicate::*;
use mockall::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tempfile::TempDir;

mock! {
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
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let tempdir = mk_temp_dir_with_permissions(0o700);
        let store = ProtoSecretKeyStore::open(tempdir.path(), None);
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

    fn retain<F>(&mut self, filter: F, scope: Scope)
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool,
    {
        self.store.retain(filter, scope)
    }
}

fn make_key_id(seed: u64) -> KeyId {
    KeyId::from(ChaCha20Rng::seed_from_u64(seed).gen::<[u8; 32]>())
}

fn make_secret_key(seed: u64) -> CspSecretKey {
    CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&ChaCha20Rng::seed_from_u64(seed).gen()),
    ))
}

pub fn should_retrieve_inserted_key<T: SecretKeyStore>(seed1: u64, seed2: u64, mut key_store: T) {
    let key_id: KeyId = make_key_id(seed1);
    let key = make_secret_key(seed2);

    assert!(key_store.insert(key_id, key.clone(), None).is_ok());

    let retrieved_key = key_store.get(&key_id).unwrap();
    assert_eq!(key, retrieved_key);
}

pub fn should_contain_existing_key<T: SecretKeyStore>(seed1: u64, seed2: u64, mut key_store: T) {
    let key_id: KeyId = make_key_id(seed1);

    assert!(key_store
        .insert(key_id, make_secret_key(seed2), None)
        .is_ok());
    assert!(key_store.contains(&key_id));
}

pub fn should_not_contain_nonexisting_key<T: SecretKeyStore>(seed1: u64, key_store: T) {
    let non_existing_key_id: KeyId = make_key_id(seed1);

    assert!(!key_store.contains(&non_existing_key_id));
}

pub fn should_remove_existing_key<T: SecretKeyStore>(seed1: u64, seed2: u64, mut key_store: T) {
    let key_id: KeyId = make_key_id(seed1);

    assert!(key_store
        .insert(key_id, make_secret_key(seed2), None)
        .is_ok());

    assert!(key_store.get(&key_id).is_some());
    assert!(key_store.remove(&key_id));
    assert!(key_store.get(&key_id).is_none());
}

pub fn should_not_remove_nonexisting_key<T: SecretKeyStore>(seed1: u64, mut key_store: T) {
    let non_existing_key_id: KeyId = make_key_id(seed1);

    assert_eq!(key_store.remove(&non_existing_key_id), false);
}

pub fn deleting_twice_should_return_false<T: SecretKeyStore>(
    seed1: u64,
    seed2: u64,
    mut key_store: T,
) {
    let key_id_1: KeyId = make_key_id(seed1);
    let key_1 = make_secret_key(seed2);

    assert!(key_store.insert(key_id_1, key_1, None).is_ok());

    assert_eq!(key_store.remove(&key_id_1), true);
    assert_eq!(key_store.contains(&key_id_1), false);
    assert_eq!(key_store.remove(&key_id_1), false);
}

pub fn no_overwrites<T: SecretKeyStore>(seed1: u64, seed2: u64, seed3: u64, mut key_store: T) {
    let key_id_1: KeyId = make_key_id(seed1);
    let key_1 = make_secret_key(seed2);
    let key_2 = make_secret_key(seed3);
    assert_ne!(key_1, key_2);

    key_store.insert(key_id_1, key_1.clone(), None).unwrap();

    assert!(key_store.insert(key_id_1, key_2, None).is_err());
    assert_eq!(key_1, key_store.get(&key_id_1).unwrap());
}

/// Verifies that `retain(..)` removes precisely the expected keys, no more, no
/// less.
pub fn should_retain_expected_keys<T: SecretKeyStore>(mut key_store: T) {
    // Note: the logic is unaffected by the values of the keys, as long as they are
    // distinct.  Greater test exposure can be sought by varying the patterns of
    // insertion, e.g. performing other operations between the insertion and the
    // retain command, calling retain several times and so on.  Varying the keys is
    // a comparatively useless exercise so we do not do so.
    let mut seeds = 0..;
    let mut next_key = || {
        (
            make_key_id(seeds.next().unwrap()),
            make_secret_key(seeds.next().unwrap()),
        )
    };
    let key_with_id_to_retain = next_key();
    let key_with_value_to_retain = next_key();
    let key_to_remove = next_key();
    let key_with_different_scope = next_key();
    let key_with_no_scope = next_key();

    let selected_scope = Scope::Const(ConstScope::Test0);
    let different_scope = Scope::Const(ConstScope::Test1);

    let mut insert_key_with_scope = |pair: &(KeyId, CspSecretKey), scope: Option<Scope>| {
        key_store.insert(pair.0, pair.1.clone(), scope).unwrap();
        assert!(key_store.contains(&pair.0));
    };

    insert_key_with_scope(&key_with_id_to_retain, Some(selected_scope));
    insert_key_with_scope(&key_with_value_to_retain, Some(selected_scope));
    insert_key_with_scope(&key_to_remove, Some(selected_scope));
    insert_key_with_scope(&key_with_different_scope, Some(different_scope));
    insert_key_with_scope(&key_with_no_scope, None);

    let id_to_retain = &key_with_id_to_retain.0;
    let value_to_retain = &key_with_value_to_retain.1;
    key_store.retain(
        |id, value| (id == id_to_retain) || (value == value_to_retain),
        selected_scope,
    );

    assert_eq!(
        key_store.contains(&key_with_id_to_retain.0),
        true,
        "Expected to retain key by ID"
    );
    assert_eq!(
        key_store.contains(&key_with_value_to_retain.0),
        true,
        "Expected to retain key by value"
    );
    assert_eq!(
        key_store.contains(&key_to_remove.0),
        false,
        "Expected to remove unselected key"
    );
    assert_eq!(
        key_store.contains(&key_with_different_scope.0),
        true,
        "Expected to keep key in different scope"
    );
    assert_eq!(
        key_store.contains(&key_with_no_scope.0),
        true,
        "Expected to keep key with no scope"
    );
}
