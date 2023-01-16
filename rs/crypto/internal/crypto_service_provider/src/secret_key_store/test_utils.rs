#![allow(clippy::unwrap_used)]
// Note: The mock and temp secret key stores are used in the IDKM.
// Weird compiler errors - can a mock from elsewhere not be used?
// Ok, let's duplicate the mock and see what happens.

use crate::key_id::KeyId;
use crate::secret_key_store::{
    Scope, SecretKeyStore, SecretKeyStoreError, SecretKeyStorePersistenceError,
};
use crate::types::CspSecretKey;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_secrets_containers::SecretArray;
use mockall::predicate::*;
use mockall::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

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

pub fn make_key_id(seed: u64) -> KeyId {
    KeyId::from(ChaCha20Rng::seed_from_u64(seed).gen::<[u8; 32]>())
}

pub fn make_secret_key(seed: u64) -> CspSecretKey {
    CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&ChaCha20Rng::seed_from_u64(seed).gen()),
    ))
}
