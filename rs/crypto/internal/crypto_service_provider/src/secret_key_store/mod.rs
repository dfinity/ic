//! Interfaces for saving and retrieving secret keys

use crate::types::CspSecretKey;
pub use ic_crypto_internal_types::scope;
use ic_types::crypto::KeyId;
pub use scope::Scope;
use std::fmt;

// Implementations
pub mod proto_store;
pub mod volatile_store;

#[cfg(test)]
pub mod test_utils;

/// A store for secret key material
///
/// If errors occur regarding reading from or writing to the underlying
/// persistency layer, the methods panic.
pub trait SecretKeyStore: Send + Sync {
    /// Adds a key with a given `id` to the store.
    ///
    /// Existing keys are not replaced: if a key with the given `id` already
    /// exists, a `DuplicateKeyId` error is returned. To replace a key with
    /// a given id, it must first be removed.
    fn insert(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError>;

    /// Inserts a key with a given `id` into the store, replacing any existing
    /// entry.
    ///
    /// * If there is no existing key with the given `id` in the store, the new
    ///   key is inserted.
    /// * If there is a key with the given `id` in the store, it is replaced.
    fn insert_or_replace(
        &mut self,
        id: KeyId,
        key: CspSecretKey,
        scope: Option<Scope>,
    ) -> Result<(), SecretKeyStoreError> {
        self.remove(&id);
        self.insert(id, key, scope)
    }

    /// Retrieves the key with the given `id`.
    ///
    /// Returns `None` if the store does not contain a key with the given `id`.
    // The database memory is safe only for the duration of the transaction, so the
    // key must be copied out.  As such it is doubtful that returning the key by
    // reference is constructive.  Also, the key should be scrubbed on removal.
    fn get(&self, id: &KeyId) -> Option<CspSecretKey>;

    /// Checks if the store contains a key with the given `id`.
    fn contains(&self, id: &KeyId) -> bool;

    /// Removes the key with the given `id` from the store.
    ///
    /// The return value indicates whether a key with the given `id` was
    /// previously contained and removed.
    fn remove(&mut self, id: &KeyId) -> bool;

    /// Keeps only entries in a scope for which the filter function returns
    /// `true` and removes the rest.
    ///
    /// Conversely, this removes entries in a given scope for which the filter
    /// function returns `false`.
    ///
    /// # Logs
    /// Implementations SHOULD log the KeyId of any deleted keys
    ///
    /// # Panics
    /// This MAY panic if the predicate panics.
    ///
    /// Details: Unlike e.g. `HashMap::filter_drain(..)` this does not
    /// (handle the case where the filter panics)[https://doc.rust-lang.org/std/collections/struct.HashMap.html#method.drain_filter].
    /// If the filter panics, the panic is likely to cause the secret key store
    /// to crash. Thus lambdas MUST NEVER be taken from untrusted sources.
    /// If panics are to be handled the predicate can be run in a separate
    /// thread and panics handles with (`thread::Result`)[https://doc.rust-lang.org/std/thread/type.Result.html]
    /// (depending on whether we are run from inside a suitable runtime), or
    /// (`panic::catch_unwind(..)`)[https://doc.rust-lang.org/nightly/std/panic/fn.catch_unwind.html]
    /// can be added to this implementation and we may require `panic="unwind"`.
    /// See the (book)[https://doc.rust-lang.org/edition-guide/rust-2018/error-handling-and-panics/controlling-panics-with-std-panic.html]
    /// and function documentation for more details.
    fn retain<F>(&mut self, _filter: F, _scope: Scope)
    where
        F: Fn(&KeyId, &CspSecretKey) -> bool,
    {
        unimplemented!()
    }
}

/// Errors that can occur while interacting with the secret key store
#[derive(Clone, Debug)]
pub enum SecretKeyStoreError {
    DuplicateKeyId(KeyId),
}

impl std::error::Error for SecretKeyStoreError {}

impl fmt::Display for SecretKeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretKeyStoreError::DuplicateKeyId(key_id) => {
                write!(f, "Key with ID {} already exists in the key store", key_id)
            }
        }
    }
}
