//! The registry public interface.
use ic_types::{
    registry::RegistryClientError, registry::RegistryDataProviderError, RegistryVersion,
};
pub use prost::Message as RegistryValue;
use serde::{Deserialize, Serialize};
use std::{cmp::Eq, fmt::Debug, hash::Hash};

/// The registry at version `0` is the empty registry.
pub const ZERO_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(0);

pub fn empty_zero_registry_record(key: &str) -> RegistryTransportRecord {
    RegistryTransportRecord {
        key: key.to_string(),
        version: ZERO_REGISTRY_VERSION,
        value: None,
    }
}

/// The RegistryClient provides methods to query the _local_ state of the
/// registry. All methods on this trait return immediately (i.e. there are no
/// side-effects on the critical path).
pub trait RegistryClient: Send + Sync {
    /// The following holds:
    ///
    /// (1) ∀ k: get_value(k, get_latest_version()).is_ok()
    ///
    ///   (A reported version is fully available)
    ///
    /// (2) ∀ k: v = get_value(k, ZERO_REGISTRY_VERSION) =>
    ///     (v.is_ok() && v.unwrap().is_none())
    ///
    ///   (The registry at version zero has a known state.)
    ///
    /// (3) ∀ k, t: (v0 = get_value(k, t); v1 = get_value(k, t))
    ///              && v0.is_ok() && v1.is_ok() => v0 == v1
    ///
    ///   (Any two method invocations with the same arguments
    ///    will always result in equal return values if both
    ///    calls do not return an error.)
    ///
    /// NOTE: The current implementation employs full replication
    /// and the cache only grows. Thus, it holds that
    ///
    ///    ∀ k, t <= get_latest_version(): get_value(k, t).is_ok().
    ///
    /// However, this might change in the future.
    ///
    /// The return value of the function is a serialized protobuf message
    /// belonging to the key. The type is opaque and the API does not provide
    /// any runtime type information. We might switch to a type such as
    /// google.protobuf.Any at some point in the future to provide general
    /// runtime type information.
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<Vec<u8>>;

    /// Returns all keys that start with `key_prefix` and are present at version
    /// `version`.
    ///
    /// Given the definition of get_value above, let K* be the set of all
    /// possible keys that start with `key_prefix`, then the following
    /// holds:
    ///
    /// (1) ∀ k ∈ K*: get_value(k, version).is_err()
    ///      <=> get_versioned_key_family(key_prefix, version).is_err()
    ///
    ///   (For a given version, all keys of a key family must be well-defined.)
    ///
    /// (2) ∀ k ∈ K*: get_value(k, version).is_ok().is_some() <=>
    ///     get_key_family(key_prefix, version).is_ok().contains(k)
    ///
    ///   (get_key_family is consistent with get_value)
    ///
    /// The returned list does not contain any duplicates. There are no
    /// guarantees wrt. the order of the contained elements.
    fn get_key_family(
        &self,
        key_prefix: &str,
        version: RegistryVersion,
    ) -> Result<Vec<String>, RegistryClientError>;

    fn get_value(&self, key: &str, version: RegistryVersion) -> RegistryClientResult<Vec<u8>> {
        self.get_versioned_value(key, version).map(|vr| vr.value)
    }

    /// Returns the latest version known to this replica. If the current version
    /// of the registry is `t`, then this method should eventually return a
    /// value no less than `t`.
    fn get_latest_version(&self) -> RegistryVersion;
}

/// A versioned (Key, Value) pair returned from the registry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RegistryVersionedRecord<T> {
    /// The key of the record.
    pub key: String,
    /// The version at which this record was added to the database. I.e., at
    /// this `version` the `key` was updated in the database.
    pub version: RegistryVersion,
    /// The value of this record. `None` means the value was deleted at
    /// `version`.
    pub value: Option<T>,
}

impl<T> RegistryVersionedRecord<T> {
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> RegistryVersionedRecord<U> {
        RegistryVersionedRecord {
            key: self.key,
            version: self.version,
            value: self.value.map(f),
        }
    }
}

impl<T> std::ops::Deref for RegistryVersionedRecord<T> {
    type Target = Option<T>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Result returns when fetching a versioned value from the registry.
pub type RegistryClientVersionedResult<T> = Result<RegistryVersionedRecord<T>, RegistryClientError>;
/// Result returns when fetching a value from the registry.
pub type RegistryClientResult<T> = Result<Option<T>, RegistryClientError>;

/// A RegistryRecord represents a versioned k/v-pair as stored in the registry
/// canister.
/// TODO(IC-102): This needs to be renamed to `RegistryRecord` after
/// we removed the legacy `RegistryRecord`.
pub type RegistryTransportRecord = RegistryVersionedRecord<Vec<u8>>;

/// A `RegistryDataProvider` is the data source that backs the `RegistryClient`,
/// i.e. the registry client uses an instances of this trait to get data from
/// the registry. In production, this trait will be instantiated by an
/// implementation that queries the registry canister on the NNS. For testing
/// and local deployment, this can be instantiated with an implementation that
/// reads from a local file, e.g.
pub trait RegistryDataProvider: Send + Sync {
    /// If successful, the call returns a pair, the first element of which is a
    /// list of records that were added to the database since `version`. The
    /// second element of the pair is the current registry version.
    ///
    /// The record version of the returned records MUST be greater than
    /// `version` and MUST be smaller or equal to the current registry version.
    ///
    /// Thus, if the local cache is at version `version`, after the returned
    /// records have been added to the local cache, the local registry is at
    /// the current version.
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion), RegistryDataProviderError>;
}

/// Whenever the local store is successfully updated, the time contained in the
/// certification is stored on disk. The `LocalStoreCertifiedTimeReader`
/// provides a method to read this time from disk.
pub trait LocalStoreCertifiedTimeReader: Send + Sync {
    /// The value returns is based on the UNIX EPOCH. If there had been no
    /// update so far, the UNIX EPOCH will be returned.
    ///
    /// Remark(2021-03-08): The time is *not* stored atomically, i.e.
    /// it might be that registry updates are observed by the
    /// `RegistryClient` but the time is not updated due to an error.
    ///
    /// It is assumed that this function is (a) called in tight loops and that
    /// (b) there are no strict requirements in terms of granularity.
    /// Thus, the implementation might cache values and only perform a read
    /// every couple of seconds.
    ///
    /// There are *NO* guarantees in terms of monotonicity.
    ///
    /// # PANICS
    ///
    /// An I/O-error when reading the value from disk is treated as a *hard
    /// failure*. In such a case, this function may panic.
    fn read_certified_time(&self) -> ic_types::time::Time;
}
