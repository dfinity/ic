//! The registry public interface.
use ic_types::{
    RegistryVersion, registry::RegistryClientError, registry::RegistryDataProviderError, time::Time,
};
pub use prost::Message as RegistryValue;
use serde::{Deserialize, Serialize};
use std::{cmp::Eq, collections::BTreeMap, fmt::Debug, hash::Hash, time::Duration};

/// The registry at version `0` is the empty registry.
pub const ZERO_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(0);

/// How often we poll the local store.
pub const POLLING_PERIOD: Duration = Duration::from_secs(5);

pub fn empty_zero_registry_record(key: &str) -> RegistryRecord {
    RegistryRecord {
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

    /// Returns the time at which the given version became available locally or
    /// None if the version is not available locally,
    fn get_version_timestamp(&self, registry_version: RegistryVersion) -> Option<Time>;

    /// Returns the time at which the registry canister applied the given
    /// version, or `None` if this node does not know it — either because the
    /// version is not available locally, or because it was applied before the
    /// registry canister recorded timestamps.
    ///
    /// Unlike [`Self::get_version_timestamp`], this never falls back to a local
    /// observation, so every node that answers `Some` answers the same value.
    /// That is what makes it usable as an input to consensus; callers that only
    /// need a rough local notion of age should use `get_version_timestamp`.
    fn get_version_canister_timestamp(&self, registry_version: RegistryVersion) -> Option<Time> {
        let _ = registry_version;
        None
    }
}

/// A versioned (Key, Value) pair returned from the registry.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
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
pub type RegistryRecord = RegistryVersionedRecord<Vec<u8>>;

/// A `RegistryDataProvider` is the data source that backs the `RegistryClient`,
/// i.e. the registry client uses an instances of this trait to get data from
/// the registry. In production, this trait will be instantiated by an
/// implementation that queries the registry canister on the NNS. For testing
/// and local deployment, this can be instantiated with an implementation that
/// reads from a local file, e.g.
pub trait RegistryDataProvider: Send + Sync {
    /// If successful, the call returns a list of records that represents the
    /// delta between `version` and some registry version larger or equal to
    /// `version`.
    ///
    /// (1) All returned records must be greater than `version`.
    ///
    /// (2) Let max_v be the maximal version in the returned records, then the
    /// return records must represent all updates to the registry for all
    /// versions in the interval (version..max_v]. In particular, each version
    /// must be fully contained.
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryRecord>, RegistryDataProviderError>;

    /// Same as [`Self::get_updates_since`], but additionally returns the times
    /// at which the registry canister applied the covered versions.
    ///
    /// Data providers that cannot supply those times use the default
    /// implementation, which reports none of them. Callers must then fall back
    /// to whatever local notion of time they had before.
    fn get_updates_since_with_timestamps(
        &self,
        version: RegistryVersion,
    ) -> Result<RegistryUpdates, RegistryDataProviderError> {
        Ok(RegistryUpdates {
            records: self.get_updates_since(version)?,
            version_timestamps: BTreeMap::new(),
        })
    }
}

/// Registry updates, together with the times at which the registry canister
/// applied the covered versions.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct RegistryUpdates {
    /// The delta, as returned by [`RegistryDataProvider::get_updates_since`].
    pub records: Vec<RegistryRecord>,

    /// The time at which the registry canister applied each covered version,
    /// in nanoseconds since UNIX EPOCH.
    ///
    /// This is replicated NNS state covered by the certified changelog, so all
    /// nodes observe the same value for a given version. Versions written
    /// before the registry canister recorded timestamps, and versions obtained
    /// from a data provider that does not supply them, are absent.
    pub version_timestamps: BTreeMap<RegistryVersion, u64>,
}
