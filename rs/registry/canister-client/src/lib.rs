//! An implementation of RegistryClient intended to be used in canister
//! where polling in the background is not required because handed over to a timer.
//! The code is entirely copied from `ic-registry-client-fake` and more tests added.

use async_trait::async_trait;
use ic_interfaces_registry::{RegistryClientResult, RegistryClientVersionedResult};
use ic_types::RegistryVersion;
use ic_types::registry::RegistryClientError;
use ic_types::registry::RegistryClientError::DecodeError;
use std::collections::{BTreeMap, HashSet};

mod stable_canister_client;
mod stable_memory;

use crate::stable_memory::UnixTsNanos;
pub use stable_canister_client::StableCanisterRegistryClient;
pub use stable_memory::{RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue};

/// The CanisterRegistryClient provides methods to maintain and read a local cache of Registry data
/// This is similar to the RegistryClient interface use in the protocol, but without the
/// method to retrieve the "timestamp" that a version was first added to the local
/// canister.
#[async_trait]
pub trait CanisterRegistryClient {
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

    fn get_key_family_with_values(
        &self,
        key_prefix: &str,
        version: RegistryVersion,
    ) -> Result<Vec<(String, Vec<u8>)>, RegistryClientError>;

    /// Returns a particular value for a key at a given version.
    fn get_value(&self, key: &str, version: RegistryVersion) -> RegistryClientResult<Vec<u8>> {
        self.get_versioned_value(key, version).map(|vr| vr.value)
    }

    /// Returns the latest version known to this canister. If the current version
    /// of the registry is `t`, then this method should eventually return a
    /// value no less than `t`.
    fn get_latest_version(&self) -> RegistryVersion;

    /// Updates the local version to the latest from the Registry. This may execute
    /// over multiple messages.  It should generally be scheduled in a timer, but if it's never called
    /// the local registry data will not be in sync with the data in the Registry canister.
    async fn sync_registry_stored(&self) -> Result<RegistryVersion, String>;

    /// Returns a map from timestamps in nanoseconds to a set of `RegistryVersion`s.
    /// Each key represents the timestamps when the registry versions have been added,
    /// and the associated value is the set of all registry versions introduced at that timestamp.
    fn timestamp_to_versions_map(&self) -> BTreeMap<UnixTsNanos, HashSet<RegistryVersion>>;
}

// Helpers

/// Get the decoded value of a key from the registry.
pub fn get_decoded_value<T: prost::Message + Default>(
    registry_client: &dyn CanisterRegistryClient,
    key: &str,
    version: RegistryVersion,
) -> RegistryClientResult<T> {
    registry_client
        .get_value(key, version)?
        .map(|bytes| {
            T::decode(bytes.as_slice()).map_err(|e| DecodeError {
                error: format!("{e:?}"),
            })
        })
        .transpose()
}
