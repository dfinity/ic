use async_trait::async_trait;
use ic_base_types::{CanisterId, RegistryVersion};
use ic_nervous_system_common::NervousSystemError;
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_transport::pb::v1::registry_mutation::Type;
use ic_registry_transport::pb::v1::{RegistryDelta, RegistryMutation, RegistryValue};
use ic_registry_transport::{
    deserialize_get_changes_since_response, deserialize_get_latest_version_response,
    serialize_get_changes_since_request, Error,
};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

#[async_trait]
pub trait Registry: Send + Sync {
    async fn get_latest_version(&self) -> Result<RegistryVersion, NervousSystemError>;
    async fn registry_changes_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryDelta>, NervousSystemError>;
}

pub struct RegistryCanister {
    canister_id: CanisterId,
}

impl RegistryCanister {
    pub fn new() -> Self {
        Self {
            canister_id: REGISTRY_CANISTER_ID,
        }
    }
}

impl Default for RegistryCanister {
    fn default() -> Self {
        // This is safe in tests because it would just point to a test registry
        Self::new()
    }
}

#[async_trait]
impl Registry for RegistryCanister {
    async fn get_latest_version(&self) -> Result<RegistryVersion, NervousSystemError> {
        let response: Result<Vec<u8>, (i32, String)> =
            CdkRuntime::call_bytes_with_cleanup(self.canister_id, "get_latest_version", &[]).await;
        response
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(format!(
                    "Request to get_latest_version failed with code {code} and message: {msg}",
                ))
            })
            .and_then(|r| {
                deserialize_get_latest_version_response(r)
                    .map_err(|e| {
                        NervousSystemError::new_with_message(format!(
                            "Could not decode response {e:?}"
                        ))
                    })
                    .map(RegistryVersion::new)
            })
    }

    async fn registry_changes_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryDelta>, NervousSystemError> {
        let bytes = serialize_get_changes_since_request(version.get()).map_err(|e| {
            NervousSystemError::new_with_message(format!(
                "Could not encode request for get_changes_since for version {:?}: {}",
                version, e
            ))
        })?;
        CdkRuntime::call_bytes_with_cleanup(self.canister_id, "get_changes_since", &bytes)
            .await
            .map_err(|(code, msg)| {
                NervousSystemError::new_with_message(format!(
                    "Request to get_changes_since failed with code {code} and message: {msg}",
                ))
            })
            .and_then(|r| {
                deserialize_get_changes_since_response(r)
                    .map_err(|e| {
                        NervousSystemError::new_with_message(format!(
                            "Could not decode response {e:?}"
                        ))
                    })
                    .map(|(deltas, _)| deltas)
            })
    }
}

type FakeGetChangesSince = BTreeMap<u64, Result<Vec<RegistryDelta>, Error>>;
type FakeGetLatestVersion = Vec<Result<u64, Error>>;

/// This uses a Vec instead of VecDeque since inserting test values won't necessarily happen
/// in the same order as it would in the real registry.
type FakeRegistryMap = BTreeMap<Vec<u8>, Vec<RegistryValue>>;

/// A fake registry client for testing.  This re-implements some internals from the Registry
/// as it is easier to interact with this store as though you were making Registry updates
/// than trying to mock out responses.  Additionally, it is possible to override the responses
/// so that you can test errors.  Responses that are explicitly set are consumed.
#[derive(Default)]
pub struct FakeRegistry {
    version: AtomicU64,
    store: Arc<Mutex<FakeRegistryMap>>,
    override_get_changes_since: Arc<Mutex<FakeGetChangesSince>>,
    override_get_latest_version: Arc<Mutex<FakeGetLatestVersion>>,
}

impl FakeRegistry {
    pub fn new() -> Self {
        FakeRegistry::default()
    }

    /// Test method to get the latest version in the FakeRegistry (as opposed to
    /// get_latest_version which implements the Registry interface and returns a Result)
    pub fn latest_version(&self) -> u64 {
        self.version.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn set_fake_response_for_get_changes_since(
        &mut self,
        version: u64,
        response: Result<Vec<RegistryDelta>, Error>,
    ) {
        self.override_get_changes_since
            .lock()
            .unwrap()
            .insert(version, response);
    }

    pub fn add_fake_response_for_get_latest_version(&self, response: Result<u64, Error>) {
        self.override_get_latest_version
            .lock()
            .unwrap()
            .push(response);
    }

    /// Encodes a prost message at latest_version + 1, and updates latest_version.
    pub fn encode_value<T: prost::Message>(&self, key: impl AsRef<str>, value: Option<T>) {
        self.encode_value_at_version(
            key,
            self.version.load(std::sync::atomic::Ordering::SeqCst) + 1,
            value,
        );
    }

    /// Encodes a prost message at the given version, and updates latest_version if the given version is
    /// greater than latest_version.  Panics if the value is already set at that version.
    pub fn encode_value_at_version<T: prost::Message>(
        &self,
        key: impl AsRef<str>,
        version: u64,
        value: Option<T>,
    ) {
        let value = value.map(|v| v.encode_to_vec());
        self.set_value_at_version(key, version, value);
    }

    pub fn get_value(&self, key: impl AsRef<str>) -> Option<Vec<u8>> {
        self.get_value_at_version(key, self.version.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn get_value_at_version(&self, key: impl AsRef<str>, version: u64) -> Option<Vec<u8>> {
        let key_bytes = key.as_ref().as_bytes().to_vec();
        let binding = self.store.lock().unwrap();
        binding.get(&key_bytes).and_then(|values| {
            values
                .iter()
                .rev()
                .find(|v| v.version <= version)
                .and_then(|v| {
                    if v.deletion_marker {
                        None
                    } else {
                        Some(v.value.clone())
                    }
                })
        })
    }

    pub fn get_decoded_value<T: prost::Message + Default>(
        &self,
        key: impl AsRef<str>,
    ) -> Option<T> {
        self.get_value(key)
            .and_then(|value| T::decode(value.as_slice()).ok())
    }

    /// Sets a value at latest_version + 1, and updates latest_version.
    pub fn set_value(&self, key: impl AsRef<str>, value: Option<Vec<u8>>) {
        self.set_value_at_version(
            key,
            self.version.load(std::sync::atomic::Ordering::SeqCst) + 1,
            value,
        );
    }

    /// Sets a value at the given version, and updates latest_version if the given version is
    /// greater than latest_version.  Panics if the value is already set at that version.
    pub fn set_value_at_version(&self, key: impl AsRef<str>, version: u64, value: Option<Vec<u8>>) {
        let key_bytes = key.as_ref().as_bytes().to_vec();
        let mut binding = self.store.lock().unwrap();

        let entry = binding.entry(key_bytes).or_default();

        match entry.binary_search_by_key(&version, |registry_value| registry_value.version) {
            Ok(_) => panic!(
                "Key {} already exists at version {version}. Cannot overwrite. \
                Please check your test setup",
                key.as_ref()
            ),
            Err(index) => {
                let deletion_marker = value.is_none();
                let value = value.unwrap_or_default();
                let registry_value = RegistryValue {
                    value,
                    version,
                    deletion_marker,
                };
                entry.insert(index, registry_value)
            }
        }
        if version > self.version.load(std::sync::atomic::Ordering::SeqCst) {
            self.version
                .store(version, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Applies mutations as latest version.  This is similar to what Registry actuall does, which
    /// is helpful for re-using other code that sets initial Registry mutations.
    pub fn apply_mutations(&self, mutations: Vec<RegistryMutation>) {
        let current_version = self.version.load(std::sync::atomic::Ordering::SeqCst);
        let next_version = current_version + 1;
        for mutation in mutations {
            let mut binding = self.store.lock().unwrap();

            let entry = binding.entry(mutation.key).or_default();
            entry.push(RegistryValue {
                value: mutation.value,
                version: next_version,
                deletion_marker: mutation.mutation_type == Type::Delete as i32,
            })
        }
        // Set next version.
        self.version
            .store(next_version, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait]
impl Registry for FakeRegistry {
    async fn get_latest_version(&self) -> Result<RegistryVersion, NervousSystemError> {
        if let Some(response) = self.override_get_latest_version.lock().unwrap().pop() {
            return response
                .map(RegistryVersion::new)
                .map_err(|e| NervousSystemError::new_with_message(format!("{e:?}")));
        }

        Ok(self
            .version
            .load(std::sync::atomic::Ordering::SeqCst)
            .into())
    }

    /// Returns the changes since the given version.  This is a fake implementation that
    /// returns the changes that are in the store.  It also allows for
    /// overriding the responses for testing.
    /// It caps the versions since the requested version to 10, to allow for simulating
    /// needing to make multiple requests
    async fn registry_changes_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryDelta>, NervousSystemError> {
        if let Some(response) = self
            .override_get_changes_since
            .lock()
            .unwrap()
            .remove(&version.get())
        {
            return response.map_err(|e| NervousSystemError::new_with_message(format!("{e:?}")));
        }

        let version = version.get();
        let max_version = version + 10;

        let changes = self
            .store
            .lock()
            .unwrap()
            .iter()
            // For every key create a delta with values versioned `(version, max_version]`.
            .map(|(key, values)| RegistryDelta {
                key: key.clone(),
                values: values
                    .iter()
                    .rev()
                    .skip_while(|value| value.version > max_version)
                    .take_while(|value| value.version > version)
                    .cloned()
                    .collect(),
            })
            // Drop empty deltas.
            .filter(|delta| !delta.values.is_empty())
            .collect();

        Ok(changes)
    }
}
