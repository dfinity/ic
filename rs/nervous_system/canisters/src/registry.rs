use async_trait::async_trait;
use ic_base_types::{CanisterId, RegistryVersion};
use ic_nervous_system_common::NervousSystemError;
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_transport::pb::v1::RegistryDelta;
use ic_registry_transport::{
    deserialize_get_changes_since_response, deserialize_get_latest_version_response,
    serialize_get_changes_since_request, Error,
};
use std::collections::BTreeMap;
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

pub type FakeRegistryResponses = BTreeMap<u64, Result<Vec<RegistryDelta>, Error>>;

/// A fake registry client for testing
#[derive(Default)]
pub struct FakeRegistry {
    latest_version: RegistryVersion,
    responses: Arc<Mutex<FakeRegistryResponses>>,
}

impl FakeRegistry {
    pub fn new(latest_version: RegistryVersion, responses: FakeRegistryResponses) -> Self {
        FakeRegistry {
            latest_version,
            responses: Arc::new(Mutex::new(responses)),
        }
    }
}

#[async_trait]
impl Registry for FakeRegistry {
    async fn get_latest_version(&self) -> Result<RegistryVersion, NervousSystemError> {
        Ok(self.latest_version)
    }

    async fn registry_changes_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryDelta>, NervousSystemError> {
        self.responses
            .lock()
            .unwrap()
            .remove(&version.get())
            .unwrap_or(Err(Error::UnknownError(format!(
                "No response in test fixture for version {}",
                version
            ))))
            .map_err(|e| NervousSystemError::new_with_message(format!("{e:?}")))
    }
}
