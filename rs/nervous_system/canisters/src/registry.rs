use async_trait::async_trait;
use ic_base_types::RegistryVersion;
use ic_nervous_system_common::NervousSystemError;
use ic_registry_transport::pb::v1::RegistryDelta;
use ic_registry_transport::Error;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[async_trait]
pub trait Registry: Send + Sync {
    async fn get_latest_version(&self) -> RegistryVersion;
    async fn registry_changes_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryDelta>, Error>;
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
    async fn get_latest_version(&self) -> RegistryVersion {
        self.latest_version
    }

    async fn registry_changes_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryDelta>, Error> {
        self.responses
            .lock()
            .unwrap()
            .remove(&version.get())
            .unwrap_or(Err(Error::UnknownError(format!(
                "No response in test fixture for version {}",
                version
            ))))
    }
}
