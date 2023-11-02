use std::sync::Arc;

use async_trait::async_trait;
use ic_registry_client::client::RegistryClient;

/// NodeRecordTmp is a temporary placeholder until we code a proper integration with the NNS
pub struct NodeRecordTmp {
    pub name: String,
    pub ports: (u16, u16),
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Load: Send + Sync {
    async fn load(&self) -> Result<NodeRecordTmp, LoadError>;
}

#[allow(dead_code)] // remove when registry_client is used
pub struct Loader {
    registry_client: Arc<dyn RegistryClient>,
}

impl Loader {
    pub fn new(registry_client: Arc<dyn RegistryClient>) -> Self {
        Self { registry_client }
    }
}

#[async_trait]
impl Load for Loader {
    async fn load(&self) -> Result<NodeRecordTmp, LoadError> {
        // TODO(or.ricon): Read data from the NNS registry

        Ok(NodeRecordTmp {
            name: "example.com".into(),
            ports: (8080, 8443),
        })
    }
}
