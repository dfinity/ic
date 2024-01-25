use std::sync::Arc;

use async_trait::async_trait;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_registry_client::client::{RegistryClient, RegistryClientError, RegistryClientImpl};
use ic_registry_nns_data_provider_wrappers::NnsDataProvider;
use prost::Message;
use thiserror;
use url::Url;

const API_BN_DOMAIN: &str = "icp-api.io";
const API_BOUNDARY_NODE_RECORD_KEY_PREFIX: &str = "api_boundary_node_";
const NODE_RECORD_KEY_PREFIX: &str = "node_record_";

#[derive(thiserror::Error, Debug)]
pub enum ApiNodeRegistryFetchError {
    #[error("Registry client error: {0}")]
    RegistryClientError(#[from] RegistryClientError),
    #[error("API Boundary Node with key {0} was not found in the registry")]
    ApiBoundaryNodeRecordNotFound(String),
    #[error("NodeRecord with key {0} was not found in the registry")]
    NodeRecordNotFound(String),
    #[error("Domain name of API Boundary Node is not set")]
    DomainEmpty,
    #[error("Failed to deserialize registry record to ApiBoundaryNodeRecord")]
    RecordDeserializationFailure,
}

pub fn api_node_domains() -> Vec<String> {
    vec![API_BN_DOMAIN.to_string()]
}

#[async_trait]
pub trait Fetch {
    async fn api_node_domains_from_registry(
        &self,
    ) -> Result<Vec<String>, ApiNodeRegistryFetchError>;
}

pub struct RegistryFetcher {
    url: Url,
}

impl RegistryFetcher {
    pub fn new(url: Url) -> Self {
        Self { url }
    }
}

#[async_trait]
impl Fetch for RegistryFetcher {
    async fn api_node_domains_from_registry(
        &self,
    ) -> Result<Vec<String>, ApiNodeRegistryFetchError> {
        let registry_client = RegistryClientImpl::new(
            Arc::new(NnsDataProvider::new(
                tokio::runtime::Handle::current(),
                vec![self.url.clone()],
            )),
            None,
        );
        registry_client.try_polling_latest_version(usize::MAX)?;
        let version = registry_client.get_latest_version();
        let node_ids: Vec<String> = registry_client
            .get_key_family(
                API_BOUNDARY_NODE_RECORD_KEY_PREFIX,
                registry_client.get_latest_version(),
            )
            .map_err(|err: RegistryClientError| {
                ApiNodeRegistryFetchError::RegistryClientError(err)
            })?
            .into_iter()
            .map(|key| {
                key.strip_prefix(API_BOUNDARY_NODE_RECORD_KEY_PREFIX)
                    .unwrap()
                    .to_string()
            })
            .collect();
        let urls: Result<Vec<String>, ApiNodeRegistryFetchError> = node_ids
            .iter()
            .map(|node_id| {
                let node_record_key = format!("{}{}", NODE_RECORD_KEY_PREFIX, node_id);
                let value = registry_client
                    .get_value(&node_record_key, version)?
                    .ok_or(ApiNodeRegistryFetchError::NodeRecordNotFound(
                        node_record_key.to_string(),
                    ))?;
                let record = NodeRecord::decode(&value[..])
                    .map_err(|_| ApiNodeRegistryFetchError::RecordDeserializationFailure)?;

                record.domain.ok_or(ApiNodeRegistryFetchError::DomainEmpty)
            })
            .collect();
        urls
    }
}
