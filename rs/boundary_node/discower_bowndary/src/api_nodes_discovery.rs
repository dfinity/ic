use std::sync::Arc;

use async_trait::async_trait;
use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
use ic_registry_client::client::{RegistryClient, RegistryClientError, RegistryClientImpl};
use ic_registry_nns_data_provider_wrappers::NnsDataProvider;
use prost::Message;
use thiserror;
use url::Url;

const API_BN_DOMAIN: &str = "icp-api.io";
const API_BOUNDARY_NODE_RECORD_KEY_PREFIX: &str = "api_boundary_node_";

#[derive(thiserror::Error, Debug)]
pub enum ApiNodeRegistryFetchError {
    #[error("Registry client error: {0}")]
    RegistryClientError(#[from] RegistryClientError),
    #[error("No Api boundary node with key {0} found in the registry")]
    NoApiBoundaryNodeRecordFound(String),
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
        let keys: Vec<String> = registry_client
            .get_key_family(
                API_BOUNDARY_NODE_RECORD_KEY_PREFIX,
                registry_client.get_latest_version(),
            )
            .map_err(|err: RegistryClientError| {
                ApiNodeRegistryFetchError::RegistryClientError(err)
            })?;
        let urls: Result<Vec<String>, ApiNodeRegistryFetchError> = keys
            .iter()
            .map(|key| {
                let value = registry_client.get_value(key, version)?.ok_or(
                    ApiNodeRegistryFetchError::NoApiBoundaryNodeRecordFound(key.to_string()),
                )?;
                let record = ApiBoundaryNodeRecord::decode(&value[..])
                    .map_err(|_| ApiNodeRegistryFetchError::RecordDeserializationFailure)?;
                Ok(record.domain)
            })
            .collect();
        urls
    }
}
