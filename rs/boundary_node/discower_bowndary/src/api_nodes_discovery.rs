use std::sync::Arc;

use async_trait::async_trait;
use ic_registry_client::client::{RegistryClient, RegistryClientError, RegistryClientImpl};
use ic_registry_nns_data_provider_wrappers::NnsDataProvider;
use thiserror;
use url::{ParseError, Url};

const API_BN_URL: &str = "https://icp-api.io";
const API_BOUNDARY_NODE_RECORD_KEY_PREFIX: &str = "api_boundary_node_";

#[derive(thiserror::Error, Debug)]
pub enum ApiNodeRegistryFetchError {
    #[error("Registry client error: {0}")]
    RegistryClientError(#[from] RegistryClientError),
    #[error("Failed to parse a url `{url}` returned from the registry: {error_msg}")]
    InvalidUrl { url: String, error_msg: ParseError },
}

pub fn api_nodes_list() -> Vec<Url> {
    vec![Url::parse(API_BN_URL).expect("invalid url")]
}

#[async_trait]
pub trait Fetch {
    async fn api_nodes_from_registry(&self) -> Result<Vec<Url>, ApiNodeRegistryFetchError>;
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
    async fn api_nodes_from_registry(&self) -> Result<Vec<Url>, ApiNodeRegistryFetchError> {
        let registry_client = RegistryClientImpl::new(
            Arc::new(NnsDataProvider::new(
                tokio::runtime::Handle::current(),
                vec![self.url.clone()],
            )),
            None,
        );
        let urls: Vec<String> = registry_client
            .get_key_family(
                API_BOUNDARY_NODE_RECORD_KEY_PREFIX,
                registry_client.get_latest_version(),
            )
            .map_err(ApiNodeRegistryFetchError::RegistryClientError)?;
        urls.iter()
            .map(|url_str| {
                Url::parse(url_str).map_err(|err| ApiNodeRegistryFetchError::InvalidUrl {
                    url: url_str.to_string(),
                    error_msg: err,
                })
            })
            .collect()
    }
}
