use ic_agent::agent::{
    http_transport::reqwest_transport::{reqwest::Client, ReqwestTransport},
    Transport,
};
use std::fmt::Debug;
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum TransportProviderError {
    #[error("Failed to get Transport: {0}")]
    UnableToGetTransport(String),
}

pub trait TransportProvider: Send + Sync + Debug {
    fn get_transport(&self, url: Url) -> Result<Arc<dyn Transport>, TransportProviderError>;
}

#[derive(Debug)]
pub struct TransportProviderImpl {
    pub http_client: Client,
}

impl TransportProviderImpl {
    pub fn new(http_client: Client) -> Self {
        Self { http_client }
    }
}

impl TransportProvider for TransportProviderImpl {
    fn get_transport(&self, url: Url) -> Result<Arc<dyn Transport>, TransportProviderError> {
        let transport = Arc::new(
            ReqwestTransport::create_with_client(url, self.http_client.clone())
                .map_err(|err| TransportProviderError::UnableToGetTransport(err.to_string()))?,
        );
        Ok(transport as Arc<dyn Transport>)
    }
}
