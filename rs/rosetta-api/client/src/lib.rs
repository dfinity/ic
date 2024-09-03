use anyhow::bail;
use reqwest::{Client, Url};
use rosetta_core::identifiers::NetworkIdentifier;
use rosetta_core::identifiers::PartialBlockIdentifier;
use rosetta_core::request_types::*;
use rosetta_core::response_types::*;
use serde::{Deserialize, Serialize};
use url::ParseError;

pub struct RosettaClient {
    pub url: Url,
    pub http_client: Client,
}

impl RosettaClient {
    pub fn from_url(url: Url) -> Self {
        Self {
            url,
            http_client: Client::new(),
        }
    }

    pub fn from_str_url(url: &str) -> Result<Self, ParseError> {
        let url = Url::parse(url)?;
        Ok(Self::from_url(url))
    }

    pub fn url(&self, path: &str) -> Url {
        self.url
            .join(path)
            .unwrap_or_else(|e| panic!("Failed to join {} with path {}: {}", self.url, path, e))
    }

    async fn call_endpoint<T: Serialize + ?Sized, R: for<'a> Deserialize<'a>>(
        &self,
        path: &str,
        arg: &T,
    ) -> anyhow::Result<R> {
        let response = self
            .http_client
            .post(self.url(path))
            .json(arg)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        let status = response.status();
        if status.is_client_error() || status.is_server_error() {
            bail!(response
                .json::<String>()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to parse error: {}", e))?)
        } else {
            Ok(response
                .json()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to parse error: {}", e))?)
        }
    }

    pub async fn network_list(&self) -> anyhow::Result<NetworkListResponse> {
        self.call_endpoint("/network/list", &MetadataRequest { metadata: None })
            .await
    }

    pub async fn network_status(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> anyhow::Result<NetworkStatusResponse> {
        self.call_endpoint(
            "/network/status",
            &NetworkRequest {
                network_identifier,
                metadata: None,
            },
        )
        .await
    }

    pub async fn search_transactions(
        &self,
        request: &SearchTransactionsRequest,
    ) -> anyhow::Result<SearchTransactionsResponse> {
        self.call_endpoint("/search/transactions", request).await
    }

    pub async fn block(
        &self,
        network_identifier: NetworkIdentifier,
        block_identifier: PartialBlockIdentifier,
    ) -> anyhow::Result<BlockResponse> {
        self.call_endpoint(
            "/block",
            &BlockRequest {
                network_identifier,
                block_identifier,
            },
        )
        .await
    }
}
