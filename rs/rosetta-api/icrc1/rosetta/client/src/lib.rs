use reqwest::{Client, Url};
use rosetta_core::identifiers::*;
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

    fn url(&self, path: &str) -> Url {
        self.url
            .join(path)
            .unwrap_or_else(|e| panic!("Failed to join {} with path {}: {}", self.url, path, e))
    }

    pub async fn health(&self) -> reqwest::Result<()> {
        self.http_client
            .get(self.url("/health"))
            .send()
            .await?
            .json()
            .await
    }

    async fn call_endpoint<T: Serialize + ?Sized, R: for<'a> Deserialize<'a>>(
        &self,
        path: &str,
        arg: &T,
    ) -> reqwest::Result<R> {
        let response = self
            .http_client
            .post(self.url(path))
            .json(arg)
            .send()
            .await?;

        match response.error_for_status() {
            Ok(res) => Ok(res.json().await?),
            Err(err) => Err(err),
        }
    }

    pub async fn network_list(&self) -> reqwest::Result<NetworkListResponse> {
        self.call_endpoint("/network/list", &MetadataRequest { metadata: None })
            .await
    }

    pub async fn network_status(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> reqwest::Result<NetworkStatusResponse> {
        self.call_endpoint(
            "/network/status",
            &NetworkRequest {
                network_identifier,
                metadata: None,
            },
        )
        .await
    }

    pub async fn block(
        &self,
        network_identifier: NetworkIdentifier,
        block_identifier: PartialBlockIdentifier,
    ) -> reqwest::Result<BlockResponse> {
        self.call_endpoint(
            "/block",
            &BlockRequest {
                network_identifier: network_identifier.clone(),
                block_identifier: block_identifier.clone(),
            },
        )
        .await
    }

    pub async fn block_transaction(
        &self,
        network_identifier: NetworkIdentifier,
        block_identifier: BlockIdentifier,
        transaction_identifier: TransactionIdentifier,
    ) -> reqwest::Result<BlockTransactionResponse> {
        self.call_endpoint(
            "/block/transaction",
            &BlockTransactionRequest {
                network_identifier,
                block_identifier,
                transaction_identifier,
            },
        )
        .await
    }

    pub async fn mempool(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> reqwest::Result<MempoolResponse> {
        self.call_endpoint(
            "/mempool",
            &NetworkRequest {
                network_identifier,
                metadata: None,
            },
        )
        .await
    }

    pub async fn mempool_transaction(
        &self,
        mempool_transaction_request: MempoolTransactionRequest,
    ) -> reqwest::Result<MempoolTransactionResponse> {
        self.call_endpoint("/mempool/transaction", &mempool_transaction_request)
            .await
    }
}
