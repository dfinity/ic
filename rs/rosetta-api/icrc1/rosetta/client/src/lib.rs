use ic_icrc_rosetta::common::types::{
    BlockRequest, BlockResponse, BlockTransactionRequest, BlockTransactionResponse,
    PartialBlockIdentifier, TransactionIdentifier,
};
use ic_rosetta_api::models::MempoolResponse;
use reqwest::{Client, Url};
use rosetta_core::identifiers::BlockIdentifier;
use rosetta_core::identifiers::NetworkIdentifier;
use rosetta_core::request_types::MetadataRequest;
use rosetta_core::request_types::NetworkRequest;
use rosetta_core::response_types::NetworkListResponse;
use rosetta_core::response_types::NetworkStatusResponse;
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

    pub async fn network_list(&self) -> reqwest::Result<NetworkListResponse> {
        self.http_client
            .post(self.url("/network/list"))
            .json(&MetadataRequest { metadata: None })
            .send()
            .await?
            .json()
            .await
    }

    pub async fn network_status(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> reqwest::Result<NetworkStatusResponse> {
        self.http_client
            .post(self.url("/network/status"))
            .json(&NetworkRequest {
                network_identifier,
                metadata: None,
            })
            .send()
            .await?
            .json()
            .await
    }

    pub async fn block(
        &self,
        network_identifier: NetworkIdentifier,
        block_identifier: PartialBlockIdentifier,
    ) -> reqwest::Result<BlockResponse> {
        self.http_client
            .post(self.url("/block"))
            .json(&BlockRequest {
                network_identifier: network_identifier.clone(),
                block_identifier: block_identifier.clone(),
            })
            .send()
            .await?
            .json()
            .await
    }

    pub async fn block_transaction(
        &self,
        network_identifier: NetworkIdentifier,
        block_identifier: BlockIdentifier,
        transaction_identifier: TransactionIdentifier,
    ) -> reqwest::Result<BlockTransactionResponse> {
        self.http_client
            .post(self.url("/block/transaction"))
            .json(&BlockTransactionRequest {
                network_identifier,
                block_identifier,
                transaction_identifier,
            })
            .send()
            .await?
            .json()
            .await
    }

    pub async fn mempool(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> reqwest::Result<MempoolResponse> {
        self.http_client
            .post(self.url("/mempool"))
            .json(&NetworkRequest {
                network_identifier,
                metadata: None,
            })
            .send()
            .await?
            .json()
            .await
    }
}
