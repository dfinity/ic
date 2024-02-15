use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta::construction_api::types::ConstructionMetadataRequestOptions;
use reqwest::{Client, Url};
use rosetta_core::identifiers::*;
use rosetta_core::objects::Operation;
use rosetta_core::objects::Signature;
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
    ) -> Result<R, Error> {
        let response = self
            .http_client
            .post(self.url(path))
            .json(arg)
            .send()
            .await?;

        let status = response.status();
        if status.is_client_error() || status.is_server_error() {
            Err(response.json().await?)
        } else {
            Ok(response.json().await?)
        }
    }

    pub async fn network_list(&self) -> Result<NetworkListResponse, Error> {
        self.call_endpoint("/network/list", &MetadataRequest { metadata: None })
            .await
    }

    pub async fn network_status(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> Result<NetworkStatusResponse, Error> {
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
    ) -> Result<BlockResponse, Error> {
        self.call_endpoint(
            "/block",
            &BlockRequest {
                network_identifier,
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
    ) -> Result<BlockTransactionResponse, Error> {
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
    ) -> Result<MempoolResponse, Error> {
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
    ) -> Result<MempoolTransactionResponse, Error> {
        self.call_endpoint("/mempool/transaction", &mempool_transaction_request)
            .await
    }

    pub async fn construction_derive(
        &self,
        construction_derive_request: ConstructionDeriveRequest,
    ) -> Result<ConstructionDeriveResponse, Error> {
        self.call_endpoint("/construction/derive", &construction_derive_request)
            .await
    }

    pub async fn construction_preprocess(
        &self,
        operations: Vec<Operation>,
        network_identifier: NetworkIdentifier,
    ) -> Result<ConstructionPreprocessResponse, Error> {
        self.call_endpoint(
            "/construction/preprocess",
            &ConstructionPreprocessRequest {
                metadata: None,
                operations,
                network_identifier,
            },
        )
        .await
    }

    pub async fn construction_metadata(
        &self,
        construction_metadata_options: ConstructionMetadataRequestOptions,
        network_identifier: NetworkIdentifier,
    ) -> Result<ConstructionMetadataResponse, Error> {
        self.call_endpoint(
            "/construction/metadata",
            &ConstructionMetadataRequest {
                options: Some(
                    construction_metadata_options
                        .try_into()
                        .map_err(|err| Error::parsing_unsuccessful(&err))?,
                ),
                network_identifier,
                public_keys: None,
            },
        )
        .await
    }

    pub async fn construction_submit(
        &self,
        network_identifier: NetworkIdentifier,
        signed_transaction: String,
    ) -> Result<ConstructionSubmitResponse, Error> {
        self.call_endpoint(
            "/construction/submit",
            &ConstructionSubmitRequest {
                network_identifier,
                signed_transaction,
            },
        )
        .await
    }

    pub async fn construction_combine(
        &self,
        network_identifier: NetworkIdentifier,
        unsigned_transaction: String,
        signatures: Vec<Signature>,
    ) -> Result<ConstructionCombineResponse, Error> {
        self.call_endpoint(
            "/construction/combine",
            &ConstructionCombineRequest {
                network_identifier,
                unsigned_transaction,
                signatures,
            },
        )
        .await
    }
}
