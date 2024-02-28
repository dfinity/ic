use anyhow::bail;
use anyhow::Context;
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta::construction_api::types::ConstructionMetadataRequestOptions;
use reqwest::{Client, Url};
use rosetta_core::identifiers::*;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::objects::Operation;
use rosetta_core::objects::PublicKey;
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

    pub fn sign_transaction<T>(
        signer_keypair: &T,
        payloads: ConstructionPayloadsResponse,
    ) -> anyhow::Result<Vec<Signature>>
    where
        T: RosettaSupportedKeyPair,
    {
        let mut signatures: Vec<Signature> = vec![];
        for payload in payloads.payloads.into_iter() {
            let signable_bytes = hex::decode(&payload.hex_bytes).with_context(|| {
                format!("Bytes not in hex representation: {:?}", payload.hex_bytes)
            })?;

            let signed_bytes = signer_keypair.sign(&signable_bytes);
            let hex_bytes = hex::encode(signed_bytes.clone());

            let signature = Signature {
                signing_payload: payload,
                public_key: signer_keypair.into(),
                signature_type: signer_keypair.get_curve_type().into(),
                hex_bytes,
            };

            // Verify that the signature is correct
            let verification_key = ed25519_consensus::VerificationKey::try_from(
                signer_keypair.get_pb_key().as_slice(),
            )
            .with_context(|| {
                format!(
                    "Failed to convert public key to verification key: {:?}",
                    signer_keypair.get_pb_key()
                )
            })?;

            if verification_key
                .verify(
                    &ed25519_consensus::Signature::try_from(signed_bytes.as_slice())?,
                    &signable_bytes,
                )
                .is_err()
            {
                bail!("Signature verification failed")
            };
            signatures.push(signature);
        }

        // TODO: Shuffle up order of signed transactions
        Ok(signatures)
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

    pub async fn account_balance(
        &self,
        block_index: u64,
        account_identifier: AccountIdentifier,
        network_identifier: NetworkIdentifier,
    ) -> Result<AccountBalanceResponse, Error> {
        self.call_endpoint(
            "/account/balance",
            &AccountBalanceRequest {
                block_identifier: Some(PartialBlockIdentifier {
                    index: Some(block_index),
                    hash: None,
                }),
                account_identifier,
                network_identifier,
                metadata: None,
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

    pub async fn construction_hash(
        &self,
        network_identifier: NetworkIdentifier,
        signed_transaction: String,
    ) -> Result<ConstructionHashResponse, Error> {
        self.call_endpoint(
            "/construction/hash",
            &ConstructionHashRequest {
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

    pub async fn construction_payloads(
        &self,
        network_identifier: NetworkIdentifier,
        operations: Vec<Operation>,
        public_keys: Option<Vec<PublicKey>>,
    ) -> Result<ConstructionPayloadsResponse, Error> {
        self.call_endpoint(
            "/construction/payloads",
            &ConstructionPayloadsRequest {
                network_identifier,
                operations,
                metadata: None,
                public_keys,
            },
        )
        .await
    }

    pub async fn construction_parse(
        &self,
        network_identifier: NetworkIdentifier,
        transaction: String,
        is_signed: bool,
    ) -> Result<ConstructionParseResponse, Error> {
        self.call_endpoint(
            "/construction/parse",
            &ConstructionParseRequest {
                network_identifier,
                transaction,
                signed: is_signed,
            },
        )
        .await
    }
}
