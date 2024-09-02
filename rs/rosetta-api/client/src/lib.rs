use anyhow::bail;
use anyhow::Context;
use candid::Nat;
use candid::Principal;
use ic_rosetta_api::convert::to_model_account_identifier;
use ic_rosetta_api::models::ConstructionMetadataRequestOptions;
use ic_rosetta_api::models::ConstructionPayloadsRequestMetadata;
use ic_rosetta_api::models::OperationIdentifier;
use ic_rosetta_api::request_types::RequestType;
use icp_ledger::AccountIdentifier;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::account::Subaccount;
use num_bigint::BigInt;
use reqwest::{Client, Url};
use rosetta_core::identifiers::NetworkIdentifier;
use rosetta_core::identifiers::PartialBlockIdentifier;
use rosetta_core::models::CurveType;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::objects::Amount;
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
            let error = response
                .json::<rosetta_core::miscellaneous::Error>()
                .await
                .unwrap();
            println!("Failed to call endpoint: {:?}", error);
            bail!("Failed to call endpoint: {:?}", error);
        } else {
            Ok(response
                .json()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to parse error: {}", e))?)
        }
    }

    pub async fn build_transfer_operations(
        &self,
        signer_principal: Principal,
        from_subaccount: Option<Subaccount>,
        to_account: Account,
        amount: Nat,
        network_identifier: NetworkIdentifier,
    ) -> anyhow::Result<Vec<Operation>> {
        let suggested_fee = self
            .construction_metadata(
                ConstructionMetadataRequestOptions {
                    request_types: vec![RequestType::Send],
                },
                network_identifier.clone(),
            )
            .await?
            .suggested_fee
            .unwrap()[0]
            .to_owned();
        let currency = suggested_fee.currency.clone();

        let transfer_from_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "TRANSACTION".to_string(),
            status: None,
            account: Some(to_model_account_identifier(&AccountIdentifier::from(
                Account {
                    owner: signer_principal,
                    subaccount: from_subaccount,
                },
            ))),
            amount: Some(Amount::new(
                BigInt::from_biguint(num_bigint::Sign::Minus, amount.0.clone()),
                currency.clone(),
            )),
            coin_change: None,
            metadata: None,
        };

        let transfer_to_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 1,
                network_index: None,
            },
            related_operations: None,
            type_: "TRANSACTION".to_string(),
            status: None,
            account: Some(to_model_account_identifier(&AccountIdentifier::from(
                to_account,
            ))),
            amount: Some(Amount::new(BigInt::from(amount), currency.clone())),
            coin_change: None,
            metadata: None,
        };

        let fee_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 2,
                network_index: None,
            },
            related_operations: None,
            type_: "FEE".to_string(),
            status: None,
            account: Some(to_model_account_identifier(&AccountIdentifier::from(
                Account {
                    owner: signer_principal,
                    subaccount: from_subaccount,
                },
            ))),
            amount: Some(Amount::new(
                BigInt::from_biguint(
                    num_bigint::Sign::Minus,
                    Nat::try_from(suggested_fee)
                        .map_err(|e| anyhow::anyhow!("Failed to convert fee: {:?}", e))?
                        .0,
                ),
                currency.clone(),
            )),
            coin_change: None,
            metadata: None,
        };

        Ok(vec![
            transfer_from_operation,
            transfer_to_operation,
            fee_operation,
        ])
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
            match signer_keypair.get_curve_type() {
                CurveType::Edwards25519 => {
                    let verification_key = ic_crypto_ed25519::PublicKey::deserialize_raw(
                        signer_keypair.get_pb_key().as_slice(),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to convert public key to verification key: {:?}",
                            signer_keypair.get_pb_key()
                        )
                    })?;
                    if verification_key
                        .verify_signature(&signable_bytes, signed_bytes.as_slice())
                        .is_err()
                    {
                        bail!("Signature verification failed")
                    };
                }
                CurveType::Secp256K1 => {
                    let verification_key = ic_crypto_secp256k1::PublicKey::deserialize_sec1(
                        &signer_keypair.get_pb_key(),
                    )
                    .with_context(|| {
                        format!(
                            "Failed to convert public key to verification key: {:?}",
                            signer_keypair.get_pb_key()
                        )
                    })?;
                    if !verification_key
                        .verify_signature(signable_bytes.as_slice(), signed_bytes.as_slice())
                    {
                        bail!("Signature verification failed")
                    };
                }
                _ => bail!(
                    "Unsupported curve type: {:?}",
                    signer_keypair.get_curve_type()
                ),
            }

            signatures.push(signature);
        }

        Ok(signatures)
    }

    pub async fn make_submit_and_wait_for_transaction<T: RosettaSupportedKeyPair>(
        &self,
        signer_keypair: &T,
        network_identifier: NetworkIdentifier,
        operations: Vec<Operation>,
        memo: Option<u64>,
        created_at_time: Option<u64>,
    ) -> anyhow::Result<ConstructionSubmitResponse> {
        println!("Making payloads request");
        println!("Operations: {:?}", operations);
        let payloads_response = self
            .construction_payloads(
                network_identifier.clone(),
                operations,
                Some(vec![signer_keypair.into()]),
                Some(ConstructionPayloadsRequestMetadata {
                    memo,
                    created_at_time,
                    ingress_end: None,
                    ingress_start: None,
                }),
            )
            .await?;
        println!("Signing transaction");
        let signatures = Self::sign_transaction(signer_keypair, payloads_response.clone())?;
        println!("Combining transaction");
        let combine_response = self
            .construction_combine(
                network_identifier.clone(),
                payloads_response.unsigned_transaction,
                signatures,
            )
            .await?;
        println!("Submitting transaction");
        let submit_response = self
            .construction_submit(
                network_identifier.clone(),
                combine_response.signed_transaction,
            )
            .await?;

        // We need to wait for the transaction to be added to the blockchain
        let mut tries = 0;
        while tries < 10 {
            let transaction = self
                .search_transactions(
                    &SearchTransactionsRequest::builder(network_identifier.clone())
                        .with_transaction_identifier(submit_response.transaction_identifier.clone())
                        .build(),
                )
                .await?;
            if !transaction.transactions.is_empty() {
                return Ok(submit_response);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            tries += 1;
        }

        bail!("Transaction was not added to the blockchain after 10 seconds")
    }

    pub async fn construction_derive(
        &self,
        construction_derive_request: ConstructionDeriveRequest,
    ) -> anyhow::Result<ConstructionDeriveResponse> {
        self.call_endpoint("/construction/derive", &construction_derive_request)
            .await
    }

    pub async fn construction_preprocess(
        &self,
        operations: Vec<Operation>,
        network_identifier: NetworkIdentifier,
    ) -> anyhow::Result<ConstructionPreprocessResponse> {
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
    ) -> anyhow::Result<ConstructionMetadataResponse> {
        self.call_endpoint(
            "/construction/metadata",
            &ConstructionMetadataRequest {
                options: Some(
                    construction_metadata_options
                        .try_into()
                        .map_err(|e| anyhow::anyhow!("Failed to convert options: {:?}", e))?,
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
    ) -> anyhow::Result<ConstructionSubmitResponse> {
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
    ) -> anyhow::Result<ConstructionHashResponse> {
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
    ) -> anyhow::Result<ConstructionCombineResponse> {
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
        metadata: Option<ConstructionPayloadsRequestMetadata>,
    ) -> anyhow::Result<ConstructionPayloadsResponse> {
        self.call_endpoint(
            "/construction/payloads",
            &ConstructionPayloadsRequest {
                network_identifier,
                operations,
                metadata: metadata
                    .map(|m| {
                        m.try_into()
                            .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))
                    })
                    .transpose()?,
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
    ) -> anyhow::Result<ConstructionParseResponse> {
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
