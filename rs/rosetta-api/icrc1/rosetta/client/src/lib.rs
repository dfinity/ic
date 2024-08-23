use anyhow::bail;
use anyhow::Context;
use candid::Nat;
use ic_icrc_rosetta::common::types::ApproveMetadata;
use ic_icrc_rosetta::common::types::Error;
use ic_icrc_rosetta::construction_api::types::ConstructionMetadataRequestOptions;
use ic_icrc_rosetta::construction_api::types::ConstructionPayloadsRequestMetadata;
use ic_rosetta_api::models::Amount;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::account::Subaccount;
use num_bigint::BigInt;
use reqwest::{Client, Url};
use rosetta_core::identifiers::*;
use rosetta_core::models::CurveType;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::objects::ObjectMap;
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

    pub async fn ready(&self) -> reqwest::StatusCode {
        self.http_client
            .get(self.url("/ready"))
            .send()
            .await
            .unwrap()
            .status()
    }

    pub async fn make_submit_and_wait_for_transaction<T: RosettaSupportedKeyPair>(
        &self,
        signer_keypair: &T,
        network_identifier: NetworkIdentifier,
        operations: Vec<Operation>,
        memo: Option<Vec<u8>>,
        created_at_time: Option<u64>,
    ) -> Result<ConstructionSubmitResponse, Error> {
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

        let signatures = Self::sign_transaction(signer_keypair, payloads_response.clone())
            .map_err(|err| Error::parsing_unsuccessful(&err))?;

        let combine_response = self
            .construction_combine(
                network_identifier.clone(),
                payloads_response.unsigned_transaction,
                signatures,
            )
            .await?;

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
                    network_identifier.clone(),
                    Some(submit_response.transaction_identifier.clone()),
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await?;
            println!("Transaction: {:?}", transaction);
            println!(
                "Transaction hash looked for: {:?}",
                submit_response.transaction_identifier
            );
            if !transaction.transactions.is_empty() {
                return Ok(submit_response);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            tries += 1;
        }

        Err(Error::unable_to_find_block(
            &"Transaction was not added to the blockchain after 10 seconds".to_owned(),
        ))
    }

    async fn fetch_transaction_metadata(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> Result<ConstructionMetadataResponse, Error> {
        let preprocess_response = self
            .construction_preprocess(vec![], network_identifier.clone())
            .await?;

        self.construction_metadata(
            preprocess_response
                .options
                .try_into()
                .map_err(|err| Error::parsing_unsuccessful(&err))?,
            network_identifier.clone(),
        )
        .await
    }

    pub async fn build_transfer_operations<T: RosettaSupportedKeyPair>(
        &self,
        signer_keypair: &T,
        from_subaccount: Option<Subaccount>,
        to_account: Account,
        amount: Nat,
        network_identifier: NetworkIdentifier,
    ) -> Result<Vec<Operation>, Error> {
        let currency = &self
            .fetch_transaction_metadata(network_identifier)
            .await?
            .suggested_fee
            .unwrap()[0]
            .currency;

        let transfer_from_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "TRANSFER".to_string(),
            status: None,
            account: Some(
                Account {
                    owner: signer_keypair
                        .generate_principal_id()
                        .map_err(|err| Error::parsing_unsuccessful(&err))?
                        .0,
                    subaccount: from_subaccount,
                }
                .into(),
            ),
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
            type_: "TRANSFER".to_string(),
            status: None,
            account: Some(to_account.into()),
            amount: Some(Amount::new(BigInt::from(amount), currency.clone())),
            coin_change: None,
            metadata: None,
        };

        Ok(vec![transfer_from_operation, transfer_to_operation])
    }

    pub async fn build_transfer_from_operations<T: RosettaSupportedKeyPair>(
        &self,
        signer_keypair: &T,
        spender_subaccount: Option<Subaccount>,
        to_account: Account,
        from_account: Account,
        amount: Nat,
        network_identifier: NetworkIdentifier,
    ) -> Result<Vec<Operation>, Error> {
        let currency = &self
            .fetch_transaction_metadata(network_identifier)
            .await?
            .suggested_fee
            .unwrap()[0]
            .currency;

        let transfer_from_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "TRANSFER".to_string(),
            status: None,
            account: Some(from_account.into()),
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
            type_: "TRANSFER".to_string(),
            status: None,
            account: Some(to_account.into()),
            amount: Some(Amount::new(BigInt::from(amount), currency.clone())),
            coin_change: None,
            metadata: None,
        };

        let spender_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 2,
                network_index: None,
            },
            related_operations: None,
            type_: "SPENDER".to_string(),
            status: None,
            account: Some(
                Account {
                    owner: signer_keypair
                        .generate_principal_id()
                        .map_err(|err| Error::parsing_unsuccessful(&err))?
                        .0,
                    subaccount: spender_subaccount,
                }
                .into(),
            ),
            amount: None,
            coin_change: None,
            metadata: None,
        };

        Ok(vec![
            transfer_from_operation,
            transfer_to_operation,
            spender_operation,
        ])
    }

    pub async fn build_approve_operations<T: RosettaSupportedKeyPair>(
        &self,
        signer_keypair: &T,
        from_subaccount: Option<Subaccount>,
        spender_account: Account,
        allowance: Nat,
        expected_allowance: Option<Nat>,
        network_identifier: NetworkIdentifier,
        expires_at: Option<u64>,
    ) -> Result<Vec<Operation>, Error> {
        let currency = &self
            .fetch_transaction_metadata(network_identifier)
            .await?
            .suggested_fee
            .unwrap()[0]
            .currency;

        let approver_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "APPROVE".to_string(),
            status: None,
            account: Some(
                Account {
                    owner: signer_keypair
                        .generate_principal_id()
                        .map_err(|err| Error::parsing_unsuccessful(&err))?
                        .0,
                    subaccount: from_subaccount,
                }
                .into(),
            ),
            amount: None,
            coin_change: None,
            metadata: Some(
                ApproveMetadata {
                    expected_allowance: expected_allowance
                        .map(|a| Amount::new(BigInt::from(a), currency.clone())),
                    allowance: Amount::new(BigInt::from(allowance), currency.clone()),
                    expires_at,
                }
                .try_into()
                .map_err(|err| Error::parsing_unsuccessful(&err))?,
            ),
        };

        let spender_operation = Operation {
            operation_identifier: OperationIdentifier {
                index: 1,
                network_index: None,
            },
            related_operations: None,
            type_: "SPENDER".to_string(),
            status: None,
            account: Some(spender_account.into()),
            amount: None,
            coin_change: None,
            metadata: None,
        };

        Ok(vec![approver_operation, spender_operation])
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

    pub async fn network_options(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> Result<NetworkOptionsResponse, Error> {
        self.call_endpoint(
            "/network/options",
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

    pub async fn search_transactions(
        &self,
        network_identifier: NetworkIdentifier,
        transaction_identifier: Option<TransactionIdentifier>,
        account_identifier: Option<AccountIdentifier>,
        type_: Option<String>,
        max_block: Option<i64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<SearchTransactionsResponse, Error> {
        self.call_endpoint(
            "/search/transactions",
            &SearchTransactionsRequest {
                network_identifier,
                transaction_identifier,
                account_identifier,
                coin_identifier: None,
                address: None,
                type_,
                success: None,
                currency: None,
                operator: None,
                status: None,
                offset,
                max_block,
                limit,
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
        metadata: Option<ConstructionPayloadsRequestMetadata>,
    ) -> Result<ConstructionPayloadsResponse, Error> {
        self.call_endpoint(
            "/construction/payloads",
            &ConstructionPayloadsRequest {
                network_identifier,
                operations,
                metadata: metadata
                    .map(|m| {
                        m.try_into()
                            .map_err(|err| Error::parsing_unsuccessful(&err))
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

    pub async fn call(
        &self,
        network_identifier: NetworkIdentifier,
        method_name: String,
        parameters: ObjectMap,
    ) -> Result<CallResponse, Error> {
        self.call_endpoint(
            "/call",
            &CallRequest {
                network_identifier,
                method_name,
                parameters,
            },
        )
        .await
    }
}
