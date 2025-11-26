use anyhow::Context;
use anyhow::bail;
use candid::Nat;
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_nns_governance_api::Proposal;
use ic_rosetta_api::ledger_client::minimum_dissolve_delay_response::MinimumDissolveDelayResponse;
use ic_rosetta_api::ledger_client::pending_proposals_response::PendingProposalsResponse;
use ic_rosetta_api::models::AccountType;
use ic_rosetta_api::models::BlockIdentifier;
use ic_rosetta_api::models::ConstructionDeriveRequestMetadata;
use ic_rosetta_api::models::ConstructionMetadataRequestOptions;
use ic_rosetta_api::models::ConstructionPayloadsRequestMetadata;
use ic_rosetta_api::models::OperationIdentifier;
use ic_rosetta_api::models::seconds::Seconds;
use ic_rosetta_api::request_types::ChangeAutoStakeMaturityMetadata;
use ic_rosetta_api::request_types::DisburseMaturityMetadata;
use ic_rosetta_api::request_types::DisburseMetadata;
use ic_rosetta_api::request_types::KeyMetadata;
use ic_rosetta_api::request_types::NeuronIdentifierMetadata;
use ic_rosetta_api::request_types::NeuronInfoMetadata;
use ic_rosetta_api::request_types::PublicKeyOrPrincipal;
use ic_rosetta_api::request_types::RegisterVoteMetadata;
use ic_rosetta_api::request_types::RequestType;
use ic_rosetta_api::request_types::SetDissolveTimestampMetadata;
use ic_rosetta_api::request_types::SpawnMetadata;
use ic_rosetta_api::request_types::StakeMaturityMetadata;
use icp_ledger::AccountIdentifier;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::account::DEFAULT_SUBACCOUNT;
use icrc_ledger_types::icrc1::account::Subaccount;
use num_bigint::BigInt;
use reqwest::{Client, Url};
use rosetta_core::identifiers::NetworkIdentifier;
use rosetta_core::identifiers::PartialBlockIdentifier;
use rosetta_core::identifiers::TransactionIdentifier;
use rosetta_core::models::CurveType;
use rosetta_core::models::RosettaSupportedKeyPair;
use rosetta_core::objects::Amount;
use rosetta_core::objects::ObjectMap;
use rosetta_core::objects::Operation;
use rosetta_core::objects::PublicKey;
use rosetta_core::objects::Signature;
use rosetta_core::request_types::*;
use rosetta_core::response_types::*;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
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

    async fn call_endpoint<T: Serialize + ?Sized + Debug, R: for<'a> Deserialize<'a>>(
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
            bail!("Failed to call endpoint: {:?}, Request: {:?}", error, arg);
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
        to_account: AccountIdentifier,
        amount: Nat,
        network_identifier: NetworkIdentifier,
    ) -> anyhow::Result<Vec<Operation>> {
        let suggested_fee = self
            .construction_metadata(
                ConstructionMetadataRequest::builder(network_identifier.clone())
                    .with_options(
                        ConstructionMetadataRequestOptions {
                            request_types: vec![RequestType::Send],
                        }
                        .try_into()
                        .map_err(|e| anyhow::anyhow!("Failed to convert options: {:?}", e))?,
                    )
                    .build(),
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
            account: Some(
                AccountIdentifier::new(
                    PrincipalId(signer_principal),
                    from_subaccount.map(icp_ledger::Subaccount),
                )
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
            type_: "TRANSACTION".to_string(),
            status: None,
            account: Some(to_account.into()),
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
            account: Some(
                AccountIdentifier::new(
                    PrincipalId(signer_principal),
                    from_subaccount.map(icp_ledger::Subaccount),
                )
                .into(),
            ),
            amount: Some(Amount::new(
                BigInt::from_biguint(
                    num_bigint::Sign::Minus,
                    Nat::try_from(suggested_fee)
                        .map_err(|e| anyhow::anyhow!("Failed to convert fee: {:?}", e))?
                        .0
                        .clone(),
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

    pub async fn build_stake_neuron_operations(
        signer_principal: Principal,
        // The index of the neuron relative to the signer of the transaction
        neuron_index: u64,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "STAKE".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index,
                    controller: None,
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub async fn call(&self, req: CallRequest) -> anyhow::Result<CallResponse> {
        self.call_endpoint("/call", &req).await
    }

    pub async fn build_set_dissolve_timestamp_operations(
        signer_principal: Principal,
        neuron_index: u64,
        // The number of seconds since Unix epoch.
        // The dissolve delay will be set to this value
        // The timestamp has to be in the future and greater or equal to the currently set timestamp
        timestamp: u64,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "SET_DISSOLVE_TIMESTAMP".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                SetDissolveTimestampMetadata {
                    neuron_index,
                    timestamp: Seconds(timestamp),
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub async fn build_start_dissolving_operations(
        signer_principal: Principal,
        neuron_index: u64,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "START_DISSOLVING".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index,
                    controller: None,
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub async fn build_stop_dissolving_operations(
        signer_principal: Principal,
        neuron_index: u64,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "STOP_DISSOLVING".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index,
                    controller: None,
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub async fn build_register_vote_operations(
        signer_principal: Principal,
        neuron_index: u64,
        proposal: u64,
        vote: i32,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "REGISTER_VOTE".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                RegisterVoteMetadata {
                    neuron_index,
                    vote,
                    proposal: Some(proposal),
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub async fn build_change_auto_stake_maturity_operations(
        signer_principal: Principal,
        neuron_index: u64,
        requested_setting_for_auto_stake_maturity: bool,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "CHANGE_AUTO_STAKE_MATURITY".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                ChangeAutoStakeMaturityMetadata {
                    neuron_index,
                    requested_setting_for_auto_stake_maturity,
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub async fn build_disburse_neuron_operations(
        signer_principal: Principal,
        neuron_index: u64,
        recipient: Option<AccountIdentifier>,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "DISBURSE".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                DisburseMetadata {
                    neuron_index,
                    recipient,
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub async fn build_disburse_maturity_operations(
        signer_principal: Principal,
        neuron_index: u64,
        recipient: Option<AccountIdentifier>,
        percentage_to_disburse: u32,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "DISBURSE_MATURITY".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                DisburseMaturityMetadata {
                    neuron_index,
                    recipient,
                    percentage_to_disburse,
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub fn build_get_neuron_info_operations(
        signer_principal: Principal,
        neuron_index: u64,
        public_key: Option<PublicKey>,
        principal_id: Option<PrincipalId>,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "NEURON_INFO".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                NeuronInfoMetadata {
                    neuron_index,
                    controller: match (public_key, principal_id) {
                        (Some(public_key), None) => {
                            Some(PublicKeyOrPrincipal::PublicKey(public_key))
                        }
                        (None, Some(principal_id)) => {
                            Some(PublicKeyOrPrincipal::Principal(principal_id))
                        }
                        _ => None,
                    },
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub fn build_add_hot_key_operations(
        signer_principal: Principal,
        neuron_index: u64,
        public_key: Option<PublicKey>,
        principal_id: Option<PrincipalId>,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "ADD_HOTKEY".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                KeyMetadata {
                    neuron_index,
                    key: match (public_key, principal_id) {
                        (Some(public_key), None) => PublicKeyOrPrincipal::PublicKey(public_key),
                        (None, Some(principal_id)) => PublicKeyOrPrincipal::Principal(principal_id),
                        _ => bail!("Either public key or principal id has to be set"),
                    },
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub fn build_remove_hot_key_operations(
        signer_principal: Principal,
        neuron_index: u64,
        public_key: Option<PublicKey>,
        principal_id: Option<PrincipalId>,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "REMOVE_HOTKEY".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                KeyMetadata {
                    neuron_index,
                    key: match (public_key, principal_id) {
                        (Some(public_key), None) => PublicKeyOrPrincipal::PublicKey(public_key),
                        (None, Some(principal_id)) => PublicKeyOrPrincipal::Principal(principal_id),
                        _ => bail!("Either public key or principal id has to be set"),
                    },
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub fn build_stake_maturity_operations(
        signer_principal: Principal,
        neuron_index: u64,
        percentage_to_stake: Option<u32>,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "STAKE_MATURITY".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                StakeMaturityMetadata {
                    neuron_index,
                    percentage_to_stake,
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub fn build_spawn_neuron_operations(
        signer_principal: Principal,
        neuron_index: u64,
        controller_principal_id: Option<PrincipalId>,
        controller_public_key: Option<PublicKey>,
        percentage_to_spawn: Option<u32>,
        spawned_neuron_index: u64,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "SPAWN".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                SpawnMetadata {
                    neuron_index,
                    controller: match (controller_public_key, controller_principal_id) {
                        (Some(public_key), None) => {
                            Some(PublicKeyOrPrincipal::PublicKey(public_key))
                        }
                        (None, Some(principal_id)) => {
                            Some(PublicKeyOrPrincipal::Principal(principal_id))
                        }
                        _ => None,
                    },
                    percentage_to_spawn,
                    spawned_neuron_index,
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub fn build_list_neurons_operations(
        signer_principal: Principal,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "LIST_NEURONS".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: None,
        }])
    }

    pub fn build_refresh_voting_power_operations(
        signer_principal: Principal,
        neuron_index: u64,
        principal_id: Option<PrincipalId>,
    ) -> anyhow::Result<Vec<Operation>> {
        Ok(vec![Operation {
            operation_identifier: OperationIdentifier {
                index: 0,
                network_index: None,
            },
            related_operations: None,
            type_: "REFRESH_VOTING_POWER".to_string(),
            status: None,
            account: Some(rosetta_core::identifiers::AccountIdentifier::from(
                AccountIdentifier::new(PrincipalId(signer_principal), None),
            )),
            amount: None,
            coin_change: None,
            metadata: Some(
                NeuronIdentifierMetadata {
                    neuron_index,
                    controller: principal_id.map(PublicKeyOrPrincipal::Principal),
                }
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
            ),
        }])
    }

    pub async fn network_list(&self) -> anyhow::Result<NetworkListResponse> {
        self.call_endpoint("/network/list", &MetadataRequest { metadata: None })
            .await
    }

    pub async fn network_options(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> anyhow::Result<NetworkOptionsResponse> {
        self.call_endpoint(
            "/network/options",
            &NetworkRequest {
                network_identifier,
                metadata: None,
            },
        )
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

    pub async fn mempool(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> anyhow::Result<MempoolResponse> {
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
        network_identifier: NetworkIdentifier,
        transaction_identifier: TransactionIdentifier,
    ) -> anyhow::Result<MempoolTransactionResponse> {
        self.call_endpoint(
            "/mempool/transaction",
            &MempoolTransactionRequest {
                network_identifier,
                transaction_identifier,
            },
        )
        .await
    }

    pub async fn account_balance(
        &self,
        request: AccountBalanceRequest,
    ) -> anyhow::Result<AccountBalanceResponse> {
        self.call_endpoint("/account/balance", &request).await
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

    pub async fn block_transaction(
        &self,
        network_identifier: NetworkIdentifier,
        transaction_identifier: TransactionIdentifier,
        block_identifier: BlockIdentifier,
    ) -> anyhow::Result<BlockTransactionResponse> {
        self.call_endpoint(
            "/block/transaction",
            &BlockTransactionRequest {
                network_identifier,
                transaction_identifier,
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
                    let verification_key = ic_ed25519::PublicKey::deserialize_raw(
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
                    let verification_key =
                        ic_secp256k1::PublicKey::deserialize_sec1(&signer_keypair.get_pb_key())
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
        let signatures = Self::sign_transaction(signer_keypair, payloads_response.clone())?;
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

        Ok(submit_response)
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
        request: ConstructionMetadataRequest,
    ) -> anyhow::Result<ConstructionMetadataResponse> {
        self.call_endpoint("/construction/metadata", &request).await
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

    pub async fn transfer<T>(
        &self,
        transfer_args: RosettaTransferArgs,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let transfer_operations = self
            .build_transfer_operations(
                signer_keypair.generate_principal_id()?.0,
                transfer_args.from_subaccount,
                transfer_args.to.into(),
                transfer_args.amount,
                network_identifier.clone(),
            )
            .await?;

        // This submit wrapper will also wait for the transaction to be finalized
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            transfer_operations,
            // We don't care about the specific memo, only that there exists a memo
            transfer_args.memo,
            transfer_args.created_at_time,
        )
        .await
    }

    pub async fn create_neuron<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        create_neuron_args: RosettaCreateNeuronArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        // Derive the AccountIdentifier that corresponds to the neuron that should be created
        let neuron_account_id = self
            .construction_derive(ConstructionDeriveRequest {
                network_identifier: network_identifier.clone(),
                public_key: PublicKey::from(signer_keypair),
                metadata: Some(
                    ConstructionDeriveRequestMetadata {
                        account_type: AccountType::Neuron {
                            neuron_index: create_neuron_args.neuron_index.unwrap_or(0),
                        },
                    }
                    .try_into()
                    .map_err(|e| anyhow::anyhow!("Failed to convert metadata: {:?}", e))?,
                ),
            })
            .await?
            .account_identifier
            .ok_or_else(|| anyhow::anyhow!("Failed to derive account identifier"))?;

        // Transfer the staked amount to the neuron account
        let transfer_operations = self
            .build_transfer_operations(
                signer_keypair.generate_principal_id()?.0,
                create_neuron_args.from_subaccount,
                neuron_account_id.try_into().map_err(|e| {
                    anyhow::anyhow!("Failed to convert account identifier: {:?}", e)
                })?,
                create_neuron_args.staked_amount,
                network_identifier.clone(),
            )
            .await?;

        // This submit wrapper will also wait for the transaction to be finalized
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier.clone(),
            transfer_operations,
            // We don't care about the specific memo, only that there exists a memo
            None,
            None,
        )
        .await?;

        let stake_operations = RosettaClient::build_stake_neuron_operations(
            signer_keypair.generate_principal_id()?.0,
            create_neuron_args.neuron_index.unwrap_or(0),
        )
        .await?;

        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            stake_operations,
            None,
            None,
        )
        .await
    }

    /// You can increase the amount of ICP that is staked in a neuron.
    pub async fn increase_neuron_stake<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        args: RosettaIncreaseNeuronStakeArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        // Create Neuron and Increase Stake are functionally identical
        self.create_neuron(
            network_identifier,
            signer_keypair,
            RosettaCreateNeuronArgs::builder(args.additional_stake)
                .with_neuron_index(args.neuron_index.unwrap_or(0))
                .with_from_subaccount(args.from_subaccount.unwrap_or(*DEFAULT_SUBACCOUNT))
                .build(),
        )
        .await
    }

    /// The amount of rewards you can expect to receive are amongst other factors dependent on the amount of time a neuron is locked up for.
    /// If the dissolve timestamp is set to a value that is less than minimum dissolve delay in the future you will not be getting any rewards for the locked period.
    /// This is because the neuron dissolve delay has to be larger than the minimum dissolve delay for the neuron to receive rewards.
    /// If the minimum dissolve delay is less than 1 year and you set the dissolve timestamp to 1 year in the future and start dissolving the neuron right away,
    /// you will receive rewards for the next 1 year - minimum dissolve delay.
    /// The minimum dissolve delay can be obtained by querying the `get_minimum_dissolve_delay` endpoint.
    /// The dissolve timestamp always increases monotonically.
    /// If the neuron is in the DISSOLVING state, this operation can move the dissolve timestamp further into the future.
    /// If the neuron is in the NOT_DISSOLVING state, invoking SET_DISSOLVE_TIMESTAMP with time T will attempt to increase the neuron’s dissolve delay (the minimal time it will take to dissolve the neuron) to T - current_time.
    /// If the neuron is in the DISSOLVED state, invoking SET_DISSOLVE_TIMESTAMP will move it to the NOT_DISSOLVING state and will set the dissolve delay accordingly.
    pub async fn set_neuron_dissolve_delay<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        set_neuron_dissolve_delay_args: RosettaSetNeuronDissolveDelayArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let set_dissolve_delay_operations = RosettaClient::build_set_dissolve_timestamp_operations(
            signer_keypair.generate_principal_id()?.0,
            set_neuron_dissolve_delay_args.neuron_index.unwrap_or(0),
            set_neuron_dissolve_delay_args.dissolve_delay_seconds,
        )
        .await?;

        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            set_dissolve_delay_operations,
            None,
            None,
        )
        .await
    }

    /// If a neuron is in the state NOT_DISSOLVING you start the dissolving process with this function.
    /// The neuron will then move to the DISSOLVING state.
    pub async fn start_dissolving_neuron<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        neuron_index: u64,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let start_dissolving_operations = RosettaClient::build_start_dissolving_operations(
            signer_keypair.generate_principal_id()?.0,
            neuron_index,
        )
        .await?;

        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            start_dissolving_operations,
            None,
            None,
        )
        .await
    }

    /// If a neuron is in the state DISSOLVING you can stop the dissolving process with this function.
    /// The neuron will then move to the NOT_DISSOLVING state.
    pub async fn stop_dissolving_neuron<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        neuron_index: u64,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let stop_dissolving_operations = RosettaClient::build_stop_dissolving_operations(
            signer_keypair.generate_principal_id()?.0,
            neuron_index,
        )
        .await?;

        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            stop_dissolving_operations,
            None,
            None,
        )
        .await
    }

    // Register a vote on a proposal using a specific neuron.
    pub async fn register_vote<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        register_vote_args: RosettaRegisterVoteArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let register_vote_operations = RosettaClient::build_register_vote_operations(
            signer_keypair.generate_principal_id()?.0,
            register_vote_args.neuron_index.unwrap_or(0),
            register_vote_args.proposal,
            register_vote_args.vote,
        )
        .await?;

        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            register_vote_operations,
            None,
            None,
        )
        .await
    }

    // Retrieves the list of proposals that are currently pending.
    pub async fn get_pending_proposals(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> anyhow::Result<Vec<Proposal>, String> {
        let response = self
            .call(CallRequest::new(
                network_identifier.clone(),
                "get_pending_proposals".to_owned(),
                ObjectMap::new(),
            ))
            .await
            .unwrap();

        let pending_proposals: Vec<Proposal> =
            PendingProposalsResponse::try_from(Some(response.result))
                .unwrap()
                .pending_proposals
                .into_iter()
                .map(|p| p.proposal.unwrap())
                .collect();

        Ok(pending_proposals)
    }

    // Retrieves the minimum neuron dissolve delay in seconds.
    pub async fn get_minimum_dissolve_delay(
        &self,
        network_identifier: NetworkIdentifier,
    ) -> anyhow::Result<Option<u64>, String> {
        let response = self
            .call(CallRequest::new(
                network_identifier.clone(),
                "get_minimum_dissolve_delay".to_owned(),
                ObjectMap::new(),
            ))
            .await
            .unwrap();

        let minimum_delay: Option<u64> =
            MinimumDissolveDelayResponse::try_from(Some(response.result))
                .unwrap()
                .neuron_minimum_dissolve_delay_to_vote_seconds;

        Ok(minimum_delay)
    }

    /// A neuron can be set to automatically restake its maturity.
    pub async fn change_auto_stake_maturity<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        change_auto_stake_maturity_args: RosettaChangeAutoStakeMaturityArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let change_auto_stake_maturity_operations =
            RosettaClient::build_change_auto_stake_maturity_operations(
                signer_keypair.generate_principal_id()?.0,
                change_auto_stake_maturity_args.neuron_index.unwrap_or(0),
                change_auto_stake_maturity_args.requested_setting_for_auto_stake_maturity,
            )
            .await?;

        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            change_auto_stake_maturity_operations,
            None,
            None,
        )
        .await
    }

    /// If a neuron is in the state DISSOLVED you can disburse the neuron with this function.
    pub async fn disburse_neuron<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        disburse_neuron_args: RosettaDisburseNeuronArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let disburse_neuron_operations = RosettaClient::build_disburse_neuron_operations(
            signer_keypair.generate_principal_id()?.0,
            disburse_neuron_args.neuron_index,
            disburse_neuron_args.recipient,
        )
        .await?;

        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            disburse_neuron_operations,
            None,
            None,
        )
        .await
    }

    /// Disburse the maturity associated with a neuron directly to an account identifier.
    pub async fn disburse_maturity<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        disburse_maturity_args: RosettaDisburseMaturityArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let disburse_maturity_operations = RosettaClient::build_disburse_maturity_operations(
            signer_keypair.generate_principal_id()?.0,
            disburse_maturity_args.neuron_index,
            disburse_maturity_args.recipient,
            disburse_maturity_args.percentage_to_disburse,
        )
        .await?;

        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            disburse_maturity_operations,
            None,
            None,
        )
        .await
    }

    pub async fn get_neuron_info<T>(
        &self,
        network_identifier: NetworkIdentifier,
        neuron_info_request: RosettaNeuronInfoArgs,
        signer_keypair: &T,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let neuron_info_operations = RosettaClient::build_get_neuron_info_operations(
            signer_keypair.generate_principal_id()?.0,
            neuron_info_request.neuron_index,
            neuron_info_request.public_key,
            neuron_info_request.principal_id,
        )?;
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            neuron_info_operations,
            None,
            None,
        )
        .await
    }

    /// The management of neurons can be delegated to another principal via a hotkey.
    /// Adding a hotkey to a specific neuron allows the hotkey holder to manage the neuron.
    pub async fn add_hot_key<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        add_hotkey_args: RosettaHotKeyArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let add_hotkey_operations = RosettaClient::build_add_hot_key_operations(
            signer_keypair.generate_principal_id()?.0,
            add_hotkey_args.neuron_index,
            add_hotkey_args.hot_key,
            add_hotkey_args.principal_id,
        )?;
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            add_hotkey_operations,
            None,
            None,
        )
        .await
    }

    pub async fn remove_hot_key<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        remove_hotkey_args: RosettaHotKeyArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let remove_hotkey_operations = RosettaClient::build_remove_hot_key_operations(
            signer_keypair.generate_principal_id()?.0,
            remove_hotkey_args.neuron_index,
            remove_hotkey_args.hot_key,
            remove_hotkey_args.principal_id,
        )?;
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            remove_hotkey_operations,
            None,
            None,
        )
        .await
    }

    /// The stake maturity is the amount of time that a neuron has been staked.
    /// You can increase the amount of ICP that is staked in a neuron by restaking a percentage of the maturity a neuron has accumulated.
    /// If the percentage is not set, the entire maturity will be restaked.
    pub async fn stake_maturity<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        stake_maturity_args: RosettaStakeMaturityArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let stake_maturity_operations = RosettaClient::build_stake_maturity_operations(
            signer_keypair.generate_principal_id()?.0,
            stake_maturity_args.neuron_index,
            stake_maturity_args.percentage_to_stake,
        )?;
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            stake_maturity_operations,
            None,
            None,
        )
        .await
    }

    /// A neuron can spawn a new neuron.
    /// The new neuron will be controlled by the controller of the spawning neuron.
    /// The new neuron will be funded with the specified percentage of the original neuron's maturity.
    pub async fn spawn_neuron<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        spawn_neuron_args: RosettaSpawnNeuronArgs,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let spawn_neuron_operations = RosettaClient::build_spawn_neuron_operations(
            signer_keypair.generate_principal_id()?.0,
            spawn_neuron_args.neuron_index,
            spawn_neuron_args.controller_principal_id,
            spawn_neuron_args.controller_public_key,
            spawn_neuron_args.percentage_to_spawn,
            spawn_neuron_args.spawned_neuron_index,
        )?;
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            spawn_neuron_operations,
            None,
            None,
        )
        .await
    }

    pub async fn list_neurons<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let list_neurons_operations = RosettaClient::build_list_neurons_operations(
            signer_keypair.generate_principal_id()?.0,
        )?;
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            list_neurons_operations,
            None,
            None,
        )
        .await
    }

    /// A neuron will lose its voting power over time when inactive
    /// To refresh the voting power of a neuron, you can use this function
    /// For reference see the proposal for periodic confirmation of following: https://dashboard.internetcomputer.org/proposal/132411
    pub async fn refresh_voting_power<T>(
        &self,
        network_identifier: NetworkIdentifier,
        signer_keypair: &T,
        neuron_index: u64,
        controller_principal_id: Option<PrincipalId>,
    ) -> anyhow::Result<ConstructionSubmitResponse>
    where
        T: RosettaSupportedKeyPair,
    {
        let refresh_voting_power_operations = RosettaClient::build_refresh_voting_power_operations(
            signer_keypair.generate_principal_id()?.0,
            neuron_index,
            controller_principal_id,
        )?;
        self.make_submit_and_wait_for_transaction(
            signer_keypair,
            network_identifier,
            refresh_voting_power_operations,
            None,
            None,
        )
        .await
    }
}

pub struct RosettaTransferArgs {
    pub from_subaccount: Option<[u8; 32]>,
    pub to: Account,
    pub amount: Nat,
    pub memo: Option<u64>,
    pub fee: Option<Nat>,
    pub created_at_time: Option<u64>,
}

impl RosettaTransferArgs {
    pub fn new(to: Account, amount: Nat) -> Self {
        Self {
            from_subaccount: None,
            to,
            amount,
            memo: None,
            fee: None,
            created_at_time: None,
        }
    }

    pub fn builder(to: Account, amount: Nat) -> RosettaTransferArgsBuilder {
        RosettaTransferArgsBuilder::new(to, amount)
    }
}

pub struct RosettaTransferArgsBuilder {
    from_subaccount: Option<[u8; 32]>,
    to: Account,
    amount: Nat,
    memo: Option<u64>,
    fee: Option<Nat>,
    created_at_time: Option<u64>,
}

impl RosettaTransferArgsBuilder {
    pub fn new(to: Account, amount: Nat) -> Self {
        Self {
            from_subaccount: None,
            to,
            amount,
            memo: None,
            fee: None,
            created_at_time: None,
        }
    }

    pub fn with_from_subaccount(mut self, from_subaccount: Subaccount) -> Self {
        self.from_subaccount = Some(from_subaccount);
        self
    }

    pub fn with_memo(mut self, memo: u64) -> Self {
        self.memo = Some(memo);
        self
    }

    pub fn with_created_at_time(mut self, created_at_time: u64) -> Self {
        self.created_at_time = Some(created_at_time);
        self
    }

    pub fn with_fee(mut self, fee: Nat) -> Self {
        self.fee = Some(fee);
        self
    }

    pub fn build(self) -> RosettaTransferArgs {
        RosettaTransferArgs {
            from_subaccount: self.from_subaccount,
            to: self.to,
            amount: self.amount,
            memo: self.memo,
            fee: self.fee,
            created_at_time: self.created_at_time,
        }
    }
}

pub struct RosettaCreateNeuronArgs {
    // The index of the neuron relative to the signer_keypair
    // If set the user specifies which index the neuron should have
    // This is especially usuful if the user wants to create multiple neurons on the same signer keypair
    // If the user for example already has a neuron at index 0, they may want to specify the the new nueral should be at index 1
    // The default value will be set to 0
    pub neuron_index: Option<u64>,
    // The amount the user wants to stake
    // The user needs to make sure they have enough ICP to stake
    pub staked_amount: Nat,
    // If the ICP that is supposed to be used to fund the neuron should be transferred from a subaccount
    pub from_subaccount: Option<Subaccount>,
}

impl RosettaCreateNeuronArgs {
    pub fn builder(staked_amount: Nat) -> RosettaCreateNeuronArgsBuilder {
        RosettaCreateNeuronArgsBuilder::new(staked_amount)
    }
}

pub struct RosettaCreateNeuronArgsBuilder {
    staked_amount: Nat,
    from_subaccount: Option<[u8; 32]>,
    neuron_index: Option<u64>,
}

impl RosettaCreateNeuronArgsBuilder {
    pub fn new(staked_amount: Nat) -> Self {
        Self {
            staked_amount,
            from_subaccount: None,
            neuron_index: None,
        }
    }

    pub fn with_from_subaccount(mut self, from_subaccount: Subaccount) -> Self {
        self.from_subaccount = Some(from_subaccount);
        self
    }

    pub fn with_neuron_index(mut self, neuron_index: u64) -> Self {
        self.neuron_index = Some(neuron_index);
        self
    }

    pub fn build(self) -> RosettaCreateNeuronArgs {
        RosettaCreateNeuronArgs {
            staked_amount: self.staked_amount,
            from_subaccount: self.from_subaccount,
            neuron_index: self.neuron_index,
        }
    }
}

pub struct RosettaSetNeuronDissolveDelayArgs {
    pub neuron_index: Option<u64>,
    pub dissolve_delay_seconds: u64,
}

impl RosettaSetNeuronDissolveDelayArgs {
    pub fn builder(dissolve_delay_seconds: u64) -> RosettaSetNeuronDissolveDelayArgsBuilder {
        RosettaSetNeuronDissolveDelayArgsBuilder::new(dissolve_delay_seconds)
    }
}

pub struct RosettaSetNeuronDissolveDelayArgsBuilder {
    dissolve_delay_seconds: u64,
    neuron_index: Option<u64>,
}

impl RosettaSetNeuronDissolveDelayArgsBuilder {
    pub fn new(dissolve_delay_seconds: u64) -> Self {
        Self {
            dissolve_delay_seconds,
            neuron_index: None,
        }
    }

    pub fn with_neuron_index(mut self, neuron_index: u64) -> Self {
        self.neuron_index = Some(neuron_index);
        self
    }

    pub fn build(self) -> RosettaSetNeuronDissolveDelayArgs {
        RosettaSetNeuronDissolveDelayArgs {
            dissolve_delay_seconds: self.dissolve_delay_seconds,
            neuron_index: self.neuron_index,
        }
    }
}

pub struct RosettaRegisterVoteArgs {
    pub neuron_index: Option<u64>,
    pub proposal: u64,
    pub vote: i32,
}

impl RosettaRegisterVoteArgs {
    pub fn builder(proposal: u64, vote: i32) -> RosettaRegisterVoteArgsBuilder {
        RosettaRegisterVoteArgsBuilder::new(proposal, vote)
    }
}

pub struct RosettaRegisterVoteArgsBuilder {
    proposal: u64,
    vote: i32,
    neuron_index: Option<u64>,
}

impl RosettaRegisterVoteArgsBuilder {
    pub fn new(proposal: u64, vote: i32) -> Self {
        Self {
            proposal,
            vote,
            neuron_index: None,
        }
    }

    pub fn with_neuron_index(mut self, neuron_index: u64) -> Self {
        self.neuron_index = Some(neuron_index);
        self
    }

    pub fn build(self) -> RosettaRegisterVoteArgs {
        RosettaRegisterVoteArgs {
            proposal: self.proposal,
            vote: self.vote,
            neuron_index: self.neuron_index,
        }
    }
}

pub struct RosettaIncreaseNeuronStakeArgs {
    pub neuron_index: Option<u64>,
    pub additional_stake: Nat,
    pub from_subaccount: Option<Subaccount>,
}

impl RosettaIncreaseNeuronStakeArgs {
    pub fn builder(additional_stake: Nat) -> RosettaIncreaseNeuronStakeArgsBuilder {
        RosettaIncreaseNeuronStakeArgsBuilder::new(additional_stake)
    }
}

pub struct RosettaIncreaseNeuronStakeArgsBuilder {
    additional_stake: Nat,
    neuron_index: Option<u64>,
    // The subaccount from which the ICP should be transferred
    from_subaccount: Option<[u8; 32]>,
}

impl RosettaIncreaseNeuronStakeArgsBuilder {
    pub fn new(additional_stake: Nat) -> Self {
        Self {
            additional_stake,
            neuron_index: None,
            from_subaccount: None,
        }
    }

    pub fn with_neuron_index(mut self, neuron_index: u64) -> Self {
        self.neuron_index = Some(neuron_index);
        self
    }

    pub fn with_from_subaccount(mut self, from_subaccount: Subaccount) -> Self {
        self.from_subaccount = Some(from_subaccount);
        self
    }

    pub fn build(self) -> RosettaIncreaseNeuronStakeArgs {
        RosettaIncreaseNeuronStakeArgs {
            additional_stake: self.additional_stake,
            neuron_index: self.neuron_index,
            from_subaccount: self.from_subaccount,
        }
    }
}

pub struct RosettaChangeAutoStakeMaturityArgs {
    pub neuron_index: Option<u64>,
    pub requested_setting_for_auto_stake_maturity: bool,
}

impl RosettaChangeAutoStakeMaturityArgs {
    pub fn builder(
        requested_setting_for_auto_stake_maturity: bool,
    ) -> RosettaChangeAutoStakeMaturityArgsBuilder {
        RosettaChangeAutoStakeMaturityArgsBuilder::new(requested_setting_for_auto_stake_maturity)
    }
}

pub struct RosettaChangeAutoStakeMaturityArgsBuilder {
    requested_setting_for_auto_stake_maturity: bool,
    neuron_index: Option<u64>,
}

impl RosettaChangeAutoStakeMaturityArgsBuilder {
    pub fn new(requested_setting_for_auto_stake_maturity: bool) -> Self {
        Self {
            requested_setting_for_auto_stake_maturity,
            neuron_index: None,
        }
    }

    pub fn with_neuron_index(mut self, neuron_index: u64) -> Self {
        self.neuron_index = Some(neuron_index);
        self
    }

    pub fn build(self) -> RosettaChangeAutoStakeMaturityArgs {
        RosettaChangeAutoStakeMaturityArgs {
            requested_setting_for_auto_stake_maturity: self
                .requested_setting_for_auto_stake_maturity,
            neuron_index: self.neuron_index,
        }
    }
}
pub struct RosettaDisburseNeuronArgs {
    pub neuron_index: u64,
    pub recipient: Option<AccountIdentifier>,
}

impl RosettaDisburseNeuronArgs {
    pub fn builder(neuron_index: u64) -> RosettaDisburseNeuronArgsBuilder {
        RosettaDisburseNeuronArgsBuilder::new(neuron_index)
    }
}

pub struct RosettaDisburseNeuronArgsBuilder {
    neuron_index: u64,
    recipient: Option<AccountIdentifier>,
}

impl RosettaDisburseNeuronArgsBuilder {
    pub fn new(neuron_index: u64) -> Self {
        Self {
            neuron_index,
            recipient: None,
        }
    }

    pub fn with_recipient(mut self, recipient: AccountIdentifier) -> Self {
        self.recipient = Some(recipient);
        self
    }

    pub fn build(self) -> RosettaDisburseNeuronArgs {
        RosettaDisburseNeuronArgs {
            neuron_index: self.neuron_index,
            recipient: self.recipient,
        }
    }
}

pub struct RosettaDisburseMaturityArgs {
    pub neuron_index: u64,
    pub percentage_to_disburse: u32,
    pub recipient: Option<AccountIdentifier>,
}

impl RosettaDisburseMaturityArgs {
    pub fn builder(
        neuron_index: u64,
        percentage_to_disburse: u32,
    ) -> RosettaDisburseMaturityArgsBuilder {
        RosettaDisburseMaturityArgsBuilder::new(neuron_index, percentage_to_disburse)
    }
}

pub struct RosettaDisburseMaturityArgsBuilder {
    neuron_index: u64,
    percentage_to_disburse: u32,
    recipient: Option<AccountIdentifier>,
}

impl RosettaDisburseMaturityArgsBuilder {
    pub fn new(neuron_index: u64, percentage_to_disburse: u32) -> Self {
        Self {
            neuron_index,
            percentage_to_disburse,
            recipient: None,
        }
    }

    pub fn with_recipient(mut self, recipient: AccountIdentifier) -> Self {
        self.recipient = Some(recipient);
        self
    }

    pub fn build(self) -> RosettaDisburseMaturityArgs {
        RosettaDisburseMaturityArgs {
            neuron_index: self.neuron_index,
            percentage_to_disburse: self.percentage_to_disburse,
            recipient: self.recipient,
        }
    }
}

pub struct RosettaNeuronInfoArgs {
    pub neuron_index: u64,
    pub public_key: Option<PublicKey>,
    pub principal_id: Option<PrincipalId>,
}

impl RosettaNeuronInfoArgs {
    pub fn builder(neuron_index: u64) -> RosettaNeuronInfoArgsBuilder {
        RosettaNeuronInfoArgsBuilder::new(neuron_index)
    }
}

pub struct RosettaNeuronInfoArgsBuilder {
    neuron_index: u64,
    public_key: Option<PublicKey>,
    principal_id: Option<PrincipalId>,
}

impl RosettaNeuronInfoArgsBuilder {
    pub fn new(neuron_index: u64) -> Self {
        Self {
            neuron_index,
            public_key: None,
            principal_id: None,
        }
    }

    pub fn with_public_key(mut self, public_key: PublicKey) -> Self {
        self.public_key = Some(public_key);
        self
    }

    pub fn with_principal_id(mut self, principal_id: PrincipalId) -> Self {
        self.principal_id = Some(principal_id);
        self
    }

    pub fn build(self) -> RosettaNeuronInfoArgs {
        RosettaNeuronInfoArgs {
            neuron_index: self.neuron_index,
            public_key: self.public_key,
            principal_id: self.principal_id,
        }
    }
}

pub struct RosettaHotKeyArgs {
    pub neuron_index: u64,
    pub hot_key: Option<PublicKey>,
    pub principal_id: Option<PrincipalId>,
}

impl RosettaHotKeyArgs {
    pub fn builder(neuron_index: u64) -> RosettaHotKeyArgsBuilder {
        RosettaHotKeyArgsBuilder::new(neuron_index)
    }
}

pub struct RosettaHotKeyArgsBuilder {
    neuron_index: u64,
    hot_key: Option<PublicKey>,
    principal_id: Option<PrincipalId>,
}

impl RosettaHotKeyArgsBuilder {
    pub fn new(neuron_index: u64) -> Self {
        Self {
            neuron_index,
            hot_key: None,
            principal_id: None,
        }
    }

    pub fn with_public_key(mut self, hot_key: PublicKey) -> Self {
        self.hot_key = Some(hot_key);
        self
    }

    pub fn with_principal_id(mut self, principal_id: PrincipalId) -> Self {
        self.principal_id = Some(principal_id);
        self
    }

    pub fn build(self) -> RosettaHotKeyArgs {
        RosettaHotKeyArgs {
            neuron_index: self.neuron_index,
            hot_key: self.hot_key,
            principal_id: self.principal_id,
        }
    }
}

pub struct RosettaStakeMaturityArgs {
    pub neuron_index: u64,
    pub percentage_to_stake: Option<u32>,
}

impl RosettaStakeMaturityArgs {
    pub fn builder(neuron_index: u64) -> RosettaStakeMaturityArgsBuilder {
        RosettaStakeMaturityArgsBuilder::new(neuron_index)
    }
}

pub struct RosettaStakeMaturityArgsBuilder {
    neuron_index: u64,
    percentage_to_stake: Option<u32>,
}

impl RosettaStakeMaturityArgsBuilder {
    pub fn new(neuron_index: u64) -> Self {
        Self {
            neuron_index,
            percentage_to_stake: None,
        }
    }

    pub fn with_percentage_to_stake(mut self, percentage_to_stake: u32) -> Self {
        self.percentage_to_stake = Some(percentage_to_stake);
        self
    }

    pub fn build(self) -> RosettaStakeMaturityArgs {
        RosettaStakeMaturityArgs {
            neuron_index: self.neuron_index,
            percentage_to_stake: self.percentage_to_stake,
        }
    }
}

pub struct RosettaSpawnNeuronArgs {
    pub neuron_index: u64,
    pub controller_principal_id: Option<PrincipalId>,
    pub controller_public_key: Option<PublicKey>,
    pub percentage_to_spawn: Option<u32>,
    pub spawned_neuron_index: u64,
}

impl RosettaSpawnNeuronArgs {
    pub fn builder(neuron_index: u64, spawned_neuron_index: u64) -> RosettaSpawnNeuronArgsBuilder {
        RosettaSpawnNeuronArgsBuilder::new(neuron_index, spawned_neuron_index)
    }
}

pub struct RosettaSpawnNeuronArgsBuilder {
    neuron_index: u64,
    controller_principal_id: Option<PrincipalId>,
    controller_public_key: Option<PublicKey>,
    percentage_to_spawn: Option<u32>,
    spawned_neuron_index: u64,
}

impl RosettaSpawnNeuronArgsBuilder {
    pub fn new(neuron_index: u64, spawned_neuron_index: u64) -> Self {
        Self {
            neuron_index,
            controller_principal_id: None,
            controller_public_key: None,
            percentage_to_spawn: None,
            spawned_neuron_index,
        }
    }

    pub fn with_controller_principal_id(mut self, controller_principal_id: PrincipalId) -> Self {
        self.controller_principal_id = Some(controller_principal_id);
        self
    }

    pub fn with_controller_public_key(mut self, controller_public_key: PublicKey) -> Self {
        self.controller_public_key = Some(controller_public_key);
        self
    }

    pub fn with_percentage_to_spawn(mut self, percentage_to_spawn: u32) -> Self {
        self.percentage_to_spawn = Some(percentage_to_spawn);
        self
    }

    pub fn build(self) -> RosettaSpawnNeuronArgs {
        RosettaSpawnNeuronArgs {
            neuron_index: self.neuron_index,
            controller_principal_id: self.controller_principal_id,
            controller_public_key: self.controller_public_key,
            percentage_to_spawn: self.percentage_to_spawn,
            spawned_neuron_index: self.spawned_neuron_index,
        }
    }
}
