use crate::driver::resource::AllocatedVm;
use ic_base_types::CanisterId;
use ic_ledger_core::block::BlockIndex;
use ic_rosetta_api::convert::to_model_account_identifier;
use ic_rosetta_api::models::operation::Operation;
use ic_rosetta_api::models::{
    AccountBalanceMetadata, AccountBalanceRequest, AccountBalanceResponse, AccountType,
    BalanceAccountType, Block, BlockRequest, BlockResponse, ConstructionCombineRequest,
    ConstructionCombineResponse, ConstructionDeriveRequest, ConstructionDeriveRequestMetadata,
    ConstructionDeriveResponse, ConstructionHashRequest, ConstructionHashResponse,
    ConstructionMetadataRequest, ConstructionMetadataRequestOptions, ConstructionMetadataResponse,
    ConstructionParseRequest, ConstructionParseResponse, ConstructionPayloadsRequest,
    ConstructionPayloadsRequestMetadata, ConstructionPayloadsResponse,
    ConstructionPreprocessRequest, ConstructionPreprocessResponse, ConstructionSubmitRequest,
    ConstructionSubmitResponse, Error, MetadataRequest, NetworkIdentifier, NetworkListResponse,
    NetworkRequest, NetworkStatusResponse, NeuronSubaccountComponents, PartialBlockIdentifier,
    PublicKey, Signature, SignedTransaction,
};
use icp_ledger::AccountIdentifier;
use rand::{seq::SliceRandom, thread_rng};
use reqwest::Client as HttpClient;
use reqwest::StatusCode as HttpStatusCode;
use slog::{debug, info, Logger};
use std::time::Duration;
use tokio::time::sleep;

/// RosettaApiClient is a rewrite of RosettaApiHandle to be used on Docker.
pub struct RosettaApiClient {
    http_client: HttpClient,
    /// The Rosetta API base url (including http prefix).
    api_url: String,
    ledger_canister_id: CanisterId,
    governance_canister_id: CanisterId,
    logger: Logger,
}

fn to_rosetta_response<T: serde::de::DeserializeOwned>(
    hyper_res: Result<(Vec<u8>, HttpStatusCode), String>,
) -> Result<Result<T, Error>, String> {
    match hyper_res {
        Ok((msg, status)) => match status.as_u16() {
            200 => {
                let resp: T = serde_json::from_slice(&msg).unwrap();
                Ok(Ok(resp))
            }
            500 => {
                let resp: Error = serde_json::from_slice(&msg).unwrap();
                Ok(Err(resp))
            }
            _ => Err(format!(
                "Expected status 200 or 500, got {}",
                status.as_u16()
            )),
        },
        Err(e) => Err(e),
    }
}

impl RosettaApiClient {
    pub fn new(
        vm: AllocatedVm, // the Rosetta API VM.
        port: u32,
        ledger_canister_id: CanisterId,
        governance_canister_id: CanisterId,
        logger: &Logger,
    ) -> RosettaApiClient {
        let api_url = format!("http://[{}]:{}", vm.ipv6, port);
        debug!(&logger, "API url: {}", api_url);
        let http_client = HttpClient::new();
        RosettaApiClient {
            http_client,
            api_url,
            ledger_canister_id,
            governance_canister_id,
            logger: logger.clone(),
        }
    }

    pub fn get_ledger_canister_id(&self) -> CanisterId {
        self.ledger_canister_id
    }

    pub fn get_governance_canister_id(&self) -> CanisterId {
        self.governance_canister_id
    }

    /// Returns the identifier of the ICP network.
    pub fn network_id(&self) -> NetworkIdentifier {
        let net_id = hex::encode(self.ledger_canister_id.get().as_slice());
        NetworkIdentifier::new("Internet Computer".to_string(), net_id)
    }

    async fn post_json_request(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> Result<(Vec<u8>, HttpStatusCode), String> {
        let resp = self
            .http_client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|err| format!("sending post request failed with {}: ", err))?;
        let resp_status = resp.status();
        let resp_body = resp
            .bytes()
            .await
            .map_err(|err| format!("receive post response failed with {}: ", err))?
            .to_vec();
        Ok((resp_body, resp_status))
    }

    pub async fn construction_derive(
        &self,
        pk: PublicKey,
    ) -> Result<Result<ConstructionDeriveResponse, Error>, String> {
        let req = ConstructionDeriveRequest::new(self.network_id(), pk);
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/derive", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn neuron_derive(
        &self,
        pk: PublicKey,
    ) -> Result<Result<ConstructionDeriveResponse, Error>, String> {
        let req = ConstructionDeriveRequest {
            network_identifier: self.network_id(),
            public_key: pk,
            metadata: Some(ConstructionDeriveRequestMetadata {
                account_type: AccountType::Neuron { neuron_index: 0 },
            }),
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/derive", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_preprocess(
        &self,
        ops: Vec<Operation>,
    ) -> Result<Result<ConstructionPreprocessResponse, Error>, String> {
        let req = ConstructionPreprocessRequest::new(self.network_id(), ops);
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/preprocess", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_combine(
        &self,
        unsigned_transaction: String,
        signatures: Vec<Signature>,
    ) -> Result<Result<ConstructionCombineResponse, Error>, String> {
        let req = ConstructionCombineRequest {
            network_identifier: self.network_id(),
            unsigned_transaction,
            signatures,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/combine", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_hash(
        &self,
        signed_transaction: String,
    ) -> Result<Result<ConstructionHashResponse, Error>, String> {
        let req = ConstructionHashRequest {
            network_identifier: self.network_id(),
            signed_transaction,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/hash", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_metadata(
        &self,
        options: Option<ConstructionMetadataRequestOptions>,
        public_keys: Option<Vec<PublicKey>>,
    ) -> Result<Result<ConstructionMetadataResponse, Error>, String> {
        let req = ConstructionMetadataRequest {
            network_identifier: self.network_id(),
            options,
            public_keys,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/metadata", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_parse(
        &self,
        signed: bool,
        transaction: String,
    ) -> Result<Result<ConstructionParseResponse, Error>, String> {
        let req = ConstructionParseRequest {
            network_identifier: self.network_id(),
            signed,
            transaction,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/parse", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_payloads(
        &self,
        metadata: Option<ConstructionPayloadsRequestMetadata>,
        operations: Vec<Operation>,
        public_keys: Option<Vec<PublicKey>>,
    ) -> Result<Result<ConstructionPayloadsResponse, Error>, String> {
        let req = ConstructionPayloadsRequest {
            network_identifier: self.network_id(),
            metadata,
            operations,
            public_keys,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/payloads", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_submit(
        &self,
        mut signed_transaction: SignedTransaction,
    ) -> Result<Result<ConstructionSubmitResponse, Error>, String> {
        // Shuffle the messages to check whether the server picks a
        // valid one to send to the IC.
        let mut rng = thread_rng();
        for request in signed_transaction.iter_mut() {
            request.1.shuffle(&mut rng);
        }

        let req = ConstructionSubmitRequest::new(self.network_id(), signed_transaction);

        to_rosetta_response(
            self.post_json_request(
                &format!("{}/construction/submit", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn network_list(&self) -> Result<Result<NetworkListResponse, Error>, String> {
        let url = format!("{}/network/list", self.api_url);
        debug!(&self.logger, "[Rosetta client] Call: {}", url);
        let req = MetadataRequest::new();
        to_rosetta_response(
            self.post_json_request(&url, serde_json::to_vec(&req).unwrap())
                .await,
        )
    }

    pub async fn network_status(&self) -> Result<Result<NetworkStatusResponse, Error>, String> {
        let url = format!("{}/network/status", self.api_url);
        let req = NetworkRequest::new(self.network_id());
        to_rosetta_response(
            self.post_json_request(&url, serde_json::to_vec(&req).unwrap())
                .await,
        )
    }

    // pub async fn network_options(&self) -> Result<Result<NetworkListResponse, Error>, String> {
    //     let url = format!("{}/network/options", self.api_url);
    //     info!(&self.logger, "POST NETWORK/OPTIONS, url: {}", url);
    //     let req = MetadataRequest::new();
    //     to_rosetta_response(
    //         self.post_json_request(&url, serde_json::to_vec(&req).unwrap())
    //             .await,
    //     )
    // }

    pub async fn account_balance_neuron(
        &self,
        acc: AccountIdentifier,
        nid: Option<u64>,
        pk_and_idx: Option<(PublicKey, u64)>,
        verified: bool,
    ) -> Result<Result<AccountBalanceResponse, Error>, String> {
        let account_balance_metadata = AccountBalanceMetadata {
            account_type: BalanceAccountType::Neuron {
                neuron_id: nid,
                subaccount_components: pk_and_idx.map(|(public_key, neuron_index)| {
                    NeuronSubaccountComponents {
                        public_key,
                        neuron_index,
                    }
                }),
                verified_query: Some(verified),
            },
        };
        let req = AccountBalanceRequest {
            network_identifier: self.network_id(),
            account_identifier: to_model_account_identifier(&acc),
            block_identifier: None,
            metadata: Some(account_balance_metadata),
        };

        to_rosetta_response(
            self.post_json_request(
                &format!("{}/account/balance", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn wait_for_startup(&self) {
        info!(&self.logger, "Waiting for Rosetta availability...");
        let now = std::time::SystemTime::now();
        let timeout = std::time::Duration::from_secs(180);
        while now.elapsed().unwrap() < timeout {
            let res = self.network_list().await;
            if res.is_ok() {
                return;
            }
            debug!(&self.logger, "Rosetta not ready: {}", res.unwrap_err());
            sleep(Duration::from_millis(1000)).await;
        }
        panic!(
            "Rosetta API failed to start in {} seconds.",
            timeout.as_secs()
        );
    }

    pub async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Result<AccountBalanceResponse, Error>, String> {
        let req =
            AccountBalanceRequest::new(self.network_id(), to_model_account_identifier(&account));
        to_rosetta_response(
            self.post_json_request(
                &format!("{}/account/balance", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn block_at(&self, idx: u64) -> Result<Result<BlockResponse, Error>, String> {
        let block_id = PartialBlockIdentifier {
            index: Some(i64::try_from(idx).unwrap()),
            hash: None,
        };
        let req = BlockRequest::new(self.network_id(), block_id);

        to_rosetta_response(
            self.post_json_request(
                &format!("{}/block", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn wait_for_block_at(&self, idx: u64) -> Result<Block, String> {
        let timeout = std::time::Duration::from_secs(5);
        let now = std::time::SystemTime::now();
        while now.elapsed().unwrap() < timeout {
            if let Ok(Ok(resp)) = self.block_at(idx).await {
                if let Some(b) = resp.block {
                    return Ok(b);
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
        Err(format!("Timeout on waiting for block at {}", idx))
    }

    pub async fn wait_for_tip_sync(&self, tip_idx: BlockIndex) -> Result<(), String> {
        debug!(
            self.logger,
            "Waiting for tip synchronization on block {}...", tip_idx
        );
        let timeout = std::time::Duration::from_secs(5);
        let now = std::time::SystemTime::now();
        while now.elapsed().unwrap() < timeout {
            if let Ok(Ok(resp)) = self.network_status().await {
                if resp.current_block_identifier.index as u64 >= tip_idx {
                    return Ok(());
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
        Err(format!("Timeout on waiting for tip at {}", tip_idx))
    }

    pub async fn raw_construction_endpoint(
        &self,
        endpoint: &str,
        body: &[u8],
    ) -> Result<(Vec<u8>, HttpStatusCode), std::string::String> {
        self.post_json_request(
            &format!("{}/construction/{}", self.api_url, endpoint),
            body.to_owned(),
        )
        .await
    }
}
