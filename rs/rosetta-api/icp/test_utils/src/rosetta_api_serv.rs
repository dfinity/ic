use ic_rosetta_api::models::Error as RosettaError;
use ic_rosetta_api::models::*;
use ic_types::CanisterId;

use icp_ledger::{AccountIdentifier, BlockIndex};
use rosetta_core::request_types::NetworkRequest;
use slog::info;

use crate::store_threshold_sig_pk;
use ic_rosetta_api::models::Operation;
use ic_types::messages::Blob;
use rand::{seq::SliceRandom, thread_rng};
use reqwest::Client as HttpClient;
use reqwest::StatusCode as HttpStatusCode;
use rosetta_core::request_types::MetadataRequest;
use rosetta_core::response_types::NetworkListResponse;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

fn to_rosetta_response<T: serde::de::DeserializeOwned>(
    hyper_res: Result<(Vec<u8>, HttpStatusCode), String>,
) -> Result<Result<T, RosettaError>, String> {
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

pub struct RosettaApiHandle {
    logger: slog::Logger,
    process: std::process::Child,
    can_panic: bool,
    http_client: HttpClient,
    api_url: String,
    ledger_can_id: CanisterId,
    governance_can_id: CanisterId,
    workspace: tempfile::TempDir,
}

impl RosettaApiHandle {
    pub async fn start<P: AsRef<Path>>(
        logger: slog::Logger,
        rosetta_api_bin_path: P,
        node_url: Url,
        port: u16,
        ledger_can_id: CanisterId,
        governance_can_id: CanisterId,
        workspace_path: String,
        root_key_blob: Option<&Blob>,
    ) -> Self {
        let workspace = tempfile::Builder::new()
            .prefix("rosetta_api_tmp_")
            .tempdir_in(workspace_path)
            .unwrap();

        let api_addr = "127.0.0.1";
        let api_port = format!("{port}");
        let api_url = format!("{api_addr}:{api_port}");

        let mut args = Vec::new();
        args.push("--ic-url".to_string());
        args.push(node_url.to_string());

        args.push("--canister-id".to_string());
        args.push(ledger_can_id.get().to_string());

        args.push("--governance-canister-id".to_string());
        args.push(governance_can_id.get().to_string());

        args.push("--address".to_string());
        args.push(api_addr.to_string());

        args.push("--port".to_string());
        args.push(api_port);

        args.push("--store-location".to_string());
        args.push(format!("{}/data", workspace.path().display()));

        args.push("--store-type".to_string());
        args.push("sqlite".to_string());

        if let Some(root_key) = root_key_blob {
            let root_key_file_path =
                std::path::PathBuf::from(format!("{}/root_key.pub", workspace.path().display()));
            store_threshold_sig_pk(root_key, &root_key_file_path);

            args.push("--root-key".to_string());
            args.push(String::from(root_key_file_path.to_str().unwrap()));
        }

        let process = std::process::Command::new(rosetta_api_bin_path.as_ref().as_os_str())
            .args(&args)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("failed to execute rosetta-cli");

        let http_client = HttpClient::new();
        let api_serv = Self {
            logger,
            process,
            can_panic: true,
            http_client,
            api_url,
            ledger_can_id,
            governance_can_id,
            workspace,
        };

        api_serv.wait_for_startup().await;
        assert_eq!(
            api_serv.network_list().await.unwrap(),
            Ok(NetworkListResponse::new(vec![api_serv.network_id()]))
        );
        api_serv
    }

    // I have hoped to avoid generating configs on the fly, but...
    pub fn generate_rosetta_cli_config(&self, cli_json: &Path, cli_ros: &Path) -> String {
        use std::fs::write;

        let ic_address = hex::encode(self.ledger_can_id);
        let dst_dir: PathBuf = self.workspace.path().to_owned();

        let cli_json = std::fs::read_to_string(cli_json).expect("Reading rosetta cli json failed");
        let cli_ros = std::fs::read_to_string(cli_ros).expect("Reading rosetta cli ros failed");

        let cli_json = cli_json.replace("PUT_ROSETTA_API_URL_HERE", &self.api_url.to_string());
        let cli_json = cli_json.replace("PUT_LEDGER_ADDRESS_HERE", &ic_address);
        let cli_ros = cli_ros.replace("PUT_LEDGER_ADDRESS_HERE", &ic_address);

        write(dst_dir.join("ros_cli.json"), cli_json).expect("Writing rosetta cli json failed");
        write(dst_dir.join("ros_workflows.ros"), cli_ros).expect("Writing rosetta cli ros failed");

        dst_dir.join("ros_cli.json").to_str().unwrap().to_string()
    }

    /// Returns the identifier of the ICP network.
    pub fn network_id(&self) -> NetworkIdentifier {
        let net_id = hex::encode(self.ledger_can_id.get().as_slice());
        NetworkIdentifier::new("Internet Computer".to_string(), net_id)
    }

    /// Returns the account address shared by all neuron subaccounts.
    pub fn neuron_account(&self) -> String {
        self.governance_can_id.to_string()
    }

    async fn wait_for_startup(&self) {
        const TIMEOUT: Duration = Duration::from_secs(10 * 60); // 10 minutes
        const WAIT_BETWEEN_ATTEMPTS: Duration = Duration::from_secs(1);

        let now = std::time::SystemTime::now();
        while now.elapsed().unwrap() < TIMEOUT {
            if self.network_list().await.is_ok() {
                return;
            }
            sleep(WAIT_BETWEEN_ATTEMPTS).await;
        }
        panic!("Rosetta failed to start in {} secs", TIMEOUT.as_secs());
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
            .map_err(|err| format!("sending post request failed with {err}: "))?;
        let resp_status = resp.status();
        let resp_body = resp
            .bytes()
            .await
            .map_err(|err| format!("receive post response failed with {err}: "))?
            .to_vec();
        Ok((resp_body, resp_status))
    }

    pub async fn construction_derive(
        &self,
        pk: PublicKey,
    ) -> Result<Result<ConstructionDeriveResponse, RosettaError>, String> {
        let req = ConstructionDeriveRequest::new(self.network_id(), pk);
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/derive", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn neuron_derive(
        &self,
        pk: PublicKey,
    ) -> Result<Result<ConstructionDeriveResponse, RosettaError>, String> {
        let req = ConstructionDeriveRequest {
            network_identifier: self.network_id(),
            public_key: pk,
            metadata: Some(
                ConstructionDeriveRequestMetadata {
                    account_type: AccountType::Neuron { neuron_index: 0 },
                }
                .try_into()
                .unwrap(),
            ),
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/derive", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_preprocess(
        &self,
        ops: Vec<Operation>,
    ) -> Result<Result<ConstructionPreprocessResponse, RosettaError>, String> {
        let req = ConstructionPreprocessRequest::new(self.network_id(), ops);
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/preprocess", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_combine(
        &self,
        unsigned_transaction: String,
        signatures: Vec<Signature>,
    ) -> Result<Result<ConstructionCombineResponse, RosettaError>, String> {
        let req = ConstructionCombineRequest {
            network_identifier: self.network_id(),
            unsigned_transaction,
            signatures,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/combine", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_hash(
        &self,
        signed_transaction: String,
    ) -> Result<Result<ConstructionHashResponse, RosettaError>, String> {
        let req = ConstructionHashRequest {
            network_identifier: self.network_id(),
            signed_transaction,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/hash", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_metadata(
        &self,
        options: Option<ConstructionMetadataRequestOptions>,
        public_keys: Option<Vec<PublicKey>>,
    ) -> Result<Result<ConstructionMetadataResponse, RosettaError>, String> {
        let req = ConstructionMetadataRequest {
            network_identifier: self.network_id(),
            options: options.map(|op| op.try_into().unwrap()),
            public_keys,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/metadata", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_parse(
        &self,
        signed: bool,
        transaction: String,
    ) -> Result<Result<ConstructionParseResponse, RosettaError>, String> {
        let req = ConstructionParseRequest {
            network_identifier: self.network_id(),
            signed,
            transaction,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/parse", self.api_url),
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
    ) -> Result<Result<ConstructionPayloadsResponse, RosettaError>, String> {
        let req = ConstructionPayloadsRequest {
            network_identifier: self.network_id(),
            metadata: metadata.map(|m| m.try_into().unwrap()),
            operations,
            public_keys,
        };
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/payloads", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn construction_submit(
        &self,
        mut signed_transaction: SignedTransaction,
    ) -> Result<Result<ConstructionSubmitResponse, RosettaError>, String> {
        // Shuffle the messages to check whether the server picks a
        // valid one to send to the IC.
        let mut rng = thread_rng();
        for request in signed_transaction.requests.iter_mut() {
            request.1.shuffle(&mut rng);
        }

        let req = ConstructionSubmitRequest::new(self.network_id(), signed_transaction.to_string());

        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/construction/submit", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn network_list(&self) -> Result<Result<NetworkListResponse, RosettaError>, String> {
        let req = MetadataRequest::new();
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/network/list", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn network_status(
        &self,
    ) -> Result<Result<NetworkStatusResponse, RosettaError>, String> {
        let req = NetworkRequest::new(self.network_id());
        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/network/status", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn account_balance_neuron(
        &self,
        acc: AccountIdentifier,
        nid: Option<u64>,
        pk_and_idx: Option<(PublicKey, u64)>,
        verified: bool,
    ) -> Result<Result<AccountBalanceResponse, RosettaError>, String> {
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
            account_identifier: ic_rosetta_api::convert::to_model_account_identifier(&acc),
            block_identifier: None,
            metadata: Some(account_balance_metadata.into()),
        };

        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/account/balance", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn balance(
        &self,
        acc: AccountIdentifier,
    ) -> Result<Result<AccountBalanceResponse, RosettaError>, String> {
        let req = AccountBalanceRequest {
            network_identifier: self.network_id(),
            account_identifier: ic_rosetta_api::convert::to_model_account_identifier(&acc),
            block_identifier: None,
            metadata: None,
        };

        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/account/balance", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn block_at(&self, idx: u64) -> Result<Result<BlockResponse, RosettaError>, String> {
        let block_id = PartialBlockIdentifier {
            index: Some(idx),
            hash: None,
        };
        let req = BlockRequest::new(self.network_id(), block_id);

        to_rosetta_response(
            self.post_json_request(
                &format!("http://{}/block", self.api_url),
                serde_json::to_vec(&req).unwrap(),
            )
            .await,
        )
    }

    pub async fn wait_for_block_at(&self, idx: u64) -> Result<Block, String> {
        const TIMEOUT: Duration = Duration::from_secs(30);
        const WAIT_BETWEEN_ATTEMPTS: Duration = Duration::from_millis(100);

        let now = std::time::SystemTime::now();
        while now.elapsed().unwrap() < TIMEOUT {
            if let Ok(Ok(resp)) = self.block_at(idx).await
                && let Some(b) = resp.block
            {
                return Ok(b);
            }
            sleep(WAIT_BETWEEN_ATTEMPTS).await;
        }
        Err(format!(
            "Timeout on waiting for block at {} after {} secs",
            idx,
            now.elapsed().unwrap().as_secs()
        ))
    }

    pub async fn wait_for_tip_sync(&self, tip_idx: BlockIndex) -> Result<(), String> {
        const TIMEOUT: Duration = Duration::from_secs(30);
        const WAIT_BETWEEN_ATTEMPTS: Duration = Duration::from_millis(100);

        let now = std::time::SystemTime::now();
        while now.elapsed().unwrap() < TIMEOUT {
            if let Ok(Ok(resp)) = self.network_status().await
                && resp.current_block_identifier.index >= tip_idx
            {
                return Ok(());
            }
            sleep(WAIT_BETWEEN_ATTEMPTS).await;
        }

        Err(format!(
            "Timeout on waiting for tip at {} after {} secs",
            tip_idx,
            now.elapsed().unwrap().as_secs()
        ))
    }

    // safe to call this multiple times
    pub fn stop(&mut self) {
        const TIMEOUT: Duration = Duration::from_secs(10 * 60); // 10 minutes
        const WAIT_BETWEEN_ATTEMPTS: Duration = Duration::from_secs(1);

        use nix::sys::signal::{Signal::SIGTERM, kill};
        use nix::unistd::Pid;
        kill(Pid::from_raw(self.process.id() as i32), SIGTERM).ok();

        let now = std::time::SystemTime::now();

        while now.elapsed().unwrap() < TIMEOUT {
            match self.process.try_wait() {
                Ok(Some(status)) => {
                    if self.can_panic {
                        assert!(
                            status.success(),
                            "Rosetta did not stop successfully. Elapsed: {} secs, exit status: {}",
                            now.elapsed().unwrap().as_secs(),
                            status,
                        );
                    } else {
                        info!(
                            self.logger,
                            "Rosetta stopped successfully after {} secs",
                            now.elapsed().unwrap().as_secs()
                        )
                    }
                    return;
                }
                Ok(None) => std::thread::sleep(WAIT_BETWEEN_ATTEMPTS),
                Err(_) => {
                    if self.can_panic {
                        panic!(
                            "Cannot wait for Rosetta to stop because Rosetta process doesn't exist. Did it start? (elapsed: {} secs)",
                            now.elapsed().unwrap().as_secs(),
                        )
                    } else {
                        return;
                    }
                }
            }
        }
        self.process.kill().ok();
        if self.can_panic {
            panic!(
                "Rosetta did not stop after {} sec",
                now.elapsed().unwrap().as_secs()
            );
        }
    }

    pub async fn raw_construction_endpoint(
        &self,
        endpoint: &str,
        body: &[u8],
    ) -> Result<(Vec<u8>, HttpStatusCode), std::string::String> {
        self.post_json_request(
            &format!("http://{}/construction/{}", self.api_url, endpoint),
            body.to_owned(),
        )
        .await
    }
}

impl Drop for RosettaApiHandle {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.can_panic = false;
        }
        self.stop();
    }
}
