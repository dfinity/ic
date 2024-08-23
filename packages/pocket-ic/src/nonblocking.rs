use crate::common::rest::{
    ApiResponse, AutoProgressConfig, BlobCompression, BlobId, CanisterHttpRequest,
    CreateHttpGatewayResponse, CreateInstanceResponse, ExtendedSubnetConfigSet, HttpGatewayBackend,
    HttpGatewayConfig, HttpGatewayInfo, HttpsConfig, InstanceConfig, InstanceId,
    MockCanisterHttpResponse, RawAddCycles, RawCanisterCall, RawCanisterHttpRequest, RawCanisterId,
    RawCanisterResult, RawCycles, RawEffectivePrincipal, RawMessageId, RawMockCanisterHttpResponse,
    RawSetStableMemory, RawStableMemory, RawSubmitIngressResult, RawSubnetId, RawTime,
    RawVerifyCanisterSigArg, RawWasmResult, SubnetId, Topology,
};
use crate::{CallError, PocketIcBuilder, UserError, WasmResult, DEFAULT_MAX_REQUEST_TIME_MS};
use candid::{
    decode_args, encode_args,
    utils::{ArgumentDecoder, ArgumentEncoder},
    CandidType, Deserialize, Nat, Principal,
};
use ic_cdk::api::management_canister::main::{
    CanisterId, CanisterIdRecord, CanisterInstallMode, CanisterSettings, CanisterStatusResponse,
    ChunkHash, ClearChunkStoreArgument, InstallChunkedCodeArgument, InstallCodeArgument,
    SkipPreUpgrade, UpdateSettingsArgument, UploadChunkArgument,
};
use reqwest::Url;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use slog::Level;
use std::fs::File;
use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tracing::{debug, instrument, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

// wait time between polling requests
const POLLING_PERIOD_MS: u64 = 10;

const LOG_DIR_PATH_ENV_NAME: &str = "POCKET_IC_LOG_DIR";
const LOG_DIR_LEVELS_ENV_NAME: &str = "POCKET_IC_LOG_DIR_LEVELS";

const LOCALHOST: &str = "localhost";

// The minimum joint size of a canister's WASM
// and its initial argument blob for which
// we install the canister WASM as a sequence of chunks.
// The size is chosen to be smaller than the maximum
// ingress message size of 2 MiB (2,097,152 B)
// on application subnet (which have the tighest
// ingress message size limit)
// to account for a few additional constant-size fields
// in the management canister payload to install code
// and the overhead of candid encoding.
const INSTALL_CHUNKED_CODE_THRESHOLD: usize = 2_000_000; // 2 MB

// The maximum size of one WASM chunk when installing a canister WASM
// as a sequence of chunks. This constant is specified
// in the IC protocol.
const INSTALL_CODE_CHUNK_SIZE: usize = 1 << 20; // 1 MiB

/// Main entry point for interacting with PocketIC.
pub struct PocketIc {
    /// The unique ID of this PocketIC instance.
    pub instance_id: InstanceId,
    // how long a get/post request may retry or poll
    max_request_time_ms: Option<u64>,
    http_gateway: Option<HttpGatewayInfo>,
    server_url: Url,
    reqwest_client: reqwest::Client,
    _log_guard: Option<WorkerGuard>,
}

impl PocketIc {
    /// Creates a new PocketIC instance with a single application subnet on the server.
    /// The server is started if it's not already running.
    pub async fn new() -> Self {
        PocketIcBuilder::new()
            .with_application_subnet()
            .build_async()
            .await
    }

    /// Creates a new PocketIC instance with the specified subnet config.
    /// The server is started if it's not already running.
    pub async fn from_config(config: impl Into<ExtendedSubnetConfigSet>) -> Self {
        let server_url = crate::start_or_reuse_server();
        Self::from_components(
            config,
            server_url,
            Some(DEFAULT_MAX_REQUEST_TIME_MS),
            None,
            false,
            None,
        )
        .await
    }

    /// Creates a new PocketIC instance with the specified subnet config and max request duration in milliseconds
    /// (`None` means that there is no timeout).
    /// The server is started if it's not already running.
    pub async fn from_config_and_max_request_time(
        config: impl Into<ExtendedSubnetConfigSet>,
        max_request_time_ms: Option<u64>,
    ) -> Self {
        let server_url = crate::start_or_reuse_server();
        Self::from_components(config, server_url, max_request_time_ms, None, false, None).await
    }

    /// Creates a new PocketIC instance with the specified subnet config and server url.
    /// This function is intended for advanced users who start the server manually.
    pub async fn from_config_and_server_url(
        config: impl Into<ExtendedSubnetConfigSet>,
        server_url: Url,
    ) -> Self {
        Self::from_components(
            config,
            server_url,
            Some(DEFAULT_MAX_REQUEST_TIME_MS),
            None,
            false,
            None,
        )
        .await
    }

    pub(crate) async fn from_components(
        subnet_config_set: impl Into<ExtendedSubnetConfigSet>,
        server_url: Url,
        max_request_time_ms: Option<u64>,
        state_dir: Option<PathBuf>,
        nonmainnet_features: bool,
        log_level: Option<Level>,
    ) -> Self {
        let subnet_config_set = subnet_config_set.into();
        if state_dir.is_none()
            || File::open(state_dir.clone().unwrap().join("topology.json")).is_err()
        {
            subnet_config_set.validate().unwrap();
        }
        let instance_config = InstanceConfig {
            subnet_config_set,
            state_dir,
            nonmainnet_features,
            log_level: log_level.map(|l| l.to_string()),
        };

        let parent_pid = std::os::unix::process::parent_id();
        let log_guard = setup_tracing(parent_pid);

        let reqwest_client = reqwest::Client::new();
        let instance_id = match reqwest_client
            .post(server_url.join("instances").unwrap())
            .json(&instance_config)
            .send()
            .await
            .expect("Failed to get result")
            .json::<CreateInstanceResponse>()
            .await
            .expect("Could not parse response for create instance request")
        {
            CreateInstanceResponse::Created { instance_id, .. } => instance_id,
            CreateInstanceResponse::Error { message } => panic!("{}", message),
        };
        debug!("instance_id={} New instance created.", instance_id);

        Self {
            instance_id,
            max_request_time_ms,
            http_gateway: None,
            server_url,
            reqwest_client,
            _log_guard: log_guard,
        }
    }

    /// Returns the topology of the different subnets of this PocketIC instance.
    pub async fn topology(&self) -> Topology {
        let endpoint = "read/topology";
        self.get(endpoint).await
    }

    /// Upload and store a binary blob to the PocketIC server.
    #[instrument(ret(Display), skip(self, blob), fields(instance_id=self.instance_id, blob_len = %blob.len(), compression = ?compression))]
    pub async fn upload_blob(&self, blob: Vec<u8>, compression: BlobCompression) -> BlobId {
        let reqwest_client = &self.reqwest_client;
        let mut request = reqwest_client
            .post(self.server_url.join("blobstore/").unwrap())
            .body(blob);
        if compression == BlobCompression::Gzip {
            request = request.header(reqwest::header::CONTENT_ENCODING, "gzip");
        }
        let blob_id = request
            .send()
            .await
            .expect("Failed to get response")
            .text()
            .await
            .expect("Failed to get text");

        let hash_vec = hex::decode(blob_id).expect("Failed to decode hex");
        BlobId(hash_vec)
    }

    /// Set stable memory of a canister. Optional GZIP compression can be used for reduced
    /// data traffic.
    #[instrument(skip(self, data), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), data_len = %data.len(), compression = ?compression))]
    pub async fn set_stable_memory(
        &self,
        canister_id: CanisterId,
        data: Vec<u8>,
        compression: BlobCompression,
    ) {
        let blob_id = self.upload_blob(data, compression).await;
        let endpoint = "update/set_stable_memory";
        self.post::<(), _>(
            endpoint,
            RawSetStableMemory {
                canister_id: canister_id.as_slice().to_vec(),
                blob_id,
            },
        )
        .await;
    }

    /// Get stable memory of a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub async fn get_stable_memory(&self, canister_id: CanisterId) -> Vec<u8> {
        let endpoint = "read/get_stable_memory";
        let RawStableMemory { blob } = self
            .post(
                endpoint,
                RawCanisterId {
                    canister_id: canister_id.as_slice().to_vec(),
                },
            )
            .await;
        blob
    }

    /// List all instances and their status.
    #[instrument(ret)]
    pub async fn list_instances() -> Vec<String> {
        let url = crate::start_or_reuse_server().join("instances").unwrap();
        let instances: Vec<String> = reqwest::Client::new()
            .get(url)
            .send()
            .await
            .expect("Failed to get result")
            .json()
            .await
            .expect("Failed to get json");
        instances
    }

    /// Verify a canister signature.
    #[instrument(skip_all, fields(instance_id=self.instance_id))]
    pub async fn verify_canister_signature(
        &self,
        msg: Vec<u8>,
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        root_pubkey: Vec<u8>,
    ) -> Result<(), String> {
        let url = self.server_url.join("verify_signature").unwrap();
        reqwest::Client::new()
            .post(url)
            .json(&RawVerifyCanisterSigArg {
                msg,
                sig,
                pubkey,
                root_pubkey,
            })
            .send()
            .await
            .expect("Failed to get result")
            .json()
            .await
            .expect("Failed to get json")
    }

    /// Make the IC produce and progress by one block.
    /// Note that multiple ticks might be necessary to observe
    /// an expected effect, e.g., if the effect depends on
    /// inter-canister calls or heartbeats.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn tick(&self) {
        let endpoint = "update/tick";
        self.post::<(), _>(endpoint, "").await;
    }

    /// Configures the IC to make progress automatically,
    /// i.e., periodically update the time of the IC
    /// to the real time and execute rounds on the subnets.
    /// Returns the URL at which `/api/v2` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn auto_progress(&self) -> Url {
        let now = std::time::SystemTime::now();
        self.set_time(now).await;
        let endpoint = "auto_progress";
        let auto_progress_config = AutoProgressConfig {
            artificial_delay_ms: None,
        };
        self.post::<(), _>(endpoint, auto_progress_config).await;
        self.instance_url()
    }

    pub(crate) fn instance_url(&self) -> Url {
        self.server_url
            .join("/instances/")
            .unwrap()
            .join(&format!("{}/", self.instance_id))
            .unwrap()
    }

    /// Stops automatic progress (see `auto_progress`) on the IC.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn stop_progress(&self) {
        let endpoint = "stop_progress";
        self.post::<(), _>(endpoint, "").await;
    }

    /// Returns the URL at which `/api/v2` requests
    /// for this instance can be made if the HTTP
    /// gateway has been started.
    pub fn url(&self) -> Option<Url> {
        self.http_gateway
            .as_ref()
            .map(|res| Url::parse(&format!("http://{}:{}/", LOCALHOST, res.port)).unwrap())
    }

    /// Creates an HTTP gateway for this IC instance
    /// listening on an optionally specified port
    /// and configures the IC instance to make progress
    /// automatically, i.e., periodically update the time
    /// of the IC to the real time and execute rounds on the subnets.
    /// Returns the URL at which `/api/v2` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn make_live(&mut self, listen_at: Option<u16>) -> Url {
        self.auto_progress().await;
        self.start_http_gateway(listen_at, None, None).await
    }

    /// Creates an HTTP gateway for this PocketIC instance listening
    /// on an optionally specified port (defaults to choosing an arbitrary unassigned port)
    /// and optionally specified domains (default to `localhost`)
    /// and using an optionally specified TLS certificate (if provided, an HTTPS gateway is created)
    /// and configures the PocketIC instance to make progress automatically, i.e.,
    /// periodically update the time of the PocketIC instance to the real time and execute rounds on the subnets.
    /// Returns the URL at which `/api/v2` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn make_live_with_params(
        &mut self,
        listen_at: Option<u16>,
        domains: Option<Vec<String>>,
        https_config: Option<HttpsConfig>,
    ) -> Url {
        self.auto_progress().await;
        self.start_http_gateway(listen_at, domains, https_config)
            .await
    }

    async fn start_http_gateway(
        &mut self,
        port: Option<u16>,
        domains: Option<Vec<String>>,
        https_config: Option<HttpsConfig>,
    ) -> Url {
        if let Some(url) = self.url() {
            return url;
        }
        let endpoint = self.server_url.join("http_gateway").unwrap();
        let http_gateway_config = HttpGatewayConfig {
            ip_addr: None,
            port,
            forward_to: HttpGatewayBackend::PocketIcInstance(self.instance_id),
            domains: domains.clone(),
            https_config: https_config.clone(),
            api_only: None,
        };
        let res = self
            .reqwest_client
            .post(endpoint)
            .json(&http_gateway_config)
            .send()
            .await
            .expect("HTTP failure")
            .json::<CreateHttpGatewayResponse>()
            .await
            .expect("Could not parse response for create HTTP gateway request");
        match res {
            CreateHttpGatewayResponse::Created(info) => {
                let port = info.port;
                self.http_gateway = Some(info);
                let proto = if https_config.is_some() {
                    "https"
                } else {
                    "http"
                };
                Url::parse(&format!(
                    "{}://{}:{}/",
                    proto,
                    domains
                        .unwrap_or_default()
                        .into_iter()
                        .next()
                        .unwrap_or(LOCALHOST.to_string()),
                    port
                ))
                .unwrap()
            }
            CreateHttpGatewayResponse::Error { message } => {
                panic!("Failed to crate http gateway: {}", message)
            }
        }
    }

    async fn stop_http_gateway(&mut self) {
        if let Some(info) = self.http_gateway.take() {
            let stop_http_gateway_url = self
                .server_url
                .join(&format!("http_gateway/{}/stop", info.instance_id))
                .unwrap();
            self.reqwest_client
                .post(stop_http_gateway_url)
                .send()
                .await
                .unwrap()
                .json::<()>()
                .await
                .expect("Could not parse response for stop HTTP gateway request");
        }
    }

    /// Stops auto progress (automatic time updates and round executions)
    /// and the HTTP gateway for this IC instance.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn stop_live(&mut self) {
        self.stop_http_gateway().await;
        self.stop_progress().await;
    }

    #[deprecated(note = "Use `stop_live` instead.")]
    /// Use `stop_live` instead.
    pub async fn make_deterministic(&mut self) {
        self.stop_live().await;
    }

    /// Get the root key of this IC instance. Returns `None` if the IC has no NNS subnet.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn root_key(&self) -> Option<Vec<u8>> {
        let subnet_id = self.topology().await.get_nns()?;
        let subnet_id: RawSubnetId = subnet_id.into();
        let endpoint = "read/pub_key";
        let res = self.post::<Vec<u8>, _>(endpoint, subnet_id).await;
        Some(res)
    }

    /// Get the current time of the IC.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id))]
    pub async fn get_time(&self) -> SystemTime {
        let endpoint = "read/get_time";
        let result: RawTime = self.get(endpoint).await;
        SystemTime::UNIX_EPOCH + Duration::from_nanos(result.nanos_since_epoch)
    }

    /// Set the current time of the IC, on all subnets.
    #[instrument(skip(self), fields(instance_id=self.instance_id, time = ?time))]
    pub async fn set_time(&self, time: SystemTime) {
        let endpoint = "update/set_time";
        self.post::<(), _>(
            endpoint,
            RawTime {
                nanos_since_epoch: time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_nanos() as u64,
            },
        )
        .await;
    }

    /// Advance the time on the IC on all subnets by some nanoseconds.
    #[instrument(skip(self), fields(instance_id=self.instance_id, duration = ?duration))]
    pub async fn advance_time(&self, duration: Duration) {
        let now = self.get_time().await;
        self.set_time(now + duration).await;
    }

    /// Get the current cycles balance of a canister.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub async fn cycle_balance(&self, canister_id: CanisterId) -> u128 {
        let endpoint = "read/get_cycles";
        let result: RawCycles = self
            .post(
                endpoint,
                RawCanisterId {
                    canister_id: canister_id.as_slice().to_vec(),
                },
            )
            .await;
        result.cycles
    }

    /// Add cycles to a canister. Returns the new balance.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), amount = %amount))]
    pub async fn add_cycles(&self, canister_id: CanisterId, amount: u128) -> u128 {
        let endpoint = "update/add_cycles";
        let result: RawCycles = self
            .post(
                endpoint,
                RawAddCycles {
                    canister_id: canister_id.as_slice().to_vec(),
                    amount,
                },
            )
            .await;
        result.cycles
    }

    /// Submit an update call (without executing it immediately).
    pub async fn submit_call(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<RawMessageId, UserError> {
        self.submit_call_with_effective_principal(
            canister_id,
            RawEffectivePrincipal::None,
            sender,
            method,
            payload,
        )
        .await
    }

    /// Submit an update call with a provided effective principal (without executing it immediately).
    pub async fn submit_call_with_effective_principal(
        &self,
        canister_id: CanisterId,
        effective_principal: RawEffectivePrincipal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<RawMessageId, UserError> {
        let endpoint = "update/submit_ingress_message";
        let raw_canister_call = RawCanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            payload,
            effective_principal,
        };
        let res: RawSubmitIngressResult = self.post(endpoint, raw_canister_call).await;
        match res {
            RawSubmitIngressResult::Ok(message_id) => Ok(message_id),
            RawSubmitIngressResult::Err(user_error) => Err(user_error),
        }
    }

    /// Await an update call submitted previously by `submit_call_with_effective_principal`.
    pub async fn await_call(&self, message_id: RawMessageId) -> Result<WasmResult, UserError> {
        let endpoint = "update/await_ingress_message";
        let result: RawCanisterResult = self.post(endpoint, message_id).await;
        match result {
            RawCanisterResult::Ok(raw_wasm_result) => match raw_wasm_result {
                RawWasmResult::Reply(data) => Ok(WasmResult::Reply(data)),
                RawWasmResult::Reject(text) => Ok(WasmResult::Reject(text)),
            },
            RawCanisterResult::Err(user_error) => Err(user_error),
        }
    }

    /// Execute an update call on a canister.
    #[instrument(skip(self, payload), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.to_string(), method = %method, payload_len = %payload.len()))]
    pub async fn update_call(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.update_call_with_effective_principal(
            canister_id,
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender,
            method,
            payload,
        )
        .await
    }

    /// Execute a query call on a canister.
    #[instrument(skip(self, payload), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.to_string(), method = %method, payload_len = %payload.len()))]
    pub async fn query_call(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let endpoint = "read/query";
        self.canister_call(
            endpoint,
            RawEffectivePrincipal::None,
            canister_id,
            sender,
            method,
            payload,
        )
        .await
    }

    /// Request a canister's status.
    #[instrument(skip(self), fields(instance_id=self.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn canister_status(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<CanisterStatusResponse, CallError> {
        call_candid_as::<(CanisterIdRecord,), (CanisterStatusResponse,)>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "canister_status",
            (CanisterIdRecord { canister_id },),
        )
        .await
        .map(|responses| responses.0)
    }

    /// Create a canister with default settings as the anonymous principal.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.instance_id))]
    pub async fn create_canister(&self) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::None,
            Principal::anonymous(),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterArgument {
                settings: None,
                amount: Some(0_u64.into()),
                specified_id: None,
            },),
        )
        .await
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    /// Create a canister with optional custom settings and a sender.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.instance_id, settings = ?settings, sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn create_canister_with_settings(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
    ) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::None,
            sender.unwrap_or(Principal::anonymous()),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterArgument {
                settings,
                amount: Some(0_u64.into()),
                specified_id: None,
            },),
        )
        .await
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    /// Creates a canister with a specific canister ID and optional custom settings.
    /// Returns an error if the canister ID is already in use.
    /// Creates a new subnet if the canister ID is not contained in any of the subnets.
    ///
    /// The canister ID must be an IC mainnet canister ID that does not belong to the NNS or II subnet,
    /// otherwise the function might panic (for NNS and II canister IDs,
    /// the PocketIC instance should already be created with those subnets).
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string(), settings = ?settings, canister_id = %canister_id.to_string()))]
    pub async fn create_canister_with_id(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
        canister_id: CanisterId,
    ) -> Result<CanisterId, String> {
        let res = call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterArgument {
                settings,
                specified_id: Some(canister_id),
                amount: Some(0_u64.into()),
            },),
        )
        .await
        .map(|(x,)| x);
        match res {
            Ok(CanisterIdRecord {
                canister_id: actual_canister_id,
            }) => Ok(actual_canister_id),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    /// Create a canister on a specific subnet with optional custom settings.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string(), settings = ?settings, subnet_id = %subnet_id.to_string()))]
    pub async fn create_canister_on_subnet(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
        subnet_id: SubnetId,
    ) -> CanisterId {
        let CanisterIdRecord { canister_id } = call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::SubnetId(subnet_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "provisional_create_canister_with_cycles",
            (ProvisionalCreateCanisterArgument {
                settings,
                amount: Some(0_u64.into()),
                specified_id: None,
            },),
        )
        .await
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    async fn install_canister_helper(
        &self,
        mode: CanisterInstallMode,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        if wasm_module.len() + arg.len() < INSTALL_CHUNKED_CODE_THRESHOLD {
            call_candid_as::<(InstallCodeArgument,), ()>(
                self,
                Principal::management_canister(),
                RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
                sender.unwrap_or(Principal::anonymous()),
                "install_code",
                (InstallCodeArgument {
                    mode,
                    canister_id,
                    wasm_module,
                    arg,
                },),
            )
            .await
        } else {
            let chunks: Vec<_> = wasm_module.chunks(INSTALL_CODE_CHUNK_SIZE).collect();
            let hashes: Vec<_> = chunks
                .iter()
                .map(|c| {
                    let mut hasher = Sha256::new();
                    hasher.update(c);
                    ChunkHash {
                        hash: hasher.finalize().to_vec(),
                    }
                })
                .collect();
            call_candid_as::<_, ()>(
                self,
                Principal::management_canister(),
                RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
                sender.unwrap_or(Principal::anonymous()),
                "clear_chunk_store",
                (ClearChunkStoreArgument { canister_id },),
            )
            .await
            .unwrap();
            for chunk in chunks {
                call_candid_as::<_, ()>(
                    self,
                    Principal::management_canister(),
                    RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
                    sender.unwrap_or(Principal::anonymous()),
                    "upload_chunk",
                    (UploadChunkArgument {
                        canister_id,
                        chunk: chunk.to_vec(),
                    },),
                )
                .await
                .unwrap();
            }
            let mut hasher = Sha256::new();
            hasher.update(wasm_module);
            let wasm_module_hash = hasher.finalize().to_vec();
            call_candid_as::<_, ()>(
                self,
                Principal::management_canister(),
                RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
                sender.unwrap_or(Principal::anonymous()),
                "install_chunked_code",
                (InstallChunkedCodeArgument {
                    mode,
                    target_canister: canister_id,
                    store_canister: None,
                    chunk_hashes_list: hashes,
                    wasm_module_hash,
                    arg,
                },),
            )
            .await
        }
    }

    /// Install a WASM module on an existing canister.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn install_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) {
        self.install_canister_helper(
            CanisterInstallMode::Install,
            canister_id,
            wasm_module,
            arg,
            sender,
        )
        .await
        .unwrap()
    }

    /// Upgrade a canister with a new WASM module.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn upgrade_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        self.install_canister_helper(
            CanisterInstallMode::Upgrade(Some(SkipPreUpgrade(Some(false)))),
            canister_id,
            wasm_module,
            arg,
            sender,
        )
        .await
    }

    /// Reinstall a canister WASM module.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn reinstall_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        self.install_canister_helper(
            CanisterInstallMode::Reinstall,
            canister_id,
            wasm_module,
            arg,
            sender,
        )
        .await
    }

    /// Uninstall a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn uninstall_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "uninstall_code",
            (CanisterIdRecord { canister_id },),
        )
        .await
    }

    /// Update canister settings.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn update_canister_settings(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        settings: CanisterSettings,
    ) -> Result<(), CallError> {
        call_candid_as::<_, ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "update_settings",
            (UpdateSettingsArgument {
                canister_id,
                settings,
            },),
        )
        .await
    }

    /// Set canister's controllers.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn set_controllers(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        new_controllers: Vec<Principal>,
    ) -> Result<(), CallError> {
        let settings = CanisterSettings {
            controllers: Some(new_controllers),
            compute_allocation: None,
            memory_allocation: None,
            freezing_threshold: None,
            reserved_cycles_limit: None,
        };
        call_candid_as::<(UpdateSettingsArgument,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "update_settings",
            (UpdateSettingsArgument {
                canister_id,
                settings,
            },),
        )
        .await
    }

    /// Start a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn start_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "start_canister",
            (CanisterIdRecord { canister_id },),
        )
        .await
    }

    /// Stop a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn stop_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "stop_canister",
            (CanisterIdRecord { canister_id },),
        )
        .await
    }

    /// Delete a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn delete_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), CallError> {
        call_candid_as::<(CanisterIdRecord,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "delete_canister",
            (CanisterIdRecord { canister_id },),
        )
        .await
    }

    /// Checks whether the provided canister exists.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub async fn canister_exists(&self, canister_id: CanisterId) -> bool {
        self.get_subnet(canister_id).await.is_some()
    }

    /// Returns the subnet ID of the canister if the canister exists.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub async fn get_subnet(&self, canister_id: CanisterId) -> Option<SubnetId> {
        let endpoint = "read/get_subnet";
        let result: Option<RawSubnetId> = self
            .post(
                endpoint,
                RawCanisterId {
                    canister_id: canister_id.as_slice().to_vec(),
                },
            )
            .await;
        result.map(|RawSubnetId { subnet_id }| SubnetId::from_slice(&subnet_id))
    }

    /// This (asynchronous) drop function must be called to drop the PocketIc instance.
    /// It must be called manually as Rust doesn't support asynchronous drop.
    pub async fn drop(mut self) {
        self.do_drop().await;
    }

    pub(crate) async fn do_drop(&mut self) {
        self.stop_http_gateway().await;
        self.reqwest_client
            .delete(self.instance_url())
            .send()
            .await
            .expect("Failed to send delete request");
    }

    async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> T {
        // we may have to try several times if the instance is busy
        let start = std::time::SystemTime::now();
        loop {
            let reqwest_client = &self.reqwest_client;
            let result = reqwest_client
                .get(self.instance_url().join(endpoint).unwrap())
                .send()
                .await
                .expect("HTTP failure");
            match ApiResponse::<_>::from_response(result).await {
                ApiResponse::Success(t) => break t,
                ApiResponse::Error { message } => panic!("{}", message),
                ApiResponse::Busy { state_label, op_id } => {
                    debug!(
                        "instance_id={} Instance is busy: state_label: {}, op_id: {}",
                        self.instance_id, state_label, op_id
                    );
                }
                ApiResponse::Started { state_label, op_id } => {
                    panic!(
                        "Error: A 'get' should not return Started: state_label: {}, op_id: {}",
                        state_label, op_id
                    )
                }
            }
            if let Some(max_request_time_ms) = self.max_request_time_ms {
                if start.elapsed().unwrap() > Duration::from_millis(max_request_time_ms) {
                    panic!("'get' request to PocketIC server timed out.");
                }
            }
            std::thread::sleep(Duration::from_millis(POLLING_PERIOD_MS));
        }
    }

    async fn post<T: DeserializeOwned, B: Serialize>(&self, endpoint: &str, body: B) -> T {
        // we may have to try several times if the instance is busy
        let start = std::time::SystemTime::now();
        loop {
            let reqwest_client = &self.reqwest_client;
            let result = reqwest_client
                .post(self.instance_url().join(endpoint).unwrap())
                .json(&body)
                .send()
                .await
                .expect("HTTP failure");
            match ApiResponse::<_>::from_response(result).await {
                ApiResponse::Success(t) => break t,
                ApiResponse::Error { message } => panic!("{}", message),
                ApiResponse::Busy { state_label, op_id } => {
                    debug!(
                        "instance_id={} Instance is busy (with a different computation): state_label: {}, op_id: {}",
                        self.instance_id, state_label, op_id
                    );
                }
                ApiResponse::Started { state_label, op_id } => {
                    // once we have a Started reply, we only want to query the result to that computation
                    debug!(
                        "instance_id={} Instance has Started: state_label: {}, op_id: {}",
                        self.instance_id, state_label, op_id
                    );
                    loop {
                        std::thread::sleep(Duration::from_millis(POLLING_PERIOD_MS));
                        let reqwest_client = &self.reqwest_client;
                        let result = reqwest_client
                            .get(
                                self.server_url
                                    .join(&format!("/read_graph/{}/{}", state_label, op_id))
                                    .unwrap(),
                            )
                            .send()
                            .await
                            .expect("HTTP failure");
                        match ApiResponse::<_>::from_response(result).await {
                            ApiResponse::Error { message } => {
                                debug!("Polling has not succeeded yet: {}", message)
                            }
                            ApiResponse::Success(t) => {
                                return t;
                            }
                            ApiResponse::Started { state_label, op_id } => {
                                warn!(
                                    "instance_id={} unexpected Started({} {})",
                                    self.instance_id, state_label, op_id
                                );
                            }
                            ApiResponse::Busy { state_label, op_id } => {
                                warn!(
                                    "instance_id={} unexpected Busy({} {})",
                                    self.instance_id, state_label, op_id
                                );
                            }
                        }
                        if let Some(max_request_time_ms) = self.max_request_time_ms {
                            if start.elapsed().unwrap() > Duration::from_millis(max_request_time_ms)
                            {
                                panic!("'post' request to PocketIC server timed out.");
                            }
                        }
                    }
                }
            }
            if let Some(max_request_time_ms) = self.max_request_time_ms {
                if start.elapsed().unwrap() > Duration::from_millis(max_request_time_ms) {
                    panic!("'post' request to PocketIC server timed out.");
                }
            }
            std::thread::sleep(Duration::from_millis(POLLING_PERIOD_MS));
        }
    }

    async fn canister_call(
        &self,
        endpoint: &str,
        effective_principal: RawEffectivePrincipal,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let raw_canister_call = RawCanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            payload,
            effective_principal,
        };

        let result: RawCanisterResult = self.post(endpoint, raw_canister_call).await;
        match result {
            RawCanisterResult::Ok(raw_wasm_result) => match raw_wasm_result {
                RawWasmResult::Reply(data) => Ok(WasmResult::Reply(data)),
                RawWasmResult::Reject(text) => Ok(WasmResult::Reject(text)),
            },
            RawCanisterResult::Err(user_error) => Err(user_error),
        }
    }

    pub(crate) async fn update_call_with_effective_principal(
        &self,
        canister_id: CanisterId,
        effective_principal: RawEffectivePrincipal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let message_id = self
            .submit_call_with_effective_principal(
                canister_id,
                effective_principal,
                sender,
                method,
                payload,
            )
            .await?;
        self.await_call(message_id).await
    }

    /// Get the pending canister HTTP outcalls.
    /// Note that an additional `PocketIc::tick` is necessary after a canister
    /// executes a message making a canister HTTP outcall for the HTTP outcall
    /// to be retrievable here.
    /// Note that, unless a PocketIC instance is in auto progress mode,
    /// a response to the pending canister HTTP outcalls
    /// must be produced by the test driver and passed on to the PocketIC instace
    /// using `PocketIc::mock_canister_http_response`.
    /// In auto progress mode, the PocketIC server produces a response for every
    /// pending canister HTTP outcall by actually making an HTTP request
    /// to the specified URL.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id))]
    pub async fn get_canister_http(&self) -> Vec<CanisterHttpRequest> {
        let endpoint = "read/get_canister_http";
        let res: Vec<RawCanisterHttpRequest> = self.get(endpoint).await;
        res.into_iter().map(|r| r.into()).collect()
    }

    /// Mock a response to a pending canister HTTP outcall.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id))]
    pub async fn mock_canister_http_response(
        &self,
        mock_canister_http_response: MockCanisterHttpResponse,
    ) {
        let endpoint = "update/mock_canister_http";
        let raw_mock_canister_http_response: RawMockCanisterHttpResponse =
            mock_canister_http_response.into();
        self.post(endpoint, raw_mock_canister_http_response).await
    }
}

/// Call a canister candid method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
/// PocketIC executes update calls synchronously, so there is no need to poll for the result.
pub async fn call_candid_as<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    effective_principal: RawEffectivePrincipal,
    sender: Principal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    with_candid(input, |payload| async {
        env.update_call_with_effective_principal(
            canister_id,
            effective_principal,
            sender,
            method,
            payload,
        )
        .await
    })
    .await
}

/// Call a canister candid method, anonymous.
/// PocketIC executes update calls synchronously, so there is no need to poll for the result.
pub async fn call_candid<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    effective_principal: RawEffectivePrincipal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    call_candid_as(
        env,
        canister_id,
        effective_principal,
        Principal::anonymous(),
        method,
        input,
    )
    .await
}

/// Call a canister candid query method, anonymous.
pub async fn query_candid<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    query_candid_as(env, canister_id, Principal::anonymous(), method, input).await
}

/// Call a canister candid query method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
pub async fn query_candid_as<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    sender: Principal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    with_candid(input, |bytes| async {
        env.query_call(canister_id, sender, method, bytes).await
    })
    .await
}

/// Call a canister candid update method, anonymous.
pub async fn update_candid<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    update_candid_as(env, canister_id, Principal::anonymous(), method, input).await
}

/// Call a canister candid update method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
pub async fn update_candid_as<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    sender: Principal,
    method: &str,
    input: Input,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    with_candid(input, |bytes| async {
        env.update_call(canister_id, sender, method, bytes).await
    })
    .await
}

/// A helper function that we use to implement both [`call_candid`] and
/// [`query_candid`].
pub async fn with_candid<Input, Output, Fut>(
    input: Input,
    f: impl FnOnce(Vec<u8>) -> Fut,
) -> Result<Output, CallError>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
    Fut: Future<Output = Result<WasmResult, UserError>>,
{
    let in_bytes = encode_args(input).expect("failed to encode args");
    match f(in_bytes).await {
        Ok(WasmResult::Reply(out_bytes)) => Ok(decode_args(&out_bytes).unwrap_or_else(|e| {
            panic!(
                "Failed to decode response as candid type {}:\nerror: {}\nbytes: {:?}\nutf8: {}",
                std::any::type_name::<Output>(),
                e,
                out_bytes,
                String::from_utf8_lossy(&out_bytes),
            )
        })),
        Ok(WasmResult::Reject(message)) => Err(CallError::Reject(message)),
        Err(user_error) => Err(CallError::UserError(user_error)),
    }
}

#[derive(
    CandidType, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default,
)]
struct ProvisionalCreateCanisterArgument {
    pub settings: Option<CanisterSettings>,
    pub specified_id: Option<Principal>,
    pub amount: Option<Nat>,
}

fn setup_tracing(pid: u32) -> Option<WorkerGuard> {
    use tracing_subscriber::prelude::*;
    match std::env::var(LOG_DIR_PATH_ENV_NAME).map(std::path::PathBuf::from) {
        Ok(p) => {
            std::fs::create_dir_all(&p).expect("Could not create directory");

            let file_name = format!("pocket_ic_client_{pid}.log");
            let appender = tracing_appender::rolling::never(&p, file_name);
            let (non_blocking_appender, guard) = tracing_appender::non_blocking(appender);
            let log_dir_filter: EnvFilter =
                tracing_subscriber::EnvFilter::try_from_env(LOG_DIR_LEVELS_ENV_NAME)
                    .unwrap_or_else(|_| "trace".parse().unwrap());

            let layers = vec![tracing_subscriber::fmt::layer()
                .with_writer(non_blocking_appender)
                // disable color escape codes in files
                .with_ansi(false)
                .with_filter(log_dir_filter)
                .boxed()];
            let _ = tracing_subscriber::registry().with(layers).try_init();
            Some(guard)
        }
        _ => None,
    }
}
