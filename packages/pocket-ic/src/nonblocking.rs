pub use crate::DefaultEffectiveCanisterIdError;
use crate::common::rest::{
    ApiResponse, AutoProgressConfig, BlobCompression, BlobId, CanisterHttpRequest,
    CreateHttpGatewayResponse, CreateInstanceResponse, ExtendedSubnetConfigSet, HttpGatewayBackend,
    HttpGatewayConfig, HttpGatewayInfo, HttpsConfig, IcpConfig, IcpFeatures, InitialTime,
    InstanceConfig, InstanceHttpGatewayConfig, InstanceId, MockCanisterHttpResponse, RawAddCycles,
    RawCanisterCall, RawCanisterHttpRequest, RawCanisterId, RawCanisterResult,
    RawCanisterSnapshotDownload, RawCanisterSnapshotId, RawCanisterSnapshotUpload, RawCycles,
    RawEffectivePrincipal, RawIngressStatusArgs, RawMessageId, RawMockCanisterHttpResponse,
    RawPrincipalId, RawSetStableMemory, RawStableMemory, RawSubnetId, RawTime,
    RawVerifyCanisterSigArg, SubnetId, TickConfigs, Topology,
};
#[cfg(windows)]
use crate::wsl_path;
use crate::{
    IngressStatusResult, PocketIcBuilder, PocketIcState, RejectResponse, StartServerParams, Time,
    copy_dir, start_server,
};
use backoff::backoff::Backoff;
use backoff::{ExponentialBackoff, ExponentialBackoffBuilder};
use candid::{
    Principal, decode_args, encode_args,
    utils::{ArgumentDecoder, ArgumentEncoder},
};
use ic_certification::{Certificate, Label, LookupResult};
use ic_management_canister_types::{
    CanisterId, CanisterIdRecord, CanisterInstallMode, CanisterLogRecord, CanisterSettings,
    CanisterStatusResult, ChunkHash, DeleteCanisterSnapshotArgs, FetchCanisterLogsResult,
    InstallChunkedCodeArgs, InstallCodeArgs, LoadCanisterSnapshotArgs,
    ProvisionalCreateCanisterWithCyclesArgs, Snapshot, StoredChunksResult,
    TakeCanisterSnapshotArgs, UpdateSettingsArgs, UpgradeFlags, UploadChunkArgs, UploadChunkResult,
    WasmMemoryPersistence,
};
use ic_transport_types::Envelope;
use ic_transport_types::EnvelopeContent::ReadState;
use ic_transport_types::{ReadStateResponse, SubnetMetrics};
use reqwest::{StatusCode, Url};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use slog::Level;
use std::fs::read_dir;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
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

enum HttpMethod {
    Get,
    Post,
}

/// Main entry point for interacting with PocketIC.
pub struct PocketIc {
    /// The unique ID of this PocketIC instance.
    pub instance_id: InstanceId,
    // how long a get/post request may retry or poll
    max_request_time_ms: Option<u64>,
    http_gateway: Option<HttpGatewayInfo>,
    server_url: Url,
    reqwest_client: reqwest::Client,
    // the instance should only be deleted when dropping this handle if this handle owns the instance
    owns_instance: bool,
    state_dir: Option<PocketIcState>,
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

    /// Creates a PocketIC handle to an existing instance on a running server.
    /// Note that this handle does not extend the lifetime of the existing instance,
    /// i.e., the existing instance is deleted and this handle stops working
    /// when the PocketIC handle that created the existing instance is dropped.
    pub fn new_from_existing_instance(
        server_url: Url,
        instance_id: InstanceId,
        max_request_time_ms: Option<u64>,
    ) -> Self {
        let test_driver_pid = std::process::id();
        let log_guard = setup_tracing(test_driver_pid);

        let reqwest_client = reqwest::Client::new();
        debug!("instance_id={} Reusing existing instance.", instance_id);

        Self {
            instance_id,
            max_request_time_ms,
            http_gateway: None,
            server_url,
            reqwest_client,
            owns_instance: false,
            state_dir: None,
            _log_guard: log_guard,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn from_components(
        subnet_config_set: impl Into<ExtendedSubnetConfigSet>,
        server_url: Option<Url>,
        server_binary: Option<PathBuf>,
        max_request_time_ms: Option<u64>,
        read_only_state_dir: Option<PathBuf>,
        mut state_dir: Option<PocketIcState>,
        icp_config: IcpConfig,
        log_level: Option<Level>,
        bitcoind_addr: Option<Vec<SocketAddr>>,
        dogecoind_addr: Option<Vec<SocketAddr>>,
        icp_features: IcpFeatures,
        initial_time: Option<InitialTime>,
        http_gateway_config: Option<InstanceHttpGatewayConfig>,
    ) -> Self {
        let server_url = if let Some(server_url) = server_url {
            server_url
        } else {
            let (_, server_url) = start_server(StartServerParams {
                server_binary,
                reuse: true,
                ttl: None,
            })
            .await;
            server_url
        };

        let subnet_config_set: ExtendedSubnetConfigSet = subnet_config_set.into();

        // copy the read-only state dir to the state dir
        // (creating an empty temp dir to serve as the state dir if no state dir is provided)
        if let Some(read_only_state_dir) = read_only_state_dir {
            if let Some(ref state_dir) = state_dir {
                let mut state_dir_contents = read_dir(state_dir.state_dir()).unwrap();
                if state_dir_contents.next().is_some() {
                    panic!(
                        "PocketIC instance state must be empty if a read-only state is mounted."
                    );
                }
            } else {
                state_dir = Some(PocketIcState::new());
            };
            copy_dir(
                read_only_state_dir,
                state_dir
                    .as_ref()
                    .map(|state_dir| state_dir.state_dir())
                    .unwrap(),
            )
            .expect("Failed to copy state directory");
        };

        let instance_config = InstanceConfig {
            subnet_config_set,
            http_gateway_config,
            #[cfg(not(windows))]
            state_dir: state_dir.as_ref().map(|state_dir| state_dir.state_dir()),
            #[cfg(windows)]
            state_dir: state_dir
                .as_ref()
                .map(|state_dir| wsl_path(&state_dir.state_dir(), "state directory").into()),
            icp_config: Some(icp_config),
            log_level: log_level.map(|l| l.to_string()),
            bitcoind_addr,
            dogecoind_addr,
            icp_features: Some(icp_features),
            incomplete_state: None,
            initial_time,
        };

        let test_driver_pid = std::process::id();
        let log_guard = setup_tracing(test_driver_pid);

        let reqwest_client = reqwest::Client::new();
        let (instance_id, http_gateway_info) = match reqwest_client
            .post(server_url.join("instances").unwrap())
            .json(&instance_config)
            .send()
            .await
            .expect("Failed to get result")
            .json::<CreateInstanceResponse>()
            .await
            .expect("Could not parse response for create instance request")
        {
            CreateInstanceResponse::Created {
                instance_id,
                http_gateway_info,
                ..
            } => (instance_id, http_gateway_info),
            CreateInstanceResponse::Error { message } => panic!("{}", message),
        };
        debug!("instance_id={} New instance created.", instance_id);

        Self {
            instance_id,
            max_request_time_ms,
            http_gateway: http_gateway_info,
            server_url,
            reqwest_client,
            owns_instance: true,
            state_dir,
            _log_guard: log_guard,
        }
    }

    pub async fn drop_and_take_state(mut self) -> Option<PocketIcState> {
        self.do_drop().await;
        self.state_dir.take()
    }

    pub(crate) fn take_state_internal(&mut self) -> Option<PocketIcState> {
        self.state_dir.take()
    }

    /// Returns the URL of the PocketIC server on which this PocketIC instance is running.
    pub fn get_server_url(&self) -> Url {
        self.server_url.clone()
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
        let (_, server_url) = start_server(StartServerParams {
            reuse: true,
            ..Default::default()
        })
        .await;
        let url = server_url.join("instances").unwrap();
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
        self.tick_with_configs(TickConfigs::default()).await;
    }

    /// Make the IC produce and progress by one block with custom
    /// configs for the round.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn tick_with_configs(&self, configs: TickConfigs) {
        let endpoint = "update/tick";
        self.post::<(), _>(endpoint, configs).await;
    }

    /// Configures the IC to make progress automatically,
    /// i.e., periodically update the time of the IC
    /// to the real time and execute rounds on the subnets.
    /// Returns the URL at which `/api` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn auto_progress(&self) -> Url {
        let endpoint = "auto_progress";
        let auto_progress_config = AutoProgressConfig {
            artificial_delay_ms: None,
        };
        self.post::<(), _>(endpoint, auto_progress_config).await;
        self.instance_url()
    }

    /// Returns whether automatic progress is enabled on the PocketIC instance.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn auto_progress_enabled(&self) -> bool {
        self.get("auto_progress").await
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

    /// Returns the URL at which `/api` requests
    /// for this instance can be made if the HTTP
    /// gateway has been started.
    pub fn url(&self) -> Option<Url> {
        self.http_gateway
            .as_ref()
            .map(|res| Url::parse(&format!("http://{}:{}/", LOCALHOST, res.port)).unwrap())
    }

    /// Creates an HTTP gateway for this PocketIC instance binding to `127.0.0.1`
    /// and an optionally specified port (defaults to choosing an arbitrary unassigned port);
    /// listening on `localhost`;
    /// and configures the PocketIC instance to make progress automatically, i.e.,
    /// periodically update the time of the PocketIC instance to the real time
    /// and process messages on the PocketIC instance.
    /// Returns the URL at which `/api` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn make_live(&mut self, listen_at: Option<u16>) -> Url {
        self.make_live_with_params(None, listen_at, None, None)
            .await
    }

    /// Creates an HTTP gateway for this PocketIC instance binding
    /// to an optionally specified IP address (defaults to `127.0.0.1`)
    /// and port (defaults to choosing an arbitrary unassigned port);
    /// listening on optionally specified domains (default to `localhost`);
    /// and using an optionally specified TLS certificate (if provided, an HTTPS gateway is created)
    /// and configures the PocketIC instance to make progress automatically, i.e.,
    /// periodically update the time of the PocketIC instance to the real time
    /// and process messages on the PocketIC instance.
    /// Returns the URL at which `/api` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.instance_id))]
    pub async fn make_live_with_params(
        &mut self,
        ip_addr: Option<IpAddr>,
        listen_at: Option<u16>,
        domains: Option<Vec<String>>,
        https_config: Option<HttpsConfig>,
    ) -> Url {
        if let Some(url) = self.url() {
            return url;
        }
        if !self.auto_progress_enabled().await {
            self.auto_progress().await;
        }
        self.start_http_gateway(
            ip_addr.map(|ip_addr| ip_addr.to_string()),
            listen_at,
            domains,
            https_config,
        )
        .await
    }

    async fn start_http_gateway(
        &mut self,
        ip_addr: Option<String>,
        port: Option<u16>,
        domains: Option<Vec<String>>,
        https_config: Option<HttpsConfig>,
    ) -> Url {
        let endpoint = self.server_url.join("http_gateway").unwrap();
        let http_gateway_config = HttpGatewayConfig {
            ip_addr,
            port,
            forward_to: HttpGatewayBackend::PocketIcInstance(self.instance_id),
            domains: domains.clone(),
            https_config: https_config.clone(),
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
                panic!("Failed to crate http gateway: {message}")
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
    pub async fn get_time(&self) -> Time {
        let endpoint = "read/get_time";
        let result: RawTime = self.get(endpoint).await;
        Time::from_nanos_since_unix_epoch(result.nanos_since_epoch)
    }

    /// Set the current time of the IC, on all subnets.
    #[instrument(skip(self), fields(instance_id=self.instance_id, time = ?time))]
    pub async fn set_time(&self, time: Time) {
        let endpoint = "update/set_time";
        self.post::<(), _>(
            endpoint,
            RawTime {
                nanos_since_epoch: time.as_nanos_since_unix_epoch(),
            },
        )
        .await;
    }

    /// Set the current certified time of the IC, on all subnets.
    #[instrument(skip(self), fields(instance_id=self.instance_id, time = ?time))]
    pub async fn set_certified_time(&self, time: Time) {
        let endpoint = "update/set_certified_time";
        self.post::<(), _>(
            endpoint,
            RawTime {
                nanos_since_epoch: time.as_nanos_since_unix_epoch(),
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

    /// Get the controllers of a canister.
    /// Panics if the canister does not exist.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string()))]
    pub async fn get_controllers(&self, canister_id: CanisterId) -> Vec<Principal> {
        let endpoint = "read/get_controllers";
        let result: Vec<RawPrincipalId> = self
            .post(
                endpoint,
                RawCanisterId {
                    canister_id: canister_id.as_slice().to_vec(),
                },
            )
            .await;
        result.into_iter().map(|p| p.into()).collect()
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
    ) -> Result<RawMessageId, RejectResponse> {
        self.submit_call_with_effective_principal(
            canister_id,
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
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
    ) -> Result<RawMessageId, RejectResponse> {
        let endpoint = "update/submit_ingress_message";
        let raw_canister_call = RawCanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            payload,
            effective_principal,
        };
        self.post(endpoint, raw_canister_call).await
    }

    /// Await an update call submitted previously by `submit_call` or `submit_call_with_effective_principal`.
    pub async fn await_call(&self, message_id: RawMessageId) -> Result<Vec<u8>, RejectResponse> {
        let endpoint = "update/await_ingress_message";
        let result: RawCanisterResult = self.post(endpoint, message_id).await;
        result.into()
    }

    /// Fetch the status of an update call submitted previously by `submit_call` or `submit_call_with_effective_principal`.
    /// Note that the status of the update call can only change if the PocketIC instance is in live mode
    /// or a round has been executed due to a separate PocketIC library call, e.g., `PocketIc::tick()`.
    pub async fn ingress_status(
        &self,
        raw_message_id: RawMessageId,
    ) -> Option<Result<Vec<u8>, RejectResponse>> {
        let status = self.ingress_status_as_caller(raw_message_id, None).await;
        match status {
            IngressStatusResult::NotAvailable => None,
            IngressStatusResult::Success(status) => Some(status),
            IngressStatusResult::Forbidden(err) => {
                panic!("Retrieving ingress status was forbidden: {err}. This is a bug!")
            }
        }
    }

    /// Fetch the status of an update call submitted previously by `submit_call` or `submit_call_with_effective_principal`.
    /// Note that the status of the update call can only change if the PocketIC instance is in live mode
    /// or a round has been executed due to a separate PocketIC library call, e.g., `PocketIc::tick()`.
    /// If the status of the update call is known, but the update call was submitted by a different caller, then an error is returned.
    pub async fn ingress_status_as(
        &self,
        raw_message_id: RawMessageId,
        caller: Principal,
    ) -> IngressStatusResult {
        self.ingress_status_as_caller(raw_message_id, Some(caller))
            .await
    }

    async fn ingress_status_as_caller(
        &self,
        raw_message_id: RawMessageId,
        caller: Option<Principal>,
    ) -> IngressStatusResult {
        let endpoint = "read/ingress_status";
        let raw_ingress_status_args = RawIngressStatusArgs {
            raw_message_id,
            raw_caller: caller.map(|caller| caller.into()),
        };
        let result: Result<Option<RawCanisterResult>, (StatusCode, String)> =
            self.try_post(endpoint, raw_ingress_status_args).await;
        match result {
            Ok(None) => IngressStatusResult::NotAvailable,
            Ok(Some(result)) => IngressStatusResult::Success(result.into()),
            Err((status, message)) => {
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "HTTP error code {status} for /read/ingress_status is not StatusCode::FORBIDDEN. This is a bug!"
                );
                IngressStatusResult::Forbidden(message)
            }
        }
    }

    /// Await an update call submitted previously by `submit_call` or `submit_call_with_effective_principal`.
    /// Note that the status of the update call can only change if the PocketIC instance is in live mode
    /// or a round has been executed due to a separate PocketIC library call.
    pub async fn await_call_no_ticks(
        &self,
        message_id: RawMessageId,
    ) -> Result<Vec<u8>, RejectResponse> {
        let mut retry_policy: ExponentialBackoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(10))
            .with_max_interval(Duration::from_secs(1))
            .with_multiplier(2.0)
            .build();
        loop {
            if let Some(ingress_status) = self.ingress_status(message_id.clone()).await {
                break ingress_status;
            }
            tokio::time::sleep(retry_policy.next_backoff().unwrap()).await;
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
    ) -> Result<Vec<u8>, RejectResponse> {
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
    ) -> Result<Vec<u8>, RejectResponse> {
        self.query_call_with_effective_principal(
            canister_id,
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender,
            method,
            payload,
        )
        .await
    }

    /// Execute a query call on a canister explicitly specifying an effective principal to route the request:
    /// this API is useful for making generic query calls (including management canister query calls) without using dedicated functions from this library
    /// (e.g., making generic query calls in dfx to a PocketIC instance).
    #[instrument(skip(self, payload), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), effective_principal = %effective_principal.to_string(), sender = %sender.to_string(), method = %method, payload_len = %payload.len()))]
    pub async fn query_call_with_effective_principal(
        &self,
        canister_id: CanisterId,
        effective_principal: RawEffectivePrincipal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RejectResponse> {
        let endpoint = "read/query";
        self.canister_call(
            endpoint,
            effective_principal,
            canister_id,
            sender,
            method,
            payload,
        )
        .await
    }

    /// Fetch canister logs via a query call to the management canister.
    pub async fn fetch_canister_logs(
        &self,
        canister_id: CanisterId,
        sender: Principal,
    ) -> Result<Vec<CanisterLogRecord>, RejectResponse> {
        with_candid::<_, (FetchCanisterLogsResult,), _>(
            (CanisterIdRecord { canister_id },),
            |payload| async {
                self.query_call_with_effective_principal(
                    Principal::management_canister(),
                    RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
                    sender,
                    "fetch_canister_logs",
                    payload,
                )
                .await
            },
        )
        .await
        .map(|responses| responses.0.canister_log_records)
    }

    /// Request a canister's status.
    #[instrument(skip(self), fields(instance_id=self.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn canister_status(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<CanisterStatusResult, RejectResponse> {
        call_candid_as::<(CanisterIdRecord,), (CanisterStatusResult,)>(
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
            (ProvisionalCreateCanisterWithCyclesArgs {
                settings: None,
                amount: Some(0_u64.into()),
                specified_id: None,
                sender_canister_version: None,
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
            (ProvisionalCreateCanisterWithCyclesArgs {
                settings,
                amount: Some(0_u64.into()),
                specified_id: None,
                sender_canister_version: None,
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
            (ProvisionalCreateCanisterWithCyclesArgs {
                settings,
                specified_id: Some(canister_id),
                amount: Some(0_u64.into()),
                sender_canister_version: None,
            },),
        )
        .await
        .map(|(x,)| x);
        match res {
            Ok(CanisterIdRecord {
                canister_id: actual_canister_id,
            }) => Ok(actual_canister_id),
            Err(e) => Err(format!("{e:?}")),
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
            (ProvisionalCreateCanisterWithCyclesArgs {
                settings,
                amount: Some(0_u64.into()),
                specified_id: None,
                sender_canister_version: None,
            },),
        )
        .await
        .map(|(x,)| x)
        .unwrap();
        canister_id
    }

    /// Upload a WASM chunk to the WASM chunk store of a canister.
    /// Returns the WASM chunk hash.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn upload_chunk(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        chunk: Vec<u8>,
    ) -> Result<Vec<u8>, RejectResponse> {
        call_candid_as::<_, (UploadChunkResult,)>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "upload_chunk",
            (UploadChunkArgs { canister_id, chunk },),
        )
        .await
        .map(|responses| responses.0.hash)
    }

    /// List WASM chunk hashes in the WASM chunk store of a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn stored_chunks(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<Vec<Vec<u8>>, RejectResponse> {
        call_candid_as::<_, (StoredChunksResult,)>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "stored_chunks",
            (CanisterIdRecord { canister_id },),
        )
        .await
        .map(|responses| responses.0.into_iter().map(|chunk| chunk.hash).collect())
    }

    /// Clear the WASM chunk store of a canister.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn clear_chunk_store(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "clear_chunk_store",
            (CanisterIdRecord { canister_id },),
        )
        .await
    }

    /// Install a WASM module assembled from chunks on an existing canister.
    #[instrument(skip(self, mode, chunk_hashes_list, wasm_module_hash, arg), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string(), store_canister_id = %store_canister_id.to_string(), arg_len = %arg.len()))]
    pub async fn install_chunked_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        mode: CanisterInstallMode,
        store_canister_id: CanisterId,
        chunk_hashes_list: Vec<Vec<u8>>,
        wasm_module_hash: Vec<u8>,
        arg: Vec<u8>,
    ) -> Result<(), RejectResponse> {
        call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "install_chunked_code",
            (InstallChunkedCodeArgs {
                mode,
                target_canister: canister_id,
                store_canister: Some(store_canister_id),
                chunk_hashes_list: chunk_hashes_list
                    .into_iter()
                    .map(|hash| ChunkHash { hash })
                    .collect(),
                wasm_module_hash,
                arg,
                sender_canister_version: None,
            },),
        )
        .await
    }

    async fn install_canister_helper(
        &self,
        mode: CanisterInstallMode,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        if wasm_module.len() + arg.len() < INSTALL_CHUNKED_CODE_THRESHOLD {
            call_candid_as::<(InstallCodeArgs,), ()>(
                self,
                Principal::management_canister(),
                RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
                sender.unwrap_or(Principal::anonymous()),
                "install_code",
                (InstallCodeArgs {
                    mode,
                    canister_id,
                    wasm_module,
                    arg,
                    sender_canister_version: None,
                },),
            )
            .await
        } else {
            self.clear_chunk_store(canister_id, sender).await.unwrap();
            let chunks: Vec<_> = wasm_module.chunks(INSTALL_CODE_CHUNK_SIZE).collect();
            let mut hashes = vec![];
            for chunk in chunks {
                let hash = self
                    .upload_chunk(canister_id, sender, chunk.to_vec())
                    .await
                    .unwrap();
                hashes.push(hash);
            }
            let mut hasher = Sha256::new();
            hasher.update(wasm_module);
            let wasm_module_hash = hasher.finalize().to_vec();
            self.install_chunked_canister(
                canister_id,
                sender,
                mode,
                canister_id,
                hashes,
                wasm_module_hash,
                arg,
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
    ) -> Result<(), RejectResponse> {
        self.install_canister_helper(
            CanisterInstallMode::Upgrade(None),
            canister_id,
            wasm_module,
            arg,
            sender,
        )
        .await
    }

    /// Upgrade a Motoko EOP canister with a new WASM module.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn upgrade_eop_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        self.install_canister_helper(
            CanisterInstallMode::Upgrade(Some(UpgradeFlags {
                wasm_memory_persistence: Some(WasmMemoryPersistence::Keep),
                skip_pre_upgrade: None,
            })),
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
    ) -> Result<(), RejectResponse> {
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
    ) -> Result<(), RejectResponse> {
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

    /// Take canister snapshot.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn take_canister_snapshot(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        replace_snapshot: Option<Vec<u8>>,
    ) -> Result<Snapshot, RejectResponse> {
        call_candid_as::<_, (Snapshot,)>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "take_canister_snapshot",
            (TakeCanisterSnapshotArgs {
                canister_id,
                replace_snapshot,
            },),
        )
        .await
        .map(|responses| responses.0)
    }

    /// Load canister snapshot.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn load_canister_snapshot(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        snapshot_id: Vec<u8>,
    ) -> Result<(), RejectResponse> {
        call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "load_canister_snapshot",
            (LoadCanisterSnapshotArgs {
                canister_id,
                snapshot_id,
                sender_canister_version: None,
            },),
        )
        .await
    }

    /// List canister snapshots.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn list_canister_snapshots(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<Vec<Snapshot>, RejectResponse> {
        call_candid_as::<_, (Vec<Snapshot>,)>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "list_canister_snapshots",
            (CanisterIdRecord { canister_id },),
        )
        .await
        .map(|responses| responses.0)
    }

    /// Delete canister snapshot.
    #[instrument(skip(self), fields(instance_id=self.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub async fn delete_canister_snapshot(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        snapshot_id: Vec<u8>,
    ) -> Result<(), RejectResponse> {
        call_candid_as(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "delete_canister_snapshot",
            (DeleteCanisterSnapshotArgs {
                canister_id,
                snapshot_id,
            },),
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
    ) -> Result<(), RejectResponse> {
        call_candid_as::<_, ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "update_settings",
            (UpdateSettingsArgs {
                canister_id,
                settings,
                sender_canister_version: None,
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
    ) -> Result<(), RejectResponse> {
        let settings = CanisterSettings {
            controllers: Some(new_controllers),
            ..CanisterSettings::default()
        };
        call_candid_as::<(UpdateSettingsArgs,), ()>(
            self,
            Principal::management_canister(),
            RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec()),
            sender.unwrap_or(Principal::anonymous()),
            "update_settings",
            (UpdateSettingsArgs {
                canister_id,
                settings,
                sender_canister_version: None,
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
    ) -> Result<(), RejectResponse> {
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
    ) -> Result<(), RejectResponse> {
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
    ) -> Result<(), RejectResponse> {
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

    /// Returns subnet metrics for a given subnet.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id, subnet_id = %subnet_id.to_string()))]
    pub async fn get_subnet_metrics(&self, subnet_id: Principal) -> Option<SubnetMetrics> {
        let path = vec![
            "subnet".into(),
            Label::from_bytes(subnet_id.as_slice()),
            "metrics".into(),
        ];
        let paths = vec![path.clone()];
        let content = ReadState {
            ingress_expiry: self.get_time().await.as_nanos_since_unix_epoch() + 240_000_000_000,
            sender: Principal::anonymous(),
            paths,
        };
        let envelope = Envelope {
            content: std::borrow::Cow::Borrowed(&content),
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };

        let mut serialized_bytes = Vec::new();
        let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
        serializer.self_describe().unwrap();
        envelope.serialize(&mut serializer).unwrap();

        let endpoint = format!("api/v2/subnet/{}/read_state", subnet_id.to_text());
        let resp = self
            .reqwest_client
            .post(self.instance_url().join(&endpoint).unwrap())
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .body(serialized_bytes)
            .send()
            .await
            .unwrap();
        let read_state_response: ReadStateResponse =
            serde_cbor::from_slice(&resp.bytes().await.unwrap()).ok()?;
        let cert: Certificate = serde_cbor::from_slice(&read_state_response.certificate).unwrap();

        let metrics = match cert.tree.lookup_path(path) {
            LookupResult::Found(value) => Some(value),
            _ => None,
        }?;
        serde_cbor::from_slice(metrics).unwrap()
    }

    /// This (asynchronous) drop function must be called to drop the PocketIc instance.
    /// It must be called manually as Rust doesn't support asynchronous drop.
    pub async fn drop(mut self) {
        self.do_drop().await;
    }

    pub(crate) async fn do_drop(&mut self) {
        if self.owns_instance {
            self.reqwest_client
                .delete(self.instance_url())
                .send()
                .await
                .expect("Failed to send delete request");
        } else {
            self.stop_http_gateway().await;
        }
    }

    async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> T {
        self.request(HttpMethod::Get, endpoint, ()).await
    }

    async fn post<T: DeserializeOwned, B: Serialize>(&self, endpoint: &str, body: B) -> T {
        self.request(HttpMethod::Post, endpoint, body).await
    }

    async fn try_post<T: DeserializeOwned, B: Serialize>(
        &self,
        endpoint: &str,
        body: B,
    ) -> Result<T, (StatusCode, String)> {
        self.try_request(HttpMethod::Post, endpoint, body).await
    }

    async fn request<T: DeserializeOwned, B: Serialize>(
        &self,
        http_method: HttpMethod,
        endpoint: &str,
        body: B,
    ) -> T {
        self.try_request(http_method, endpoint, body).await.unwrap()
    }

    async fn try_request<T: DeserializeOwned, B: Serialize>(
        &self,
        http_method: HttpMethod,
        endpoint: &str,
        body: B,
    ) -> Result<T, (StatusCode, String)> {
        // we may have to try several times if the instance is busy
        let start = std::time::SystemTime::now();
        loop {
            let reqwest_client = &self.reqwest_client;
            let url = self.instance_url().join(endpoint).unwrap();
            let builder = match http_method {
                HttpMethod::Get => reqwest_client.get(url),
                HttpMethod::Post => reqwest_client.post(url).json(&body),
            };
            let result = builder.send().await.expect("HTTP failure");
            let status = result.status();
            match ApiResponse::<_>::from_response(result).await {
                ApiResponse::Success(t) => break Ok(t),
                ApiResponse::Error { message } => break Err((status, message)),
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
                    let cleanup = || {
                        tokio::spawn(
                            reqwest_client
                                .delete(
                                    self.server_url
                                        .join(&format!("/prune_graph/{state_label}/{op_id}"))
                                        .unwrap(),
                                )
                                .send(),
                        );
                    };
                    loop {
                        std::thread::sleep(Duration::from_millis(POLLING_PERIOD_MS));
                        let result = reqwest_client
                            .get(
                                self.server_url
                                    .join(&format!("/read_graph/{state_label}/{op_id}"))
                                    .unwrap(),
                            )
                            .send()
                            .await
                            .expect("HTTP failure");
                        if result.status() == reqwest::StatusCode::NOT_FOUND {
                            let message =
                                String::from_utf8(result.bytes().await.unwrap().to_vec()).unwrap();
                            debug!("Polling has not succeeded yet: {}", message);
                        } else {
                            let status = result.status();
                            match ApiResponse::<_>::from_response(result).await {
                                ApiResponse::Error { message } => {
                                    cleanup();
                                    return Err((status, message));
                                }
                                ApiResponse::Success(t) => {
                                    cleanup();
                                    return Ok(t);
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
                        }
                        if let Some(max_request_time_ms) = self.max_request_time_ms
                            && start.elapsed().unwrap_or_default()
                                > Duration::from_millis(max_request_time_ms)
                        {
                            panic!("request to PocketIC server timed out.");
                        }
                    }
                }
            }
            if let Some(max_request_time_ms) = self.max_request_time_ms
                && start.elapsed().unwrap_or_default() > Duration::from_millis(max_request_time_ms)
            {
                panic!("request to PocketIC server timed out.");
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
    ) -> Result<Vec<u8>, RejectResponse> {
        let raw_canister_call = RawCanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            payload,
            effective_principal,
        };

        let result: RawCanisterResult = self.post(endpoint, raw_canister_call).await;
        result.into()
    }

    pub async fn update_call_with_effective_principal(
        &self,
        canister_id: CanisterId,
        effective_principal: RawEffectivePrincipal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RejectResponse> {
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

    /// Download a canister snapshot to a given snapshot directory.
    /// The sender must be a controller of the canister.
    /// The snapshot directory must be empty if it exists.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id))]
    pub async fn canister_snapshot_download(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        snapshot_id: Vec<u8>,
        snapshot_dir: PathBuf,
    ) {
        let endpoint = "update/canister_snapshot_download";
        #[cfg(not(windows))]
        let snapshot_dir = snapshot_dir;
        #[cfg(windows)]
        let snapshot_dir = wsl_path(&snapshot_dir, "snapshot directory").into();
        let raw_canister_snapshot_download = RawCanisterSnapshotDownload {
            sender: sender.into(),
            canister_id: canister_id.into(),
            snapshot_id,
            snapshot_dir,
        };
        self.post(endpoint, raw_canister_snapshot_download).await
    }

    /// Upload a canister snapshot from a given snapshot directory.
    /// The sender must be a controller of the canister.
    /// Returns the snapshot ID of the uploaded snapshot.
    #[instrument(ret, skip(self), fields(instance_id=self.instance_id))]
    pub async fn canister_snapshot_upload(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        replace_snapshot: Option<Vec<u8>>,
        snapshot_dir: PathBuf,
    ) -> Vec<u8> {
        let endpoint = "update/canister_snapshot_upload";
        let replace_snapshot =
            replace_snapshot.map(|snapshot_id| RawCanisterSnapshotId { snapshot_id });
        #[cfg(not(windows))]
        let snapshot_dir = snapshot_dir;
        #[cfg(windows)]
        let snapshot_dir = wsl_path(&snapshot_dir, "snapshot directory").into();
        let raw_canister_snapshot_upload = RawCanisterSnapshotUpload {
            sender: sender.into(),
            canister_id: canister_id.into(),
            replace_snapshot,
            snapshot_dir,
        };
        self.post::<RawCanisterSnapshotId, _>(endpoint, raw_canister_snapshot_upload)
            .await
            .snapshot_id
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
) -> Result<Output, RejectResponse>
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
) -> Result<Output, RejectResponse>
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
) -> Result<Output, RejectResponse>
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
) -> Result<Output, RejectResponse>
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
) -> Result<Output, RejectResponse>
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
) -> Result<Output, RejectResponse>
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
) -> Result<Output, RejectResponse>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
    Fut: Future<Output = Result<Vec<u8>, RejectResponse>>,
{
    let in_bytes = encode_args(input).expect("failed to encode args");
    f(in_bytes).await.map(|out_bytes| {
        decode_args(&out_bytes).unwrap_or_else(|e| {
            panic!(
                "Failed to decode response as candid type {}:\nerror: {}\nbytes: {:?}\nutf8: {}",
                std::any::type_name::<Output>(),
                e,
                out_bytes,
                String::from_utf8_lossy(&out_bytes),
            )
        })
    })
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

            let layers = vec![
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking_appender)
                    // disable color escape codes in files
                    .with_ansi(false)
                    .with_filter(log_dir_filter)
                    .boxed(),
            ];
            let _ = tracing_subscriber::registry().with(layers).try_init();
            Some(guard)
        }
        _ => None,
    }
}

/// Retrieves a default effective canister id for canister creation on a PocketIC instance
/// characterized by:
///  - a PocketIC instance URL of the form http://<ip>:<port>/instances/<instance_id>;
///  - a PocketIC HTTP gateway URL of the form http://<ip>:port for a PocketIC instance.
///
/// Returns an error if the PocketIC instance topology could not be fetched or parsed, e.g.,
/// because the given URL points to a replica (i.e., does not meet any of the above two properties).
pub async fn get_default_effective_canister_id(
    pocket_ic_url: String,
) -> Result<Principal, DefaultEffectiveCanisterIdError> {
    let client = reqwest::Client::new();
    let res = loop {
        let res = client
            .get(format!(
                "{}{}",
                pocket_ic_url.trim_end_matches('/'),
                "/_/topology"
            ))
            .send()
            .await?;
        if res.status() == StatusCode::CONFLICT {
            std::thread::sleep(Duration::from_millis(POLLING_PERIOD_MS));
        } else {
            break res.error_for_status()?;
        }
    };
    let topology_bytes = res.bytes().await?;
    let topology_str = String::from_utf8(topology_bytes.to_vec())?;
    let topology: Topology = serde_json::from_str(&topology_str)?;
    let default_effective_canister_id =
        Principal::from_slice(&topology.default_effective_canister_id.canister_id);
    Ok(default_effective_canister_id)
}
