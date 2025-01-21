#![allow(clippy::test_attr_in_doctest)]
/// # PocketIC: A Canister Testing Platform
///
/// PocketIC is the local canister smart contract testing platform for the [Internet Computer](https://internetcomputer.org/).
///
/// It consists of the PocketIC server, which can run many independent IC instances, and a client library (this crate), which provides an interface to your IC instances.
///
/// With PocketIC, testing canisters is as simple as calling rust functions. Here is a minimal example:
///
/// ```rust
/// use candid::{Principal, encode_one};
/// use pocket_ic::PocketIc;
///
/// // 2T cycles
/// const INIT_CYCLES: u128 = 2_000_000_000_000;
///
/// // Create a counter canister and charge it with 2T cycles.
/// fn deploy_counter_canister(pic: &PocketIc) -> Principal {
///     let canister_id = pic.create_canister();
///     pic.add_cycles(canister_id, INIT_CYCLES);
///     let counter_wasm = todo!();
///     pic.install_canister(canister_id, counter_wasm, vec![], None);
///     canister_id
/// }
///
/// // Call a method on the counter canister as the anonymous principal.
/// fn call_counter_canister(pic: &PocketIc, canister_id: Principal, method: &str) -> Vec<u8> {
///     pic.update_call(
///         canister_id,
///         Principal::anonymous(),
///         method,
///         encode_one(()).unwrap(),
///     )
///     .expect("Failed to call counter canister")
/// }
///
/// #[test]
/// fn test_counter_canister() {
///     let pic = PocketIc::new();
///     let canister_id = deploy_counter_canister(&pic);
///
///     // Make some calls to the counter canister.
///     let reply = call_counter_canister(&pic, canister_id, "read");
///     assert_eq!(reply, vec![0, 0, 0, 0]);
///     let reply = call_counter_canister(&pic, canister_id, "write");
///     assert_eq!(reply, vec![1, 0, 0, 0]);
///     let reply = call_counter_canister(&pic, canister_id, "write");
///     assert_eq!(reply, vec![2, 0, 0, 0]);
///     let reply = call_counter_canister(&pic, canister_id, "read");
///     assert_eq!(reply, vec![2, 0, 0, 0]);
/// }
/// ```
/// For more information, see the [README](https://crates.io/crates/pocket-ic).
///
use crate::{
    common::rest::{
        BlobCompression, BlobId, CanisterHttpRequest, ExtendedSubnetConfigSet, HttpsConfig,
        InstanceId, MockCanisterHttpResponse, RawEffectivePrincipal, RawMessageId, SubnetId,
        SubnetKind, SubnetSpec, Topology,
    },
    management_canister::{
        CanisterId, CanisterInstallMode, CanisterLogRecord, CanisterSettings, CanisterStatusResult,
        Snapshot,
    },
    nonblocking::PocketIc as PocketIcAsync,
};
use candid::{
    decode_args, encode_args,
    utils::{ArgumentDecoder, ArgumentEncoder},
    Principal,
};
use ic_transport_types::SubnetMetrics;
use reqwest::Url;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Level;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{mpsc::channel, Arc},
    thread,
    thread::JoinHandle,
    time::{Duration, SystemTime},
};
use strum_macros::EnumIter;
use thiserror::Error;
use tokio::runtime::Runtime;
use tracing::{instrument, warn};
#[cfg(windows)]
use wslpath::windows_to_wsl;

pub mod common;
pub mod management_canister;
pub mod nonblocking;

const EXPECTED_SERVER_VERSION: &str = "pocket-ic-server 7.0.0";

// the default timeout of a PocketIC operation
const DEFAULT_MAX_REQUEST_TIME_MS: u64 = 300_000;

const LOCALHOST: &str = "127.0.0.1";

pub struct PocketIcBuilder {
    config: Option<ExtendedSubnetConfigSet>,
    server_url: Option<Url>,
    max_request_time_ms: Option<u64>,
    state_dir: Option<PathBuf>,
    nonmainnet_features: bool,
    log_level: Option<Level>,
    bitcoind_addr: Option<Vec<SocketAddr>>,
}

#[allow(clippy::new_without_default)]
impl PocketIcBuilder {
    pub fn new() -> Self {
        Self {
            config: None,
            server_url: None,
            max_request_time_ms: Some(DEFAULT_MAX_REQUEST_TIME_MS),
            state_dir: None,
            nonmainnet_features: false,
            log_level: None,
            bitcoind_addr: None,
        }
    }

    pub fn new_with_config(config: impl Into<ExtendedSubnetConfigSet>) -> Self {
        let mut builder = Self::new();
        builder.config = Some(config.into());
        builder
    }

    pub fn build(self) -> PocketIc {
        let server_url = self.server_url.unwrap_or_else(crate::start_or_reuse_server);
        PocketIc::from_components(
            self.config.unwrap_or_default(),
            server_url,
            self.max_request_time_ms,
            self.state_dir,
            self.nonmainnet_features,
            self.log_level,
            self.bitcoind_addr,
        )
    }

    pub async fn build_async(self) -> PocketIcAsync {
        let server_url = self.server_url.unwrap_or_else(crate::start_or_reuse_server);
        PocketIcAsync::from_components(
            self.config.unwrap_or_default(),
            server_url,
            self.max_request_time_ms,
            self.state_dir,
            self.nonmainnet_features,
            self.log_level,
            self.bitcoind_addr,
        )
        .await
    }

    /// Use an already running PocketIC server.
    pub fn with_server_url(mut self, server_url: Url) -> Self {
        self.server_url = Some(server_url);
        self
    }

    pub fn with_max_request_time_ms(mut self, max_request_time_ms: Option<u64>) -> Self {
        self.max_request_time_ms = max_request_time_ms;
        self
    }

    pub fn with_state_dir(mut self, state_dir: PathBuf) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    pub fn with_nonmainnet_features(mut self, nonmainnet_features: bool) -> Self {
        self.nonmainnet_features = nonmainnet_features;
        self
    }

    pub fn with_log_level(mut self, log_level: Level) -> Self {
        self.log_level = Some(log_level);
        self
    }

    pub fn with_bitcoind_addr(self, bitcoind_addr: SocketAddr) -> Self {
        self.with_bitcoind_addrs(vec![bitcoind_addr])
    }

    pub fn with_bitcoind_addrs(self, bitcoind_addrs: Vec<SocketAddr>) -> Self {
        Self {
            bitcoind_addr: Some(bitcoind_addrs),
            ..self
        }
    }

    /// Add an empty NNS subnet
    pub fn with_nns_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.nns = Some(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an NNS subnet loaded form the given state directory. Note that the provided path must
    /// be accessible for the PocketIC server process.
    ///
    /// `path_to_nns_state` should lead to the `ic_state` directory which is expected to have
    /// the following structure:
    ///
    /// ic_state/
    ///  |-- backups
    ///  |-- checkpoints
    ///  |-- diverged_checkpoints
    ///  |-- diverged_state_markers
    ///  |-- fs_tmp
    ///  |-- page_deltas
    ///  |-- states_metadata.pbuf
    ///  |-- tip
    ///  `-- tmp
    ///
    /// `nns_subnet_id` should be the subnet ID of the NNS subnet in the state under
    /// `path_to_state`, e.g.:
    /// ```rust
    /// use pocket_ic::common::rest::SubnetId;
    ///
    /// let nns_subnet_id: SubnetId = candid::Principal::from_text(
    ///     "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe",
    /// ).unwrap().into();
    /// ```
    ///
    /// The value can be obtained, e.g., via the following command:
    /// ```sh
    /// ic-regedit snapshot <path-to-ic_registry_local_store> | jq -r ".nns_subnet_id"
    /// ```
    pub fn with_nns_state(self, nns_subnet_id: SubnetId, path_to_state: PathBuf) -> Self {
        self.with_subnet_state(SubnetKind::NNS, nns_subnet_id, path_to_state)
    }

    /// Add a subnet with state loaded form the given state directory.
    /// Note that the provided path must be accessible for the PocketIC server process.
    ///
    /// `state_dir` should point to a directory which is expected to have
    /// the following structure:
    ///
    /// state_dir/
    ///  |-- backups
    ///  |-- checkpoints
    ///  |-- diverged_checkpoints
    ///  |-- diverged_state_markers
    ///  |-- fs_tmp
    ///  |-- page_deltas
    ///  |-- states_metadata.pbuf
    ///  |-- tip
    ///  `-- tmp
    ///
    /// `subnet_id` should be the subnet ID of the subnet in the state to be loaded
    pub fn with_subnet_state(
        mut self,
        subnet_kind: SubnetKind,
        subnet_id: Principal,
        state_dir: PathBuf,
    ) -> Self {
        let mut config = self.config.unwrap_or_default();
        let subnet_spec = SubnetSpec::default().with_state_dir(state_dir, subnet_id);
        match subnet_kind {
            SubnetKind::NNS => config.nns = Some(subnet_spec),
            SubnetKind::SNS => config.sns = Some(subnet_spec),
            SubnetKind::II => config.ii = Some(subnet_spec),
            SubnetKind::Fiduciary => config.fiduciary = Some(subnet_spec),
            SubnetKind::Bitcoin => config.bitcoin = Some(subnet_spec),
            SubnetKind::Application => config.application.push(subnet_spec),
            SubnetKind::System => config.system.push(subnet_spec),
            SubnetKind::VerifiedApplication => config.verified_application.push(subnet_spec),
        };
        self.config = Some(config);
        self
    }

    /// Add an empty sns subnet
    pub fn with_sns_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.sns = Some(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty internet identity subnet
    pub fn with_ii_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.ii = Some(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty fiduciary subnet
    pub fn with_fiduciary_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.fiduciary = Some(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty bitcoin subnet
    pub fn with_bitcoin_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.bitcoin = Some(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty generic system subnet
    pub fn with_system_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.system.push(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty generic application subnet
    pub fn with_application_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.application.push(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty verified application subnet
    pub fn with_verified_application_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.verified_application.push(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    pub fn with_benchmarking_application_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config
            .application
            .push(SubnetSpec::default().with_benchmarking_instruction_config());
        self.config = Some(config);
        self
    }

    pub fn with_benchmarking_system_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config
            .system
            .push(SubnetSpec::default().with_benchmarking_instruction_config());
        self.config = Some(config);
        self
    }
}

/// Main entry point for interacting with PocketIC.
pub struct PocketIc {
    pocket_ic: PocketIcAsync,
    runtime: Arc<tokio::runtime::Runtime>,
    thread: Option<JoinHandle<()>>,
}

impl PocketIc {
    /// Creates a new PocketIC instance with a single application subnet on the server.
    /// The server is started if it's not already running.
    pub fn new() -> Self {
        PocketIcBuilder::new().with_application_subnet().build()
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
        let (tx, rx) = channel();
        let thread = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            tx.send(rt).unwrap();
        });
        let runtime = rx.recv().unwrap();

        let pocket_ic =
            PocketIcAsync::new_from_existing_instance(server_url, instance_id, max_request_time_ms);

        Self {
            pocket_ic,
            runtime: Arc::new(runtime),
            thread: Some(thread),
        }
    }

    pub(crate) fn from_components(
        subnet_config_set: impl Into<ExtendedSubnetConfigSet>,
        server_url: Url,
        max_request_time_ms: Option<u64>,
        state_dir: Option<PathBuf>,
        nonmainnet_features: bool,
        log_level: Option<Level>,
        bitcoind_addr: Option<Vec<SocketAddr>>,
    ) -> Self {
        let (tx, rx) = channel();
        let thread = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            tx.send(rt).unwrap();
        });
        let runtime = rx.recv().unwrap();

        let pocket_ic = runtime.block_on(async {
            PocketIcAsync::from_components(
                subnet_config_set,
                server_url,
                max_request_time_ms,
                state_dir,
                nonmainnet_features,
                log_level,
                bitcoind_addr,
            )
            .await
        });

        Self {
            pocket_ic,
            runtime: Arc::new(runtime),
            thread: Some(thread),
        }
    }

    /// Returns the URL of the PocketIC server on which this PocketIC instance is running.
    pub fn get_server_url(&self) -> Url {
        self.pocket_ic.get_server_url()
    }

    /// Returns the instance ID.
    pub fn instance_id(&self) -> InstanceId {
        self.pocket_ic.instance_id
    }

    /// Returns the topology of the different subnets of this PocketIC instance.
    pub fn topology(&self) -> Topology {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.topology().await })
    }

    /// Upload and store a binary blob to the PocketIC server.
    #[instrument(ret(Display), skip(self, blob), fields(instance_id=self.pocket_ic.instance_id, blob_len = %blob.len(), compression = ?compression))]
    pub fn upload_blob(&self, blob: Vec<u8>, compression: BlobCompression) -> BlobId {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.upload_blob(blob, compression).await })
    }

    /// Set stable memory of a canister. Optional GZIP compression can be used for reduced
    /// data traffic.
    #[instrument(skip(self, data), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), data_len = %data.len(), compression = ?compression))]
    pub fn set_stable_memory(
        &self,
        canister_id: CanisterId,
        data: Vec<u8>,
        compression: BlobCompression,
    ) {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .set_stable_memory(canister_id, data, compression)
                .await
        })
    }

    /// Get stable memory of a canister.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string()))]
    pub fn get_stable_memory(&self, canister_id: CanisterId) -> Vec<u8> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.get_stable_memory(canister_id).await })
    }

    /// List all instances and their status.
    #[instrument(ret)]
    pub fn list_instances() -> Vec<String> {
        let url = crate::start_or_reuse_server().join("instances").unwrap();
        let instances: Vec<String> = reqwest::blocking::Client::new()
            .get(url)
            .send()
            .expect("Failed to get result")
            .json()
            .expect("Failed to get json");
        instances
    }

    /// Verify a canister signature.
    #[instrument(skip_all, fields(instance_id=self.pocket_ic.instance_id))]
    pub fn verify_canister_signature(
        &self,
        msg: Vec<u8>,
        sig: Vec<u8>,
        pubkey: Vec<u8>,
        root_pubkey: Vec<u8>,
    ) -> Result<(), String> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .verify_canister_signature(msg, sig, pubkey, root_pubkey)
                .await
        })
    }

    /// Make the IC produce and progress by one block.
    /// Note that multiple ticks might be necessary to observe
    /// an expected effect, e.g., if the effect depends on
    /// inter-canister calls or heartbeats.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn tick(&self) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.tick().await })
    }

    /// Configures the IC to make progress automatically,
    /// i.e., periodically update the time of the IC
    /// to the real time and execute rounds on the subnets.
    /// Returns the URL at which `/api/v2` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn auto_progress(&self) -> Url {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.auto_progress().await })
    }

    /// Stops automatic progress (see `auto_progress`) on the IC.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn stop_progress(&self) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.stop_progress().await })
    }

    /// Returns the URL at which `/api/v2` requests
    /// for this instance can be made if the HTTP
    /// gateway has been started.
    pub fn url(&self) -> Option<Url> {
        self.pocket_ic.url()
    }

    /// Creates an HTTP gateway for this IC instance
    /// listening on an optionally specified port
    /// and configures the IC instance to make progress
    /// automatically, i.e., periodically update the time
    /// of the IC to the real time and execute rounds on the subnets.
    /// Returns the URL at which `/api/v2` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn make_live(&mut self, listen_at: Option<u16>) -> Url {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.make_live(listen_at).await })
    }

    /// Creates an HTTP gateway for this PocketIC instance listening
    /// on an optionally specified port (defaults to choosing an arbitrary unassigned port)
    /// and optionally specified domains (default to `localhost`)
    /// and using an optionally specified TLS certificate (if provided, an HTTPS gateway is created)
    /// and configures the PocketIC instance to make progress automatically, i.e.,
    /// periodically update the time of the PocketIC instance to the real time and execute rounds on the subnets.
    /// Returns the URL at which `/api/v2` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub async fn make_live_with_params(
        &mut self,
        listen_at: Option<u16>,
        domains: Option<Vec<String>>,
        https_config: Option<HttpsConfig>,
    ) -> Url {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .make_live_with_params(listen_at, domains, https_config)
                .await
        })
    }

    /// Stops auto progress (automatic time updates and round executions)
    /// and the HTTP gateway for this IC instance.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn stop_live(&mut self) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.stop_live().await })
    }

    #[deprecated(note = "Use `stop_live` instead.")]
    /// Use `stop_live` instead.
    pub fn make_deterministic(&mut self) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.stop_live().await })
    }

    /// Get the root key of this IC instance. Returns `None` if the IC has no NNS subnet.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn root_key(&self) -> Option<Vec<u8>> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.root_key().await })
    }

    /// Get the current time of the IC.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn get_time(&self) -> SystemTime {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.get_time().await })
    }

    /// Set the current time of the IC, on all subnets.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, time = ?time))]
    pub fn set_time(&self, time: SystemTime) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.set_time(time).await })
    }

    /// Advance the time on the IC on all subnets by some nanoseconds.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, duration = ?duration))]
    pub fn advance_time(&self, duration: Duration) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.advance_time(duration).await })
    }

    /// Get the controllers of a canister.
    /// Panics if the canister does not exist.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string()))]
    pub fn get_controllers(&self, canister_id: CanisterId) -> Vec<Principal> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.get_controllers(canister_id).await })
    }

    /// Get the current cycles balance of a canister.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string()))]
    pub fn cycle_balance(&self, canister_id: CanisterId) -> u128 {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.cycle_balance(canister_id).await })
    }

    /// Add cycles to a canister. Returns the new balance.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), amount = %amount))]
    pub fn add_cycles(&self, canister_id: CanisterId, amount: u128) -> u128 {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.add_cycles(canister_id, amount).await })
    }

    /// Submit an update call (without executing it immediately).
    pub fn submit_call(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<RawMessageId, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .submit_call(canister_id, sender, method, payload)
                .await
        })
    }

    /// Submit an update call with a provided effective principal (without executing it immediately).
    pub fn submit_call_with_effective_principal(
        &self,
        canister_id: CanisterId,
        effective_principal: RawEffectivePrincipal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<RawMessageId, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .submit_call_with_effective_principal(
                    canister_id,
                    effective_principal,
                    sender,
                    method,
                    payload,
                )
                .await
        })
    }

    /// Await an update call submitted previously by `submit_call` or `submit_call_with_effective_principal`.
    pub fn await_call(&self, message_id: RawMessageId) -> Result<Vec<u8>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.await_call(message_id).await })
    }

    /// Fetch the status of an update call submitted previously by `submit_call` or `submit_call_with_effective_principal`.
    /// Note that the status of the update call can only change if the PocketIC instance is in live mode
    /// or a round has been executed due to a separate PocketIC library call, e.g., `PocketIc::tick()`.
    pub fn ingress_status(
        &self,
        message_id: RawMessageId,
    ) -> Option<Result<Vec<u8>, RejectResponse>> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.ingress_status(message_id).await })
    }

    /// Fetch the status of an update call submitted previously by `submit_call` or `submit_call_with_effective_principal`.
    /// Note that the status of the update call can only change if the PocketIC instance is in live mode
    /// or a round has been executed due to a separate PocketIC library call, e.g., `PocketIc::tick()`.
    /// If the status of the update call is known, but the update call was submitted by a different caller, then an error is returned.
    pub fn ingress_status_as(
        &self,
        message_id: RawMessageId,
        caller: Principal,
    ) -> IngressStatusResult {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.ingress_status_as(message_id, caller).await })
    }

    /// Await an update call submitted previously by `submit_call` or `submit_call_with_effective_principal`.
    /// Note that the status of the update call can only change if the PocketIC instance is in live mode
    /// or a round has been executed due to a separate PocketIC library call, e.g., `PocketIc::tick()`.
    pub fn await_call_no_ticks(&self, message_id: RawMessageId) -> Result<Vec<u8>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.await_call_no_ticks(message_id).await })
    }

    /// Execute an update call on a canister.
    #[instrument(skip(self, payload), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.to_string(), method = %method, payload_len = %payload.len()))]
    pub fn update_call(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .update_call(canister_id, sender, method, payload)
                .await
        })
    }

    /// Execute a query call on a canister.
    #[instrument(skip(self, payload), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.to_string(), method = %method, payload_len = %payload.len()))]
    pub fn query_call(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .query_call(canister_id, sender, method, payload)
                .await
        })
    }

    /// Fetch canister logs via a query call to the management canister.
    pub fn fetch_canister_logs(
        &self,
        canister_id: CanisterId,
        sender: Principal,
    ) -> Result<Vec<CanisterLogRecord>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .fetch_canister_logs(canister_id, sender)
                .await
        })
    }

    /// Request a canister's status.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn canister_status(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<CanisterStatusResult, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.canister_status(canister_id, sender).await })
    }

    /// Create a canister with default settings as the anonymous principal.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn create_canister(&self) -> CanisterId {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.create_canister().await })
    }

    /// Create a canister with optional custom settings and a sender.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.pocket_ic.instance_id, settings = ?settings, sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn create_canister_with_settings(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
    ) -> CanisterId {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .create_canister_with_settings(sender, settings)
                .await
        })
    }

    /// Creates a canister with a specific canister ID and optional custom settings.
    /// Returns an error if the canister ID is already in use.
    /// Creates a new subnet if the canister ID is not contained in any of the subnets.
    ///
    /// The canister ID must be an IC mainnet canister ID that does not belong to the NNS or II subnet,
    /// otherwise the function might panic (for NNS and II canister IDs,
    /// the PocketIC instance should already be created with those subnets).
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string(), settings = ?settings, canister_id = %canister_id.to_string()))]
    pub fn create_canister_with_id(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
        canister_id: CanisterId,
    ) -> Result<CanisterId, String> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .create_canister_with_id(sender, settings, canister_id)
                .await
        })
    }

    /// Create a canister on a specific subnet with optional custom settings.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.pocket_ic.instance_id, sender = %sender.unwrap_or(Principal::anonymous()).to_string(), settings = ?settings, subnet_id = %subnet_id.to_string()))]
    pub fn create_canister_on_subnet(
        &self,
        sender: Option<Principal>,
        settings: Option<CanisterSettings>,
        subnet_id: SubnetId,
    ) -> CanisterId {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .create_canister_on_subnet(sender, settings, subnet_id)
                .await
        })
    }

    /// Upload a WASM chunk to the WASM chunk store of a canister.
    /// Returns the WASM chunk hash.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn upload_chunk(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        chunk: Vec<u8>,
    ) -> Result<Vec<u8>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .upload_chunk(canister_id, sender, chunk)
                .await
        })
    }

    /// List WASM chunk hashes in the WASM chunk store of a canister.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn stored_chunks(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<Vec<Vec<u8>>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.stored_chunks(canister_id, sender).await })
    }

    /// Clear the WASM chunk store of a canister.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn clear_chunk_store(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.clear_chunk_store(canister_id, sender).await })
    }

    /// Install a WASM module assembled from chunks on an existing canister.
    #[instrument(skip(self, mode, chunk_hashes_list, wasm_module_hash, arg), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string(), store_canister_id = %store_canister_id.to_string(), arg_len = %arg.len()))]
    pub fn install_chunked_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        mode: CanisterInstallMode,
        store_canister_id: CanisterId,
        chunk_hashes_list: Vec<Vec<u8>>,
        wasm_module_hash: Vec<u8>,
        arg: Vec<u8>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .install_chunked_canister(
                    canister_id,
                    sender,
                    mode,
                    store_canister_id,
                    chunk_hashes_list,
                    wasm_module_hash,
                    arg,
                )
                .await
        })
    }

    /// Install a WASM module on an existing canister.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn install_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .install_canister(canister_id, wasm_module, arg, sender)
                .await
        })
    }

    /// Upgrade a canister with a new WASM module.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn upgrade_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .upgrade_canister(canister_id, wasm_module, arg, sender)
                .await
        })
    }

    /// Reinstall a canister WASM module.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn reinstall_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .reinstall_canister(canister_id, wasm_module, arg, sender)
                .await
        })
    }

    /// Uninstall a canister.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn uninstall_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.uninstall_canister(canister_id, sender).await })
    }

    /// Take canister snapshot.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn take_canister_snapshot(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        replace_snapshot: Option<Vec<u8>>,
    ) -> Result<Snapshot, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .take_canister_snapshot(canister_id, sender, replace_snapshot)
                .await
        })
    }

    /// Load canister snapshot.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn load_canister_snapshot(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        snapshot_id: Vec<u8>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .load_canister_snapshot(canister_id, sender, snapshot_id)
                .await
        })
    }

    /// List canister snapshots.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn list_canister_snapshots(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<Vec<Snapshot>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .list_canister_snapshots(canister_id, sender)
                .await
        })
    }

    /// Delete canister snapshot.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn delete_canister_snapshot(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        snapshot_id: Vec<u8>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .delete_canister_snapshot(canister_id, sender, snapshot_id)
                .await
        })
    }

    /// Update canister settings.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn update_canister_settings(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        settings: CanisterSettings,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .update_canister_settings(canister_id, sender, settings)
                .await
        })
    }

    /// Set canister's controllers.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn set_controllers(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
        new_controllers: Vec<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .set_controllers(canister_id, sender, new_controllers)
                .await
        })
    }

    /// Start a canister.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn start_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.start_canister(canister_id, sender).await })
    }

    /// Stop a canister.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn stop_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.stop_canister(canister_id, sender).await })
    }

    /// Delete a canister.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn delete_canister(
        &self,
        canister_id: CanisterId,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.delete_canister(canister_id, sender).await })
    }

    /// Checks whether the provided canister exists.
    #[instrument(ret(Display), skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string()))]
    pub fn canister_exists(&self, canister_id: CanisterId) -> bool {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.canister_exists(canister_id).await })
    }

    /// Returns the subnet ID of the canister if the canister exists.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string()))]
    pub fn get_subnet(&self, canister_id: CanisterId) -> Option<SubnetId> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.get_subnet(canister_id).await })
    }

    /// Returns subnet metrics for a given subnet.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id, subnet_id = %subnet_id.to_string()))]
    pub fn get_subnet_metrics(&self, subnet_id: Principal) -> Option<SubnetMetrics> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.get_subnet_metrics(subnet_id).await })
    }

    fn update_call_with_effective_principal(
        &self,
        canister_id: CanisterId,
        effective_principal: RawEffectivePrincipal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .update_call_with_effective_principal(
                    canister_id,
                    effective_principal,
                    sender,
                    method,
                    payload,
                )
                .await
        })
    }

    /// Execute a query call on a canister explicitly specifying an effective principal to route the request:
    /// this API is useful for making generic query calls (including management canister query calls) without using dedicated functions from this library
    /// (e.g., making generic query calls in dfx to a PocketIC instance).
    #[instrument(skip(self, payload), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), effective_principal = %effective_principal.to_string(), sender = %sender.to_string(), method = %method, payload_len = %payload.len()))]
    pub fn query_call_with_effective_principal(
        &self,
        canister_id: CanisterId,
        effective_principal: RawEffectivePrincipal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .query_call_with_effective_principal(
                    canister_id,
                    effective_principal,
                    sender,
                    method,
                    payload,
                )
                .await
        })
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
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn get_canister_http(&self) -> Vec<CanisterHttpRequest> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.get_canister_http().await })
    }

    /// Mock a response to a pending canister HTTP outcall.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn mock_canister_http_response(
        &self,
        mock_canister_http_response: MockCanisterHttpResponse,
    ) {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .mock_canister_http_response(mock_canister_http_response)
                .await
        })
    }
}

impl Default for PocketIc {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PocketIc {
    fn drop(&mut self) {
        self.runtime.block_on(async {
            self.pocket_ic.do_drop().await;
        });
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

/// Call a canister candid method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
/// PocketIC executes update calls synchronously, so there is no need to poll for the result.
pub fn call_candid_as<Input, Output>(
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
    with_candid(input, |payload| {
        env.update_call_with_effective_principal(
            canister_id,
            effective_principal,
            sender,
            method,
            payload,
        )
    })
}

/// Call a canister candid method, anonymous.
/// PocketIC executes update calls synchronously, so there is no need to poll for the result.
pub fn call_candid<Input, Output>(
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
}

/// Call a canister candid query method, anonymous.
pub fn query_candid<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    method: &str,
    input: Input,
) -> Result<Output, RejectResponse>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    query_candid_as(env, canister_id, Principal::anonymous(), method, input)
}

/// Call a canister candid query method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
pub fn query_candid_as<Input, Output>(
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
    with_candid(input, |bytes| {
        env.query_call(canister_id, sender, method, bytes)
    })
}

/// Call a canister candid update method, anonymous.
pub fn update_candid<Input, Output>(
    env: &PocketIc,
    canister_id: CanisterId,
    method: &str,
    input: Input,
) -> Result<Output, RejectResponse>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    update_candid_as(env, canister_id, Principal::anonymous(), method, input)
}

/// Call a canister candid update method, authenticated. The sender can be impersonated (i.e., the
/// signature is not verified).
pub fn update_candid_as<Input, Output>(
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
    with_candid(input, |bytes| {
        env.update_call(canister_id, sender, method, bytes)
    })
}

/// A helper function that we use to implement both [`call_candid`] and
/// [`query_candid`].
pub fn with_candid<Input, Output>(
    input: Input,
    f: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, RejectResponse>,
) -> Result<Output, RejectResponse>
where
    Input: ArgumentEncoder,
    Output: for<'a> ArgumentDecoder<'a>,
{
    let in_bytes = encode_args(input).expect("failed to encode args");
    f(in_bytes).map(|out_bytes| {
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

/// Error type for [`TryFrom<u64>`].
#[derive(Clone, Copy, Debug)]
pub enum TryFromError {
    ValueOutOfRange(u64),
}

/// User-facing error codes.
///
/// The error codes are currently assigned using an HTTP-like
/// convention: the most significant digit is the corresponding reject
/// code and the rest is just a sequentially assigned two-digit
/// number.
#[derive(
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
    EnumIter,
)]
pub enum ErrorCode {
    // 1xx -- `RejectCode::SysFatal`
    SubnetOversubscribed = 101,
    MaxNumberOfCanistersReached = 102,
    // 2xx -- `RejectCode::SysTransient`
    CanisterQueueFull = 201,
    IngressMessageTimeout = 202,
    CanisterQueueNotEmpty = 203,
    IngressHistoryFull = 204,
    CanisterIdAlreadyExists = 205,
    StopCanisterRequestTimeout = 206,
    CanisterOutOfCycles = 207,
    CertifiedStateUnavailable = 208,
    CanisterInstallCodeRateLimited = 209,
    CanisterHeapDeltaRateLimited = 210,
    // 3xx -- `RejectCode::DestinationInvalid`
    CanisterNotFound = 301,
    CanisterSnapshotNotFound = 305,
    // 4xx -- `RejectCode::CanisterReject`
    InsufficientMemoryAllocation = 402,
    InsufficientCyclesForCreateCanister = 403,
    SubnetNotFound = 404,
    CanisterNotHostedBySubnet = 405,
    CanisterRejectedMessage = 406,
    UnknownManagementMessage = 407,
    InvalidManagementPayload = 408,
    // 5xx -- `RejectCode::CanisterError`
    CanisterTrapped = 502,
    CanisterCalledTrap = 503,
    CanisterContractViolation = 504,
    CanisterInvalidWasm = 505,
    CanisterDidNotReply = 506,
    CanisterOutOfMemory = 507,
    CanisterStopped = 508,
    CanisterStopping = 509,
    CanisterNotStopped = 510,
    CanisterStoppingCancelled = 511,
    CanisterInvalidController = 512,
    CanisterFunctionNotFound = 513,
    CanisterNonEmpty = 514,
    QueryCallGraphLoopDetected = 517,
    InsufficientCyclesInCall = 520,
    CanisterWasmEngineError = 521,
    CanisterInstructionLimitExceeded = 522,
    CanisterMemoryAccessLimitExceeded = 524,
    QueryCallGraphTooDeep = 525,
    QueryCallGraphTotalInstructionLimitExceeded = 526,
    CompositeQueryCalledInReplicatedMode = 527,
    QueryTimeLimitExceeded = 528,
    QueryCallGraphInternal = 529,
    InsufficientCyclesInComputeAllocation = 530,
    InsufficientCyclesInMemoryAllocation = 531,
    InsufficientCyclesInMemoryGrow = 532,
    ReservedCyclesLimitExceededInMemoryAllocation = 533,
    ReservedCyclesLimitExceededInMemoryGrow = 534,
    InsufficientCyclesInMessageMemoryGrow = 535,
    CanisterMethodNotFound = 536,
    CanisterWasmModuleNotFound = 537,
    CanisterAlreadyInstalled = 538,
    CanisterWasmMemoryLimitExceeded = 539,
    ReservedCyclesLimitIsTooLow = 540,
    // 6xx -- `RejectCode::SysUnknown`
    DeadlineExpired = 601,
    ResponseDropped = 602,
}

impl TryFrom<u64> for ErrorCode {
    type Error = TryFromError;
    fn try_from(err: u64) -> Result<ErrorCode, Self::Error> {
        match err {
            // 1xx -- `RejectCode::SysFatal`
            101 => Ok(ErrorCode::SubnetOversubscribed),
            102 => Ok(ErrorCode::MaxNumberOfCanistersReached),
            // 2xx -- `RejectCode::SysTransient`
            201 => Ok(ErrorCode::CanisterQueueFull),
            202 => Ok(ErrorCode::IngressMessageTimeout),
            203 => Ok(ErrorCode::CanisterQueueNotEmpty),
            204 => Ok(ErrorCode::IngressHistoryFull),
            205 => Ok(ErrorCode::CanisterIdAlreadyExists),
            206 => Ok(ErrorCode::StopCanisterRequestTimeout),
            207 => Ok(ErrorCode::CanisterOutOfCycles),
            208 => Ok(ErrorCode::CertifiedStateUnavailable),
            209 => Ok(ErrorCode::CanisterInstallCodeRateLimited),
            210 => Ok(ErrorCode::CanisterHeapDeltaRateLimited),
            // 3xx -- `RejectCode::DestinationInvalid`
            301 => Ok(ErrorCode::CanisterNotFound),
            305 => Ok(ErrorCode::CanisterSnapshotNotFound),
            // 4xx -- `RejectCode::CanisterReject`
            402 => Ok(ErrorCode::InsufficientMemoryAllocation),
            403 => Ok(ErrorCode::InsufficientCyclesForCreateCanister),
            404 => Ok(ErrorCode::SubnetNotFound),
            405 => Ok(ErrorCode::CanisterNotHostedBySubnet),
            406 => Ok(ErrorCode::CanisterRejectedMessage),
            407 => Ok(ErrorCode::UnknownManagementMessage),
            408 => Ok(ErrorCode::InvalidManagementPayload),
            // 5xx -- `RejectCode::CanisterError`
            502 => Ok(ErrorCode::CanisterTrapped),
            503 => Ok(ErrorCode::CanisterCalledTrap),
            504 => Ok(ErrorCode::CanisterContractViolation),
            505 => Ok(ErrorCode::CanisterInvalidWasm),
            506 => Ok(ErrorCode::CanisterDidNotReply),
            507 => Ok(ErrorCode::CanisterOutOfMemory),
            508 => Ok(ErrorCode::CanisterStopped),
            509 => Ok(ErrorCode::CanisterStopping),
            510 => Ok(ErrorCode::CanisterNotStopped),
            511 => Ok(ErrorCode::CanisterStoppingCancelled),
            512 => Ok(ErrorCode::CanisterInvalidController),
            513 => Ok(ErrorCode::CanisterFunctionNotFound),
            514 => Ok(ErrorCode::CanisterNonEmpty),
            517 => Ok(ErrorCode::QueryCallGraphLoopDetected),
            520 => Ok(ErrorCode::InsufficientCyclesInCall),
            521 => Ok(ErrorCode::CanisterWasmEngineError),
            522 => Ok(ErrorCode::CanisterInstructionLimitExceeded),
            524 => Ok(ErrorCode::CanisterMemoryAccessLimitExceeded),
            525 => Ok(ErrorCode::QueryCallGraphTooDeep),
            526 => Ok(ErrorCode::QueryCallGraphTotalInstructionLimitExceeded),
            527 => Ok(ErrorCode::CompositeQueryCalledInReplicatedMode),
            528 => Ok(ErrorCode::QueryTimeLimitExceeded),
            529 => Ok(ErrorCode::QueryCallGraphInternal),
            530 => Ok(ErrorCode::InsufficientCyclesInComputeAllocation),
            531 => Ok(ErrorCode::InsufficientCyclesInMemoryAllocation),
            532 => Ok(ErrorCode::InsufficientCyclesInMemoryGrow),
            533 => Ok(ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation),
            534 => Ok(ErrorCode::ReservedCyclesLimitExceededInMemoryGrow),
            535 => Ok(ErrorCode::InsufficientCyclesInMessageMemoryGrow),
            536 => Ok(ErrorCode::CanisterMethodNotFound),
            537 => Ok(ErrorCode::CanisterWasmModuleNotFound),
            538 => Ok(ErrorCode::CanisterAlreadyInstalled),
            539 => Ok(ErrorCode::CanisterWasmMemoryLimitExceeded),
            540 => Ok(ErrorCode::ReservedCyclesLimitIsTooLow),
            // 6xx -- `RejectCode::SysUnknown`
            601 => Ok(ErrorCode::DeadlineExpired),
            602 => Ok(ErrorCode::ResponseDropped),
            _ => Err(TryFromError::ValueOutOfRange(err)),
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // E.g. "IC0301"
        write!(f, "IC{:04}", *self as i32)
    }
}

/// User-facing reject codes.
///
/// They can be derived from the most significant digit of the
/// corresponding error code.
#[derive(
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
    EnumIter,
)]
pub enum RejectCode {
    SysFatal = 1,
    SysTransient = 2,
    DestinationInvalid = 3,
    CanisterReject = 4,
    CanisterError = 5,
    SysUnknown = 6,
}

impl TryFrom<u64> for RejectCode {
    type Error = TryFromError;
    fn try_from(err: u64) -> Result<RejectCode, Self::Error> {
        match err {
            1 => Ok(RejectCode::SysFatal),
            2 => Ok(RejectCode::SysTransient),
            3 => Ok(RejectCode::DestinationInvalid),
            4 => Ok(RejectCode::CanisterReject),
            5 => Ok(RejectCode::CanisterError),
            6 => Ok(RejectCode::SysUnknown),
            _ => Err(TryFromError::ValueOutOfRange(err)),
        }
    }
}

/// User-facing type describing an unsuccessful (also called reject) call response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct RejectResponse {
    pub reject_code: RejectCode,
    pub reject_message: String,
    pub error_code: ErrorCode,
    pub certified: bool,
}

impl std::fmt::Display for RejectResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Follows [agent-rs](https://github.com/dfinity/agent-rs/blob/a651dbbe69e61d4e8508c144cd60cfa3118eeb3a/ic-agent/src/agent/agent_error.rs#L54)
        write!(f, "PocketIC returned a rejection error: reject code {:?}, reject message {}, error code {:?}", self.reject_code, self.reject_message, self.error_code)
    }
}

/// This enum describes the result of retrieving ingress status.
/// The `IngressStatusResult::Forbidden` variant is produced
/// if an optional caller is provided and a corresponding read state request
/// for the status of the same update call signed by that specified caller
/// was rejected because the update call was submitted by a different caller.
#[derive(Debug, Serialize, Deserialize)]
pub enum IngressStatusResult {
    NotAvailable,
    Forbidden(String),
    Success(Result<Vec<u8>, RejectResponse>),
}

#[cfg(windows)]
fn wsl_path(path: &std::ffi::OsStr, desc: &str) -> String {
    windows_to_wsl(
        path.to_str()
            .unwrap_or_else(|| panic!("Could not convert {} path ({:?}) to String", desc, path)),
    )
    .unwrap_or_else(|e| {
        panic!(
            "Could not convert {} path ({:?}) to WSL path: {:?}",
            desc, path, e
        )
    })
}

#[cfg(windows)]
fn pocket_ic_server_cmd(bin_path: &std::ffi::OsStr) -> Command {
    let mut cmd = Command::new("wsl");
    cmd.arg(wsl_path(bin_path, "PocketIC binary"));
    cmd
}

#[cfg(not(windows))]
fn pocket_ic_server_cmd(bin_path: &std::ffi::OsStr) -> Command {
    Command::new(bin_path)
}

/// Attempt to start a new PocketIC server if it's not already running.
pub fn start_or_reuse_server() -> Url {
    let bin_path: std::ffi::OsString =
        std::env::var_os("POCKET_IC_BIN").unwrap_or("./pocket-ic".into());

    if !Path::new(&bin_path).is_file() {
        let is_dir = if Path::new(&bin_path).is_dir() {
            " (this is a directory, but it should be a binary file)"
        } else {
            ""
        };
        panic!("
Could not find the PocketIC binary.

The PocketIC binary could not be found at {:?}{}. Please specify the path to the binary with the POCKET_IC_BIN environment variable, \
or place it in your current working directory (you are running PocketIC from {:?}).

To download the binary, please visit https://github.com/dfinity/pocketic."
, &bin_path, is_dir, &std::env::current_dir().map(|x| x.display().to_string()).unwrap_or_else(|_| "an unknown directory".to_string()));
    }

    // check PocketIC server version compatibility
    let mut cmd = pocket_ic_server_cmd(&bin_path);
    cmd.arg("--version");
    let version = cmd
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "Failed to get version of PocketIC binary ({:?}): {}",
                bin_path, e
            )
        })
        .stdout;
    let version_str = String::from_utf8(version)
        .unwrap_or_else(|e| panic!("Failed to parse PocketIC binary version string: {}", e));
    let version_line = version_str.trim_end_matches('\n');
    if version_line != EXPECTED_SERVER_VERSION {
        panic!(
            "Incompatible PocketIC server version: got {}; expected {}.",
            version_line, EXPECTED_SERVER_VERSION
        );
    }

    // We use the test driver's process ID to share the PocketIC server between multiple tests
    // launched by the same test driver.
    let test_driver_pid = std::process::id();
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", test_driver_pid));
    let mut cmd = pocket_ic_server_cmd(&bin_path);
    cmd.arg("--port-file");
    #[cfg(windows)]
    cmd.arg(wsl_path(
        port_file_path.as_path().as_os_str(),
        "PocketIC port file",
    ));
    #[cfg(not(windows))]
    cmd.arg(port_file_path.clone());
    if let Ok(mute_server) = std::env::var("POCKET_IC_MUTE_SERVER") {
        if !mute_server.is_empty() {
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());
        }
    }

    // TODO: SDK-1936
    #[allow(clippy::zombie_processes)]
    cmd.spawn()
        .unwrap_or_else(|_| panic!("Failed to start PocketIC binary ({:?})", bin_path));

    loop {
        if let Ok(port_string) = std::fs::read_to_string(port_file_path.clone()) {
            if port_string.contains("\n") {
                let port: u16 = port_string
                    .trim_end()
                    .parse()
                    .expect("Failed to parse port to number");
                break Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[derive(Error, Debug)]
pub enum DefaultEffectiveCanisterIdError {
    ReqwestError(#[from] reqwest::Error),
    JsonError(#[from] serde_json::Error),
    Utf8Error(#[from] std::string::FromUtf8Error),
}

impl std::fmt::Display for DefaultEffectiveCanisterIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DefaultEffectiveCanisterIdError::ReqwestError(err) => {
                write!(f, "ReqwestError({})", err)
            }
            DefaultEffectiveCanisterIdError::JsonError(err) => write!(f, "JsonError({})", err),
            DefaultEffectiveCanisterIdError::Utf8Error(err) => write!(f, "Utf8Error({})", err),
        }
    }
}

/// Retrieves a default effective canister id for canister creation on a PocketIC instance
/// characterized by:
///  - a PocketIC instance URL of the form http://<ip>:<port>/instances/<instance_id>;
///  - a PocketIC HTTP gateway URL of the form http://<ip>:port for a PocketIC instance.
///
/// Returns an error if the PocketIC instance topology could not be fetched or parsed, e.g.,
/// because the given URL points to a replica (i.e., does not meet any of the above two properties).
pub fn get_default_effective_canister_id(
    pocket_ic_url: String,
) -> Result<Principal, DefaultEffectiveCanisterIdError> {
    let runtime = Runtime::new().expect("Unable to create a runtime");
    runtime.block_on(crate::nonblocking::get_default_effective_canister_id(
        pocket_ic_url,
    ))
}

#[cfg(test)]
mod test {
    use crate::{ErrorCode, RejectCode};
    use strum::IntoEnumIterator;

    #[test]
    fn reject_code_round_trip() {
        for initial in RejectCode::iter() {
            let round_trip = RejectCode::try_from(initial as u64).unwrap();

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn error_code_round_trip() {
        for initial in ErrorCode::iter() {
            let round_trip = ErrorCode::try_from(initial as u64).unwrap();

            assert_eq!(initial, round_trip);
        }
    }

    #[test]
    fn reject_code_matches_ic_error_code() {
        assert_eq!(
            RejectCode::iter().len(),
            ic_error_types::RejectCode::iter().len()
        );
        for ic_reject_code in ic_error_types::RejectCode::iter() {
            let reject_code: RejectCode = (ic_reject_code as u64).try_into().unwrap();
            assert_eq!(
                format!("{:?}", reject_code),
                format!("{:?}", ic_reject_code)
            );
        }
    }

    #[test]
    fn error_code_matches_ic_error_code() {
        assert_eq!(
            ErrorCode::iter().len(),
            ic_error_types::ErrorCode::iter().len()
        );
        for ic_error_code in ic_error_types::ErrorCode::iter() {
            let error_code: ErrorCode = (ic_error_code as u64).try_into().unwrap();
            assert_eq!(format!("{:?}", error_code), format!("{:?}", ic_error_code));
        }
    }
}
