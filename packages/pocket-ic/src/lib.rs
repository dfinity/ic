#![allow(clippy::test_attr_in_doctest)]
#![doc = include_str!("../README.md")]
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
        AutoProgressConfig, BlobCompression, BlobId, CanisterHttpRequest, ExtendedSubnetConfigSet,
        HttpsConfig, IcpConfig, IcpFeatures, InitialTime, InstanceHttpGatewayConfig, InstanceId,
        MockCanisterHttpResponse, RawEffectivePrincipal, RawMessageId, RawSubnetBlockmakers,
        RawTickConfigs, RawTime, SubnetId, SubnetKind, SubnetSpec, Topology,
    },
    nonblocking::PocketIc as PocketIcAsync,
};
use candid::{
    Principal, decode_args, encode_args,
    utils::{ArgumentDecoder, ArgumentEncoder},
};
use flate2::read::GzDecoder;
use ic_management_canister_types::{
    CanisterId, CanisterInstallMode, CanisterLogRecord, CanisterSettings, CanisterStatusResult,
    Snapshot,
};
use ic_transport_types::SubnetMetrics;
use reqwest::Url;
use schemars::JsonSchema;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use slog::Level;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::OpenOptions,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::{Child, Command},
    sync::{Arc, mpsc::channel},
    thread,
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use strum_macros::EnumIter;
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;
use tokio::runtime::Runtime;
use tracing::{instrument, warn};
#[cfg(windows)]
use wslpath::windows_to_wsl;

pub mod common;
pub mod nonblocking;

const POCKET_IC_SERVER_NAME: &str = "pocket-ic-server";

const MIN_SERVER_VERSION: &str = "11.0.0";
const MAX_SERVER_VERSION: &str = "12";

/// Public to facilitate downloading the PocketIC server.
pub const LATEST_SERVER_VERSION: &str = "11.0.0";

// the default timeout of a PocketIC operation
const DEFAULT_MAX_REQUEST_TIME_MS: u64 = 300_000;

const LOCALHOST: &str = "127.0.0.1";

enum PocketIcStateKind {
    /// A persistent state dir managed by the user.
    StateDir(PathBuf),
    /// A fresh temporary directory used if the user does not provide
    /// a persistent state directory managed by the user.
    /// The temporary directory is deleted when `PocketIcState` is dropped
    /// unless `PocketIcState` is turned into a persistent state
    /// at the path given by `PocketIcState::into_path`.
    TempDir(TempDir),
}

pub struct PocketIcState {
    state: PocketIcStateKind,
}

impl PocketIcState {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let temp_dir = TempDir::new().unwrap();
        Self {
            state: PocketIcStateKind::TempDir(temp_dir),
        }
    }

    pub fn new_from_path(state_dir: PathBuf) -> Self {
        Self {
            state: PocketIcStateKind::StateDir(state_dir),
        }
    }

    pub fn into_path(self) -> PathBuf {
        match self.state {
            PocketIcStateKind::StateDir(state_dir) => state_dir,
            PocketIcStateKind::TempDir(temp_dir) => temp_dir.keep(),
        }
    }

    pub(crate) fn state_dir(&self) -> PathBuf {
        match &self.state {
            PocketIcStateKind::StateDir(state_dir) => state_dir.clone(),
            PocketIcStateKind::TempDir(temp_dir) => temp_dir.path().to_path_buf(),
        }
    }
}

pub struct PocketIcBuilder {
    config: Option<ExtendedSubnetConfigSet>,
    http_gateway_config: Option<InstanceHttpGatewayConfig>,
    server_binary: Option<PathBuf>,
    server_url: Option<Url>,
    max_request_time_ms: Option<u64>,
    read_only_state_dir: Option<PathBuf>,
    state_dir: Option<PocketIcState>,
    icp_config: IcpConfig,
    log_level: Option<Level>,
    bitcoind_addr: Option<Vec<SocketAddr>>,
    dogecoind_addr: Option<Vec<SocketAddr>>,
    icp_features: IcpFeatures,
    initial_time: Option<InitialTime>,
}

#[allow(clippy::new_without_default)]
impl PocketIcBuilder {
    pub fn new() -> Self {
        Self {
            config: None,
            http_gateway_config: None,
            server_binary: None,
            server_url: None,
            max_request_time_ms: Some(DEFAULT_MAX_REQUEST_TIME_MS),
            read_only_state_dir: None,
            state_dir: None,
            icp_config: IcpConfig::default(),
            log_level: None,
            bitcoind_addr: None,
            dogecoind_addr: None,
            icp_features: IcpFeatures::default(),
            initial_time: None,
        }
    }

    pub fn new_with_config(config: impl Into<ExtendedSubnetConfigSet>) -> Self {
        let mut builder = Self::new();
        builder.config = Some(config.into());
        builder
    }

    pub fn build(self) -> PocketIc {
        PocketIc::from_components(
            self.config.unwrap_or_default(),
            self.server_url,
            self.server_binary,
            self.max_request_time_ms,
            self.read_only_state_dir,
            self.state_dir,
            self.icp_config,
            self.log_level,
            self.bitcoind_addr,
            self.dogecoind_addr,
            self.icp_features,
            self.initial_time,
            self.http_gateway_config,
        )
    }

    pub async fn build_async(self) -> PocketIcAsync {
        PocketIcAsync::from_components(
            self.config.unwrap_or_default(),
            self.server_url,
            self.server_binary,
            self.max_request_time_ms,
            self.read_only_state_dir,
            self.state_dir,
            self.icp_config,
            self.log_level,
            self.bitcoind_addr,
            self.dogecoind_addr,
            self.icp_features,
            self.initial_time,
            self.http_gateway_config,
        )
        .await
    }

    /// Provide the path to the PocketIC server binary used instead of the environment variable `POCKET_IC_BIN`.
    pub fn with_server_binary(mut self, server_binary: PathBuf) -> Self {
        self.server_binary = Some(server_binary);
        self
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
        self.state_dir = Some(PocketIcState::new_from_path(state_dir));
        self
    }

    pub fn with_state(mut self, state_dir: PocketIcState) -> Self {
        self.state_dir = Some(state_dir);
        self
    }

    pub fn with_read_only_state(mut self, read_only_state_dir: &PocketIcState) -> Self {
        self.read_only_state_dir = Some(read_only_state_dir.state_dir());
        self
    }

    pub fn with_icp_config(mut self, icp_config: IcpConfig) -> Self {
        self.icp_config = icp_config;
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

    pub fn with_dogecoind_addrs(self, dogecoind_addrs: Vec<SocketAddr>) -> Self {
        Self {
            dogecoind_addr: Some(dogecoind_addrs),
            ..self
        }
    }

    /// Add an empty NNS subnet unless an NNS subnet has already been added.
    pub fn with_nns_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.nns = Some(config.nns.unwrap_or_default());
        self.config = Some(config);
        self
    }

    /// Add an NNS subnet with state loaded from the given state directory.
    /// Note that the provided path must be accessible for the PocketIC server process.
    ///
    /// `path_to_state` should lead to a directory which is expected to have
    /// the following structure:
    ///
    /// path_to_state/
    ///  |-- backups
    ///  |-- checkpoints
    ///  |-- diverged_checkpoints
    ///  |-- diverged_state_markers
    ///  |-- fs_tmp
    ///  |-- page_deltas
    ///  |-- states_metadata.pbuf
    ///  |-- tip
    ///  `-- tmp
    pub fn with_nns_state(self, path_to_state: PathBuf) -> Self {
        self.with_subnet_state(SubnetKind::NNS, path_to_state)
    }

    /// Add a subnet with state loaded from the given state directory.
    /// Note that the provided path must be accessible for the PocketIC server process.
    ///
    /// `path_to_state` should point to a directory which is expected to have
    /// the following structure:
    ///
    /// path_to_state/
    ///  |-- backups
    ///  |-- checkpoints
    ///  |-- diverged_checkpoints
    ///  |-- diverged_state_markers
    ///  |-- fs_tmp
    ///  |-- page_deltas
    ///  |-- states_metadata.pbuf
    ///  |-- tip
    ///  `-- tmp
    pub fn with_subnet_state(mut self, subnet_kind: SubnetKind, path_to_state: PathBuf) -> Self {
        let mut config = self.config.unwrap_or_default();
        let subnet_spec = SubnetSpec::default().with_state_dir(path_to_state);
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

    /// Add an empty sns subnet unless an SNS subnet has already been added.
    pub fn with_sns_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.sns = Some(config.sns.unwrap_or_default());
        self.config = Some(config);
        self
    }

    /// Add an empty II subnet unless an II subnet has already been added.
    pub fn with_ii_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.ii = Some(config.ii.unwrap_or_default());
        self.config = Some(config);
        self
    }

    /// Add an empty fiduciary subnet unless a fiduciary subnet has already been added.
    pub fn with_fiduciary_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.fiduciary = Some(config.fiduciary.unwrap_or_default());
        self.config = Some(config);
        self
    }

    /// Add an empty bitcoin subnet unless a bitcoin subnet has already been added.
    pub fn with_bitcoin_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.bitcoin = Some(config.bitcoin.unwrap_or_default());
        self.config = Some(config);
        self
    }

    /// Add an empty generic system subnet.
    pub fn with_system_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.system.push(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty generic application subnet.
    pub fn with_application_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.application.push(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty generic verified application subnet.
    pub fn with_verified_application_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config.verified_application.push(SubnetSpec::default());
        self.config = Some(config);
        self
    }

    /// Add an empty generic application subnet with benchmarking instruction configuration.
    pub fn with_benchmarking_application_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config
            .application
            .push(SubnetSpec::default().with_benchmarking_instruction_config());
        self.config = Some(config);
        self
    }

    /// Add an empty generic system subnet with benchmarking instruction configuration.
    pub fn with_benchmarking_system_subnet(mut self) -> Self {
        let mut config = self.config.unwrap_or_default();
        config
            .system
            .push(SubnetSpec::default().with_benchmarking_instruction_config());
        self.config = Some(config);
        self
    }

    /// Enables selected ICP features supported by PocketIC and implemented by system canisters
    /// (deployed to the PocketIC instance automatically when creating a new PocketIC instance).
    /// Subnets to which the system canisters are deployed are automatically declared as empty subnets,
    /// e.g., `PocketIcBuilder::with_nns_subnet` is implicitly implied by specifying the `icp_token` feature.
    pub fn with_icp_features(mut self, icp_features: IcpFeatures) -> Self {
        self.icp_features = icp_features;
        self
    }

    /// Sets the initial timestamp of the new instance to the provided value which must be at least
    /// - 10 May 2021 10:00:01 AM CEST if the `cycles_minting` feature is enabled in `icp_features`;
    /// - 06 May 2021 21:17:10 CEST otherwise.
    #[deprecated(note = "Use `with_initial_time` instead")]
    pub fn with_initial_timestamp(mut self, initial_timestamp_nanos: u64) -> Self {
        self.initial_time = Some(InitialTime::Timestamp(RawTime {
            nanos_since_epoch: initial_timestamp_nanos,
        }));
        self
    }

    /// Sets the initial time of the new instance to the provided value which must be at least
    /// - 10 May 2021 10:00:01 AM CEST if the `cycles_minting` feature is enabled in `icp_features`;
    /// - 06 May 2021 21:17:10 CEST otherwise.
    pub fn with_initial_time(mut self, initial_time: Time) -> Self {
        self.initial_time = Some(InitialTime::Timestamp(RawTime {
            nanos_since_epoch: initial_time.as_nanos_since_unix_epoch(),
        }));
        self
    }

    /// Configures the new instance to make progress automatically,
    /// i.e., periodically update the time of the IC instance
    /// to the real time and execute rounds on the subnets.
    pub fn with_auto_progress(mut self) -> Self {
        let config = AutoProgressConfig {
            artificial_delay_ms: None,
        };
        self.initial_time = Some(InitialTime::AutoProgress(config));
        self
    }

    pub fn with_http_gateway(mut self, http_gateway_config: InstanceHttpGatewayConfig) -> Self {
        self.http_gateway_config = Some(http_gateway_config);
        self
    }
}

/// Representation of system time as duration since UNIX epoch
/// with cross-platform nanosecond precision.
#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub struct Time(Duration);

impl Time {
    /// Number of nanoseconds since UNIX EPOCH.
    pub fn as_nanos_since_unix_epoch(&self) -> u64 {
        self.0.as_nanos().try_into().unwrap()
    }

    pub const fn from_nanos_since_unix_epoch(nanos: u64) -> Self {
        Time(Duration::from_nanos(nanos))
    }
}

impl std::fmt::Debug for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nanos_since_unix_epoch = self.as_nanos_since_unix_epoch();
        write!(f, "{nanos_since_unix_epoch}")
    }
}

impl std::ops::Add<Duration> for Time {
    type Output = Time;
    fn add(self, dur: Duration) -> Time {
        Time(self.0 + dur)
    }
}

impl From<SystemTime> for Time {
    fn from(time: SystemTime) -> Self {
        Self::from_nanos_since_unix_epoch(
            time.duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .try_into()
                .unwrap(),
        )
    }
}

impl TryFrom<Time> for SystemTime {
    type Error = String;

    fn try_from(time: Time) -> Result<SystemTime, String> {
        let nanos = time.as_nanos_since_unix_epoch();
        let system_time = UNIX_EPOCH + Duration::from_nanos(nanos);
        let roundtrip: Time = system_time.into();
        if roundtrip.as_nanos_since_unix_epoch() == nanos {
            Ok(system_time)
        } else {
            Err(format!(
                "Converting UNIX timestamp {nanos} in nanoseconds to SystemTime failed due to losing precision"
            ))
        }
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_components(
        subnet_config_set: impl Into<ExtendedSubnetConfigSet>,
        server_url: Option<Url>,
        server_binary: Option<PathBuf>,
        max_request_time_ms: Option<u64>,
        read_only_state_dir: Option<PathBuf>,
        state_dir: Option<PocketIcState>,
        icp_config: IcpConfig,
        log_level: Option<Level>,
        bitcoind_addr: Option<Vec<SocketAddr>>,
        dogecoind_addr: Option<Vec<SocketAddr>>,
        icp_features: IcpFeatures,
        initial_time: Option<InitialTime>,
        http_gateway_config: Option<InstanceHttpGatewayConfig>,
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
                server_binary,
                max_request_time_ms,
                read_only_state_dir,
                state_dir,
                icp_config,
                log_level,
                bitcoind_addr,
                dogecoind_addr,
                icp_features,
                initial_time,
                http_gateway_config,
            )
            .await
        });

        Self {
            pocket_ic,
            runtime: Arc::new(runtime),
            thread: Some(thread),
        }
    }

    pub fn drop_and_take_state(mut self) -> Option<PocketIcState> {
        self.pocket_ic.take_state_internal()
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let url = runtime.block_on(async {
            let (_, server_url) = start_server(StartServerParams {
                reuse: true,
                ..Default::default()
            })
            .await;
            server_url.join("instances").unwrap()
        });
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

    /// Make the IC produce and progress by one block with custom
    /// configs for the round.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn tick_with_configs(&self, configs: TickConfigs) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.tick_with_configs(configs).await })
    }

    /// Configures the IC to make progress automatically,
    /// i.e., periodically update the time of the IC
    /// to the real time and execute rounds on the subnets.
    /// Returns the URL at which `/api` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn auto_progress(&self) -> Url {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.auto_progress().await })
    }

    /// Returns whether automatic progress is enabled on the PocketIC instance.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn auto_progress_enabled(&self) -> bool {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.auto_progress_enabled().await })
    }

    /// Stops automatic progress (see `auto_progress`) on the IC.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn stop_progress(&self) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.stop_progress().await })
    }

    /// Returns the URL at which `/api` requests
    /// for this instance can be made if the HTTP
    /// gateway has been started.
    pub fn url(&self) -> Option<Url> {
        self.pocket_ic.url()
    }

    /// Creates an HTTP gateway for this PocketIC instance binding to `127.0.0.1`
    /// and an optionally specified port (defaults to choosing an arbitrary unassigned port);
    /// listening on `localhost`;
    /// and configures the PocketIC instance to make progress automatically, i.e.,
    /// periodically update the time of the PocketIC instance to the real time
    /// and process messages on the PocketIC instance.
    /// Returns the URL at which `/api` requests
    /// for this instance can be made.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn make_live(&mut self, listen_at: Option<u16>) -> Url {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.make_live(listen_at).await })
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
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn make_live_with_params(
        &mut self,
        ip_addr: Option<IpAddr>,
        listen_at: Option<u16>,
        domains: Option<Vec<String>>,
        https_config: Option<HttpsConfig>,
    ) -> Url {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .make_live_with_params(ip_addr, listen_at, domains, https_config)
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

    /// Get the root key of this IC instance. Returns `None` if the IC has no NNS subnet.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn root_key(&self) -> Option<Vec<u8>> {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.root_key().await })
    }

    /// Get the current time of the IC.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn get_time(&self) -> Time {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.get_time().await })
    }

    /// Set the current time of the IC, on all subnets.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, time = ?time))]
    pub fn set_time(&self, time: Time) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.set_time(time).await })
    }

    /// Set the current certified time of the IC, on all subnets.
    #[instrument(skip(self), fields(instance_id=self.pocket_ic.instance_id, time = ?time))]
    pub fn set_certified_time(&self, time: Time) {
        let runtime = self.runtime.clone();
        runtime.block_on(async { self.pocket_ic.set_certified_time(time).await })
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

    /// Upgrade a Motoko EOP canister with a new WASM module.
    #[instrument(skip(self, wasm_module, arg), fields(instance_id=self.pocket_ic.instance_id, canister_id = %canister_id.to_string(), wasm_module_len = %wasm_module.len(), arg_len = %arg.len(), sender = %sender.unwrap_or(Principal::anonymous()).to_string()))]
    pub fn upgrade_eop_canister(
        &self,
        canister_id: CanisterId,
        wasm_module: Vec<u8>,
        arg: Vec<u8>,
        sender: Option<Principal>,
    ) -> Result<(), RejectResponse> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .upgrade_eop_canister(canister_id, wasm_module, arg, sender)
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

    pub fn update_call_with_effective_principal(
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

    /// Download a canister snapshot to a given snapshot directory.
    /// The sender must be a controller of the canister.
    /// The snapshot directory must be empty if it exists.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn canister_snapshot_download(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        snapshot_id: Vec<u8>,
        snapshot_dir: PathBuf,
    ) {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .canister_snapshot_download(canister_id, sender, snapshot_id, snapshot_dir)
                .await
        })
    }

    /// Upload a canister snapshot from a given snapshot directory.
    /// The sender must be a controller of the canister.
    /// Returns the snapshot ID of the uploaded snapshot.
    #[instrument(ret, skip(self), fields(instance_id=self.pocket_ic.instance_id))]
    pub fn canister_snapshot_upload(
        &self,
        canister_id: CanisterId,
        sender: Principal,
        replace_snapshot: Option<Vec<u8>>,
        snapshot_dir: PathBuf,
    ) -> Vec<u8> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            self.pocket_ic
                .canister_snapshot_upload(canister_id, sender, replace_snapshot, snapshot_dir)
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
    CanisterSnapshotImmutable = 409,
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
            409 => Ok(ErrorCode::CanisterSnapshotImmutable),
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
        write!(
            f,
            "PocketIC returned a rejection error: reject code {:?}, reject message {}, error code {:?}",
            self.reject_code, self.reject_message, self.error_code
        )
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

#[derive(Clone, Debug, Default)]
pub struct TickConfigs {
    pub blockmakers: Option<Vec<SubnetBlockmakers>>,
}

impl From<TickConfigs> for RawTickConfigs {
    fn from(tick_configs: TickConfigs) -> Self {
        Self {
            blockmakers: tick_configs.blockmakers.map(|blockmakers| {
                blockmakers
                    .into_iter()
                    .map(|blockmaker| blockmaker.into())
                    .collect()
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SubnetBlockmakers {
    pub subnet: Principal,
    pub blockmaker: Principal,
    pub failed_blockmakers: Vec<Principal>,
}

impl From<SubnetBlockmakers> for RawSubnetBlockmakers {
    fn from(blockmaker: SubnetBlockmakers) -> Self {
        Self {
            subnet: blockmaker.subnet.into(),
            blockmaker: blockmaker.blockmaker.into(),
            failed_blockmakers: blockmaker
                .failed_blockmakers
                .into_iter()
                .map(|p| p.into())
                .collect(),
        }
    }
}

#[cfg(windows)]
fn wsl_path(path: &PathBuf, desc: &str) -> String {
    windows_to_wsl(
        path.as_os_str()
            .to_str()
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
fn pocket_ic_server_cmd(bin_path: &PathBuf) -> Command {
    let mut cmd = Command::new("wsl");
    cmd.arg(wsl_path(bin_path, "PocketIC binary"));
    cmd
}

#[cfg(not(windows))]
fn pocket_ic_server_cmd(bin_path: &PathBuf) -> Command {
    Command::new(bin_path)
}

fn check_pocketic_server_version(version_line: &str) -> Result<(), String> {
    let unexpected_version = format!(
        "Unexpected PocketIC server version: got `{version_line}`; expected `{POCKET_IC_SERVER_NAME} x.y.z`."
    );
    let Some((pocket_ic_server, version)) = version_line.split_once(' ') else {
        return Err(unexpected_version);
    };
    if pocket_ic_server != POCKET_IC_SERVER_NAME {
        return Err(unexpected_version);
    }
    let req = VersionReq::parse(&format!(">={MIN_SERVER_VERSION},<{MAX_SERVER_VERSION}")).unwrap();
    let version = Version::parse(version)
        .map_err(|e| format!("Failed to parse PocketIC server version: {e}"))?;
    if !req.matches(&version) {
        return Err(format!(
            "Incompatible PocketIC server version: got {version}; expected {req}."
        ));
    }

    Ok(())
}

fn get_and_check_pocketic_server_version(server_binary: &PathBuf) -> Result<(), String> {
    let mut cmd = pocket_ic_server_cmd(server_binary);
    cmd.arg("--version");
    let version = cmd.output().map_err(|e| e.to_string())?.stdout;
    let version_str = String::from_utf8(version)
        .map_err(|e| format!("Failed to parse PocketIC server version: {e}."))?;
    let version_line = version_str.trim_end_matches('\n');
    check_pocketic_server_version(version_line)
}

async fn download_pocketic_server(
    server_url: String,
    mut out: std::fs::File,
) -> Result<(), String> {
    let binary = reqwest::get(server_url)
        .await
        .map_err(|e| format!("Failed to download PocketIC server: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("Failed to download PocketIC server: {e}"))?
        .to_vec();
    let mut gz = GzDecoder::new(&binary[..]);
    let _ = std::io::copy(&mut gz, &mut out)
        .map_err(|e| format!("Failed to write PocketIC server binary: {e}"));
    Ok(())
}

#[derive(Default)]
pub struct StartServerParams {
    pub server_binary: Option<PathBuf>,
    /// Reuse an existing PocketIC server spawned by this process.
    pub reuse: bool,
    /// TTL for the PocketIC server.
    /// The server stops if no request has been received during its TTL
    /// and if there are no more pending requests.
    /// A default value of TTL is used if no `ttl` is specified here.
    /// Note: The TTL might not be overriden if the same process sets `reuse` to `true`
    /// and passes different values of `ttl`.
    pub ttl: Option<Duration>,
}

/// Attempt to start a new PocketIC server.
pub async fn start_server(params: StartServerParams) -> (Child, Url) {
    let default_bin_dir =
        std::env::temp_dir().join(format!("{POCKET_IC_SERVER_NAME}-{LATEST_SERVER_VERSION}"));
    let default_bin_path = default_bin_dir.join("pocket-ic");
    let bin_path_provided =
        params.server_binary.is_some() || std::env::var_os("POCKET_IC_BIN").is_some();
    let mut bin_path: PathBuf = params.server_binary.unwrap_or_else(|| {
        std::env::var_os("POCKET_IC_BIN")
            .unwrap_or_else(|| default_bin_path.clone().into())
            .into()
    });

    if let Err(e) = get_and_check_pocketic_server_version(&bin_path) {
        if bin_path_provided {
            panic!(
                "Failed to validate PocketIC server binary `{}`: `{}`.",
                bin_path.display(),
                e
            );
        }
        bin_path = default_bin_path.clone();
        std::fs::create_dir_all(&default_bin_dir)
            .expect("Failed to create PocketIC server directory");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o777);
        match options.open(&default_bin_path) {
            Ok(out) => {
                #[cfg(target_os = "macos")]
                let os = "darwin";
                #[cfg(not(target_os = "macos"))]
                let os = "linux";
                #[cfg(target_arch = "aarch64")]
                let arch = "arm64";
                #[cfg(not(target_arch = "aarch64"))]
                let arch = "x86_64";
                let server_url = format!(
                    "https://github.com/dfinity/pocketic/releases/download/{LATEST_SERVER_VERSION}/pocket-ic-{arch}-{os}.gz"
                );
                println!(
                    "Failed to validate PocketIC server binary `{}`: `{}`. Going to download PocketIC server {} from {} to the local path {}. To avoid downloads during test execution, please specify the path to the (ungzipped and executable) PocketIC server {} using the function `PocketIcBuilder::with_server_binary` or using the `POCKET_IC_BIN` environment variable.",
                    bin_path.display(),
                    e,
                    LATEST_SERVER_VERSION,
                    server_url,
                    default_bin_path.display(),
                    LATEST_SERVER_VERSION
                );
                if let Err(e) = download_pocketic_server(server_url, out).await {
                    let _ = std::fs::remove_file(default_bin_path);
                    panic!("{}", e);
                }
            }
            _ => {
                // PocketIC server has already been created by another test: wait until it's fully downloaded.
                let start = std::time::Instant::now();
                loop {
                    if get_and_check_pocketic_server_version(&default_bin_path).is_ok() {
                        break;
                    }
                    if start.elapsed() > std::time::Duration::from_secs(60) {
                        let _ = std::fs::remove_file(&default_bin_path);
                        panic!(
                            "Timed out waiting for PocketIC server being available at the local path {}.",
                            default_bin_path.display()
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    }

    let port_file_path = if params.reuse {
        // We use the test driver's process ID to share the PocketIC server between multiple tests
        // launched by the same test driver.
        let test_driver_pid = std::process::id();
        std::env::temp_dir().join(format!("pocket_ic_{test_driver_pid}.port"))
    } else {
        NamedTempFile::new().unwrap().into_temp_path().to_path_buf()
    };
    let mut cmd = pocket_ic_server_cmd(&bin_path);
    if let Some(ttl) = params.ttl {
        cmd.arg("--ttl").arg(ttl.as_secs().to_string());
    }
    cmd.arg("--port-file");
    #[cfg(windows)]
    cmd.arg(wsl_path(&port_file_path, "PocketIC port file"));
    #[cfg(not(windows))]
    cmd.arg(port_file_path.clone());
    if let Ok(mute_server) = std::env::var("POCKET_IC_MUTE_SERVER")
        && !mute_server.is_empty()
    {
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }

    // Start the server in the background so that it doesn't receive signals such as CTRL^C
    // from the foreground terminal.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    // TODO: SDK-1936
    #[allow(clippy::zombie_processes)]
    let child = cmd
        .spawn()
        .unwrap_or_else(|_| panic!("Failed to start PocketIC binary ({})", bin_path.display()));

    loop {
        if let Ok(port_string) = std::fs::read_to_string(port_file_path.clone())
            && port_string.contains("\n")
        {
            let port: u16 = port_string
                .trim_end()
                .parse()
                .expect("Failed to parse port to number");
            break (
                child,
                Url::parse(&format!("http://{LOCALHOST}:{port}/")).unwrap(),
            );
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
                write!(f, "ReqwestError({err})")
            }
            DefaultEffectiveCanisterIdError::JsonError(err) => write!(f, "JsonError({err})"),
            DefaultEffectiveCanisterIdError::Utf8Error(err) => write!(f, "Utf8Error({err})"),
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

pub fn copy_dir(
    src: impl AsRef<std::path::Path>,
    dst: impl AsRef<std::path::Path>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{ErrorCode, RejectCode, check_pocketic_server_version};
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
            assert_eq!(format!("{reject_code:?}"), format!("{:?}", ic_reject_code));
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
            assert_eq!(format!("{error_code:?}"), format!("{:?}", ic_error_code));
        }
    }

    #[test]
    fn test_check_pocketic_server_version() {
        assert!(
            check_pocketic_server_version("pocket-ic-server")
                .unwrap_err()
                .contains("Unexpected PocketIC server version")
        );
        assert!(
            check_pocketic_server_version("pocket-ic 11.0.0")
                .unwrap_err()
                .contains("Unexpected PocketIC server version")
        );
        assert!(
            check_pocketic_server_version("pocket-ic-server 11 0 0")
                .unwrap_err()
                .contains("Failed to parse PocketIC server version")
        );
        assert!(
            check_pocketic_server_version("pocket-ic-server 10.0.0")
                .unwrap_err()
                .contains("Incompatible PocketIC server version")
        );
        check_pocketic_server_version("pocket-ic-server 11.0.0").unwrap();
        check_pocketic_server_version("pocket-ic-server 11.0.1").unwrap();
        check_pocketic_server_version("pocket-ic-server 11.1.0").unwrap();
        assert!(
            check_pocketic_server_version("pocket-ic-server 12.0.0")
                .unwrap_err()
                .contains("Incompatible PocketIC server version")
        );
    }
}
