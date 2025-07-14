use crate::state_api::state::{HasStateLabel, OpOut, PocketIcError, StateLabel};
use crate::{BlobStore, OpId, Operation, SubnetBlockmaker};
use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Response as AxumResponse},
};
use bitcoin::Network;
use candid::{Decode, Encode, Principal};
use cycles_minting_canister::{
    ChangeSubnetTypeAssignmentArgs, CyclesCanisterInitPayload, SetAuthorizedSubnetworkListArgs,
    SubnetListWithType, UpdateSubnetTypeArgs,
};
use futures::future::BoxFuture;
use futures::FutureExt;
use hyper::body::Bytes;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Method, StatusCode};
use ic_boundary::{status, Health, RootKey};
use ic_btc_adapter::config::{Config as BitcoinAdapterConfig, IncomingSource as BtcIncomingSource};
use ic_btc_adapter::start_server as start_btc_server;
use ic_config::adapters::AdaptersConfig;
use ic_config::execution_environment::MAX_CANISTER_HTTP_REQUESTS_IN_FLIGHT;
use ic_config::{
    execution_environment, flag_status::FlagStatus, http_handler, logger::Config as LoggerConfig,
    subnet_config::SubnetConfig,
};
use ic_crypto_sha2::Sha256;
use ic_http_endpoints_public::{
    call_v2, call_v3, metrics::HttpHandlerMetrics, CanisterReadStateServiceBuilder,
    IngressValidatorBuilder, QueryServiceBuilder, SubnetReadStateServiceBuilder,
};
use ic_https_outcalls_adapter::{
    start_server as start_canister_http_server, Config as HttpsOutcallsConfig,
    IncomingSource as CanisterHttpIncomingSource,
};
use ic_https_outcalls_adapter_client::{setup_canister_http_client, CanisterHttpAdapterClientImpl};
use ic_https_outcalls_service::https_outcalls_service_server::HttpsOutcallsService;
use ic_https_outcalls_service::https_outcalls_service_server::HttpsOutcallsServiceServer;
use ic_https_outcalls_service::HttpsOutcallRequest;
use ic_https_outcalls_service::HttpsOutcallResponse;
use ic_interfaces::{crypto::BasicSigner, ingress_pool::IngressPoolThrottler};
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_interfaces_registry::{RegistryValue, ZERO_REGISTRY_VERSION};
use ic_interfaces_state_manager::StateReader;
use ic_logger::{no_op_logger, ReplicaLogger};
use ic_management_canister_types_private::{
    BoundedVec, CanisterIdRecord, CanisterInstallMode, CanisterSettingsArgs, EcdsaCurve,
    EcdsaKeyId, LogVisibilityV2, MasterPublicKeyId, Method as Ic00Method,
    ProvisionalCreateCanisterWithCyclesArgs, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
    VetKdKeyId,
};
use ic_metrics::MetricsRegistry;
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{
    are_disjoint, is_subset_of, CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    add_global_registry_records, add_initial_registry_records, FakeVerifier, StateMachine,
    StateMachineBuilder, StateMachineConfig, StateMachineStateDir, SubmitIngressError, Subnets,
};
use ic_state_manager::StateManagerImpl;
use ic_types::batch::BlockmakerMetrics;
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    canister_http::{
        CanisterHttpReject, CanisterHttpRequest as AdapterCanisterHttpRequest,
        CanisterHttpRequestId, CanisterHttpResponse as AdapterCanisterHttpResponse,
        CanisterHttpResponseContent,
    },
    crypto::{BasicSig, BasicSigOf, CryptoResult, Signable},
    malicious_flags::MaliciousFlags,
    messages::{
        CertificateDelegation, HttpCallContent, HttpRequestEnvelope, MessageId as OtherMessageId,
        QueryResponseHash, ReplicaHealthStatus, SignedIngress,
    },
    time::GENESIS,
    CanisterId, Cycles, Height, NodeId, NumInstructions, PrincipalId, RegistryVersion, SubnetId,
};
use ic_types::{NumBytes, Time};
use ic_validator_ingress_message::StandaloneIngressSigVerifier;
use icp_ledger::AccountIdentifier;
use itertools::Itertools;
use pocket_ic::common::rest::{
    self, BinaryBlob, BlobCompression, CanisterHttpHeader, CanisterHttpMethod, CanisterHttpRequest,
    CanisterHttpResponse, ExtendedSubnetConfigSet, IcpFeatures, MockCanisterHttpResponse,
    RawAddCycles, RawCanisterCall, RawCanisterId, RawEffectivePrincipal, RawMessageId,
    RawSetStableMemory, SubnetInstructionConfig, SubnetKind, TickConfigs, Topology,
};
use pocket_ic::{copy_dir, ErrorCode, RejectCode, RejectResponse};
use registry_canister::init::RegistryCanisterInitPayload;
use serde::{Deserialize, Serialize};
use slog::Level;
use std::cmp::max;
use std::hash::Hash;
use std::str::FromStr;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{remove_file, File},
    io::{BufReader, Read, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime},
};
use strum::IntoEnumIterator;
use tempfile::{NamedTempFile, TempDir};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::{runtime::Runtime, sync::mpsc};
use tonic::transport::{Channel, Server};
use tonic::transport::{Endpoint, Uri};
use tonic::{Code, Request, Response, Status};
use tower::{service_fn, util::ServiceExt};

// See build.rs
include!(concat!(env!("OUT_DIR"), "/dashboard.rs"));

const REGISTRY_CANISTER_WASM: &[u8] = include_bytes!(env!("REGISTRY_CANISTER_WASM_PATH"));
const CYCLES_MINTING_CANISTER_WASM: &[u8] =
    include_bytes!(env!("CYCLES_MINTING_CANISTER_WASM_PATH"));

// Maximum duration of waiting for bitcoin/canister http adapter server to start.
const MAX_START_SERVER_DURATION: Duration = Duration::from_secs(60);

// Clippy complains that these are interior-mutable.
// We don't mutate them, so silence it.
// https://rust-lang.github.io/rust-clippy/master/index.html#/declare_interior_mutable_const
#[allow(clippy::declare_interior_mutable_const)]
const CONTENT_TYPE_CBOR: HeaderValue = HeaderValue::from_static("application/cbor");

/// The response type for `/api/v2` and `/api/v3` IC endpoint operations.
pub(crate) type ApiResponse = BoxFuture<'static, (u16, BTreeMap<String, Vec<u8>>, Vec<u8>)>;

/// We assume that the maximum number of subnets on the mainnet is 1024.
/// Used for generating canister ID ranges that do not appear on mainnet.
pub const MAXIMUM_NUMBER_OF_SUBNETS_ON_MAINNET: u64 = 1024;

fn wasm_result_to_canister_result(
    res: ic_state_machine_tests::WasmResult,
    certified: bool,
) -> Result<Vec<u8>, RejectResponse> {
    match res {
        ic_state_machine_tests::WasmResult::Reply(data) => Ok(data),
        ic_state_machine_tests::WasmResult::Reject(reject_message) => Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            reject_message,
            error_code: ErrorCode::CanisterRejectedMessage,
            certified,
        }),
    }
}

fn user_error_to_reject_response(
    err: ic_error_types::UserError,
    certified: bool,
) -> RejectResponse {
    RejectResponse {
        reject_code: RejectCode::try_from(err.reject_code() as u64).unwrap(),
        reject_message: err.description().to_string(),
        error_code: ErrorCode::try_from(err.code() as u64).unwrap(),
        certified,
    }
}

async fn into_api_response(resp: AxumResponse) -> (u16, BTreeMap<String, Vec<u8>>, Vec<u8>) {
    (
        resp.status().into(),
        resp.headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect(),
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
}

fn compute_subnet_seed(
    mut ranges: Vec<CanisterIdRange>,
    alloc_range: Option<CanisterIdRange>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if let Some(range) = alloc_range {
        ranges.push(range);
    }
    ranges.sort();
    hasher.write(format!("{:?}", ranges).as_bytes());
    hasher.finish()
}

#[derive(Clone, Deserialize, Serialize)]
struct RawTopologyInternal {
    pub subnet_configs: Vec<SubnetConfigInternal>,
    pub default_effective_canister_id: RawCanisterId,
    pub icp_features: Option<IcpFeatures>,
    pub synced_registry_version: Option<u64>,
    pub time: SystemTime,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SubnetConfigInternal {
    pub subnet_id: SubnetId,
    pub subnet_kind: SubnetKind,
    pub instruction_config: SubnetInstructionConfig,
    pub ranges: Vec<CanisterIdRange>,
    pub alloc_range: Option<CanisterIdRange>,
}

impl SubnetConfigInternal {
    fn default_effective_canister_id(&self) -> Principal {
        if let Some(range) = self.alloc_range {
            range.start.into()
        } else {
            self.ranges[0].start.into()
        }
    }
}

fn logger_config_from_level(log_level: Option<Level>) -> LoggerConfig {
    let level = match log_level.unwrap_or(Level::Warning) {
        Level::Critical => ic_config::logger::Level::Critical,
        Level::Error => ic_config::logger::Level::Error,
        Level::Warning => ic_config::logger::Level::Warning,
        Level::Info => ic_config::logger::Level::Info,
        Level::Debug => ic_config::logger::Level::Debug,
        Level::Trace => ic_config::logger::Level::Trace,
    };
    LoggerConfig {
        level,
        ..Default::default()
    }
}

struct BitcoinAdapterParts {
    adapter: JoinHandle<()>,
    uds_path: PathBuf,
}

impl BitcoinAdapterParts {
    fn new(
        bitcoind_addr: Vec<SocketAddr>,
        uds_path: PathBuf,
        log_level: Option<Level>,
        replica_logger: ReplicaLogger,
        metrics_registry: MetricsRegistry,
        runtime: Arc<Runtime>,
    ) -> Self {
        let bitcoin_adapter_config = BitcoinAdapterConfig {
            network: Network::Regtest,
            nodes: bitcoind_addr,
            socks_proxy: None,
            ipv6_only: false,
            logger: logger_config_from_level(log_level),
            incoming_source: BtcIncomingSource::Path(uds_path.clone()),
            address_limits: (1, 1),
            ..Default::default()
        };
        let adapter = tokio::spawn(async move {
            start_btc_server(
                &replica_logger,
                &metrics_registry,
                runtime.handle(),
                bitcoin_adapter_config,
            )
        });
        let start = std::time::Instant::now();
        loop {
            if let Ok(true) = std::fs::exists(uds_path.clone()) {
                break;
            }
            if start.elapsed() > MAX_START_SERVER_DURATION {
                panic!(
                    "Bitcoin adapter server took more than {:?} to start.",
                    MAX_START_SERVER_DURATION
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        BitcoinAdapterParts { adapter, uds_path }
    }
}

impl Drop for BitcoinAdapterParts {
    fn drop(&mut self) {
        self.adapter.abort();
        remove_file(self.uds_path.clone()).unwrap();
    }
}

struct CanisterHttpAdapterParts {
    adapter: JoinHandle<()>,
    uds_path: PathBuf,
}

impl CanisterHttpAdapterParts {
    fn new(
        uds_path: PathBuf,
        log_level: Option<Level>,
        replica_logger: ReplicaLogger,
        metrics_registry: MetricsRegistry,
        runtime: Arc<Runtime>,
    ) -> Self {
        let canister_http_adapter_config = HttpsOutcallsConfig {
            incoming_source: CanisterHttpIncomingSource::Path(uds_path.clone()),
            logger: logger_config_from_level(log_level),
            ..Default::default()
        };
        let adapter = tokio::spawn(async move {
            start_canister_http_server(
                &replica_logger,
                &metrics_registry,
                runtime.handle(),
                canister_http_adapter_config,
            )
        });
        let start = std::time::Instant::now();
        loop {
            if let Ok(true) = std::fs::exists(uds_path.clone()) {
                break;
            }
            if start.elapsed() > MAX_START_SERVER_DURATION {
                panic!(
                    "Canister http adapter server took more than {:?} to start.",
                    MAX_START_SERVER_DURATION
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        CanisterHttpAdapterParts { adapter, uds_path }
    }
}

impl Drop for CanisterHttpAdapterParts {
    fn drop(&mut self) {
        self.adapter.abort();
        remove_file(self.uds_path.clone()).unwrap();
    }
}

pub(crate) type CanisterHttpClient = Arc<
    Mutex<
        Box<
            dyn NonBlockingChannel<
                    AdapterCanisterHttpRequest,
                    Response = AdapterCanisterHttpResponse,
                > + Send,
        >,
    >,
>;

pub(crate) struct CanisterHttp {
    pub client: CanisterHttpClient,
    pub pending: BTreeSet<CanisterHttpRequestId>,
}

pub(crate) struct Subnet {
    pub state_machine: Arc<StateMachine>,
    pub canister_http: Arc<Mutex<CanisterHttp>>,
    delegation_from_nns: watch::Sender<Option<CertificateDelegation>>,
    _canister_http_adapter_parts: CanisterHttpAdapterParts,
}

impl Subnet {
    fn new(state_machine: Arc<StateMachine>) -> Self {
        let uds_path = NamedTempFile::new().unwrap().into_temp_path().to_path_buf();
        let canister_http_adapter_parts = CanisterHttpAdapterParts::new(
            uds_path.clone(),
            state_machine.log_level,
            state_machine.replica_logger.clone(),
            state_machine.metrics_registry.clone(),
            state_machine.runtime.clone(),
        );
        let adapter_config = AdaptersConfig {
            https_outcalls_uds_path: Some(uds_path),
            ..Default::default()
        };
        let (nns_delegation_tx, nns_delegation_rx) = watch::channel(None);
        let client = setup_canister_http_client(
            state_machine.runtime.handle().clone(),
            &state_machine.metrics_registry,
            adapter_config,
            state_machine.query_handler.lock().unwrap().clone(),
            MAX_CANISTER_HTTP_REQUESTS_IN_FLIGHT,
            state_machine.replica_logger.clone(),
            state_machine.get_subnet_type(),
            nns_delegation_rx,
        );
        let canister_http = Arc::new(Mutex::new(CanisterHttp {
            client: Arc::new(Mutex::new(client)),
            pending: BTreeSet::new(),
        }));
        Self {
            state_machine,
            canister_http,
            delegation_from_nns: nns_delegation_tx,
            _canister_http_adapter_parts: canister_http_adapter_parts,
        }
    }

    fn get_subnet_id(&self) -> SubnetId {
        self.state_machine.get_subnet_id()
    }

    fn set_delegation_from_nns(&self, delegation_from_nns: CertificateDelegation) {
        self.delegation_from_nns
            .send(Some(delegation_from_nns))
            .unwrap();
    }
}

pub(crate) struct SubnetsImpl {
    subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<Subnet>>>>,
}

impl SubnetsImpl {
    fn new() -> Self {
        Self {
            subnets: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    fn len(&self) -> usize {
        self.subnets.read().unwrap().len()
    }
    fn get_subnet(&self, subnet_id: SubnetId) -> Option<Arc<Subnet>> {
        self.subnets.read().unwrap().get(&subnet_id).cloned()
    }
    pub(crate) fn get_all(&self) -> Vec<Arc<Subnet>> {
        self.subnets.read().unwrap().values().cloned().collect()
    }
    fn clear(&self) {
        self.subnets.write().unwrap().clear();
    }
}

impl Subnets for SubnetsImpl {
    fn insert(&self, state_machine: Arc<StateMachine>) {
        self.subnets.write().unwrap().insert(
            state_machine.get_subnet_id(),
            Arc::new(Subnet::new(state_machine)),
        );
    }
    fn get(&self, subnet_id: SubnetId) -> Option<Arc<StateMachine>> {
        self.subnets
            .read()
            .unwrap()
            .get(&subnet_id)
            .as_ref()
            .map(|subnet| subnet.state_machine.clone())
    }
}

struct PocketIcSubnets {
    subnet_configs: Vec<SubnetConfigInternal>,
    subnets: Arc<SubnetsImpl>,
    nns_subnet: Option<Arc<Subnet>>,
    runtime: Arc<Runtime>,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    state_dir: Option<PathBuf>,
    routing_table: RoutingTable,
    chain_keys: BTreeMap<MasterPublicKeyId, Vec<SubnetId>>,
    nonmainnet_features: bool,
    log_level: Option<Level>,
    bitcoind_addr: Option<Vec<SocketAddr>>,
    icp_features: Option<IcpFeatures>,
    synced_registry_version: RegistryVersion,
    _bitcoin_adapter_parts: Option<BitcoinAdapterParts>,
}

impl PocketIcSubnets {
    fn state_machine_builder(
        state_machine_state_dir: Box<dyn StateMachineStateDir>,
        runtime: Arc<Runtime>,
        subnet_kind: SubnetKind,
        subnet_seed: [u8; 32],
        instruction_config: SubnetInstructionConfig,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
        create_at_registry_version: RegistryVersion,
        nonmainnet_features: bool,
        log_level: Option<Level>,
        bitcoin_adapter_uds_path: Option<PathBuf>,
    ) -> StateMachineBuilder {
        let subnet_type = conv_type(subnet_kind);
        let subnet_size = subnet_size(subnet_kind);
        let mut subnet_config = SubnetConfig::new(subnet_type);
        let mut hypervisor_config = if nonmainnet_features {
            crate::nonmainnet_features::hypervisor_config(true)
        } else {
            execution_environment::Config::default()
        };
        if let SubnetInstructionConfig::Benchmarking = instruction_config {
            let instruction_limit = NumInstructions::new(99_999_999_999_999);
            if instruction_limit > subnet_config.scheduler_config.max_instructions_per_round {
                subnet_config.scheduler_config.max_instructions_per_round = instruction_limit;
            }
            subnet_config.scheduler_config.max_instructions_per_message = instruction_limit;
            subnet_config.scheduler_config.max_instructions_per_slice = instruction_limit;
            subnet_config
                .scheduler_config
                .max_instructions_per_message_without_dts = instruction_limit;
            hypervisor_config.max_query_call_graph_instructions = instruction_limit;

            // exported functions limits
            hypervisor_config
                .embedders_config
                .max_number_exported_functions = 100_000;
            hypervisor_config
                .embedders_config
                .max_sum_exported_function_name_lengths = 5_000_000;
        }
        // bound PocketIc resource consumption
        hypervisor_config.embedders_config.max_sandbox_count = 64;
        hypervisor_config.embedders_config.max_sandbox_idle_time = Duration::from_secs(30);
        hypervisor_config.embedders_config.max_sandboxes_rss =
            NumBytes::new(2 * 1024 * 1024 * 1024);
        // shorter query stats epoch length for faster query stats aggregation
        hypervisor_config.query_stats_epoch_length = 60;
        // enable canister debug prints
        hypervisor_config
            .embedders_config
            .feature_flags
            .rate_limiting_of_debug_prints = FlagStatus::Disabled;
        let state_machine_config = StateMachineConfig::new(subnet_config, hypervisor_config);
        StateMachineBuilder::new()
            .with_runtime(runtime)
            .with_config(Some(state_machine_config))
            .with_subnet_seed(subnet_seed)
            .with_subnet_size(subnet_size.try_into().unwrap())
            .with_subnet_type(subnet_type)
            .with_state_machine_state_dir(state_machine_state_dir)
            .with_registry_data_provider(registry_data_provider.clone())
            .with_log_level(log_level)
            .with_bitcoin_testnet_uds_path(bitcoin_adapter_uds_path)
            .create_at_registry_version(create_at_registry_version)
    }

    fn new(
        runtime: Arc<Runtime>,
        state_dir: Option<PathBuf>,
        nonmainnet_features: bool,
        log_level: Option<Level>,
        bitcoind_addr: Option<Vec<SocketAddr>>,
        icp_features: Option<IcpFeatures>,
        synced_registry_version: Option<u64>,
    ) -> Self {
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
        add_initial_registry_records(registry_data_provider.clone());
        let routing_table = RoutingTable::new();
        let chain_keys = BTreeMap::new();
        // `ZERO_REGISTRY_VERSION` is unused in the registry set up by PocketIC.
        let synced_registry_version = synced_registry_version
            .map(RegistryVersion::new)
            .unwrap_or(ZERO_REGISTRY_VERSION);
        Self {
            subnet_configs: vec![],
            subnets: Arc::new(SubnetsImpl::new()),
            nns_subnet: None,
            runtime,
            state_dir,
            registry_data_provider,
            routing_table,
            chain_keys,
            nonmainnet_features,
            log_level,
            bitcoind_addr,
            icp_features,
            synced_registry_version,
            _bitcoin_adapter_parts: None,
        }
    }

    fn persist_topology(&self, default_effective_canister_id: Principal) {
        if let Some(ref state_dir) = self.state_dir {
            let raw_topology: RawTopologyInternal = RawTopologyInternal {
                subnet_configs: self.subnet_configs.clone(),
                default_effective_canister_id: default_effective_canister_id.into(),
                icp_features: self.icp_features.clone(),
                synced_registry_version: Some(self.synced_registry_version.get()),
                time: self.time(),
            };
            let topology_json = serde_json::to_string(&raw_topology).unwrap();
            let mut topology_file = File::create(state_dir.join("topology.json")).unwrap();
            topology_file.write_all(topology_json.as_bytes()).unwrap();
        }
    }

    fn get_all(&self) -> Vec<Arc<Subnet>> {
        self.subnets.get_all()
    }

    fn get(&self, subnet_id: SubnetId) -> Option<Arc<StateMachine>> {
        self.subnets
            .get_subnet(subnet_id)
            .as_ref()
            .map(|subnet| subnet.state_machine.clone())
    }

    fn clear(&mut self) {
        self.subnets.clear();
        self.nns_subnet.take();
    }

    fn route(&self, canister_id: CanisterId) -> Option<Arc<StateMachine>> {
        let subnet_id = self.routing_table.route(canister_id.get());
        subnet_id.map(|subnet_id| self.get(subnet_id).unwrap())
    }

    fn time(&self) -> SystemTime {
        self.subnets
            .get_all()
            .first()
            .map(|subnet| subnet.state_machine.time())
            .unwrap_or(GENESIS.into())
    }

    fn create_subnet(
        &mut self,
        subnet_config_info: SubnetConfigInfo,
    ) -> Result<SubnetConfigInternal, String> {
        let SubnetConfigInfo {
            ranges,
            alloc_range,
            subnet_id,
            subnet_state_dir,
            subnet_kind,
            instruction_config,
            time,
        } = subnet_config_info;

        let subnet_seed = compute_subnet_seed(ranges.clone(), alloc_range);

        let state_machine_state_dir: Box<dyn StateMachineStateDir> =
            if let Some(ref state_dir) = self.state_dir {
                Box::new(state_dir.join(hex::encode(subnet_seed)))
            } else {
                Box::new(TempDir::new().unwrap())
            };

        // We copy the subnet state (if applicable) since the subnet state is read-only.
        if let Some(subnet_state_dir) = subnet_state_dir {
            copy_dir(subnet_state_dir, state_machine_state_dir.path())
                .expect("Failed to copy state directory");
        }

        let bitcoin_adapter_uds_path =
            if matches!(subnet_kind, SubnetKind::Bitcoin) && self.bitcoind_addr.is_some() {
                Some(NamedTempFile::new().unwrap().into_temp_path().to_path_buf())
            } else {
                None
            };

        let create_at_registry_version = RegistryVersion::new(self.subnets.len() as u64 + 1);
        let mut builder = Self::state_machine_builder(
            state_machine_state_dir,
            self.runtime.clone(),
            subnet_kind,
            subnet_seed,
            instruction_config.clone(),
            self.registry_data_provider.clone(),
            create_at_registry_version,
            self.nonmainnet_features,
            self.log_level,
            bitcoin_adapter_uds_path.clone(),
        );

        if let Some(subnet_id) = subnet_id {
            builder = builder.with_subnet_id(subnet_id);
        }

        let mut subnet_chain_keys = vec![];
        if subnet_kind == SubnetKind::II || subnet_kind == SubnetKind::Fiduciary {
            for algorithm in [SchnorrAlgorithm::Bip340Secp256k1, SchnorrAlgorithm::Ed25519] {
                for name in ["key_1", "test_key_1", "dfx_test_key"] {
                    let key_id = SchnorrKeyId {
                        algorithm,
                        name: name.to_string(),
                    };
                    subnet_chain_keys.push(MasterPublicKeyId::Schnorr(key_id));
                }
            }

            for name in ["key_1", "test_key_1", "dfx_test_key"] {
                let key_id = EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: name.to_string(),
                };
                subnet_chain_keys.push(MasterPublicKeyId::Ecdsa(key_id));
            }

            if self.nonmainnet_features {
                for name in ["key_1", "test_key_1", "dfx_test_key"] {
                    let key_id = VetKdKeyId {
                        curve: VetKdCurve::Bls12_381_G2,
                        name: name.to_string(),
                    };
                    subnet_chain_keys.push(MasterPublicKeyId::VetKd(key_id));
                }
            }
        }
        for chain_key in &subnet_chain_keys {
            builder = builder.with_chain_key(chain_key.clone());
        }

        let sm = builder.build_with_subnets(self.subnets.clone());

        // The actual subnet ID (matching the subnet ID in the input `SubnetConfigInfo`
        // if one was provided).
        let subnet_id = sm.get_subnet_id();

        if let Some(expected_time) = time {
            let actual_time: SystemTime = sm.get_state_time().into();
            if actual_time != expected_time {
                return Err(format!("The state of subnet {} is corrupted.", subnet_id));
            }
        }

        // The subnet created first is marked as the NNS subnet.
        if self.nns_subnet.is_none() {
            self.nns_subnet = Some(self.subnets.get_subnet(subnet_id).unwrap());
        }

        // We need the actual subnet ID to update the chain keys.
        for chain_key in subnet_chain_keys {
            self.chain_keys
                .entry(chain_key)
                .or_default()
                .push(subnet_id);
        }

        // We need `StateMachine` components (metrics/logger)
        // to create a bitcoin adapter (if applicable).
        if let Some(bitcoin_adapter_uds_path) = bitcoin_adapter_uds_path {
            self._bitcoin_adapter_parts = Some(BitcoinAdapterParts::new(
                self.bitcoind_addr.clone().unwrap(),
                bitcoin_adapter_uds_path,
                self.log_level,
                sm.replica_logger.clone(),
                sm.metrics_registry.clone(),
                self.runtime.clone(),
            ));
        }

        // Update the routing table.
        for range in &ranges {
            self.routing_table.insert(*range, subnet_id).unwrap();
        }
        // The allocation range must be added last because
        // canister IDs are allocated from the last available range
        // (replica implementation).
        if let Some(alloc_range) = alloc_range {
            self.routing_table.insert(alloc_range, subnet_id).unwrap();
        }

        // Update global registry records.
        let subnet_list = self
            .subnets
            .get_all()
            .into_iter()
            .map(|subnet| subnet.get_subnet_id())
            .collect();
        add_global_registry_records(
            self.nns_subnet.clone().unwrap().get_subnet_id(),
            self.routing_table.clone(),
            subnet_list,
            self.chain_keys.clone(),
            self.registry_data_provider.clone(),
        );

        // Update the registry file on disk.
        if let Some(ref state_dir) = self.state_dir {
            let registry_proto_path = PathBuf::from(state_dir).join("registry.proto");
            self.registry_data_provider
                .write_to_file(registry_proto_path);
        }

        // Reload registry on every `StateMachine` in `self.subnets` to make sure
        // they have a consistent view of the (latest) registry.
        for subnet in self.subnets.get_all() {
            subnet.state_machine.reload_registry();
        }

        // All subnets must have the same time and time can only advance =>
        // set the time to the maximum time in the latest state across all subnets.
        let mut time: SystemTime = GENESIS.into();
        for subnet in self.subnets.get_all() {
            time = max(time, subnet.state_machine.get_state_time().into());
        }

        // Make sure time is strictly monotone.
        time += Duration::from_nanos(1);

        // Make sure that all subnets in `self.subnets` have the same time
        // and execute a round so that their latest certified state
        // reflects the registry changes from above.
        for subnet in self.subnets.get_all() {
            subnet.state_machine.set_time(time);
            subnet.state_machine.execute_round();
        }

        // Fetch the NNS delegation for the newly created subnet.
        // This can only be done after updating the registry and executing
        // a round on the NNS subnet (above).
        let nns_subnet = self.get_nns().unwrap();
        if subnet_id != nns_subnet.get_subnet_id() {
            let delegation = nns_subnet.get_delegation_for_subnet(subnet_id).unwrap();
            let subnet = self.subnets.get_subnet(subnet_id).unwrap();
            subnet.set_delegation_from_nns(delegation);
        }

        let subnet_config = SubnetConfigInternal {
            subnet_id,
            subnet_kind,
            instruction_config,
            ranges,
            alloc_range,
        };
        self.subnet_configs.push(subnet_config.clone());

        if let Some(icp_features) = self.icp_features.clone() {
            if icp_features.registry {
                self.update_registry();
            }
            if icp_features.cmc {
                self.update_cmc();
            }
        }

        Ok(subnet_config)
    }

    fn get_nns(&self) -> Option<Arc<StateMachine>> {
        self.nns_subnet
            .as_ref()
            .map(|subnet| subnet.state_machine.clone())
    }

    fn update_registry(&mut self) {
        let nns_subnet = self.nns_subnet.clone().expect(
            "The NNS subnet is supposed to already exist if the registry is to be deployed.",
        );

        if !nns_subnet
            .state_machine
            .canister_exists(REGISTRY_CANISTER_ID)
        {
            // Create the registry canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"rwlgt-iiaaa-aaaaa-aaaaa-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       wasm_memory_limit = opt (3_221_225_472 : nat);
            //       memory_allocation = opt (0 : nat);
            //       compute_allocation = opt (0 : nat);
            //     };
            let settings = CanisterSettingsArgs {
                controllers: Some(BoundedVec::new(vec![ROOT_CANISTER_ID.get()])),
                compute_allocation: Some(0_u64.into()),
                memory_allocation: Some(0_u64.into()),
                freezing_threshold: Some(2_592_000_u64.into()),
                reserved_cycles_limit: Some(5_000_000_000_000_u128.into()),
                log_visibility: Some(LogVisibilityV2::Controllers),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(REGISTRY_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, REGISTRY_CANISTER_ID);

            // Install the registry canister.
            let registry_init_payload = RegistryCanisterInitPayload { mutations: vec![] };
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    REGISTRY_CANISTER_WASM.to_vec(),
                    Encode!(&registry_init_payload).unwrap(),
                )
                .unwrap();
        }

        // Upload registry to the registry canister.
        let mutation_requests: Vec<_> = self
            .registry_data_provider
            .export_versions_as_atomic_mutation_requests()
            .into_iter()
            .skip(self.synced_registry_version.get() as usize)
            .collect();
        for mutation_request in mutation_requests {
            let mutation_request_bytes = mutation_request.encode_to_vec();
            self.execute_ingress_on(
                nns_subnet.clone(),
                ROOT_CANISTER_ID.get(),
                REGISTRY_CANISTER_ID,
                "atomic_mutate".to_string(),
                mutation_request_bytes,
            );
        }
        self.synced_registry_version = self.registry_data_provider.latest_version();
    }

    fn update_cmc(&mut self) {
        let nns_subnet = self
            .nns_subnet
            .clone()
            .expect("The NNS subnet is supposed to already exist if the CMC is to be deployed.");

        if !nns_subnet
            .state_machine
            .canister_exists(CYCLES_MINTING_CANISTER_ID)
        {
            // Create the CMC with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"rkp4c-7iaaa-aaaaa-aaaca-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       wasm_memory_limit = opt (3_221_225_472 : nat);
            //       memory_allocation = opt (1_073_741_824 : nat);
            //       compute_allocation = opt (0 : nat);
            //     };
            let settings = CanisterSettingsArgs {
                controllers: Some(BoundedVec::new(vec![ROOT_CANISTER_ID.get()])),
                compute_allocation: Some(0_u64.into()),
                memory_allocation: Some(1_073_741_824_u64.into()),
                freezing_threshold: Some(2_592_000_u64.into()),
                reserved_cycles_limit: Some(5_000_000_000_000_u128.into()),
                log_visibility: Some(LogVisibilityV2::Controllers),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(CYCLES_MINTING_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, CYCLES_MINTING_CANISTER_ID);

            // Install the CMC.
            let cmc_init_payload = Some(CyclesCanisterInitPayload {
                ledger_canister_id: Some(LEDGER_CANISTER_ID),
                governance_canister_id: Some(GOVERNANCE_CANISTER_ID),
                minting_account_id: Some(AccountIdentifier::new(
                    GOVERNANCE_CANISTER_ID.get(),
                    None,
                )),
                last_purged_notification: None,
                exchange_rate_canister: None,
                cycles_ledger_canister_id: None,
            });
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    CYCLES_MINTING_CANISTER_WASM.to_vec(),
                    Encode!(&cmc_init_payload).unwrap(),
                )
                .unwrap();

            // Set XDR exchange rate.
            // The values have been obtained by calling
            // `dfx canister call rkp4c-7iaaa-aaaaa-aaaca-cai get_icp_xdr_conversion_rate --ic`:
            //     data = record {
            //       xdr_permyriad_per_icp = 35_200 : nat64;
            //       timestamp_seconds = 1_751_617_980 : nat64;
            //     };
            let timestamp_seconds = 1_751_617_980;
            let xdr_permyriad_per_icp = 35_200;
            let update_icp_xdr_conversion_rate_payload = UpdateIcpXdrConversionRatePayload {
                data_source: "PocketIC".to_string(),
                timestamp_seconds,
                xdr_permyriad_per_icp,
                reason: None,
            };
            self.execute_ingress_on(
                nns_subnet.clone(),
                GOVERNANCE_CANISTER_ID.get(),
                CYCLES_MINTING_CANISTER_ID,
                "set_icp_xdr_conversion_rate".to_string(),
                Encode!(&update_icp_xdr_conversion_rate_payload).unwrap(),
            );
        }

        // set default (application) subnets on CMC
        // by setting authorized subnets associated with no principal (CMC API)
        let authorized_subnets = self
            .subnet_configs
            .iter()
            .filter_map(|subnet_config| {
                if matches!(subnet_config.subnet_kind, SubnetKind::Application) {
                    Some(subnet_config.subnet_id)
                } else {
                    None
                }
            })
            .collect();
        let set_authorized_subnetwork_list_args = SetAuthorizedSubnetworkListArgs {
            who: None,
            subnets: authorized_subnets,
        };
        self.execute_ingress_on(
            nns_subnet.clone(),
            GOVERNANCE_CANISTER_ID.get(),
            CYCLES_MINTING_CANISTER_ID,
            "set_authorized_subnetwork_list".to_string(),
            Encode!(&set_authorized_subnetwork_list_args).unwrap(),
        );

        // add fiduciary subnet to CMC
        let maybe_fiduciary_subnet_id = self
            .subnet_configs
            .iter()
            .find(|subnet_config| matches!(subnet_config.subnet_kind, SubnetKind::Fiduciary))
            .map(|subnet_config| subnet_config.subnet_id);
        if let Some(fiduciary_subnet_id) = maybe_fiduciary_subnet_id {
            let update_subnet_type_args = UpdateSubnetTypeArgs::Add("fiduciary".to_string());
            self.execute_ingress_on(
                nns_subnet.clone(),
                GOVERNANCE_CANISTER_ID.get(),
                CYCLES_MINTING_CANISTER_ID,
                "update_subnet_type".to_string(),
                Encode!(&update_subnet_type_args).unwrap(),
            );
            let change_subnet_type_assignment_args =
                ChangeSubnetTypeAssignmentArgs::Add(SubnetListWithType {
                    subnets: vec![fiduciary_subnet_id],
                    subnet_type: "fiduciary".to_string(),
                });
            self.execute_ingress_on(
                nns_subnet.clone(),
                GOVERNANCE_CANISTER_ID.get(),
                CYCLES_MINTING_CANISTER_ID,
                "change_subnet_type_assignment".to_string(),
                Encode!(&change_subnet_type_assignment_args).unwrap(),
            );
        }
    }

    // This function should only be called for ingress messages that complete quickly
    // (within 100 rounds).
    fn execute_ingress_on(
        &self,
        subnet: Arc<Subnet>,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: String,
        payload: Vec<u8>,
    ) {
        let msg_id = subnet
            .state_machine
            .submit_ingress_as(sender, canister_id, &method, payload)
            .unwrap();
        for _ in 0..100 {
            for subnet in self.get_all() {
                subnet.state_machine.execute_round();
            }
            match subnet.state_machine.ingress_status(&msg_id) {
                IngressStatus::Known {
                    state: IngressState::Completed(_),
                    ..
                } => return,
                IngressStatus::Known {
                    state: IngressState::Failed(error),
                    ..
                } => panic!(
                    "Failed to execute method {} on canister {}: {}",
                    method, canister_id, error
                ),
                _ => (),
            }
        }
        panic!(
            "Failed to complete execution of method {} on canister {} after 100 rounds.",
            method, canister_id
        );
    }
}

pub struct PocketIc {
    range_gen: RangeGen,
    runtime: Arc<Runtime>,
    state_label: StateLabel,
    subnets: PocketIcSubnets,
    default_effective_canister_id: Principal,
}

impl Drop for PocketIc {
    fn drop(&mut self) {
        if self.subnets.state_dir.is_some() {
            let subnets = self.subnets.get_all();
            for subnet in &subnets {
                subnet.state_machine.checkpointed_tick();
            }
            for subnet in &subnets {
                subnet.state_machine.await_state_hash();
            }
            self.subnets
                .persist_topology(self.default_effective_canister_id);
        }
        for subnet in self.subnets.get_all() {
            subnet.state_machine.drop_payload_builder();
        }
        let state_machines: Vec<_> = self
            .subnets
            .get_all()
            .into_iter()
            .map(|subnet| subnet.state_machine.clone())
            .collect();
        self.subnets.clear();
        // for every StateMachine, wait until nobody else has an Arc to that StateMachine
        // and then drop that StateMachine
        let start = std::time::Instant::now();
        for state_machine in state_machines {
            let mut state_machine = Some(state_machine);
            while state_machine.is_some() {
                match Arc::try_unwrap(state_machine.take().unwrap()) {
                    Ok(sm) => {
                        sm.drop();
                        break;
                    }
                    Err(sm) => {
                        state_machine = Some(sm);
                    }
                }
                if start.elapsed() > std::time::Duration::from_secs(5 * 60) {
                    panic!("Timed out while dropping PocketIC.");
                }
            }
        }
    }
}

impl PocketIc {
    pub(crate) fn topology(&self) -> Topology {
        let mut subnet_configs = BTreeMap::new();
        for config in self.subnets.subnet_configs.iter() {
            // What will be returned to the client:
            let mut canister_ranges: Vec<rest::CanisterIdRange> =
                config.ranges.iter().map(from_range).collect();
            if let Some(alloc_range) = config.alloc_range {
                canister_ranges.push(from_range(&alloc_range));
            }
            let subnet_seed = compute_subnet_seed(config.ranges.clone(), config.alloc_range);
            let subnet_config = pocket_ic::common::rest::SubnetConfig {
                subnet_kind: config.subnet_kind,
                subnet_seed,
                node_ids: self
                    .subnets
                    .get(config.subnet_id)
                    .unwrap()
                    .nodes
                    .iter()
                    .map(|n| n.node_id.get().0.into())
                    .collect(),
                canister_ranges,
                instruction_config: config.instruction_config.clone(),
            };
            subnet_configs.insert(config.subnet_id.get().into(), subnet_config);
        }
        Topology {
            subnet_configs,
            default_effective_canister_id: self.default_effective_canister_id.into(),
        }
    }

    pub(crate) fn try_new(
        runtime: Arc<Runtime>,
        seed: u64,
        mut subnet_configs: ExtendedSubnetConfigSet,
        state_dir: Option<PathBuf>,
        nonmainnet_features: bool,
        log_level: Option<Level>,
        bitcoind_addr: Option<Vec<SocketAddr>>,
        icp_features: Option<IcpFeatures>,
        allow_corrupted_state: Option<bool>,
    ) -> Result<Self, String> {
        if let Some(ref icp_features) = icp_features {
            subnet_configs = subnet_configs.try_with_icp_features(icp_features)?;
        }

        let registry: Option<Vec<u8>> = if let Some(ref state_dir) = state_dir {
            let registry_file_path = state_dir.join("registry.proto");
            File::open(registry_file_path).ok().map(|file| {
                let mut reader = BufReader::new(file);
                let mut buffer = Vec::new();
                reader.read_to_end(&mut buffer).unwrap();
                buffer
            })
        } else {
            None
        };

        let topology: Option<RawTopologyInternal> = if let Some(ref state_dir) = state_dir {
            let topology_file_path = state_dir.join("topology.json");
            File::open(topology_file_path).ok().map(|file| {
                let reader = BufReader::new(file);
                serde_json::from_reader(reader).unwrap()
            })
        } else {
            None
        };

        let icp_features = topology
            .as_ref()
            .map(|topology| topology.icp_features.clone())
            .unwrap_or(icp_features);
        let synced_registry_version = topology
            .as_ref()
            .and_then(|topology| topology.synced_registry_version);

        let mut range_gen = RangeGen::new();

        let mut subnet_config_info: Vec<SubnetConfigInfo> = if let Some(topology) = topology {
            topology
                .subnet_configs
                .into_iter()
                .map(|config| {
                    range_gen.add_assigned(config.ranges.clone()).unwrap();
                    if let Some(allocation_range) = config.alloc_range {
                        range_gen.add_assigned(vec![allocation_range]).unwrap();
                    }
                    let time = if let Some(true) = allow_corrupted_state {
                        None
                    } else {
                        Some(topology.time)
                    };
                    SubnetConfigInfo {
                        ranges: config.ranges,
                        alloc_range: config.alloc_range,
                        subnet_id: Some(config.subnet_id),
                        subnet_state_dir: None,
                        subnet_kind: config.subnet_kind,
                        instruction_config: config.instruction_config,
                        time,
                    }
                })
                .collect()
        } else {
            let fixed_range_subnets = subnet_configs.get_named();
            let flexible_subnets = {
                let sys = subnet_configs.system.iter().map(|spec| {
                    (
                        SubnetKind::System,
                        spec.get_state_path(),
                        spec.get_instruction_config(),
                    )
                });
                let app = subnet_configs.application.iter().map(|spec| {
                    (
                        SubnetKind::Application,
                        spec.get_state_path(),
                        spec.get_instruction_config(),
                    )
                });
                let verified_app = subnet_configs.verified_application.iter().map(|spec| {
                    (
                        SubnetKind::VerifiedApplication,
                        spec.get_state_path(),
                        spec.get_instruction_config(),
                    )
                });
                sys.chain(app).chain(verified_app)
            };

            let mut all_subnets: Vec<_> = fixed_range_subnets
                .into_iter()
                .chain(flexible_subnets)
                .collect();

            // we sort subnets with a given state first
            // so that their canister ranges do not conflict with canister ranges
            // of fresh subnets (which are more flexible)
            all_subnets.sort_by(
                |(_, a, _): &(_, Option<PathBuf>, _), (_, b, _): &(_, Option<PathBuf>, _)| {
                    a.is_none().cmp(&b.is_none())
                },
            );

            let mut subnet_config_info: Vec<SubnetConfigInfo> = vec![];

            for (subnet_kind, subnet_state_dir, instruction_config) in all_subnets {
                let (ranges, alloc_range, subnet_id) = if let Some(ref subnet_state_dir) =
                    subnet_state_dir
                {
                    match std::fs::read_dir(subnet_state_dir) {
                        // Return a comprehensible error if the provided state directory is not a (readable) directory.
                        Err(err) => {
                            return Err(format!(
                                "The path {} is not a (subnet state) directory: {}",
                                subnet_state_dir.display(),
                                err,
                            ));
                        }
                        Ok(mut dir) => {
                            // Return a comprehensible error if the provided state directory is empty.
                            if dir.next().is_none() {
                                return Err(format!(
                                    "Provided an empty state directory at path {}.",
                                    subnet_state_dir.display()
                                ));
                            }
                        }
                    };

                    let metadata = {
                        // We create a temporary state manager used to read the given state metadata.
                        // We first copy the subnet state directory into a temporary directory
                        // so that the temporary state manager has a private copy
                        // of the subnet state directory (otherwise, it might crash).
                        let temp_state_dir = TempDir::new().unwrap();
                        copy_dir(subnet_state_dir, temp_state_dir.path())
                            .expect("Failed to copy state directory");
                        let state_manager = StateManagerImpl::new(
                            Arc::new(FakeVerifier),
                            SubnetId::new(PrincipalId::default()),
                            conv_type(subnet_kind),
                            no_op_logger(),
                            &MetricsRegistry::new(),
                            &ic_config::state_manager::Config::new(
                                temp_state_dir.path().to_path_buf(),
                            ),
                            None,
                            MaliciousFlags::default(),
                        );
                        let metadata = state_manager.get_latest_state().take().metadata.clone();
                        // Shut down the temporary state manager to avoid race conditions.
                        state_manager.flush_tip_channel();
                        metadata
                    };

                    let subnet_id = metadata.own_subnet_id;
                    let ranges: Vec<_> = metadata
                        .network_topology
                        .routing_table
                        .ranges(subnet_id)
                        .iter()
                        .cloned()
                        .collect();
                    range_gen.add_assigned(ranges.clone())?;

                    // We validate the given canister ranges.
                    let mut sorted_ranges = ranges.clone();
                    sorted_ranges.sort();
                    if let Some(mut subnet_kind_ranges) = subnet_kind_canister_range(subnet_kind) {
                        subnet_kind_ranges.sort();
                        if !is_subset_of(subnet_kind_ranges.iter(), sorted_ranges.iter()) {
                            return Err(format!("The actual subnet canister ranges {:?} do not contain the canister ranges {:?} expected for the subnet kind {:?}.", sorted_ranges, subnet_kind_ranges, subnet_kind));
                        }
                    }
                    for other_subnet_kind in SubnetKind::iter() {
                        if subnet_kind != other_subnet_kind {
                            if let Some(mut other_subnet_kind_ranges) =
                                subnet_kind_canister_range(other_subnet_kind)
                            {
                                other_subnet_kind_ranges.sort();
                                if !are_disjoint(
                                    other_subnet_kind_ranges.iter(),
                                    sorted_ranges.iter(),
                                ) {
                                    return Err(format!("The actual subnet canister ranges {:?} for the subnet kind {:?} are not disjoint from the canister ranges {:?} for a different subnet kind {:?}.", sorted_ranges, subnet_kind, other_subnet_kind_ranges, other_subnet_kind));
                                }
                            }
                        }
                    }

                    (ranges, None, Some(subnet_id))
                } else {
                    let RangeConfig {
                        canister_id_ranges: ranges,
                        canister_allocation_range: alloc_range,
                    } = get_range_config(subnet_kind, &mut range_gen)?;

                    (ranges, alloc_range, None)
                };

                subnet_config_info.push(SubnetConfigInfo {
                    ranges,
                    alloc_range,
                    subnet_id,
                    subnet_state_dir,
                    subnet_kind,
                    instruction_config,
                    time: None,
                });
            }

            subnet_config_info
        };

        // NNS subnet must be sorted first
        subnet_config_info.sort_by(|subnet_config_info1, subnet_config_info2| {
            let non_nns1 = !matches!(subnet_config_info1.subnet_kind, SubnetKind::NNS);
            let non_nns2 = !matches!(subnet_config_info2.subnet_kind, SubnetKind::NNS);
            non_nns1.cmp(&non_nns2)
        });

        // Create all subnets and store their configs.
        let mut subnets = PocketIcSubnets::new(
            runtime.clone(),
            state_dir,
            nonmainnet_features,
            log_level,
            bitcoind_addr,
            icp_features,
            synced_registry_version,
        );
        let mut subnet_configs = Vec::new();
        for subnet_config_info in subnet_config_info.into_iter() {
            let subnet_config_internal = subnets.create_subnet(subnet_config_info)?;
            subnet_configs.push(subnet_config_internal);
        }

        if let Some(registry) = registry {
            let mut buffer = Vec::new();
            subnets.registry_data_provider.encode(&mut buffer);
            if registry != buffer {
                return Err("Registry could not be restored.".to_string());
            }
        }

        let default_effective_canister_id = subnet_configs
            .iter()
            .find(|config| config.subnet_kind == SubnetKind::Application)
            .unwrap_or_else(|| {
                subnet_configs
                    .iter()
                    .find(|config| config.subnet_kind == SubnetKind::VerifiedApplication)
                    .unwrap_or_else(|| {
                        subnet_configs
                            .iter()
                            .find(|config| config.subnet_kind == SubnetKind::System)
                            .unwrap_or_else(|| subnet_configs.first().unwrap())
                    })
            })
            .default_effective_canister_id();

        subnets.persist_topology(default_effective_canister_id);

        let state_label = StateLabel::new(seed);

        Ok(Self {
            range_gen,
            runtime,
            state_label,
            subnets,
            default_effective_canister_id,
        })
    }

    pub(crate) fn bump_state_label(&mut self) {
        self.state_label.bump();
    }

    fn try_route_canister(&self, canister_id: CanisterId) -> Option<Arc<StateMachine>> {
        self.subnets.route(canister_id)
    }

    fn nns_subnet(&self) -> Option<Arc<StateMachine>> {
        self.subnets.get_nns()
    }

    fn get_nns_delegation_for_subnet(&self, subnet_id: SubnetId) -> Option<CertificateDelegation> {
        let nns_subnet = match self.nns_subnet() {
            Some(nns_subnet) => nns_subnet,
            None => {
                return None;
            }
        };
        if nns_subnet.get_subnet_id() == subnet_id {
            None
        } else {
            nns_subnet.get_delegation_for_subnet(subnet_id).ok()
        }
    }
}

impl HasStateLabel for PocketIc {
    fn get_state_label(&self) -> StateLabel {
        self.state_label.clone()
    }
}

fn conv_type(inp: rest::SubnetKind) -> SubnetType {
    use rest::SubnetKind::*;
    match inp {
        Application | Fiduciary | SNS => SubnetType::Application,
        Bitcoin | II | NNS | System => SubnetType::System,
        VerifiedApplication => SubnetType::VerifiedApplication,
    }
}

fn subnet_size(subnet: SubnetKind) -> u64 {
    use rest::SubnetKind::*;
    match subnet {
        Application => 13,
        VerifiedApplication => 13,
        Fiduciary => 34,
        SNS => 34,
        Bitcoin => 13,
        II => 34,
        NNS => 40,
        System => 13,
    }
}

fn from_range(range: &CanisterIdRange) -> rest::CanisterIdRange {
    let CanisterIdRange { start, end } = range;
    let start = start.get().0.into();
    let end = end.get().0.into();
    rest::CanisterIdRange { start, end }
}

fn subnet_kind_canister_range(subnet_kind: SubnetKind) -> Option<Vec<CanisterIdRange>> {
    use rest::SubnetKind::*;
    match subnet_kind {
        Application | VerifiedApplication | System => None,
        NNS => Some(vec![
            gen_range("rwlgt-iiaaa-aaaaa-aaaaa-cai", "renrk-eyaaa-aaaaa-aaada-cai"),
            gen_range("qoctq-giaaa-aaaaa-aaaea-cai", "n5n4y-3aaaa-aaaaa-p777q-cai"),
        ]),
        II => Some(vec![
            gen_range("rdmx6-jaaaa-aaaaa-aaadq-cai", "rdmx6-jaaaa-aaaaa-aaadq-cai"),
            gen_range("uc7f6-kaaaa-aaaaq-qaaaa-cai", "ijz7v-ziaaa-aaaaq-7777q-cai"),
        ]),
        Bitcoin => Some(vec![gen_range(
            "g3wsl-eqaaa-aaaan-aaaaa-cai",
            "2qqia-xyaaa-aaaan-p777q-cai",
        )]),
        Fiduciary => Some(vec![gen_range(
            "mf7xa-laaaa-aaaar-qaaaa-cai",
            "qoznl-yiaaa-aaaar-7777q-cai",
        )]),
        SNS => Some(vec![gen_range(
            "ybpmr-kqaaa-aaaaq-aaaaa-cai",
            "ekjw2-zyaaa-aaaaq-p777q-cai",
        )]),
    }
}

fn subnet_kind_from_canister_id(canister_id: CanisterId) -> SubnetKind {
    use rest::SubnetKind::*;
    for subnet_kind in [NNS, II, Bitcoin, Fiduciary, SNS] {
        if let Some(ranges) = subnet_kind_canister_range(subnet_kind) {
            if ranges.iter().any(|r| r.contains(&canister_id)) {
                return subnet_kind;
            }
        }
    }
    Application
}

fn get_range_config(
    subnet_kind: rest::SubnetKind,
    range_gen: &mut RangeGen,
) -> Result<RangeConfig, String> {
    let (canister_id_ranges, canister_allocation_range) =
        match subnet_kind_canister_range(subnet_kind) {
            Some(ranges) => {
                range_gen.add_assigned(ranges.clone())?;
                (ranges, Some(range_gen.next_range()))
            }
            None => (vec![range_gen.next_range()], None),
        };
    Ok(RangeConfig {
        canister_id_ranges,
        canister_allocation_range,
    })
}

/// A stateful helper for finding available canister ranges.
#[derive(Default)]
struct RangeGen {
    already_assigned: Vec<CanisterIdRange>,
    range_offset: u64,
}

impl RangeGen {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_assigned(&mut self, mut assigned: Vec<CanisterIdRange>) -> Result<(), String> {
        assigned.sort();
        if !are_disjoint(self.already_assigned.iter(), assigned.iter()) {
            return Err("Invalid canister ranges.".to_string());
        }
        self.already_assigned.extend(assigned);
        self.already_assigned.sort();
        Ok(())
    }

    /// Returns the next canister id range from the top
    pub fn next_range(&mut self) -> CanisterIdRange {
        loop {
            let offset = (u64::MAX / CANISTER_IDS_PER_SUBNET) - 1 - self.range_offset;
            self.range_offset += 1;
            let start = offset * CANISTER_IDS_PER_SUBNET;
            let end = ((offset + 1) * CANISTER_IDS_PER_SUBNET) - 1;
            let range = CanisterIdRange {
                start: CanisterId::from_u64(start),
                end: CanisterId::from_u64(end),
            };
            if are_disjoint(self.already_assigned.iter(), [range].iter()) {
                break range;
            }
        }
    }
}

fn gen_range(start: &str, end: &str) -> CanisterIdRange {
    CanisterIdRange {
        start: CanisterId::from_str(start).unwrap(),
        end: CanisterId::from_str(end).unwrap(),
    }
}

struct RangeConfig {
    /// Ranges for manual allocation where the user provides a canister_id.
    pub canister_id_ranges: Vec<CanisterIdRange>,
    /// Range for automatic allocation: The management canister chooses
    /// a canister_id from this range.
    pub canister_allocation_range: Option<CanisterIdRange>,
}

/// Internal struct used during initialization.
struct SubnetConfigInfo {
    pub ranges: Vec<CanisterIdRange>,
    pub alloc_range: Option<CanisterIdRange>,
    pub subnet_id: Option<SubnetId>,
    pub subnet_state_dir: Option<PathBuf>,
    pub subnet_kind: SubnetKind,
    pub instruction_config: SubnetInstructionConfig,
    pub time: Option<SystemTime>,
}

// ---------------------------------------------------------------------------------------- //
// Operations on PocketIc

// When raw (rest) types are cast to operations, errors can occur.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConversionError {
    message: String,
}

#[derive(Clone, Debug)]
pub struct SetTime {
    pub time: Time,
}

fn set_time(pic: &mut PocketIc, time: Time, certified: bool) -> OpOut {
    // Time is kept in sync across subnets, so one can take any subnet.
    let current_time: SystemTime = pic.subnets.time();
    let set_time: SystemTime = time.into();
    match current_time.cmp(&set_time) {
        std::cmp::Ordering::Greater => OpOut::Error(PocketIcError::SettingTimeIntoPast((
            systemtime_to_unix_epoch_nanos(current_time),
            systemtime_to_unix_epoch_nanos(set_time),
        ))),
        std::cmp::Ordering::Equal => OpOut::NoOutput,
        std::cmp::Ordering::Less => {
            // Sets the time on all subnets.
            for subnet in pic.subnets.get_all() {
                if certified {
                    subnet.state_machine.set_certified_time(set_time);
                } else {
                    subnet.state_machine.set_time(set_time);
                }
            }
            OpOut::NoOutput
        }
    }
}

impl Operation for SetTime {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        set_time(pic, self.time, false)
    }

    fn id(&self) -> OpId {
        OpId(format!("set_time_{}", self.time))
    }
}

#[derive(Clone, Debug)]
pub struct SetCertifiedTime {
    pub time: Time,
}

impl Operation for SetCertifiedTime {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        set_time(pic, self.time, true)
    }

    fn id(&self) -> OpId {
        OpId(format!("set_certified_time_{}", self.time))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct GetTopology;

impl Operation for GetTopology {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        OpOut::Topology(pic.topology())
    }

    fn retry_if_busy(&self) -> bool {
        true
    }

    fn id(&self) -> OpId {
        OpId("get_topology".into())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct GetTime;

impl Operation for GetTime {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        // Time is kept in sync across subnets, so one can take any subnet.
        let nanos = systemtime_to_unix_epoch_nanos(pic.subnets.time());
        OpOut::Time(nanos)
    }

    fn id(&self) -> OpId {
        OpId("get_time".into())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct GetCanisterHttp;

fn http_method_from(
    http_method: &ic_types::canister_http::CanisterHttpMethod,
) -> CanisterHttpMethod {
    match http_method {
        ic_types::canister_http::CanisterHttpMethod::GET => CanisterHttpMethod::GET,
        ic_types::canister_http::CanisterHttpMethod::POST => CanisterHttpMethod::POST,
        ic_types::canister_http::CanisterHttpMethod::HEAD => CanisterHttpMethod::HEAD,
    }
}

fn http_header_from(
    http_header: &ic_types::canister_http::CanisterHttpHeader,
) -> CanisterHttpHeader {
    CanisterHttpHeader {
        name: http_header.name.clone(),
        value: http_header.value.clone(),
    }
}

fn get_canister_http_requests(pic: &PocketIc) -> Vec<CanisterHttpRequest> {
    let mut res = vec![];
    for subnet in pic.subnets.get_all() {
        let subnet_id = subnet.get_subnet_id().get().0;
        let canister_http = subnet.canister_http.lock().unwrap();
        let mut cur: Vec<_> = subnet
            .state_machine
            .canister_http_request_contexts()
            .into_iter()
            .filter(|(id, _)| !canister_http.pending.contains(id))
            .map(|(id, c)| CanisterHttpRequest {
                subnet_id,
                request_id: id.get(),
                http_method: http_method_from(&c.http_method),
                url: c.url,
                headers: c.headers.iter().map(http_header_from).collect(),
                body: c.body.unwrap_or_default(),
                max_response_bytes: c.max_response_bytes.map(|b| b.get()),
            })
            .collect();
        res.append(&mut cur);
    }
    res
}

impl Operation for GetCanisterHttp {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let canister_http_requests = get_canister_http_requests(pic);
        OpOut::CanisterHttp(canister_http_requests)
    }

    fn id(&self) -> OpId {
        OpId("get_canister_http".into())
    }
}

/// The operation `ProcessCanisterHttpInternal` changes the instance state in a non-deterministic way!
/// It should only be used internally in auto-progress mode
/// which changes the instance state in a non-deterministic way anyway.
#[derive(Copy, Clone, Debug)]
pub struct ProcessCanisterHttpInternal;

impl Operation for ProcessCanisterHttpInternal {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        for subnet in pic.subnets.get_all() {
            let sm = subnet.state_machine.clone();
            let mut canister_http = subnet.canister_http.lock().unwrap();
            let new_requests: Vec<_> = sm
                .canister_http_request_contexts()
                .into_iter()
                .filter(|(id, _)| !canister_http.pending.contains(id))
                .collect();
            let client = canister_http.client.clone();
            let mut client = client.lock().unwrap();
            for (id, context) in new_requests {
                if let Ok(()) = client.send(AdapterCanisterHttpRequest {
                    timeout: context.time + Duration::from_secs(5 * 60),
                    id,
                    context,
                    socks_proxy_addrs: vec![],
                }) {
                    canister_http.pending.insert(id);
                }
            }
            loop {
                match client.try_receive() {
                    Err(_) => {
                        break;
                    }
                    Ok(response) => {
                        canister_http.pending.remove(&response.id);
                        if let Some(context) = sm.canister_http_request_contexts().get(&response.id)
                        {
                            sm.mock_canister_http_response(
                                response.id.get(),
                                response.timeout,
                                context.request.sender,
                                vec![response.content; sm.nodes.len()],
                            );
                        }
                    }
                }
            }
        }
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId("process_canister_http_internal".into())
    }
}

// START COPY from rs/https_outcalls/client/src/client.rs

#[derive(Clone)]
pub struct SingleResponseAdapter {
    response: Result<HttpsOutcallResponse, (Code, String)>,
}

impl SingleResponseAdapter {
    fn new(response: Result<HttpsOutcallResponse, (Code, String)>) -> Self {
        Self { response }
    }
}

#[async_trait::async_trait]
impl HttpsOutcallsService for SingleResponseAdapter {
    async fn https_outcall(
        &self,
        _request: Request<HttpsOutcallRequest>,
    ) -> Result<Response<HttpsOutcallResponse>, Status> {
        match self.response.clone() {
            Ok(resp) => Ok(Response::new(resp)),
            Err((code, msg)) => Err(Status::new(code, msg)),
        }
    }
}

async fn setup_adapter_mock(
    adapter_response: Result<HttpsOutcallResponse, (Code, String)>,
) -> Channel {
    let (client, server) = tokio::io::duplex(1024);
    let mock_adapter = SingleResponseAdapter::new(adapter_response);
    tokio::spawn(async move {
        Server::builder()
            .add_service(HttpsOutcallsServiceServer::new(mock_adapter))
            .serve_with_incoming(futures::stream::iter(vec![Ok::<_, std::io::Error>(server)]))
            .await
    });

    let mut client = Some(client);
    Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let client = client.take();

            async move {
                if let Some(client) = client {
                    Ok(hyper_util::rt::TokioIo::new(client))
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Client already taken",
                    ))
                }
            }
        }))
        .await
        .unwrap()
}

// END COPY

fn process_mock_canister_https_response(
    pic: &PocketIc,
    mock_canister_http_response: &MockCanisterHttpResponse,
) -> OpOut {
    let response_to_reject_code = |response: &CanisterHttpResponse| match response {
        CanisterHttpResponse::CanisterHttpReply(_) => None,
        CanisterHttpResponse::CanisterHttpReject(reject) => Some(reject.reject_code),
    };
    let mut reject_codes: Vec<_> = mock_canister_http_response
        .additional_responses
        .iter()
        .filter_map(response_to_reject_code)
        .collect();
    if let Some(reject_code) = response_to_reject_code(&mock_canister_http_response.response) {
        reject_codes.push(reject_code)
    }
    for reject_code in reject_codes {
        if ic_error_types::RejectCode::try_from(reject_code).is_err() {
            return OpOut::Error(PocketIcError::InvalidRejectCode(reject_code));
        }
    }
    let subnet_id =
        ic_types::SubnetId::new(ic_types::PrincipalId(mock_canister_http_response.subnet_id));
    let Some(subnet) = pic.subnets.get(subnet_id) else {
        return OpOut::Error(PocketIcError::SubnetNotFound(
            mock_canister_http_response.subnet_id,
        ));
    };
    let canister_http_request_id =
        CanisterHttpRequestId::from(mock_canister_http_response.request_id);
    let contexts = subnet.canister_http_request_contexts();
    let Some(context) = contexts.get(&canister_http_request_id) else {
        return OpOut::Error(PocketIcError::InvalidCanisterHttpRequestId((
            subnet_id,
            canister_http_request_id,
        )));
    };
    let timeout = context.time + Duration::from_secs(5 * 60);
    let canister_id = context.request.sender;
    let delegation = pic.get_nns_delegation_for_subnet(subnet.get_subnet_id());
    let (_, delegation_rx) = watch::channel(delegation);

    let response_to_content = |response: &CanisterHttpResponse| match response {
        CanisterHttpResponse::CanisterHttpReply(reply) => {
            let grpc_channel = pic
                .runtime
                .block_on(setup_adapter_mock(Ok(HttpsOutcallResponse {
                    status: reply.status.into(),
                    headers: reply
                        .headers
                        .iter()
                        .map(|h| ic_https_outcalls_service::HttpHeader {
                            name: h.name.clone(),
                            value: h.value.clone(),
                        })
                        .collect(),
                    content: reply.body.clone(),
                })));
            let mut client = CanisterHttpAdapterClientImpl::new(
                pic.runtime.handle().clone(),
                grpc_channel,
                subnet.query_handler.lock().unwrap().clone(),
                1,
                MetricsRegistry::new(),
                subnet.get_subnet_type(),
                delegation_rx.clone(),
                subnet.replica_logger.clone(),
            );
            client
                .send(AdapterCanisterHttpRequest {
                    timeout,
                    id: canister_http_request_id,
                    context: context.clone(),
                    socks_proxy_addrs: vec![],
                })
                .unwrap();
            let response = loop {
                match client.try_receive() {
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    Ok(r) => {
                        break r;
                    }
                }
            };
            response.content
        }
        CanisterHttpResponse::CanisterHttpReject(reject) => {
            CanisterHttpResponseContent::Reject(CanisterHttpReject {
                reject_code: ic_error_types::RejectCode::try_from(reject.reject_code).unwrap(),
                message: reject.message.clone(),
            })
        }
    };
    let content = response_to_content(&mock_canister_http_response.response);
    let mut contents: Vec<_> = if !mock_canister_http_response.additional_responses.is_empty() {
        mock_canister_http_response
            .additional_responses
            .iter()
            .map(response_to_content)
            .collect()
    } else {
        vec![content.clone(); subnet.nodes.len() - 1]
    };
    contents.push(content);
    if contents.len() != subnet.nodes.len() {
        return OpOut::Error(PocketIcError::InvalidMockCanisterHttpResponses((
            contents.len(),
            subnet.nodes.len(),
        )));
    }
    subnet.mock_canister_http_response(
        mock_canister_http_response.request_id,
        timeout,
        canister_id,
        contents,
    );
    OpOut::NoOutput
}

#[derive(Clone, Debug)]
pub struct MockCanisterHttp {
    pub mock_canister_http_response: MockCanisterHttpResponse,
}

impl Operation for MockCanisterHttp {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        process_mock_canister_https_response(pic, &self.mock_canister_http_response)
    }

    fn id(&self) -> OpId {
        OpId(format!(
            "mock_canister_http({:?})",
            self.mock_canister_http_response
        ))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PubKey {
    pub subnet_id: SubnetId,
}

impl Operation for PubKey {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = pic.subnets.get(self.subnet_id);
        match subnet {
            Some(subnet) => OpOut::Bytes(subnet.root_key_der()),
            None => OpOut::Error(PocketIcError::SubnetNotFound(self.subnet_id.get().0)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("root_key_{}", self.subnet_id))
    }
}

#[derive(Clone, Debug)]
pub struct Tick {
    pub configs: TickConfigs,
}

impl Tick {
    fn validate_blockmakers_per_subnet(
        &self,
        pic: &mut PocketIc,
        subnets_blockmaker: &[SubnetBlockmaker],
    ) -> Result<(), OpOut> {
        for subnet_blockmaker in subnets_blockmaker {
            if subnet_blockmaker
                .failed_blockmakers
                .contains(&subnet_blockmaker.blockmaker)
            {
                return Err(OpOut::Error(PocketIcError::BlockmakerContainedInFailed(
                    subnet_blockmaker.blockmaker,
                )));
            }

            let Some(state_machine) = pic.subnets.get(subnet_blockmaker.subnet) else {
                return Err(OpOut::Error(PocketIcError::SubnetNotFound(
                    subnet_blockmaker.subnet.get().0,
                )));
            };

            let mut request_blockmakers = subnet_blockmaker.failed_blockmakers.clone();
            request_blockmakers.push(subnet_blockmaker.blockmaker);
            let subnet_nodes: Vec<_> = state_machine.nodes.iter().map(|n| n.node_id).collect();
            for blockmaker in request_blockmakers {
                if !subnet_nodes.contains(&blockmaker) {
                    return Err(OpOut::Error(PocketIcError::BlockmakerNotFound(blockmaker)));
                }
            }
        }
        Ok(())
    }
}

impl Operation for Tick {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let blockmakers_per_subnet = self.configs.blockmakers.as_ref().map(|cfg| {
            cfg.blockmakers_per_subnet
                .iter()
                .cloned()
                .map(SubnetBlockmaker::from)
                .collect_vec()
        });

        if let Some(ref bm_per_subnet) = blockmakers_per_subnet {
            if let Err(error) = self.validate_blockmakers_per_subnet(pic, bm_per_subnet) {
                return error;
            }
        }

        for subnet in pic.subnets.get_all() {
            let subnet_id = subnet.get_subnet_id();
            let blockmaker_metrics = blockmakers_per_subnet.as_ref().and_then(|bm_per_subnet| {
                bm_per_subnet
                    .iter()
                    .find(|bm| bm.subnet == subnet_id)
                    .map(|bm| BlockmakerMetrics {
                        blockmaker: bm.blockmaker,
                        failed_blockmakers: bm.failed_blockmakers.clone(),
                    })
            });

            match blockmaker_metrics {
                Some(metrics) => subnet
                    .state_machine
                    .execute_round_with_blockmaker_metrics(metrics),
                None => subnet.state_machine.execute_round(),
            }
        }

        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId("tick".to_string())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct AdvanceTimeAndTick(pub Duration);

impl Operation for AdvanceTimeAndTick {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        for subnet in pic.subnets.get_all() {
            subnet.state_machine.advance_time(self.0);
            subnet.state_machine.execute_round();
        }
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId(format!("advance_time_and_tick({:?})", self.0))
    }
}

#[derive(Clone, Debug)]
pub struct SubmitIngressMessage(pub CanisterCall);

impl Operation for SubmitIngressMessage {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let canister_call = self.0.clone();
        let subnet = route_call(pic, canister_call);
        match subnet {
            Ok(subnet) => {
                match subnet.submit_ingress_as(
                    self.0.sender,
                    self.0.canister_id,
                    self.0.method.clone(),
                    self.0.payload.clone(),
                ) {
                    Err(SubmitIngressError::HttpError(e)) => {
                        eprintln!("Failed to submit ingress message: {}", e);
                        OpOut::Error(PocketIcError::BadIngressMessage(e))
                    }
                    Err(SubmitIngressError::UserError(e)) => {
                        eprintln!("Failed to submit ingress message: {:?}", e);
                        OpOut::CanisterResult(Err(user_error_to_reject_response(e, false)))
                    }
                    Ok(msg_id) => OpOut::MessageId((
                        EffectivePrincipal::SubnetId(subnet.get_subnet_id()),
                        msg_id.as_bytes().to_vec(),
                    )),
                }
            }
            Err(e) => OpOut::Error(PocketIcError::BadIngressMessage(e)),
        }
    }

    fn id(&self) -> OpId {
        let call_id = self.0.id();
        OpId(format!("submit_update_{}", call_id.0))
    }
}

#[derive(Clone, Debug)]
pub struct MessageId {
    effective_principal: EffectivePrincipal,
    msg_id: OtherMessageId,
}

impl TryFrom<RawMessageId> for MessageId {
    type Error = ConversionError;
    fn try_from(
        RawMessageId {
            effective_principal,
            message_id,
        }: RawMessageId,
    ) -> Result<Self, Self::Error> {
        let effective_principal = effective_principal.try_into()?;
        let msg_id = match OtherMessageId::try_from(message_id.as_slice()) {
            Ok(msg_id) => msg_id,
            Err(_) => {
                return Err(ConversionError {
                    message: "Bad message id".to_string(),
                })
            }
        };
        Ok(MessageId {
            effective_principal,
            msg_id,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AwaitIngressMessage(pub MessageId);

impl Operation for AwaitIngressMessage {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = route(pic, self.0.effective_principal.clone(), false);
        match subnet {
            Ok(subnet) => {
                // Now, we execute on all subnets until we have the result
                let max_rounds = 100;
                for _i in 0..max_rounds {
                    match subnet.ingress_status(&self.0.msg_id) {
                        IngressStatus::Known {
                            state: IngressState::Completed(result),
                            ..
                        } => {
                            return OpOut::CanisterResult(wasm_result_to_canister_result(
                                result, true,
                            ));
                        }
                        IngressStatus::Known {
                            state: IngressState::Failed(error),
                            ..
                        } => {
                            return OpOut::CanisterResult(Err(user_error_to_reject_response(
                                error, true,
                            )));
                        }
                        _ => {}
                    }
                    for subnet_ in pic.subnets.get_all() {
                        subnet_.state_machine.execute_round();
                    }
                }
                OpOut::Error(PocketIcError::BadIngressMessage(format!(
                    "Failed to answer to ingress {} after {} rounds.",
                    self.0.msg_id, max_rounds
                )))
            }
            Err(e) => OpOut::Error(PocketIcError::BadIngressMessage(e)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("await_update_{}", self.0.msg_id))
    }
}

#[derive(Clone, Debug)]
pub struct IngressMessageStatus {
    pub message_id: MessageId,
    pub caller: Option<Principal>,
}

impl Operation for IngressMessageStatus {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = route(pic, self.message_id.effective_principal.clone(), false);
        match subnet {
            Ok(subnet) => {
                if let Some(caller) = self.caller {
                    if let Some(actual_caller) = subnet.ingress_caller(&self.message_id.msg_id) {
                        if caller != actual_caller.get().0 {
                            return OpOut::Error(PocketIcError::Forbidden(
                                "The user tries to access Request ID not signed by the caller."
                                    .to_string(),
                            ));
                        }
                    }
                }
                match subnet.ingress_status(&self.message_id.msg_id) {
                    IngressStatus::Known {
                        state: IngressState::Completed(result),
                        ..
                    } => OpOut::CanisterResult(wasm_result_to_canister_result(result, true)),
                    IngressStatus::Known {
                        state: IngressState::Failed(error),
                        ..
                    } => OpOut::CanisterResult(Err(user_error_to_reject_response(error, true))),
                    _ => OpOut::NoOutput,
                }
            }
            Err(e) => OpOut::Error(PocketIcError::BadIngressMessage(e)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!(
            "ingress_status({},{:?},{:?})",
            self.message_id.msg_id,
            self.message_id.effective_principal,
            self.caller.map(|caller| caller.to_string())
        ))
    }
}

pub struct Query(pub CanisterCall);

impl Operation for Query {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let canister_call = self.0.clone();
        let subnet = route_call(pic, canister_call);
        match subnet {
            Ok(subnet) => {
                let delegation = pic.get_nns_delegation_for_subnet(subnet.get_subnet_id());
                match subnet.query_as_with_delegation(
                    self.0.sender,
                    self.0.canister_id,
                    self.0.method.clone(),
                    self.0.payload.clone(),
                    delegation,
                ) {
                    Ok(result) => {
                        OpOut::CanisterResult(wasm_result_to_canister_result(result, false))
                    }
                    Err(user_error) => {
                        OpOut::CanisterResult(Err(user_error_to_reject_response(user_error, false)))
                    }
                }
            }
            Err(e) => OpOut::Error(PocketIcError::BadIngressMessage(e)),
        }
    }

    fn id(&self) -> OpId {
        let call_id = self.0.id();
        OpId(format!("canister_query_{}", call_id.0))
    }
}

pub struct DashboardRequest {}

impl Operation for DashboardRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnets = pic.subnets.get_all();

        // All PocketIC subnets have the same height and thus we fetch the height from an arbitrary subnet.
        let arbitrary_subnet = subnets.first().unwrap().state_machine.clone();
        let height = arbitrary_subnet.state_manager.latest_state_height();

        let states: Vec<_> = subnets
            .iter()
            .map(|subnet| {
                (
                    subnet.state_machine.state_manager.get_latest_state(),
                    subnet.get_subnet_id(),
                )
            })
            .collect();
        let canisters = states
            .iter()
            .map(|(state, subnet_id)| {
                state
                    .get_ref()
                    .canisters_iter()
                    .map(|c| (c, *subnet_id))
                    .collect::<Vec<_>>()
            })
            .concat();

        let dashboard = Dashboard {
            height,
            canisters: &canisters,
        };

        let resp = match dashboard.render() {
            Ok(content) => Html(content).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: {}", e),
            )
                .into_response(),
        };

        let fut: ApiResponse = Box::pin(into_api_response(resp));
        OpOut::RawResponse(fut.shared())
    }

    fn retry_if_busy(&self) -> bool {
        true
    }

    fn id(&self) -> OpId {
        OpId("dashboard".to_string())
    }
}

pub struct StatusRequest {
    pub bytes: Bytes,
}

struct PocketHealth;

impl Health for PocketHealth {
    fn health(&self) -> ReplicaHealthStatus {
        ReplicaHealthStatus::Healthy
    }
}

struct PocketRootKey(pub Option<Vec<u8>>);

impl RootKey for PocketRootKey {
    fn root_key(&self) -> Option<Vec<u8>> {
        self.0.clone()
    }
}

impl Operation for StatusRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let root_key_bytes = pic.nns_subnet().map(|nns_subnet| nns_subnet.root_key_der());
        let root_key = PocketRootKey(root_key_bytes);

        let resp = pic
            .runtime
            .block_on(async { status(State((Arc::new(root_key), Arc::new(PocketHealth)))).await })
            .into_response();

        let fut: ApiResponse = Box::pin(into_api_response(resp));
        OpOut::RawResponse(fut.shared())
    }

    fn retry_if_busy(&self) -> bool {
        true
    }

    fn id(&self) -> OpId {
        let mut hasher = Sha256::new();
        self.bytes.hash(&mut hasher);
        let hash = Digest(hasher.finish());
        OpId(format!("status({})", hash,))
    }
}

pub enum CallRequestVersion {
    V2,
    V3,
}

pub struct CallRequest {
    pub effective_canister_id: CanisterId,
    pub bytes: Bytes,
    pub version: CallRequestVersion,
}

#[derive(Clone)]
struct PocketIngressPoolThrottler;

impl IngressPoolThrottler for PocketIngressPoolThrottler {
    fn exceeds_threshold(&self) -> bool {
        false
    }
}

impl Operation for CallRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let is_provisional_create_canister =
            match serde_cbor::from_slice::<HttpRequestEnvelope<HttpCallContent>>(&self.bytes) {
                Ok(envelope) => {
                    let HttpCallContent::Call { update: payload } = envelope.content;
                    payload.canister_id.0 == PrincipalId::default().to_vec()
                        && Ic00Method::from_str(&payload.method_name)
                            == Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
                }
                Err(_) => false,
            };
        let subnet = route(
            pic,
            EffectivePrincipal::CanisterId(self.effective_canister_id),
            is_provisional_create_canister,
        );
        match subnet {
            Err(e) => OpOut::Error(PocketIcError::RequestRoutingError(e)),
            Ok(subnet) => {
                let node = &subnet.nodes[0];
                #[allow(clippy::disallowed_methods)]
                let (s, mut r) =
                    mpsc::unbounded_channel::<UnvalidatedArtifactMutation<SignedIngress>>();
                let ingress_filter = subnet.ingress_filter.clone();

                let ingress_validator = IngressValidatorBuilder::builder(
                    subnet.replica_logger.clone(),
                    node.node_id,
                    subnet.get_subnet_id(),
                    subnet.registry_client.clone(),
                    Arc::new(StandaloneIngressSigVerifier),
                    ingress_filter,
                    Arc::new(RwLock::new(PocketIngressPoolThrottler)),
                    s,
                )
                .with_time_source(subnet.time_source.clone())
                .build();

                // Task that waits for call service to submit the ingress message, and
                // forwards it to the state machine. The task will automatically terminate
                // once it submits an ingress message received from the call service to the
                // `StateMachine`, or if the call service is dropped (in which case `r.recv().await` returns `None`).
                let subnet_clone = subnet.clone();
                let ingress_proxy_task = pic.runtime.spawn(async move {
                    if let Some(UnvalidatedArtifactMutation::Insert((msg, _node_id))) =
                        r.recv().await
                    {
                        subnet_clone.push_signed_ingress(msg);
                    }
                });

                let svc = match self.version {
                    CallRequestVersion::V2 => call_v2::new_service(ingress_validator),
                    CallRequestVersion::V3 => {
                        let delegation = pic.get_nns_delegation_for_subnet(subnet.get_subnet_id());
                        let (_, delegation_rx) = watch::channel(delegation);
                        let metrics_registry = MetricsRegistry::new();
                        let metrics = HttpHandlerMetrics::new(&metrics_registry);

                        call_v3::new_service(
                            ingress_validator,
                            subnet.ingress_watcher_handle.clone(),
                            metrics,
                            http_handler::Config::default()
                                .ingress_message_certificate_timeout_seconds,
                            delegation_rx,
                            subnet.state_manager.clone(),
                        )
                    }
                };

                let api_version = match self.version {
                    CallRequestVersion::V2 => "v2",
                    CallRequestVersion::V3 => "v3",
                };

                let request = axum::http::Request::builder()
                    .method(Method::POST)
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .uri(format!(
                        "/api/{}/canister/{}/call",
                        api_version,
                        PrincipalId(self.effective_canister_id.get().into())
                    ))
                    .body(self.bytes.clone().into())
                    .unwrap();

                let fut: ApiResponse = Box::pin(async {
                    let resp = svc.oneshot(request).await.unwrap();
                    into_api_response(resp).await
                });
                let api_resp = fut.shared();
                let service_task = pic.runtime.spawn(api_resp.clone());

                // For the sake of determinism, we need to wait until one of
                // `service_task` or `ingress_proxy_task` terminates:
                // then all the state modifications have been performed
                // and we can return from the operation.
                while !service_task.is_finished() && !ingress_proxy_task.is_finished() {}

                OpOut::RawResponse(api_resp)
            }
        }
    }

    fn retry_if_busy(&self) -> bool {
        true
    }

    fn id(&self) -> OpId {
        let mut hasher = Sha256::new();
        self.bytes.hash(&mut hasher);
        let hash = Digest(hasher.finish());
        OpId(format!("call({},{})", self.effective_canister_id, hash,))
    }
}

pub struct QueryRequest {
    pub effective_canister_id: CanisterId,
    pub bytes: Bytes,
}

#[derive(Clone)]
struct PocketNodeSigner(pub ic_ed25519::PrivateKey);

impl BasicSigner<QueryResponseHash> for PocketNodeSigner {
    fn sign_basic(
        &self,
        message: &QueryResponseHash,
        _signer: NodeId,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<QueryResponseHash>> {
        Ok(BasicSigOf::new(BasicSig(
            self.0.sign_message(&message.as_signed_bytes()).to_vec(),
        )))
    }
}

impl Operation for QueryRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = route(
            pic,
            EffectivePrincipal::CanisterId(self.effective_canister_id),
            false,
        );
        match subnet {
            Err(e) => OpOut::Error(PocketIcError::RequestRoutingError(e)),
            Ok(subnet) => {
                let delegation = pic.get_nns_delegation_for_subnet(subnet.get_subnet_id());
                let (_, delegation_rx) = watch::channel(delegation);
                let node = &subnet.nodes[0];
                subnet.certify_latest_state();
                let query_handler = subnet.query_handler.lock().unwrap().clone();
                let svc = QueryServiceBuilder::builder(
                    subnet.replica_logger.clone(),
                    node.node_id,
                    Arc::new(PocketNodeSigner(node.node_signing_key.clone())),
                    subnet.registry_client.clone(),
                    Arc::new(StandaloneIngressSigVerifier),
                    delegation_rx,
                    query_handler,
                )
                .with_time_source(subnet.time_source.clone())
                .build_service();

                let request = axum::http::Request::builder()
                    .method(Method::POST)
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .uri(format!(
                        "/api/v2/canister/{}/query",
                        PrincipalId(self.effective_canister_id.get().into())
                    ))
                    .body(self.bytes.clone().into())
                    .unwrap();
                let resp = pic.runtime.block_on(svc.oneshot(request)).unwrap();

                let fut: ApiResponse = Box::pin(into_api_response(resp));
                OpOut::RawResponse(fut.shared())
            }
        }
    }

    fn retry_if_busy(&self) -> bool {
        true
    }

    fn id(&self) -> OpId {
        let mut hasher = Sha256::new();
        self.bytes.hash(&mut hasher);
        let hash = Digest(hasher.finish());
        OpId(format!("query({},{})", self.effective_canister_id, hash,))
    }
}

#[derive(Debug)]
pub struct CanisterReadStateRequest {
    pub effective_canister_id: CanisterId,
    pub bytes: Bytes,
}

impl Operation for CanisterReadStateRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        match route(
            pic,
            EffectivePrincipal::CanisterId(self.effective_canister_id),
            false,
        ) {
            Err(e) => OpOut::Error(PocketIcError::RequestRoutingError(e)),
            Ok(subnet) => {
                let delegation = pic.get_nns_delegation_for_subnet(subnet.get_subnet_id());
                let (_, delegation_rx) = watch::channel(delegation);
                subnet.certify_latest_state();
                let svc = CanisterReadStateServiceBuilder::builder(
                    subnet.replica_logger.clone(),
                    subnet.state_manager.clone(),
                    subnet.registry_client.clone(),
                    Arc::new(StandaloneIngressSigVerifier),
                    delegation_rx,
                )
                .with_time_source(subnet.time_source.clone())
                .build_service();

                let request = axum::http::Request::builder()
                    .method(Method::POST)
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .uri(format!(
                        "/api/v2/canister/{}/read_state",
                        PrincipalId(self.effective_canister_id.get().into())
                    ))
                    .body(self.bytes.clone().into())
                    .unwrap();
                let resp = pic.runtime.block_on(svc.oneshot(request)).unwrap();

                let fut: ApiResponse = Box::pin(into_api_response(resp));
                OpOut::RawResponse(fut.shared())
            }
        }
    }

    fn retry_if_busy(&self) -> bool {
        true
    }

    fn id(&self) -> OpId {
        let mut hasher = Sha256::new();
        self.bytes.hash(&mut hasher);
        let hash = Digest(hasher.finish());
        OpId(format!(
            "canister_read_state({},{})",
            self.effective_canister_id, hash,
        ))
    }
}

#[derive(Debug)]
pub struct SubnetReadStateRequest {
    pub subnet_id: SubnetId,
    pub bytes: Bytes,
}

impl Operation for SubnetReadStateRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        match route(pic, EffectivePrincipal::SubnetId(self.subnet_id), false) {
            Err(e) => OpOut::Error(PocketIcError::RequestRoutingError(e)),
            Ok(subnet) => {
                let delegation = pic.get_nns_delegation_for_subnet(subnet.get_subnet_id());
                let (_, delegation_rx) = watch::channel(delegation);
                subnet.certify_latest_state();
                let svc = SubnetReadStateServiceBuilder::builder(
                    delegation_rx,
                    subnet.state_manager.clone(),
                )
                .build_service();

                let request = axum::http::Request::builder()
                    .method(Method::POST)
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .uri(format!(
                        "/api/v2/subnet/{}/read_state",
                        PrincipalId(self.subnet_id.get().into())
                    ))
                    .body(self.bytes.clone().into())
                    .unwrap();
                let resp = pic.runtime.block_on(svc.oneshot(request)).unwrap();

                let fut: ApiResponse = Box::pin(into_api_response(resp));
                OpOut::RawResponse(fut.shared())
            }
        }
    }

    fn retry_if_busy(&self) -> bool {
        true
    }

    fn id(&self) -> OpId {
        let mut hasher = Sha256::new();
        self.bytes.hash(&mut hasher);
        let hash = Digest(hasher.finish());
        OpId(format!("subnet_read_state({},{})", self.subnet_id, hash,))
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub enum EffectivePrincipal {
    None,
    SubnetId(SubnetId),
    CanisterId(CanisterId),
}

impl TryFrom<RawEffectivePrincipal> for EffectivePrincipal {
    type Error = ConversionError;
    fn try_from(effective_principal: RawEffectivePrincipal) -> Result<Self, Self::Error> {
        match effective_principal {
            RawEffectivePrincipal::SubnetId(subnet_id) => {
                let sid = PrincipalId::try_from(subnet_id);
                match sid {
                    Ok(sid) => Ok(EffectivePrincipal::SubnetId(SubnetId::new(sid))),
                    Err(_) => Err(ConversionError {
                        message: "Bad subnet id".to_string(),
                    }),
                }
            }
            RawEffectivePrincipal::CanisterId(canister_id) => {
                match CanisterId::try_from(canister_id) {
                    Ok(canister_id) => Ok(EffectivePrincipal::CanisterId(canister_id)),
                    Err(_) => Err(ConversionError {
                        message: "Bad effective canister id".to_string(),
                    }),
                }
            }
            RawEffectivePrincipal::None => Ok(EffectivePrincipal::None),
        }
    }
}

impl From<EffectivePrincipal> for RawEffectivePrincipal {
    fn from(effective_principal: EffectivePrincipal) -> Self {
        match effective_principal {
            EffectivePrincipal::None => RawEffectivePrincipal::None,
            EffectivePrincipal::CanisterId(canister_id) => {
                RawEffectivePrincipal::CanisterId(canister_id.get().to_vec())
            }
            EffectivePrincipal::SubnetId(subnet_id) => {
                RawEffectivePrincipal::SubnetId(subnet_id.get().to_vec())
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct CanisterCall {
    pub effective_principal: EffectivePrincipal,
    pub sender: PrincipalId,
    pub canister_id: CanisterId,
    pub method: String,
    pub payload: Vec<u8>,
}

impl TryFrom<RawCanisterCall> for CanisterCall {
    type Error = ConversionError;
    fn try_from(
        RawCanisterCall {
            sender,
            canister_id,
            method,
            payload,
            effective_principal,
        }: RawCanisterCall,
    ) -> Result<Self, Self::Error> {
        let effective_principal = effective_principal.try_into()?;
        let sender = match PrincipalId::try_from(sender) {
            Ok(sender) => sender,
            Err(_) => {
                return Err(ConversionError {
                    message: "Bad sender principal".to_string(),
                })
            }
        };
        let canister_id = match CanisterId::try_from(canister_id) {
            Ok(canister_id) => canister_id,
            Err(_) => {
                return Err(ConversionError {
                    message: "Bad canister id".to_string(),
                })
            }
        };

        Ok(CanisterCall {
            effective_principal,
            sender,
            canister_id,
            method,
            payload,
        })
    }
}

impl CanisterCall {
    fn id(&self) -> OpId {
        let mut hasher = Sha256::new();
        hasher.write(&self.payload);
        let hash = Digest(hasher.finish());
        OpId(format!(
            "call({:?},{},{},{},{})",
            self.effective_principal, self.sender, self.canister_id, self.method, hash
        ))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SetStableMemory {
    pub canister_id: CanisterId,
    pub data: Vec<u8>,
}

impl SetStableMemory {
    pub async fn from_store(
        raw: RawSetStableMemory,
        store: Arc<dyn BlobStore>,
    ) -> Result<Self, ConversionError> {
        if let Ok(canister_id) = CanisterId::try_from(raw.canister_id) {
            if let Some(BinaryBlob { data, compression }) = store.fetch(raw.blob_id).await {
                if let Some(data) = decompress(data, compression) {
                    Ok(SetStableMemory { canister_id, data })
                } else {
                    Err(ConversionError {
                        message: "Decompression failed".to_string(),
                    })
                }
            } else {
                Err(ConversionError {
                    message: "Bad blob id".to_string(),
                })
            }
        } else {
            Err(ConversionError {
                message: "Bad canister id".to_string(),
            })
        }
    }
}

fn decompress(data: Vec<u8>, compression: BlobCompression) -> Option<Vec<u8>> {
    use std::io::Read;
    match compression {
        BlobCompression::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(&data[..]);
            let mut out = Vec::new();
            let result = decoder.read_to_end(&mut out);
            if result.is_err() {
                return None;
            }
            Some(out)
        }
        BlobCompression::NoCompression => Some(data),
    }
}

impl Operation for SetStableMemory {
    fn compute(&self, pocket_ic: &mut PocketIc) -> OpOut {
        let subnet = pocket_ic.try_route_canister(self.canister_id);
        match subnet {
            Some(subnet) => {
                if !subnet.canister_exists(self.canister_id) {
                    OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id))
                } else if !subnet.canister_not_empty(self.canister_id) {
                    OpOut::Error(PocketIcError::CanisterIsEmpty(self.canister_id))
                } else {
                    subnet.set_stable_memory(self.canister_id, &self.data);
                    OpOut::NoOutput
                }
            }
            None => OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id)),
        }
    }

    fn id(&self) -> OpId {
        // TODO: consider tupling the hash with the data everywhere,
        // from the sender up to here. so the blobstore can be lazier,
        // we _can_ check for consistency, but we don't _have to_ re-
        // calculate it here.
        let mut hasher = Sha256::new();
        hasher.write(&self.data);
        let hash = Digest(hasher.finish());
        OpId(format!("set_stable_memory({}_{})", self.canister_id, hash))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct GetStableMemory {
    pub canister_id: CanisterId,
}

impl Operation for GetStableMemory {
    fn compute(&self, pocket_ic: &mut PocketIc) -> OpOut {
        let subnet = pocket_ic.try_route_canister(self.canister_id);
        match subnet {
            Some(subnet) => {
                if !subnet.canister_exists(self.canister_id) {
                    OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id))
                } else if !subnet.canister_not_empty(self.canister_id) {
                    OpOut::Error(PocketIcError::CanisterIsEmpty(self.canister_id))
                } else {
                    OpOut::StableMemBytes(subnet.stable_memory(self.canister_id))
                }
            }
            None => OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("get_stable_memory({})", self.canister_id))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct GetControllers {
    pub canister_id: CanisterId,
}

impl Operation for GetControllers {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = pic.try_route_canister(self.canister_id);
        match subnet {
            Some(subnet) => subnet
                .get_controllers(self.canister_id)
                .map(OpOut::Controllers)
                .unwrap_or(OpOut::Error(PocketIcError::CanisterNotFound(
                    self.canister_id,
                ))),
            None => OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("get_controllers({})", self.canister_id))
    }
}

#[derive(Clone, Debug)]
pub struct GetCyclesBalance {
    pub canister_id: CanisterId,
}

impl Operation for GetCyclesBalance {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = pic.try_route_canister(self.canister_id);
        match subnet {
            Some(subnet) => {
                if !subnet.canister_exists(self.canister_id) {
                    OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id))
                } else {
                    OpOut::Cycles(subnet.cycle_balance(self.canister_id))
                }
            }
            None => OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("get_cycles_balance({})", self.canister_id))
    }
}

#[derive(Clone, Debug)]
pub struct GetSubnet {
    pub canister_id: CanisterId,
}

impl Operation for GetSubnet {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let sm = pic.try_route_canister(self.canister_id);
        match sm {
            Some(sm) => {
                if sm.canister_exists(self.canister_id) {
                    OpOut::MaybeSubnetId(Some(sm.get_subnet_id()))
                } else {
                    OpOut::MaybeSubnetId(None)
                }
            }
            None => OpOut::MaybeSubnetId(None),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("get_subnet({})", self.canister_id))
    }
}

/// Add cycles to a given canister.
///
/// # Panics
///
/// Panics if the canister does not exist.
#[derive(Clone, Debug)]
pub struct AddCycles {
    canister_id: CanisterId,
    amount: u128,
}

impl TryFrom<RawAddCycles> for AddCycles {
    type Error = ConversionError;
    fn try_from(
        RawAddCycles {
            canister_id,
            amount,
        }: RawAddCycles,
    ) -> Result<Self, Self::Error> {
        match CanisterId::try_from(canister_id) {
            Ok(canister_id) => Ok(AddCycles {
                canister_id,
                amount,
            }),
            Err(_) => Err(ConversionError {
                message: "Bad canister id".to_string(),
            }),
        }
    }
}

impl Operation for AddCycles {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = pic.try_route_canister(self.canister_id);
        match subnet {
            Some(subnet) => {
                if !subnet.canister_exists(self.canister_id) {
                    OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id))
                } else {
                    OpOut::Cycles(subnet.add_cycles(self.canister_id, self.amount))
                }
            }
            None => OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("add_cycles({},{})", self.canister_id, self.amount))
    }
}

struct Digest([u8; 32]);

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest(")?;
        self.0.iter().try_for_each(|b| write!(f, "{:02X}", b))?;
        write!(f, ")")
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ================================================================================================================= //
// Helpers

fn route(
    pic: &mut PocketIc,
    effective_principal: EffectivePrincipal,
    is_provisional_create_canister: bool,
) -> Result<Arc<StateMachine>, String> {
    match effective_principal {
        EffectivePrincipal::SubnetId(subnet_id) => pic
            .subnets
            .get(subnet_id)
            .ok_or(format!("Subnet with ID {subnet_id} not found")),
        EffectivePrincipal::CanisterId(canister_id) => match pic.try_route_canister(canister_id) {
            Some(subnet) => Ok(subnet),
            None => {
                // Canisters created via `provisional_create_canister_with_cycles`
                // with the management canister ID as the effective canister ID
                // are created on the subnet with the default effective canister ID.
                if is_provisional_create_canister && canister_id == CanisterId::ic_00() {
                    Ok(pic
                        .try_route_canister(
                            PrincipalId(pic.default_effective_canister_id)
                                .try_into()
                                .unwrap(),
                        )
                        .unwrap())
                } else if is_provisional_create_canister {
                    // We create a new subnet with the IC mainnet configuration containing the effective canister ID.
                    // NNS and II subnets cannot be created at this point though because NNS is the root subnet
                    // and both NNS and II subnets on the IC mainnet do not have a single canister range
                    // (the PocketIC instance must be created with those subnets if applicable).
                    let subnet_kind = subnet_kind_from_canister_id(canister_id);
                    if matches!(subnet_kind, SubnetKind::NNS)
                        || matches!(subnet_kind, SubnetKind::II)
                    {
                        return Err(format!("The effective canister ID {canister_id} belongs to the NNS or II subnet on the IC mainnet for which PocketIC provides a `SubnetKind`: please set up your PocketIC instance with a subnet of that `SubnetKind`."));
                    }
                    let instruction_config = SubnetInstructionConfig::Production;
                    // The binary representation of canister IDs on the IC mainnet consists of exactly 10 bytes.
                    let canister_id_slice: &[u8] = canister_id.as_ref();
                    if canister_id_slice.len() != 10 {
                        return Err(format!("The binary representation {} of effective canister ID {canister_id} should consist of 10 bytes.", hex::encode(canister_id_slice)));
                    }
                    // The first 8 bytes of the binary representation of a canister ID on the IC mainnet represent:
                    // - the sequence number of the canister's subnet on the IC mainnet (all but the last 20 bits);
                    // - the sequence number of the canister within its subnet (the last 20 bits).
                    let canister_id_u64: u64 =
                        u64::from_be_bytes(canister_id_slice[..8].try_into().unwrap());
                    if (canister_id_u64 >> 20) >= MAXIMUM_NUMBER_OF_SUBNETS_ON_MAINNET {
                        return Err(format!("The effective canister ID {canister_id} does not belong to an existing subnet and it is not a mainnet canister ID."));
                    }
                    // Hence, we derive the canister range of the canister ID on the IC mainnet by masking in/out the last 20 bits.
                    // This works for all IC mainnet subnets that have not been split.
                    let range = CanisterIdRange {
                        start: CanisterId::from_u64(canister_id_u64 & 0xFFFFFFFFFFF00000),
                        end: CanisterId::from_u64(canister_id_u64 | 0xFFFFF),
                    };
                    // The canister allocation range must be disjoint from the canister ranges on the IC mainnet
                    // and all existing canister ranges within the PocketIC instance and thus we use
                    // `RangeGen::next_range()` to produce such a canister range.
                    let canister_allocation_range = pic.range_gen.next_range();
                    pic.subnets.create_subnet(SubnetConfigInfo {
                        ranges: vec![range],
                        alloc_range: Some(canister_allocation_range),
                        subnet_id: None,
                        subnet_state_dir: None,
                        subnet_kind,
                        instruction_config,
                        time: None,
                    })?;
                    pic.subnets
                        .persist_topology(pic.default_effective_canister_id);
                    Ok(pic.try_route_canister(canister_id).unwrap())
                } else {
                    // If the request is not an update call to create a canister using the provisional API,
                    // we return an error (since such an update call to a newly created subnet would fail anyway).
                    Err(format!(
                        "Canister {canister_id} does not belong to any subnet."
                    ))
                }
            }
        },
        EffectivePrincipal::None => {
            if is_provisional_create_canister {
                Ok(pic
                    .try_route_canister(
                        PrincipalId(pic.default_effective_canister_id)
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap())
            } else {
                Err("Effective principal must be specified for all calls but canister creation via the provisional management canister API.".to_string())
            }
        }
    }
}

fn route_call(
    pic: &mut PocketIc,
    canister_call: CanisterCall,
) -> Result<Arc<StateMachine>, String> {
    let effective_principal = match canister_call.effective_principal {
        EffectivePrincipal::SubnetId(subnet_id) => EffectivePrincipal::SubnetId(subnet_id),
        EffectivePrincipal::CanisterId(canister_id) => EffectivePrincipal::CanisterId(canister_id),
        EffectivePrincipal::None => {
            // We attempt to derive the effective principal if it is not provided.
            if canister_call.canister_id == CanisterId::ic_00() {
                if Ic00Method::from_str(&canister_call.method)
                    == Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
                {
                    let payload = Decode!(
                        &canister_call.payload,
                        ProvisionalCreateCanisterWithCyclesArgs
                    )
                    .map_err(|e| format!("Error decoding candid: {:?}", e))?;
                    if let Some(specified_id) = payload.specified_id {
                        EffectivePrincipal::CanisterId(CanisterId::unchecked_from_principal(
                            specified_id,
                        ))
                    } else {
                        // We can't derive an effective principal and thus a canister will be created
                        // on a random subnet.
                        EffectivePrincipal::None
                    }
                } else {
                    // Management canister calls that do not create a canister strictly require
                    // an effective principal. We derive it from the Candid payload.
                    let payload = Decode!(&canister_call.payload, CanisterIdRecord)
                        .map_err(|e| format!("Error decoding candid: {:?}", e))?;
                    EffectivePrincipal::CanisterId(payload.get_canister_id())
                }
            } else {
                // For calls to canisters other than the management canister,
                // we use the call's target canister as the effective principal.
                EffectivePrincipal::CanisterId(canister_call.canister_id)
            }
        }
    };
    let is_provisional_create_canister = canister_call.canister_id == CanisterId::ic_00()
        && Ic00Method::from_str(&canister_call.method)
            == Ok(Ic00Method::ProvisionalCreateCanisterWithCycles);
    route(pic, effective_principal, is_provisional_create_canister)
}

fn systemtime_to_unix_epoch_nanos(st: SystemTime) -> u64 {
    st.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pocket_ic::common::rest::SubnetSpec;

    #[tokio::test]
    async fn state_label_test() {
        let runtime = Arc::new(Runtime::new().unwrap());
        tokio::task::spawn_blocking(move || {
            // State label changes.
            let mut pic0 = PocketIc::try_new(
                runtime.clone(),
                0,
                ExtendedSubnetConfigSet {
                    application: vec![SubnetSpec::default()],
                    ..Default::default()
                },
                None,
                false,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            let mut pic1 = PocketIc::try_new(
                runtime.clone(),
                1,
                ExtendedSubnetConfigSet {
                    application: vec![SubnetSpec::default()],
                    ..Default::default()
                },
                None,
                false,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            assert_ne!(pic0.get_state_label(), pic1.get_state_label());

            let pic0_state_label = pic0.get_state_label();
            pic0.bump_state_label();
            assert_ne!(pic0.get_state_label(), pic0_state_label);
            assert_ne!(pic0.get_state_label(), pic1.get_state_label());

            let pic1_state_label = pic1.get_state_label();
            pic1.bump_state_label();
            assert_ne!(pic1.get_state_label(), pic0_state_label);
            assert_ne!(pic1.get_state_label(), pic1_state_label);
            assert_ne!(pic1.get_state_label(), pic0.get_state_label());
        })
        .await
        .unwrap();
    }
}
