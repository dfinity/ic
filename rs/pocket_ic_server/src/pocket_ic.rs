use crate::external_canister_types::{
    CaptchaConfig, CaptchaTrigger, CyclesLedgerArgs, CyclesLedgerConfig, InternetIdentityInit,
    NnsDappCanisterArguments, OpenIdConfig, RateLimitConfig, SnsAggregatorConfig,
    StaticCaptchaTrigger,
};
use crate::state_api::routes::into_api_response;
use crate::state_api::state::{HasStateLabel, OpOut, PocketIcError, StateLabel};
use crate::{BlobStore, OpId, Operation, SubnetBlockmaker};
use askama::Template;
use async_trait::async_trait;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use bitcoin::Network as BitcoinAdapterNetwork;
use bitcoin::dogecoin::Network as DogecoinAdapterNetwork;
use bytes::Bytes;
use candid::{CandidType, Decode, Encode, Principal};
use cycles_minting_canister::{
    ChangeSubnetTypeAssignmentArgs, CyclesCanisterInitPayload,
    DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS, SetAuthorizedSubnetworkListArgs,
    SubnetListWithType, UpdateSubnetTypeArgs,
};
use futures::FutureExt;
use futures::future::BoxFuture;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::{Method, StatusCode};
use ic_boundary::{Health, RootKey, status};
use ic_btc_adapter::config::{Config as BitcoinAdapterConfig, IncomingSource as BtcIncomingSource};
use ic_btc_adapter::{AdapterNetwork, start_server as start_btc_server};
use ic_btc_interface::{
    Fees as BitcoinFees, InitConfig as BitcoinInitConfig, Network as BitcoinNetwork,
};
use ic_config::adapters::AdaptersConfig;
use ic_config::execution_environment::MAX_CANISTER_HTTP_REQUESTS_IN_FLIGHT;
use ic_config::{
    execution_environment, flag_status::FlagStatus, http_handler, logger::Config as LoggerConfig,
    subnet_config::SubnetConfig,
};
use ic_crypto_sha2::Sha256;
use ic_doge_interface::{
    Fees as DogecoinFees, InitConfig as DogecoinInitConfig, Network as DogecoinNetwork,
};
use ic_http_endpoints_public::query;
use ic_http_endpoints_public::{
    CanisterReadStateServiceBuilder, IngressValidatorBuilder, QueryServiceBuilder,
    SubnetReadStateServiceBuilder, call_async, call_sync, metrics::HttpHandlerMetrics, read_state,
};
use ic_https_outcalls_adapter::{
    Config as HttpsOutcallsConfig, IncomingSource as CanisterHttpIncomingSource,
    start_server as start_canister_http_server,
};
use ic_https_outcalls_adapter_client::{CanisterHttpAdapterClientImpl, setup_canister_http_client};
use ic_https_outcalls_service::HttpsOutcallRequest;
use ic_https_outcalls_service::HttpsOutcallResponse;
use ic_https_outcalls_service::HttpsOutcallResult;
use ic_https_outcalls_service::https_outcalls_service_server::HttpsOutcallsService;
use ic_https_outcalls_service::https_outcalls_service_server::HttpsOutcallsServiceServer;
use ic_icp_index::InitArg as IcpIndexInitArg;
use ic_icrc1_index_ng::{IndexArg as CyclesLedgerIndexArg, InitArg as CyclesLedgerIndexInitArg};
use ic_interfaces::{crypto::BasicSigner, ingress_pool::IngressPoolThrottler};
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_interfaces_registry::{RegistryValue, ZERO_REGISTRY_VERSION};
use ic_interfaces_state_manager::StateReader;
use ic_limits::MAX_P2P_IO_CHANNEL_SIZE;
use ic_logger::{ReplicaLogger, no_op_logger};
use ic_management_canister_types_private::{
    BoundedVec, CanisterIdRecord, CanisterInstallMode, CanisterSettingsArgs,
    CanisterSnapshotDataKind, CanisterSnapshotDataOffset, EcdsaCurve, EcdsaKeyId, LogVisibilityV2,
    MasterPublicKeyId, Method as Ic00Method, ProvisionalCreateCanisterWithCyclesArgs,
    ReadCanisterSnapshotDataArgs, ReadCanisterSnapshotMetadataArgs,
    ReadCanisterSnapshotMetadataResponse, SchnorrAlgorithm, SchnorrKeyId,
    UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs, VetKdCurve, VetKdKeyId,
};
use ic_metrics::MetricsRegistry;
use ic_nervous_system_common::ONE_YEAR_SECONDS;
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_nns_constants::{
    BITCOIN_TESTNET_CANISTER_ID, CYCLES_LEDGER_CANISTER_ID, CYCLES_LEDGER_INDEX_CANISTER_ID,
    CYCLES_MINTING_CANISTER_ID, DOGECOIN_CANISTER_ID, GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID,
    LEDGER_CANISTER_ID, LEDGER_INDEX_CANISTER_ID, LIFELINE_CANISTER_ID, MIGRATION_CANISTER_ID,
    NNS_UI_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_AGGREGATOR_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
use ic_nns_delegation_manager::{NNSDelegationBuilder, NNSDelegationReader};
use ic_nns_governance_api::{NetworkEconomics, Neuron, neuron::DissolveState};
use ic_nns_governance_init::GovernanceCanisterInitPayloadBuilder;
use ic_nns_handler_root::init::RootCanisterInitPayloadBuilder;
use ic_registry_canister_api::GetChunkRequest;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::routing_table::RoutingTableRegistry;
use ic_registry_nns_data_provider::registry::registry_deltas_to_registry_records;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{
    CANISTER_IDS_PER_SUBNET, CanisterIdRange, RoutingTable, are_disjoint, is_subset_of,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{
    GetChunk, dechunkify_delta, deserialize_atomic_mutate_response,
    deserialize_get_changes_since_response, serialize_get_changes_since_request,
};
use ic_sns_wasm::init::SnsWasmCanisterInitPayloadBuilder;
use ic_sns_wasm::pb::v1::add_wasm_response::Result as AddWasmResult;
use ic_sns_wasm::pb::v1::{AddWasmRequest, AddWasmResponse, SnsCanisterType, SnsWasm};
use ic_state_machine_tests::{
    FakeVerifier, StateMachine, StateMachineBuilder, StateMachineConfig, StateMachineStateDir,
    SubmitIngressError, Subnets, WasmResult, add_global_registry_records,
    add_initial_registry_records,
};
use ic_state_manager::StateManagerImpl;
use ic_types::batch::BlockmakerMetrics;
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::messages::{CertificateDelegationFormat, CertificateDelegationMetadata};
use ic_types::{
    CanisterId, Cycles, Height, NodeId, NumInstructions, PrincipalId, RegistryVersion, SnapshotId,
    SubnetId,
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
        QueryResponseHash, ReplicaHealthStatus,
    },
    time::GENESIS,
};
use ic_types::{NumBytes, Time};
use ic_validator_ingress_message::StandaloneIngressSigVerifier;
use icp_ledger::{AccountIdentifier, LedgerCanisterInitPayloadBuilder, Subaccount, Tokens};
use icrc_ledger_types::icrc1::account::Account;
use itertools::Itertools;
use pocket_ic::common::rest::{
    self, BinaryBlob, BlobCompression, CanisterHttpHeader, CanisterHttpMethod, CanisterHttpRequest,
    CanisterHttpResponse, ExtendedSubnetConfigSet, IcpConfig, IcpConfigFlag, IcpFeatures,
    IcpFeaturesConfig, IncompleteStateFlag, MockCanisterHttpResponse, RawAddCycles,
    RawCanisterCall, RawCanisterId, RawEffectivePrincipal, RawMessageId, RawSetStableMemory,
    SubnetInstructionConfig, SubnetKind, TickConfigs, Topology,
};
use pocket_ic::{ErrorCode, RejectCode, RejectResponse, copy_dir};
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use serde::{Deserialize, Serialize};
use slog::Level;
use std::cmp::max;
use std::hash::Hash;
use std::str::FromStr;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{File, OpenOptions, remove_file},
    io::{BufReader, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
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

const MAINNET_NNS_SUBNET_ID: &str =
    "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";
const MAINNET_II_SUBNET_ID: &str =
    "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe";
const MAINNET_BITCOIN_SUBNET_ID: &str =
    "w4rem-dv5e3-widiz-wbpea-kbttk-mnzfm-tzrc7-svcj3-kbxyb-zamch-hqe";
const MAINNET_FIDUCIARY_SUBNET_ID: &str =
    "pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae";
const MAINNET_SNS_SUBNET_ID: &str =
    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae";

const REGISTRY_CANISTER_WASM: &[u8] = include_bytes!(env!("REGISTRY_CANISTER_WASM_PATH"));
const CYCLES_MINTING_CANISTER_WASM: &[u8] =
    include_bytes!(env!("CYCLES_MINTING_CANISTER_WASM_PATH"));
const ICP_LEDGER_CANISTER_WASM: &[u8] = include_bytes!(env!("ICP_LEDGER_CANISTER_WASM_PATH"));
const ICP_INDEX_CANISTER_WASM: &[u8] = include_bytes!(env!("ICP_INDEX_CANISTER_WASM_PATH"));
const CYCLES_LEDGER_CANISTER_WASM: &[u8] = include_bytes!(env!("CYCLES_LEDGER_CANISTER_WASM_PATH"));
const CYCLES_LEDGER_INDEX_CANISTER_WASM: &[u8] =
    include_bytes!(env!("CYCLES_LEDGER_INDEX_CANISTER_WASM_PATH"));
const GOVERNANCE_TEST_CANISTER_WASM: &[u8] =
    include_bytes!(env!("GOVERNANCE_TEST_CANISTER_WASM_PATH"));
const ROOT_CANISTER_WASM: &[u8] = include_bytes!(env!("ROOT_CANISTER_WASM_PATH"));
const SNS_WASM_CANISTER_WASM: &[u8] = include_bytes!(env!("SNS_WASM_CANISTER_WASM_PATH"));
const SNS_ROOT_CANISTER_WASM: &[u8] = include_bytes!(env!("SNS_ROOT_CANISTER_WASM_PATH"));
const SNS_GOVERNANCE_CANISTER_WASM: &[u8] =
    include_bytes!(env!("SNS_GOVERNANCE_CANISTER_WASM_PATH"));
const SNS_SWAP_CANISTER_WASM: &[u8] = include_bytes!(env!("SNS_SWAP_CANISTER_WASM_PATH"));
const SNS_LEDGER_CANISTER_WASM: &[u8] = include_bytes!(env!("SNS_LEDGER_CANISTER_WASM_PATH"));
const SNS_LEDGER_ARCHIVE_CANISTER_WASM: &[u8] =
    include_bytes!(env!("SNS_LEDGER_ARCHIVE_CANISTER_WASM_PATH"));
const SNS_LEDGER_INDEX_CANISTER_WASM: &[u8] =
    include_bytes!(env!("SNS_LEDGER_INDEX_CANISTER_WASM_PATH"));
const SNS_AGGREGATOR_TEST_CANISTER_WASM: &[u8] =
    include_bytes!(env!("SNS_AGGREGATOR_TEST_CANISTER_WASM_PATH"));
const INTERNET_IDENTITY_TEST_CANISTER_WASM: &[u8] =
    include_bytes!(env!("INTERNET_IDENTITY_TEST_CANISTER_WASM_PATH"));
const NNS_DAPP_TEST_CANISTER_WASM: &[u8] = include_bytes!(env!("NNS_DAPP_TEST_CANISTER_WASM_PATH"));
const BITCOIN_TESTNET_CANISTER_WASM: &[u8] =
    include_bytes!(env!("BITCOIN_TESTNET_CANISTER_WASM_PATH"));
const DOGECOIN_CANISTER_WASM: &[u8] = include_bytes!(env!("DOGECOIN_CANISTER_WASM_PATH"));
const MIGRATION_CANISTER_WASM: &[u8] = include_bytes!(env!("MIGRATION_CANISTER_WASM_PATH"));

const DEFAULT_SUBACCOUNT: Subaccount = Subaccount([0; 32]);

// Initial amount of cycles when bootstrapping system canisters so that
// - the canister has enough cycles to never run out of cycles;
// - it is still possible to top up the canister with further cycles without overflowing 128-bit range.
const INITIAL_CYCLES: u128 = u128::MAX / 2;

// Initial amount of cycles when bootstrapping system canisters so that
// - the canister has enough cycles to never run out of cycles;
// - it is still possible to top up the canister with further cycles without overflowing 64-bit range.
const INITIAL_CYCLES_64_BIT: u64 = u64::MAX / 2;

// Maximum duration of waiting for bitcoin/dogecoin/canister http adapter server to start.
const MAX_START_SERVER_DURATION: Duration = Duration::from_secs(60);

// Clippy complains that these are interior-mutable.
// We don't mutate them, so silence it.
// https://rust-lang.github.io/rust-clippy/master/index.html#/declare_interior_mutable_const
#[allow(clippy::declare_interior_mutable_const)]
const CONTENT_TYPE_CBOR: HeaderValue = HeaderValue::from_static("application/cbor");

// Maximum data chunk size when downloading/uploading canister snapshots.
const MAX_CHUNK_SIZE: u64 = 2_000_000;

fn default_timestamp(icp_features: &Option<IcpFeatures>) -> SystemTime {
    // To set the ICP/XDR conversion rate, the PocketIC time (in seconds) must be strictly larger than the default timestamp in CMC state.
    let cycles_minting_feature = icp_features
        .as_ref()
        .map(|icp_features| icp_features.cycles_minting.is_some())
        .unwrap_or_default();
    if cycles_minting_feature {
        UNIX_EPOCH + Duration::from_secs(DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS + 1)
    } else {
        GENESIS.into()
    }
}

/// The response type for `/api` IC endpoint operations.
pub(crate) type ApiResponse = BoxFuture<'static, (StatusCode, BTreeMap<String, Vec<u8>>, Vec<u8>)>;

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

fn compute_subnet_seed(
    mut ranges: Vec<CanisterIdRange>,
    alloc_range: Option<CanisterIdRange>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if let Some(range) = alloc_range {
        ranges.push(range);
    }
    ranges.sort();
    hasher.write(format!("{ranges:?}").as_bytes());
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
        network: AdapterNetwork,
        log_level: Option<Level>,
        replica_logger: ReplicaLogger,
        metrics_registry: MetricsRegistry,
    ) -> Self {
        let bitcoin_adapter_config = BitcoinAdapterConfig {
            nodes: bitcoind_addr,
            socks_proxy: None,
            ipv6_only: false,
            logger: logger_config_from_level(log_level),
            incoming_source: BtcIncomingSource::Path(uds_path.clone()),
            address_limits: (1, 1),
            ..BitcoinAdapterConfig::default_with(network)
        };
        let adapter = tokio::spawn(async move {
            start_btc_server(replica_logger, metrics_registry, bitcoin_adapter_config).await
        });
        let start = std::time::Instant::now();
        loop {
            if let Ok(true) = std::fs::exists(uds_path.clone()) {
                break;
            }
            if start.elapsed() > MAX_START_SERVER_DURATION {
                panic!(
                    "Bitcoin adapter server took more than {MAX_START_SERVER_DURATION:?} to start."
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
                    "Canister http adapter server took more than {MAX_START_SERVER_DURATION:?} to start."
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
        let client = setup_canister_http_client(
            state_machine.runtime.handle().clone(),
            &state_machine.metrics_registry,
            adapter_config,
            state_machine.transform_handler.lock().unwrap().clone(),
            MAX_CANISTER_HTTP_REQUESTS_IN_FLIGHT,
            state_machine.replica_logger.clone(),
        );
        let canister_http = Arc::new(Mutex::new(CanisterHttp {
            client: Arc::new(Mutex::new(client)),
            pending: BTreeSet::new(),
        }));
        Self {
            state_machine,
            canister_http,
            _canister_http_adapter_parts: canister_http_adapter_parts,
        }
    }

    fn get_subnet_id(&self) -> SubnetId {
        self.state_machine.get_subnet_id()
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
    fn is_empty(&self) -> bool {
        self.subnets.read().unwrap().is_empty()
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
    sns_subnet: Option<Arc<Subnet>>,
    ii_subnet: Option<Arc<Subnet>>,
    btc_subnet: Option<Arc<Subnet>>,
    runtime: Arc<Runtime>,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    state_dir: Option<PathBuf>,
    routing_table: RoutingTable,
    chain_keys: BTreeMap<MasterPublicKeyId, Vec<SubnetId>>,
    icp_config: IcpConfig,
    log_level: Option<Level>,
    bitcoind_addr: Option<Vec<SocketAddr>>,
    dogecoind_addr: Option<Vec<SocketAddr>>,
    icp_features: Option<IcpFeatures>,
    initial_time: SystemTime,
    auto_progress_enabled: bool,
    gateway_port: Option<u16>,
    synced_registry_version: RegistryVersion,
    _bitcoin_adapter_parts: Option<BitcoinAdapterParts>,
    _dogecoin_adapter_parts: Option<BitcoinAdapterParts>,
}

impl PocketIcSubnets {
    fn state_machine_builder(
        state_machine_state_dir: Box<dyn StateMachineStateDir>,
        runtime: Arc<Runtime>,
        subnet_kind: SubnetKind,
        subnet_seed: [u8; 32],
        instruction_config: SubnetInstructionConfig,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
        create_at_registry_version: Option<RegistryVersion>,
        icp_config: &IcpConfig,
        log_level: Option<Level>,
        bitcoin_adapter_uds_path: Option<PathBuf>,
        dogecoin_adapter_uds_path: Option<PathBuf>,
    ) -> StateMachineBuilder {
        let subnet_type = conv_type(subnet_kind);
        let subnet_size = subnet_size(subnet_kind);
        let mut subnet_config = SubnetConfig::new(subnet_type);
        // using `let IcpConfig { }` with explicit field names
        // to force an update after adding a new field to `IcpConfig`
        let IcpConfig {
            beta_features,
            canister_backtrace,
            function_name_length_limits,
            canister_execution_rate_limiting,
        } = icp_config;
        let mut hypervisor_config = match beta_features.clone().unwrap_or(IcpConfigFlag::Disabled) {
            IcpConfigFlag::Disabled => execution_environment::Config::default(),
            IcpConfigFlag::Enabled => crate::beta_features::hypervisor_config(),
        };
        match canister_backtrace {
            None => (),
            Some(IcpConfigFlag::Enabled) => {
                hypervisor_config
                    .embedders_config
                    .feature_flags
                    .canister_backtrace = FlagStatus::Enabled;
            }
            Some(IcpConfigFlag::Disabled) => {
                hypervisor_config
                    .embedders_config
                    .feature_flags
                    .canister_backtrace = FlagStatus::Disabled;
            }
        };
        match function_name_length_limits {
            None | Some(IcpConfigFlag::Enabled) => (),
            Some(IcpConfigFlag::Disabled) => {
                // the maximum size of a canister WASM is much less than 1GB
                // and thus the following limits effectively disable all limits
                hypervisor_config
                    .embedders_config
                    .max_number_exported_functions = 1_000_000_000;
                hypervisor_config
                    .embedders_config
                    .max_sum_exported_function_name_lengths = 1_000_000_000;
            }
        };
        match canister_execution_rate_limiting {
            None => (),
            Some(IcpConfigFlag::Enabled) => {
                hypervisor_config.rate_limiting_of_heap_delta = FlagStatus::Enabled;
                hypervisor_config.rate_limiting_of_instructions = FlagStatus::Enabled;
            }
            Some(IcpConfigFlag::Disabled) => {
                hypervisor_config.rate_limiting_of_heap_delta = FlagStatus::Disabled;
                hypervisor_config.rate_limiting_of_instructions = FlagStatus::Disabled;
            }
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
            .with_dogecoin_testnet_uds_path(dogecoin_adapter_uds_path)
            .create_at_registry_version(create_at_registry_version)
    }

    fn new(
        runtime: Arc<Runtime>,
        state_dir: Option<PathBuf>,
        icp_config: IcpConfig,
        log_level: Option<Level>,
        bitcoind_addr: Option<Vec<SocketAddr>>,
        dogecoind_addr: Option<Vec<SocketAddr>>,
        icp_features: Option<IcpFeatures>,
        initial_time: SystemTime,
        auto_progress_enabled: bool,
        gateway_port: Option<u16>,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
        synced_registry_version: Option<u64>,
    ) -> Self {
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
            sns_subnet: None,
            ii_subnet: None,
            btc_subnet: None,
            runtime,
            state_dir,
            registry_data_provider,
            routing_table,
            chain_keys,
            icp_config,
            log_level,
            bitcoind_addr,
            dogecoind_addr,
            icp_features,
            initial_time,
            auto_progress_enabled,
            gateway_port,
            synced_registry_version,
            _bitcoin_adapter_parts: None,
            _dogecoin_adapter_parts: None,
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
        self.sns_subnet.take();
        self.ii_subnet.take();
        self.btc_subnet.take();
    }

    fn route(&self, canister_id: CanisterId) -> Option<Arc<StateMachine>> {
        self.get(SubnetId::from(canister_id.get())).or_else(|| {
            self.routing_table
                .lookup_entry(canister_id)
                .and_then(|(_, subnet_id)| self.get(subnet_id))
        })
    }

    fn time(&self) -> SystemTime {
        self.subnets.get_all().first().unwrap().state_machine.time()
    }

    fn create_subnet(
        &mut self,
        subnet_config_info: SubnetConfigInfo,
        update_registry_and_system_canisters: bool,
    ) -> Result<SubnetConfigInternal, String> {
        let SubnetConfigInfo {
            ranges,
            alloc_range,
            subnet_id,
            subnet_state_dir,
            subnet_kind,
            instruction_config,
            expected_state_time,
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
        let dogecoin_adapter_uds_path =
            if matches!(subnet_kind, SubnetKind::Bitcoin) && self.dogecoind_addr.is_some() {
                Some(NamedTempFile::new().unwrap().into_temp_path().to_path_buf())
            } else {
                None
            };

        let latest_registry_version = self.registry_data_provider.latest_version().get();
        let create_at_registry_version = if update_registry_and_system_canisters {
            if self.subnets.is_empty() {
                Some(latest_registry_version) // we need to make sure that the NNS subnet is created at the initial registry version
            } else {
                Some(latest_registry_version + 1)
            }
        } else {
            None
        };
        let mut builder = Self::state_machine_builder(
            state_machine_state_dir,
            self.runtime.clone(),
            subnet_kind,
            subnet_seed,
            instruction_config.clone(),
            self.registry_data_provider.clone(),
            create_at_registry_version.map(RegistryVersion::new),
            &self.icp_config,
            self.log_level,
            bitcoin_adapter_uds_path.clone(),
            dogecoin_adapter_uds_path.clone(),
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

            for name in ["key_1", "test_key_1", "dfx_test_key"] {
                let key_id = VetKdKeyId {
                    curve: VetKdCurve::Bls12_381_G2,
                    name: name.to_string(),
                };
                subnet_chain_keys.push(MasterPublicKeyId::VetKd(key_id));
            }
        }
        for chain_key in &subnet_chain_keys {
            builder = builder.with_chain_key(chain_key.clone());
        }

        let sm = builder.build_with_subnets(self.subnets.clone());

        // The actual subnet ID (matching the subnet ID in the input `SubnetConfigInfo`
        // if one was provided).
        let subnet_id = sm.get_subnet_id();

        if let Some(expected_time) = expected_state_time {
            let actual_time: SystemTime = sm.get_state_time().into();
            if actual_time != expected_time {
                return Err(format!(
                    "The state of subnet with seed {} is incomplete.",
                    hex::encode(subnet_seed)
                ));
            }
        }

        // The subnet created first is marked as the NNS subnet.
        if self.nns_subnet.is_none() {
            self.nns_subnet = Some(self.subnets.get_subnet(subnet_id).unwrap());
        }

        if let SubnetKind::SNS = subnet_kind {
            self.sns_subnet = Some(self.subnets.get_subnet(subnet_id).unwrap());
        }
        if let SubnetKind::II = subnet_kind {
            self.ii_subnet = Some(self.subnets.get_subnet(subnet_id).unwrap());
        }
        if let SubnetKind::Bitcoin = subnet_kind {
            self.btc_subnet = Some(self.subnets.get_subnet(subnet_id).unwrap());
        }

        // We need the actual subnet ID to update the chain keys.
        for chain_key in subnet_chain_keys {
            self.chain_keys
                .entry(chain_key)
                .or_default()
                .push(subnet_id);
        }

        // We need `StateMachine` components (metrics/logger)
        // to create a bitcoin/dogecoin adapter (if applicable).
        if let Some(bitcoin_adapter_uds_path) = bitcoin_adapter_uds_path {
            self._bitcoin_adapter_parts = Some(BitcoinAdapterParts::new(
                self.bitcoind_addr.clone().unwrap(),
                bitcoin_adapter_uds_path,
                AdapterNetwork::Bitcoin(BitcoinAdapterNetwork::Regtest),
                self.log_level,
                sm.replica_logger.clone(),
                sm.metrics_registry.clone(),
            ));
        }
        if let Some(dogecoin_adapter_uds_path) = dogecoin_adapter_uds_path {
            self._dogecoin_adapter_parts = Some(BitcoinAdapterParts::new(
                self.dogecoind_addr.clone().unwrap(),
                dogecoin_adapter_uds_path,
                AdapterNetwork::Dogecoin(DogecoinAdapterNetwork::Regtest),
                self.log_level,
                sm.replica_logger.clone(),
                sm.metrics_registry.clone(),
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
        if update_registry_and_system_canisters {
            add_global_registry_records(
                self.nns_subnet.clone().unwrap().get_subnet_id(),
                self.routing_table.clone(),
                subnet_list,
                self.chain_keys.clone(),
                self.registry_data_provider.clone(),
            );
            self.persist_registry_changes();
        }

        // All subnets must have the same time and time can only advance =>
        // set the time to the maximum time in the latest state across all subnets.
        let mut time: SystemTime = self.initial_time;
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

        let subnet_config = SubnetConfigInternal {
            subnet_id,
            subnet_kind,
            instruction_config,
            ranges,
            alloc_range,
        };
        self.subnet_configs.push(subnet_config.clone());

        if let Some(icp_features) = self.icp_features.clone()
            && update_registry_and_system_canisters
        {
            // using `let IcpFeatures { }` with explicit field names
            // to force an update after adding a new field to `IcpFeatures`
            let IcpFeatures {
                registry,
                cycles_minting,
                icp_token,
                cycles_token,
                nns_governance,
                sns,
                ii,
                nns_ui,
                bitcoin,
                dogecoin,
                canister_migration,
            } = icp_features;
            if let Some(ref config) = registry {
                self.update_registry(config);
            }
            if let Some(ref config) = cycles_minting {
                self.update_cmc(config, &subnet_kind);
            }
            if let Some(ref config) = icp_token {
                self.deploy_icp_token(config);
            }
            if let Some(ref config) = cycles_token {
                self.deploy_cycles_token(config);
            }
            if let Some(ref config) = nns_governance {
                self.deploy_nns_governance(config);
            }
            if let Some(ref config) = sns {
                self.deploy_sns(config);
            }
            if let Some(ref config) = ii {
                self.deploy_ii(config);
            }
            if let Some(ref config) = nns_ui {
                self.deploy_nns_ui(config);
            }
            if let Some(ref config) = bitcoin {
                self.deploy_bitcoin(config);
            }
            if let Some(ref config) = dogecoin {
                self.deploy_dogecoin(config);
            }
            if let Some(ref config) = canister_migration {
                self.deploy_canister_migration(config);
            }
        }

        Ok(subnet_config)
    }

    fn get_nns(&self) -> Option<Arc<StateMachine>> {
        self.nns_subnet
            .as_ref()
            .map(|subnet| subnet.state_machine.clone())
    }

    fn update_registry(&mut self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        let nns_subnet = self.nns_subnet.clone().expect(
            "The NNS subnet is supposed to already exist if the `registry` ICP feature is specified.",
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
            //       log_memory_limit = opt (4_096 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
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
            let registry_init_payload = RegistryCanisterInitPayloadBuilder::new().build();
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
            let res = self.execute_ingress_on(
                nns_subnet.clone(),
                GOVERNANCE_CANISTER_ID.get(),
                REGISTRY_CANISTER_ID,
                "atomic_mutate".to_string(),
                mutation_request_bytes,
            );
            deserialize_atomic_mutate_response(res).unwrap();
        }
        self.synced_registry_version = self.registry_data_provider.latest_version();
    }

    fn update_cmc(&mut self, config: &IcpFeaturesConfig, subnet_kind: &SubnetKind) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        let nns_subnet = self
            .nns_subnet
            .clone()
            .expect("The NNS subnet is supposed to already exist if the `cycles_minting` ICP feature is specified.");

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
            //       log_memory_limit = opt (4_096 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
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
            let cycles_ledger_canister_id = if self
                .icp_features
                .as_ref()
                .map(|icp_features| icp_features.cycles_token.is_some())
                .unwrap_or_default()
            {
                Some(CYCLES_LEDGER_CANISTER_ID)
            } else {
                None
            };
            let cmc_init_payload = Some(CyclesCanisterInitPayload {
                ledger_canister_id: Some(LEDGER_CANISTER_ID),
                governance_canister_id: Some(GOVERNANCE_CANISTER_ID),
                minting_account_id: Some(AccountIdentifier::new(
                    GOVERNANCE_CANISTER_ID.get(),
                    None,
                )),
                last_purged_notification: None,
                exchange_rate_canister: None,
                cycles_ledger_canister_id,
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
            // We use the PocketIC time (instead of the actual time at which the rate was obtained by the above call)
            // because CMC does not expect rates in the future w.r.t. the PocketIC time.
            let timestamp_seconds = nns_subnet
                .state_machine
                .time()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let xdr_permyriad_per_icp = 35_200;
            let update_icp_xdr_conversion_rate_payload = UpdateIcpXdrConversionRatePayload {
                data_source: "PocketIC".to_string(),
                timestamp_seconds,
                xdr_permyriad_per_icp,
                reason: None,
            };
            let res = self.execute_ingress_on(
                nns_subnet.clone(),
                GOVERNANCE_CANISTER_ID.get(),
                CYCLES_MINTING_CANISTER_ID,
                "set_icp_xdr_conversion_rate".to_string(),
                Encode!(&update_icp_xdr_conversion_rate_payload).unwrap(),
            );
            let decoded = Decode!(&res, Result<(), String>).unwrap();
            decoded.unwrap();
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
        // returns ()
        self.execute_ingress_on(
            nns_subnet.clone(),
            GOVERNANCE_CANISTER_ID.get(),
            CYCLES_MINTING_CANISTER_ID,
            "set_authorized_subnetwork_list".to_string(),
            Encode!(&set_authorized_subnetwork_list_args).unwrap(),
        );

        // add fiduciary subnet to CMC
        if let SubnetKind::Fiduciary = subnet_kind {
            let fiduciary_subnet_id = self
                .subnet_configs
                .iter()
                .find(|subnet_config| matches!(subnet_config.subnet_kind, SubnetKind::Fiduciary))
                .map(|subnet_config| subnet_config.subnet_id)
                .unwrap();
            let update_subnet_type_args = UpdateSubnetTypeArgs::Add("fiduciary".to_string());
            // returns ()
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
            // returns ()
            self.execute_ingress_on(
                nns_subnet.clone(),
                GOVERNANCE_CANISTER_ID.get(),
                CYCLES_MINTING_CANISTER_ID,
                "change_subnet_type_assignment".to_string(),
                Encode!(&change_subnet_type_assignment_args).unwrap(),
            );
        }
    }

    fn deploy_icp_token(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        let nns_subnet = self
            .nns_subnet
            .clone()
            .expect("The NNS subnet is supposed to already exist if the `icp_token` ICP feature is specified.");

        if !nns_subnet.state_machine.canister_exists(LEDGER_CANISTER_ID) {
            // Create the ICP ledger with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"ryjl3-tyaaa-aaaaa-aaaba-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
            //       wasm_memory_limit = opt (3_221_225_472 : nat);
            //       memory_allocation = opt (4_294_967_296 : nat);
            //       compute_allocation = opt (0 : nat);
            //     };
            let settings = CanisterSettingsArgs {
                controllers: Some(BoundedVec::new(vec![ROOT_CANISTER_ID.get()])),
                compute_allocation: Some(0_u64.into()),
                memory_allocation: Some(4_294_967_296_u64.into()),
                freezing_threshold: Some(2_592_000_u64.into()),
                reserved_cycles_limit: Some(5_000_000_000_000_u128.into()),
                log_visibility: Some(LogVisibilityV2::Controllers),
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(LEDGER_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, LEDGER_CANISTER_ID);

            // Install the ICP ledger.
            // The following initial values are used by the `dfx nns extension` (https://github.com/dfinity/dfx-extensions/blob/2949dd3cbf6e8a52093da32c7ff27011f5ff3f3d/extensions/nns/src/install_nns.rs#L128-L131).
            let mut initial_values = HashMap::new();
            initial_values.insert(
                AccountIdentifier::from_hex(
                    "5b315d2f6702cb3a27d826161797d7b2c2e131cd312aece51d4d5574d1247087",
                )
                .unwrap(),
                Tokens::from_tokens(1_000_000_000).unwrap(),
            );
            initial_values.insert(
                AccountIdentifier::from_hex(
                    "2b8fbde99de881f695f279d2a892b1137bfe81a42d7694e064b1be58701e1138",
                )
                .unwrap(),
                Tokens::from_tokens(1_000_000_000).unwrap(),
            );
            // The following account is the account of the anonymous principal
            // from which funds can be transfered to any other account
            // without hard-coding any fixed identity controlling
            // one of the above accounts.
            initial_values.insert(
                AccountIdentifier::from_hex(
                    "1c7a48ba6a562aa9eaa2481a9049cdf0433b9738c992d698c31d8abf89cadc79",
                )
                .unwrap(),
                Tokens::from_tokens(1_000_000_000).unwrap(),
            );
            let icp_ledger_init_payload =
                LedgerCanisterInitPayloadBuilder::new_with_mainnet_settings()
                    .initial_values(initial_values)
                    .build()
                    .unwrap();
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    ICP_LEDGER_CANISTER_WASM.to_vec(),
                    Encode!(&icp_ledger_init_payload).unwrap(),
                )
                .unwrap();
        }

        if !nns_subnet
            .state_machine
            .canister_exists(LEDGER_INDEX_CANISTER_ID)
        {
            // Create the ICP index with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"qhbym-qaaaa-aaaaa-aaafq-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(LEDGER_INDEX_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, LEDGER_INDEX_CANISTER_ID);

            // Install the ICP index.
            let icp_index_init_arg = IcpIndexInitArg {
                ledger_id: LEDGER_CANISTER_ID.get().0,
            };
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    ICP_INDEX_CANISTER_WASM.to_vec(),
                    Encode!(&icp_index_init_arg).unwrap(),
                )
                .unwrap();
        }
    }

    fn deploy_cycles_token(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        // Nothing to do if the II subnet does not exist (yet).
        let Some(ref ii_subnet) = self.ii_subnet else {
            return;
        };

        if !ii_subnet
            .state_machine
            .canister_exists(CYCLES_LEDGER_CANISTER_ID)
        {
            // Create the cycles ledger with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"um5iw-rqaaa-aaaaq-qaaba-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = ii_subnet.state_machine.create_canister_with_cycles(
                Some(CYCLES_LEDGER_CANISTER_ID.get()),
                /* The cycles ledger needs cycles for the test identities to withdraw. */
                Cycles::from(INITIAL_CYCLES),
                Some(settings),
            );
            assert_eq!(canister_id, CYCLES_LEDGER_CANISTER_ID);

            // Install the cycles ledger.
            // The values of the initial payload have been obtained by calling
            // `dfx canister call um5iw-rqaaa-aaaaq-qaaba-cai icrc1_metadata --ic --update`:
            //   record { "dfn:max_blocks_per_request"; variant { Nat = 50 : nat } };
            //   record { "dfn:index_id"; variant { Blob = blob "\00\00\00\00\02\10\00\03\01\01" }; };
            let anonymous_account = Account {
                owner: Principal::anonymous(),
                subaccount: None,
            };
            let cycles_ledger_config = CyclesLedgerConfig {
                max_blocks_per_request: 50,
                index_id: Some(CYCLES_LEDGER_INDEX_CANISTER_ID.into()),
                initial_balances: Some(vec![(anonymous_account, INITIAL_CYCLES)]),
            };
            let cycles_ledger_args = CyclesLedgerArgs::Init(cycles_ledger_config);
            ii_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    CYCLES_LEDGER_CANISTER_WASM.to_vec(),
                    Encode!(&cycles_ledger_args).unwrap(),
                )
                .unwrap();
        }

        if !ii_subnet
            .state_machine
            .canister_exists(CYCLES_LEDGER_INDEX_CANISTER_ID)
        {
            // Create the ICP index with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"ul4oc-4iaaa-aaaaq-qaabq-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = ii_subnet.state_machine.create_canister_with_cycles(
                Some(CYCLES_LEDGER_INDEX_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, CYCLES_LEDGER_INDEX_CANISTER_ID);

            // Install the cycles ledger index.
            let cycles_ledger_index_init_arg = CyclesLedgerIndexInitArg {
                ledger_id: CYCLES_LEDGER_CANISTER_ID.into(),
                retrieve_blocks_from_ledger_interval_seconds: None,
            };
            let cycles_ledger_index_arg = CyclesLedgerIndexArg::Init(cycles_ledger_index_init_arg);
            ii_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    CYCLES_LEDGER_INDEX_CANISTER_WASM.to_vec(),
                    Encode!(&cycles_ledger_index_arg).unwrap(),
                )
                .unwrap();
        }
    }

    fn deploy_nns_governance(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        let nns_subnet = self
            .nns_subnet
            .clone()
            .expect("The NNS subnet is supposed to already exist if the `nns_governance` ICP feature is specified.");

        if !nns_subnet
            .state_machine
            .canister_exists(GOVERNANCE_CANISTER_ID)
        {
            // Create the governance canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"rrkah-fqaaa-aaaaa-aaaaq-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
            //       wasm_memory_limit = opt (4_294_967_296 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(4_294_967_296_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(GOVERNANCE_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, GOVERNANCE_CANISTER_ID);

            // Install the governance canister with a tiny initial neuron to satisfy the governance canister invariants.
            let mut governance_init_payload_builder = GovernanceCanisterInitPayloadBuilder::new();
            let neuron_id = governance_init_payload_builder.new_neuron_id();
            let current_timestamp_seconds = nns_subnet
                .state_machine
                .time()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            // We create an initial NNS neuron so that the total voting power is not zero.
            // The initial NNS neuron has the following properties:
            // - controlled by the anonymous principal;
            // - stake of 1 ICP;
            // - the maximum possible dissolve delay (8 years).
            let initial_neuron = Neuron {
                id: Some(neuron_id.into()),
                controller: Some(PrincipalId(Principal::anonymous())),
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(8 * ONE_YEAR_SECONDS)),
                cached_neuron_stake_e8s: 100_000_000,
                created_timestamp_seconds: current_timestamp_seconds,
                aging_since_timestamp_seconds: 0,
                account: DEFAULT_SUBACCOUNT.into(),
                not_for_profit: false,
                voting_power_refreshed_timestamp_seconds: Some(current_timestamp_seconds),
                ..Default::default()
            };
            let network_economics = NetworkEconomics::with_mainnet_values();
            let governance_init_payload = GovernanceCanisterInitPayloadBuilder::new()
                .with_network_economics(network_economics)
                .with_genesis_timestamp_seconds(current_timestamp_seconds)
                .with_additional_neurons(vec![initial_neuron])
                .build();
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    GOVERNANCE_TEST_CANISTER_WASM.to_vec(),
                    Encode!(&governance_init_payload).unwrap(),
                )
                .unwrap();
        }

        if !nns_subnet.state_machine.canister_exists(ROOT_CANISTER_ID) {
            // Create the root canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"r7inp-6aaaa-aaaaa-aaabq-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "rno2w-sqaaa-aaaaa-aaacq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
            //       wasm_memory_limit = opt (3_221_225_472 : nat);
            //       memory_allocation = opt (1_073_741_824 : nat);
            //       compute_allocation = opt (0 : nat);
            //     };
            let settings = CanisterSettingsArgs {
                controllers: Some(BoundedVec::new(vec![LIFELINE_CANISTER_ID.get()])),
                compute_allocation: Some(0_u64.into()),
                memory_allocation: Some(1_073_741_824_u64.into()),
                freezing_threshold: Some(2_592_000_u64.into()),
                reserved_cycles_limit: Some(5_000_000_000_000_u128.into()),
                log_visibility: Some(LogVisibilityV2::Controllers),
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(ROOT_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, ROOT_CANISTER_ID);

            // Install the root canister.
            let root_canister_init_payload = RootCanisterInitPayloadBuilder::new().build();
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    ROOT_CANISTER_WASM.to_vec(),
                    Encode!(&root_canister_init_payload).unwrap(),
                )
                .unwrap();
        }
    }

    fn deploy_sns(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        // Nothing to do if the SNS subnet does not exist (yet).
        let Some(ref sns_subnet) = self.sns_subnet else {
            return;
        };

        let nns_subnet = self.nns_subnet.clone().expect(
            "The NNS subnet is supposed to already exist if the `sns` ICP feature is specified.",
        );

        if !nns_subnet
            .state_machine
            .canister_exists(SNS_WASM_CANISTER_ID)
        {
            // Create the SNS-W canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"qaa6y-5yaaa-aaaaa-aaafa-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(SNS_WASM_CANISTER_ID.get()),
                /* The SNS-W canister requires cycles to deploy SNSs and uses 64-bit cycles API. */
                Cycles::from(INITIAL_CYCLES_64_BIT),
                Some(settings),
            );
            assert_eq!(canister_id, SNS_WASM_CANISTER_ID);

            // Install the SNS-W canister and upload SNS canister WASMs.
            let sns_subnet_id = sns_subnet.get_subnet_id();
            let sns_wasm_init_payload = SnsWasmCanisterInitPayloadBuilder::new()
                .with_sns_subnet_ids(vec![sns_subnet_id])
                .build();
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    SNS_WASM_CANISTER_WASM.to_vec(),
                    Encode!(&sns_wasm_init_payload).unwrap(),
                )
                .unwrap();

            for (sns_canister_type, sns_canister_wasm) in [
                (SnsCanisterType::Root, SNS_ROOT_CANISTER_WASM),
                (SnsCanisterType::Governance, SNS_GOVERNANCE_CANISTER_WASM),
                (SnsCanisterType::Swap, SNS_SWAP_CANISTER_WASM),
                (SnsCanisterType::Ledger, SNS_LEDGER_CANISTER_WASM),
                (SnsCanisterType::Archive, SNS_LEDGER_ARCHIVE_CANISTER_WASM),
                (SnsCanisterType::Index, SNS_LEDGER_INDEX_CANISTER_WASM),
            ] {
                let mut hasher = Sha256::new();
                hasher.write(sns_canister_wasm);
                let sns_canister_wasm_hash = hasher.finish();
                let add_sns_wasm_request = AddWasmRequest {
                    wasm: Some(SnsWasm {
                        wasm: sns_canister_wasm.to_vec(),
                        canister_type: sns_canister_type as i32,
                        // `proposal_id` would have been filled by NNS governance if there was an actual NNS proposal
                        proposal_id: None,
                    }),
                    hash: sns_canister_wasm_hash.to_vec(),
                    skip_update_latest_version: Some(false),
                };
                let res = self.execute_ingress_on(
                    nns_subnet.clone(),
                    GOVERNANCE_CANISTER_ID.get(),
                    SNS_WASM_CANISTER_ID,
                    "add_wasm".to_string(),
                    Encode!(&add_sns_wasm_request).unwrap(),
                );
                let decoded = Decode!(&res, AddWasmResponse).unwrap();
                let inner_res = decoded.result.unwrap();
                match inner_res {
                    AddWasmResult::Hash(hash) => assert_eq!(hash, sns_canister_wasm_hash),
                    AddWasmResult::Error(err) => {
                        panic!("Unexpected error when calling add_wasm on SNS-W: {err:?}")
                    }
                }
            }
        }

        if !sns_subnet
            .state_machine
            .canister_exists(SNS_AGGREGATOR_CANISTER_ID)
        {
            // Create the SNS aggregator canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"3r4gx-wqaaa-aaaaq-aaaia-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec {
            //         principal "r7inp-6aaaa-aaaaa-aaabq-cai";
            //         principal "qaa6y-5yaaa-aaaaa-aaafa-cai";
            //       };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
            //       wasm_memory_limit = opt (3_221_225_472 : nat);
            //       memory_allocation = opt (0 : nat);
            //       compute_allocation = opt (0 : nat);
            //     };
            let settings = CanisterSettingsArgs {
                controllers: Some(BoundedVec::new(vec![
                    ROOT_CANISTER_ID.get(),
                    SNS_WASM_CANISTER_ID.get(),
                ])),
                compute_allocation: Some(0_u64.into()),
                memory_allocation: Some(0_u64.into()),
                freezing_threshold: Some(2_592_000_u64.into()),
                reserved_cycles_limit: Some(5_000_000_000_000_u128.into()),
                log_visibility: Some(LogVisibilityV2::Controllers),
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = sns_subnet.state_machine.create_canister_with_cycles(
                Some(SNS_AGGREGATOR_CANISTER_ID.get()),
                /* The SNS aggregator is deployed to an application subnet. */
                Cycles::from(INITIAL_CYCLES),
                Some(settings),
            );
            assert_eq!(canister_id, SNS_AGGREGATOR_CANISTER_ID);

            // Install the SNS aggregator canister.
            // The configuration values have been obtained by calling
            // `dfx canister call 3r4gx-wqaaa-aaaaq-aaaia-cai get_canister_config --update --ic`:
            //     record {
            //       update_interval_ms = 120_000 : nat64;
            //       fast_interval_ms = 10_000 : nat64;
            //     },
            let sns_aggregator_init_payload = SnsAggregatorConfig {
                update_interval_ms: 120_000,
                fast_interval_ms: 10_000,
            };
            sns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    SNS_AGGREGATOR_TEST_CANISTER_WASM.to_vec(),
                    Encode!(&Some(sns_aggregator_init_payload)).unwrap(),
                )
                .unwrap();
        }
    }

    fn deploy_ii(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        // Nothing to do if the II subnet does not exist (yet).
        let Some(ref ii_subnet) = self.ii_subnet else {
            return;
        };

        if !ii_subnet
            .state_machine
            .canister_exists(IDENTITY_CANISTER_ID)
        {
            // Create the Internet Identity canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"rdmx6-jaaaa-aaaaa-aaadq-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = ii_subnet.state_machine.create_canister_with_cycles(
                Some(IDENTITY_CANISTER_ID.get()),
                /* The Internet Identity always attaches cycles to canister http outcalls. */
                Cycles::from(INITIAL_CYCLES),
                Some(settings),
            );
            assert_eq!(canister_id, IDENTITY_CANISTER_ID);

            // Install the Internet Identity canister.
            // The initial values have been adapted from the mainnet values obtained by calling
            // `dfx canister call rdmx6-jaaaa-aaaaa-aaadq-cai config --ic`:
            //     record {
            //       fetch_root_key = null;
            //       is_production = opt true;
            //       enable_dapps_explorer = opt false;
            //       assigned_user_number_range = opt record {
            //         10_000 : nat64;
            //         7_569_744 : nat64;
            //       };
            //       new_flow_origins = opt vec { "https://id.ai" };
            //       archive_config = opt record {
            //         polling_interval_ns = 15_000_000_000 : nat64;
            //         entries_buffer_limit = 10_000 : nat64;
            //         module_hash = blob "\f5\59\00\84\1f\c3\d6\3d\58\01\c1\b6\65\c3\34\6b\c4\8c\58\24\ba\84\3f\55\6a\26\22\6b\60\2f\79\5e";
            //         entries_fetch_limit = 1_000 : nat16;
            //       };
            //       canister_creation_cycles_cost = opt (0 : nat64);
            //       analytics_config = opt opt variant {
            //         Plausible = record {
            //           domain = opt "identity.internetcomputer.org";
            //           track_localhost = null;
            //           hash_mode = null;
            //           api_host = null;
            //         }
            //       };
            //       related_origins = opt vec {
            //         "https://id.ai";
            //         "https://identity.ic0.app";
            //         "https://identity.internetcomputer.org";
            //         "https://identity.icp0.io";
            //       };
            //       openid_configs = opt vec {
            //         record {
            //           auth_uri = "https://accounts.google.com/o/oauth2/v2/auth";
            //           jwks_uri = "https://www.googleapis.com/oauth2/v3/certs";
            //           logo = "<svg viewBox=\"0 0 24 24\"><path d=\"M12.19 2.83A9.15 9.15 0 0 0 4 16.11c1.5 3 4.6 5.06 8.18 5.06 2.47 0 4.55-.82 6.07-2.22a8.95 8.95 0 0 0 2.73-6.74c0-.65-.06-1.28-.17-1.88h-8.63v3.55h4.93a4.23 4.23 0 0 1-1.84 2.76c-3.03 2-7.12.55-8.22-2.9h-.01a5.5 5.5 0 0 1 5.14-7.26 5 5 0 0 1 3.5 1.37l2.63-2.63a8.8 8.8 0 0 0-6.13-2.39z\" style=\"fill: currentColor;\"></path></svg>";
            //           name = "Google";
            //           fedcm_uri = opt "";
            //           issuer = "https://accounts.google.com";
            //           auth_scope = vec { "openid"; "profile"; "email" };
            //           client_id = "775077467414-rgoesk3egruq26c61s6ta8bpjetjqvgo.apps.googleusercontent.com";
            //         };
            //         record {
            //           auth_uri = "https://appleid.apple.com/auth/authorize";
            //           jwks_uri = "https://appleid.apple.com/auth/keys";
            //           logo = "<svg viewBox=\"0 0 24 24\"><path d=\"M14.8 3.2c1-1.2 1.2-2.7 1-3.2-1 0-2.2.7-2.9 1.5-.9 1.2-1.1 2.6-.9 3 .6.2 2-.3 2.8-1.3ZM9.2 20c1.2 0 1.6-.8 3.2-.8 1.5 0 1.8.8 3.1.8s2.3-1.2 3-2.5c1-1.4 1.3-2.8 1.4-2.8 0 0-2.6-1.2-2.6-4.1 0-2.5 2-3.7 2.1-3.8a4.5 4.5 0 0 0-3.9-2c-1.4 0-2.6.8-3.4.8-.8 0-1.9-.8-3.2-.8-2.3 0-4.8 2-4.8 6 0 2.3 1 4.8 2 6.5 1 1.5 1.9 2.7 3 2.7Z\" style=\"fill: currentColor;\"></path></svg>";
            //           name = "Apple";
            //           fedcm_uri = opt "";
            //           issuer = "https://appleid.apple.com";
            //           auth_scope = vec { "openid" };
            //           client_id = "ai.id.auth";
            //         };
            //         record {
            //           auth_uri = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
            //           jwks_uri = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
            //           logo = "<svg viewBox=\"0 0 24 24\"><path d=\"M2.5 2.5h9v9h-9zm10 0h9v9h-9zm-10 10h9v9h-9zm10 0h9v9h-9z\" style=\"fill: currentColor;\"></path></svg>";
            //           name = "Microsoft";
            //           fedcm_uri = opt "";
            //           issuer = "https://login.microsoftonline.com/{tid}/v2.0";
            //           auth_scope = vec { "openid"; "profile"; "email" };
            //           client_id = "80d5203e-9ba2-4acf-97a1-88d926a0bbbf";
            //         };
            //       };
            //       captcha_config = opt record {
            //         max_unsolved_captchas = 500 : nat64;
            //         captcha_trigger = variant { Static = variant { CaptchaDisabled } };
            //       };
            //       dummy_auth = opt null;
            //       register_rate_limit = opt record {
            //         max_tokens = 25_000 : nat64;
            //         time_per_token_ns = 1_000_000_000 : nat64;
            //       };
            //     }

            // The Internet Identity canister makes canister http outcalls if an `OpenIdConfig` is provided
            // and thus we should only provide one if auto progress is enabled
            // (and canister http outcalls are handled by PocketIC automically).
            let openid_google = if self.auto_progress_enabled {
                // We use a different id than in production:
                // https://github.com/dfinity/internet-identity/blob/22d1d7659f0832d010aba7c84948c42bc771af0d/dfx.json#L8
                Some(vec![OpenIdConfig {
                  name: "Google".to_string(),
                  logo: "<svg viewBox=\"0 0 24 24\"><path d=\"M12.19 2.83A9.15 9.15 0 0 0 4 16.11c1.5 3 4.6 5.06 8.18 5.06 2.47 0 4.55-.82 6.07-2.22a8.95 8.95 0 0 0 2.73-6.74c0-.65-.06-1.28-.17-1.88h-8.63v3.55h4.93a4.23 4.23 0 0 1-1.84 2.76c-3.03 2-7.12.55-8.22-2.9h-.01a5.5 5.5 0 0 1 5.14-7.26 5 5 0 0 1 3.5 1.37l2.63-2.63a8.8 8.8 0 0 0-6.13-2.39z\" style=\"fill: currentColor;\"></path></svg>".to_string(),
                  issuer: "https://accounts.google.com".to_string(),
                  client_id: "775077467414-q1ajffledt8bjj82p2rl5a09co8cf4rf.apps.googleusercontent.com".to_string(),
                  jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
                  auth_uri: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                  auth_scope: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
                  fedcm_uri: Some("".to_string()),
                }])
            } else {
                None
            };
            let internet_identity_test_args = Some(InternetIdentityInit {
                assigned_user_number_range: None, // DIFFERENT FROM ICP MAINNET
                archive_config: None,             // DIFFERENT FROM ICP MAINNET
                canister_creation_cycles_cost: Some(0),
                register_rate_limit: Some(RateLimitConfig {
                    max_tokens: 25_000,
                    time_per_token_ns: 1_000_000_000,
                }),
                captcha_config: Some(CaptchaConfig {
                    max_unsolved_captchas: 500,
                    captcha_trigger: CaptchaTrigger::Static(StaticCaptchaTrigger::CaptchaDisabled),
                }),
                related_origins: None,         // DIFFERENT FROM ICP MAINNET
                new_flow_origins: None,        // DIFFERENT FROM ICP MAINNET
                openid_configs: openid_google, // DIFFERENT FROM ICP MAINNET
                analytics_config: None,        // DIFFERENT FROM ICP MAINNET
                fetch_root_key: Some(true),    // DIFFERENT FROM ICP MAINNET
                enable_dapps_explorer: Some(false),
                is_production: Some(false), // DIFFERENT FROM ICP MAINNET
                dummy_auth: Some(None),
            });
            ii_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    INTERNET_IDENTITY_TEST_CANISTER_WASM.to_vec(),
                    Encode!(&internet_identity_test_args).unwrap(),
                )
                .unwrap();
        }
    }

    fn deploy_nns_ui(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        let nns_subnet = self.nns_subnet.clone().expect(
            "The NNS subnet is supposed to already exist if the `nns_ui` ICP feature is specified.",
        );
        let gateway_port = self.gateway_port.expect(
            "The HTTP gateway is supposed to be created if the `nns_ui` ICP feature is specified.",
        );

        if !nns_subnet.state_machine.canister_exists(NNS_UI_CANISTER_ID) {
            // Create the NNS dapp canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"qoctq-giaaa-aaaaa-aaaea-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec { principal "r7inp-6aaaa-aaaaa-aaabq-cai" };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       log_memory_limit = opt (4_096 : nat);
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
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(NNS_UI_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, NNS_UI_CANISTER_ID);

            // Install the NNS dapp canister.
            // The configuration values have been adapted from
            // `https://github.com/dfinity/nns-dapp/blob/5126b011ac52f9f8544c37d18bc15603756a7e3c/scripts/nns-dapp/test-config-assets/mainnet/arg.did`.
            let localhost_url = format!("http://localhost:{gateway_port}");
            let args = vec![
              ("API_HOST".to_string(), localhost_url.clone()),
              ("CYCLES_MINTING_CANISTER_ID".to_string(), CYCLES_MINTING_CANISTER_ID.to_string()),
              ("DFX_NETWORK".to_string(), "local".to_string()),
              ("FEATURE_FLAGS".to_string(), "{\"DISABLE_CKTOKENS\":true,\"DISABLE_IMPORT_TOKEN_VALIDATION_FOR_TESTING\":false,\"ENABLE_APY_PORTFOLIO\":true,\"ENABLE_CKTESTBTC\":false,\"ENABLE_DISBURSE_MATURITY\":true,\"ENABLE_LAUNCHPAD_REDESIGN\":true,\"ENABLE_NEW_TABLES\":true,\"ENABLE_NNS_TOPICS\":false,\"ENABLE_SNS_TOPICS\":true}".to_string()),
              ("FETCH_ROOT_KEY".to_string(), "true".to_string()),
              ("GOVERNANCE_CANISTER_ID".to_string(), GOVERNANCE_CANISTER_ID.to_string()),
              ("HOST".to_string(), localhost_url.clone()),
              /* ICP swap canister is not deployed by PocketIC! */
              ("ICP_SWAP_URL".to_string(), format!("http://uvevg-iyaaa-aaaak-ac27q-cai.raw.localhost:{gateway_port}/")),
              ("IDENTITY_SERVICE_URL".to_string(), format!("http://{IDENTITY_CANISTER_ID}.localhost:{gateway_port}")),
              ("INDEX_CANISTER_ID".to_string(), LEDGER_INDEX_CANISTER_ID.to_string()),
              ("LEDGER_CANISTER_ID".to_string(), LEDGER_CANISTER_ID.to_string()),
              ("OWN_CANISTER_ID".to_string(), NNS_UI_CANISTER_ID.to_string()),
              /* plausible.io API might not work anyway so the value of `PLAUSIBLE_DOMAIN` is pretty much arbitrary */
              ("PLAUSIBLE_DOMAIN".to_string(), format!("{NNS_UI_CANISTER_ID}.localhost")),
              ("ROBOTS".to_string(), "".to_string()),
              ("SNS_AGGREGATOR_URL".to_string(), format!("http://{SNS_AGGREGATOR_CANISTER_ID}.localhost:{gateway_port}")),
              ("STATIC_HOST".to_string(), localhost_url.clone()),
              ("TVL_CANISTER_ID".to_string(), NNS_UI_CANISTER_ID.to_string()),
              ("WASM_CANISTER_ID".to_string(), SNS_WASM_CANISTER_ID.to_string()),
            ];
            let nns_dapp_test_init_payload = NnsDappCanisterArguments { args };
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    NNS_DAPP_TEST_CANISTER_WASM.to_vec(),
                    Encode!(&Some(nns_dapp_test_init_payload)).unwrap(),
                )
                .unwrap();
        }
    }

    fn deploy_bitcoin(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        // Nothing to do if the Bitcoin subnet does not exist (yet).
        let Some(ref btc_subnet) = self.btc_subnet else {
            return;
        };

        if !btc_subnet
            .state_machine
            .canister_exists(BITCOIN_TESTNET_CANISTER_ID)
        {
            // Create the Bitcoin testnet canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"g4xu7-jiaaa-aaaan-aaaaq-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec {
            //         principal "r7inp-6aaaa-aaaaa-aaabq-cai";
            //         principal "cmqvo-qqaaa-aaaai-q3waa-cai";
            //         principal "yfb3o-hyaaa-aaaaj-qno4q-cai";
            //       };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       wasm_memory_limit = opt (2_000_000_000 : nat);
            //       memory_allocation = opt (0 : nat);
            //       compute_allocation = opt (0 : nat);
            //     };
            let settings = CanisterSettingsArgs {
                controllers: Some(BoundedVec::new(vec![
                    ROOT_CANISTER_ID.get(),
                    PrincipalId::from_str("cmqvo-qqaaa-aaaai-q3waa-cai").unwrap(),
                    PrincipalId::from_str("yfb3o-hyaaa-aaaaj-qno4q-cai").unwrap(),
                ])),
                compute_allocation: Some(0_u64.into()),
                memory_allocation: Some(0_u64.into()),
                freezing_threshold: Some(2_592_000_u64.into()),
                reserved_cycles_limit: Some(5_000_000_000_000_u128.into()),
                log_visibility: Some(LogVisibilityV2::Controllers),
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(2_000_000_000_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = btc_subnet.state_machine.create_canister_with_cycles(
                Some(BITCOIN_TESTNET_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, BITCOIN_TESTNET_CANISTER_ID);

            // Install the Bitcoin testnet canister.
            let args = BitcoinInitConfig {
                network: Some(BitcoinNetwork::Regtest),
                fees: Some(BitcoinFees::testnet()),
                ..Default::default()
            };
            btc_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    BITCOIN_TESTNET_CANISTER_WASM.to_vec(),
                    Encode!(&args).unwrap(),
                )
                .unwrap();
        }
    }

    fn deploy_dogecoin(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        // Nothing to do if the Bitcoin subnet does not exist (yet).
        let Some(ref btc_subnet) = self.btc_subnet else {
            return;
        };

        if !btc_subnet
            .state_machine
            .canister_exists(DOGECOIN_CANISTER_ID)
        {
            // Create the Dogecoin mainnet canister with its ICP mainnet settings and configured for the regtest network.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"gordg-fyaaa-aaaan-aaadq-cai";})' --ic`:
            //     settings = record {
            //       freezing_threshold = opt (2_592_000 : nat);
            //       wasm_memory_threshold = opt (0 : nat);
            //       controllers = vec {
            //         principal "r7inp-6aaaa-aaaaa-aaabq-cai";
            //         principal "gordg-fyaaa-aaaan-aaadq-cai";
            //       };
            //       reserved_cycles_limit = opt (5_000_000_000_000 : nat);
            //       log_visibility = opt variant { controllers };
            //       wasm_memory_limit = opt (3_221_225_472 : nat);
            //       memory_allocation = opt (0 : nat);
            //       compute_allocation = opt (0 : nat);
            //     };

            let settings = CanisterSettingsArgs {
                controllers: Some(BoundedVec::new(vec![
                    ROOT_CANISTER_ID.get(),
                    DOGECOIN_CANISTER_ID.get(),
                ])),
                compute_allocation: Some(0_u64.into()),
                memory_allocation: Some(0_u64.into()),
                freezing_threshold: Some(2_592_000_u64.into()),
                reserved_cycles_limit: Some(5_000_000_000_000_u128.into()),
                log_visibility: Some(LogVisibilityV2::Controllers),
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = btc_subnet.state_machine.create_canister_with_cycles(
                Some(DOGECOIN_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, DOGECOIN_CANISTER_ID);

            // Install the Dogecoin mainnet canister configured for the regtest network.
            let args = DogecoinInitConfig {
                network: Some(DogecoinNetwork::Regtest),
                fees: Some(DogecoinFees::mainnet()),
                ..Default::default()
            };
            btc_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    DOGECOIN_CANISTER_WASM.to_vec(),
                    Encode!(&args).unwrap(),
                )
                .unwrap();
        }
    }

    fn deploy_canister_migration(&self, config: &IcpFeaturesConfig) {
        // Using a match here to force an update after changing
        // the type of `IcpFeaturesConfig`.
        match config {
            IcpFeaturesConfig::DefaultConfig => (),
        };

        let nns_subnet = self.nns_subnet.clone().expect(
            "The NNS subnet is supposed to already exist if the `canister_migration` ICP feature is specified.",
        );

        if !nns_subnet
            .state_machine
            .canister_exists(MIGRATION_CANISTER_ID)
        {
            // Create the canister migration orchestrator canister with its ICP mainnet settings.
            // These settings have been obtained by calling
            // `dfx canister call r7inp-6aaaa-aaaaa-aaabq-cai canister_status '(record {canister_id=principal"sbzkb-zqaaa-aaaaa-aaaiq-cai";})' --ic`:
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
                log_memory_limit: Some(4_096_u64.into()),
                wasm_memory_limit: Some(3_221_225_472_u64.into()),
                wasm_memory_threshold: Some(0_u64.into()),
                environment_variables: None,
            };
            let canister_id = nns_subnet.state_machine.create_canister_with_cycles(
                Some(MIGRATION_CANISTER_ID.get()),
                Cycles::zero(),
                Some(settings),
            );
            assert_eq!(canister_id, MIGRATION_CANISTER_ID);

            // Install the canister migration orchestrator canister.
            // TODO: replace by public interface
            #[derive(CandidType, Deserialize, Default)]
            struct MigrationCanisterInitArgs {
                allowlist: Option<Vec<Principal>>,
            }
            nns_subnet
                .state_machine
                .install_wasm_in_mode(
                    canister_id,
                    CanisterInstallMode::Install,
                    MIGRATION_CANISTER_WASM.to_vec(),
                    Encode!(&MigrationCanisterInitArgs::default()).unwrap(),
                )
                .unwrap();
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
    ) -> Vec<u8> {
        let msg_id = subnet
            .state_machine
            .submit_ingress_as(sender, canister_id, &method, payload)
            .unwrap();
        for _ in 0..100 {
            for subnet in self.get_all() {
                subnet.state_machine.execute_round();
            }
            match subnet.state_machine.ingress_status(&msg_id) {
                IngressStatus::Known { state, .. } => match state {
                    IngressState::Completed(WasmResult::Reply(reply)) => return reply,
                    IngressState::Completed(WasmResult::Reject(error)) => panic!(
                        "Failed to execute method {method} on canister {canister_id}: {error}"
                    ),
                    IngressState::Failed(error) => panic!(
                        "Failed to execute method {method} on canister {canister_id}: {error}"
                    ),
                    IngressState::Done => panic!(
                        "Failed to execute method {method} on canister {canister_id}: response has been pruned",
                    ),
                    IngressState::Received | IngressState::Processing => (),
                },
                IngressStatus::Unknown => (),
            }
        }
        panic!(
            "Failed to complete execution of method {method} on canister {canister_id} after 100 rounds."
        );
    }

    fn sync_registry_from_canister(&mut self) {
        if let Some(icp_features) = &self.icp_features
            && icp_features.registry.is_some()
        {
            let nns_subnet = self.nns_subnet.clone().expect("The NNS subnet is supposed to already exist if the `registry` ICP feature is specified.").state_machine.clone();

            let synced_registry_version_before = self.synced_registry_version;
            loop {
                let get_changes_since_request =
                    serialize_get_changes_since_request(self.synced_registry_version.get())
                        .unwrap();
                let wasm_result = nns_subnet
                    .query(
                        REGISTRY_CANISTER_ID,
                        "get_changes_since",
                        get_changes_since_request,
                    )
                    .unwrap();
                let res = match wasm_result {
                    WasmResult::Reply(bytes) => bytes,
                    WasmResult::Reject(err) => {
                        panic!("Unexpected reject from registry canister: {}", err)
                    }
                };
                let (high_capacity_deltas, latest_version) =
                    deserialize_get_changes_since_response(res).unwrap();
                let mut inlined_deltas = vec![];
                for delta in high_capacity_deltas {
                    let delta = self
                        .runtime
                        .block_on(dechunkify_delta(delta, self))
                        .unwrap();
                    inlined_deltas.push(delta);
                }
                let records = registry_deltas_to_registry_records(inlined_deltas).unwrap();
                self.registry_data_provider.add_registry_records(records);
                self.synced_registry_version = self.registry_data_provider.latest_version();
                if self.synced_registry_version == latest_version.into() {
                    break;
                }
            }
            if synced_registry_version_before != self.synced_registry_version {
                self.persist_registry_changes();
                // update routing table
                let registry_client =
                    RegistryClientImpl::new(self.registry_data_provider.clone(), None);
                registry_client.poll_once().unwrap();
                let routing_table = registry_client
                    .get_routing_table(self.registry_data_provider.latest_version())
                    .expect("Failed to get routing table")
                    .expect("Failed to get routing table");
                self.routing_table = routing_table;
            }
        }
    }

    fn persist_registry_changes(&mut self) {
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
    }
}

#[async_trait]
impl GetChunk for PocketIcSubnets {
    async fn get_chunk_without_validation(&self, content_sha256: &[u8]) -> Result<Vec<u8>, String> {
        let nns_subnet = self.nns_subnet.clone().expect("The NNS subnet is supposed to already exist if the `registry` ICP feature is specified.").state_machine.clone();

        let get_chunk_request = GetChunkRequest {
            content_sha256: Some(content_sha256.to_vec()),
        };
        let wasm_result = nns_subnet
            .query(
                REGISTRY_CANISTER_ID,
                "get_chunk",
                Encode!(&get_chunk_request).unwrap(),
            )
            .unwrap();
        match wasm_result {
            WasmResult::Reply(bytes) => Decode!(&bytes, Result<Vec<u8>, String>).unwrap(),
            WasmResult::Reject(err) => {
                panic!("Unexpected reject from registry canister: {}", err)
            }
        }
    }
}

pub struct PocketIc {
    range_gen: RangeGen,
    runtime: Arc<Runtime>,
    mainnet_routing_table: RoutingTable,
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        runtime: Arc<Runtime>,
        mainnet_routing_table: RoutingTable,
        seed: u64,
        subnet_configs: ExtendedSubnetConfigSet,
        state_dir: Option<PathBuf>,
        icp_config: IcpConfig,
        log_level: Option<Level>,
        bitcoind_addr: Option<Vec<SocketAddr>>,
        dogecoind_addr: Option<Vec<SocketAddr>>,
        icp_features: Option<IcpFeatures>,
        incomplete_state: Option<IncompleteStateFlag>,
        initial_time: Option<Time>,
        auto_progress_enabled: bool,
        gateway_port: Option<u16>,
    ) -> Result<Self, String> {
        if let Some(time) = initial_time {
            let systime: SystemTime = time.into();
            let minimum_systime = default_timestamp(&icp_features);
            if systime < minimum_systime {
                return Err(format!(
                    "The initial timestamp (unix timestamp in nanoseconds) must be no earlier than {} (provided {}).",
                    systemtime_to_unix_epoch_nanos(minimum_systime),
                    systemtime_to_unix_epoch_nanos(systime)
                ));
            }
        }
        let initial_time: SystemTime = initial_time
            .map(|time| time.into())
            .unwrap_or_else(|| default_timestamp(&icp_features));

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

        // We only update registry and system canisters during subnet creation
        // if the PocketIC does not resume from an existing state
        // in which case registry and system canisters have already been updated before.
        let update_registry_and_system_canisters = topology.is_none();
        let mut subnet_config_info: Vec<SubnetConfigInfo> = if let Some(topology) = topology {
            topology
                .subnet_configs
                .into_iter()
                .map(|config| {
                    range_gen.add_assigned(config.ranges.clone()).unwrap();
                    if let Some(allocation_range) = config.alloc_range {
                        range_gen.add_assigned(vec![allocation_range]).unwrap();
                    }
                    let expected_state_time = match incomplete_state {
                        None | Some(IncompleteStateFlag::Disabled) => Some(topology.time),
                        Some(IncompleteStateFlag::Enabled) => None,
                    };
                    SubnetConfigInfo {
                        ranges: config.ranges,
                        alloc_range: config.alloc_range,
                        subnet_id: Some(config.subnet_id),
                        subnet_state_dir: None,
                        subnet_kind: config.subnet_kind,
                        instruction_config: config.instruction_config,
                        expected_state_time,
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
                    if let Some(mut subnet_kind_ranges) =
                        subnet_kind_canister_ranges(&mainnet_routing_table, subnet_kind)
                    {
                        subnet_kind_ranges.sort();
                        if !is_subset_of(subnet_kind_ranges.iter(), sorted_ranges.iter()) {
                            return Err(format!(
                                "The actual subnet canister ranges {sorted_ranges:?} do not contain the canister ranges {subnet_kind_ranges:?} expected for the subnet kind {subnet_kind:?}."
                            ));
                        }
                    }
                    for other_subnet_kind in SubnetKind::iter() {
                        if subnet_kind != other_subnet_kind
                            && let Some(mut other_subnet_kind_ranges) = subnet_kind_canister_ranges(
                                &mainnet_routing_table,
                                other_subnet_kind,
                            )
                        {
                            other_subnet_kind_ranges.sort();
                            if !are_disjoint(other_subnet_kind_ranges.iter(), sorted_ranges.iter())
                            {
                                return Err(format!(
                                    "The actual subnet canister ranges {sorted_ranges:?} for the subnet kind {subnet_kind:?} are not disjoint from the canister ranges {other_subnet_kind_ranges:?} for a different subnet kind {other_subnet_kind:?}."
                                ));
                            }
                        }
                    }

                    (ranges, None, Some(subnet_id))
                } else {
                    let RangeConfig {
                        canister_id_ranges: ranges,
                        canister_allocation_range: alloc_range,
                    } = get_range_config(&mainnet_routing_table, subnet_kind, &mut range_gen)?;

                    (ranges, alloc_range, None)
                };

                subnet_config_info.push(SubnetConfigInfo {
                    ranges,
                    alloc_range,
                    subnet_id,
                    subnet_state_dir,
                    subnet_kind,
                    instruction_config,
                    expected_state_time: None,
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
        let registry_data_provider = if let Some(registry) = registry {
            Arc::new(ProtoRegistryDataProvider::try_decode(Bytes::from(
                registry,
            ))?)
        } else {
            let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
            add_initial_registry_records(registry_data_provider.clone());
            registry_data_provider
        };
        let mut subnets = PocketIcSubnets::new(
            runtime.clone(),
            state_dir,
            icp_config,
            log_level,
            bitcoind_addr,
            dogecoind_addr,
            icp_features,
            initial_time,
            auto_progress_enabled,
            gateway_port,
            registry_data_provider,
            synced_registry_version,
        );
        let mut subnet_configs = Vec::new();
        for subnet_config_info in subnet_config_info.into_iter() {
            let subnet_config_internal =
                subnets.create_subnet(subnet_config_info, update_registry_and_system_canisters)?;
            subnet_configs.push(subnet_config_internal);
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
            mainnet_routing_table,
            state_label,
            subnets,
            default_effective_canister_id,
        })
    }

    pub(crate) fn sync_registry_from_canister(&mut self) {
        self.subnets.sync_registry_from_canister();
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

fn subnet_kind_canister_ranges(
    mainnet_routing_table: &RoutingTable,
    subnet_kind: SubnetKind,
) -> Option<Vec<CanisterIdRange>> {
    use rest::SubnetKind::*;
    match subnet_kind {
        Application | VerifiedApplication | System => None,
        NNS => {
            let nns_subnet_id = PrincipalId::from_str(MAINNET_NNS_SUBNET_ID).unwrap().into();
            Some(
                mainnet_routing_table
                    .ranges(nns_subnet_id)
                    .iter()
                    .cloned()
                    .collect(),
            )
        }
        II => {
            let ii_subnet_id = PrincipalId::from_str(MAINNET_II_SUBNET_ID).unwrap().into();
            Some(
                mainnet_routing_table
                    .ranges(ii_subnet_id)
                    .iter()
                    .cloned()
                    .collect(),
            )
        }
        Bitcoin => {
            let bitcoin_subnet_id = PrincipalId::from_str(MAINNET_BITCOIN_SUBNET_ID)
                .unwrap()
                .into();
            Some(
                mainnet_routing_table
                    .ranges(bitcoin_subnet_id)
                    .iter()
                    .cloned()
                    .collect(),
            )
        }
        Fiduciary => {
            let fiduciary_subnet_id = PrincipalId::from_str(MAINNET_FIDUCIARY_SUBNET_ID)
                .unwrap()
                .into();
            Some(
                mainnet_routing_table
                    .ranges(fiduciary_subnet_id)
                    .iter()
                    .cloned()
                    .collect(),
            )
        }
        SNS => {
            let sns_subnet_id = PrincipalId::from_str(MAINNET_SNS_SUBNET_ID).unwrap().into();
            Some(
                mainnet_routing_table
                    .ranges(sns_subnet_id)
                    .iter()
                    .cloned()
                    .collect(),
            )
        }
    }
}

fn subnet_kind_from_canister_id(
    mainnet_routing_table: &RoutingTable,
    canister_id: CanisterId,
) -> SubnetKind {
    for subnet_kind in SubnetKind::iter() {
        if let Some(ranges) = subnet_kind_canister_ranges(mainnet_routing_table, subnet_kind)
            && ranges.iter().any(|r| r.contains(&canister_id))
        {
            return subnet_kind;
        }
    }
    SubnetKind::Application
}

fn get_range_config(
    mainnet_routing_table: &RoutingTable,
    subnet_kind: rest::SubnetKind,
    range_gen: &mut RangeGen,
) -> Result<RangeConfig, String> {
    let (canister_id_ranges, canister_allocation_range) =
        match subnet_kind_canister_ranges(mainnet_routing_table, subnet_kind) {
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
    pub expected_state_time: Option<SystemTime>,
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
    response: Result<HttpsOutcallResult, (Code, String)>,
}

impl SingleResponseAdapter {
    fn new(response: Result<HttpsOutcallResult, (Code, String)>) -> Self {
        Self { response }
    }
}

#[tonic::async_trait]
impl HttpsOutcallsService for SingleResponseAdapter {
    async fn https_outcall(
        &self,
        _request: Request<HttpsOutcallRequest>,
    ) -> Result<Response<HttpsOutcallResult>, Status> {
        match self.response.clone() {
            Ok(resp) => Ok(Response::new(resp)),
            Err((code, msg)) => Err(Status::new(code, msg)),
        }
    }
}

async fn setup_adapter_mock(
    adapter_response: Result<HttpsOutcallResult, (Code, String)>,
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
                    Err(std::io::Error::other("Client already taken"))
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

    let response_to_content = |response: &CanisterHttpResponse| match response {
        CanisterHttpResponse::CanisterHttpReply(reply) => {
            let response = HttpsOutcallResponse {
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
            };

            let headers_size: usize = response
                .headers
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum();
            let total_size = (response.content.len() + headers_size) as u64;

            let result = ic_https_outcalls_service::HttpsOutcallResult {
                metrics: Some(ic_https_outcalls_service::CanisterHttpAdapterMetrics {
                    downloaded_bytes: total_size,
                }),
                result: Some(
                    ic_https_outcalls_service::https_outcall_result::Result::Response(response),
                ),
            };

            let grpc_channel = pic.runtime.block_on(setup_adapter_mock(Ok(result)));

            let mut client = CanisterHttpAdapterClientImpl::new(
                pic.runtime.handle().clone(),
                grpc_channel,
                subnet.transform_handler.lock().unwrap().clone(),
                1,
                MetricsRegistry::new(),
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

        if let Some(ref bm_per_subnet) = blockmakers_per_subnet
            && let Err(error) = self.validate_blockmakers_per_subnet(pic, bm_per_subnet)
        {
            return error;
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
pub struct CanisterSnapshotDownload {
    pub sender: PrincipalId,
    pub canister_id: CanisterId,
    pub snapshot_id: SnapshotId,
    pub snapshot_dir: PathBuf,
}

fn ensure_empty_dir(path: &Path) -> Result<(), String> {
    // Create the directory if needed (including parents).
    // Succeeds silently if the directory already exists.
    std::fs::create_dir_all(path)
        .map_err(|e| format!("Could not create snapshot directory: {}", e))?;

    // Now ensure it's actually a directory.
    if !path.is_dir() {
        return Err("Snapshot directory path exists but is not a directory".to_string());
    }

    // Check if it is empty.
    if std::fs::read_dir(path)
        .map_err(|e| format!("Could not read snapshot directory: {}", e))?
        .next()
        .is_some()
    {
        return Err("Snapshot directory is not empty".to_string());
    }

    Ok(())
}

enum BlobKind {
    WasmModule,
    WasmMemory,
    StableMemory,
}

impl BlobKind {
    fn description(&self) -> &str {
        match self {
            BlobKind::WasmModule => "WASM module",
            BlobKind::WasmMemory => "WASM memory",
            BlobKind::StableMemory => "stable memory",
        }
    }
}

fn download_blob_to_file(
    subnet: Arc<StateMachine>,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
    blob_kind: BlobKind,
    length: u64,
    file: PathBuf,
) -> Result<(), String> {
    let mut offset = 0;
    let mut file = OpenOptions::new()
        .create(true) // create the file if it doesn't exist
        .append(true) // allow appending
        .open(file)
        .map_err(|e| format!("Could not create {} file: {}", blob_kind.description(), e))?;
    while offset < length {
        let chunk_size = std::cmp::min(length - offset, MAX_CHUNK_SIZE);
        let kind = match blob_kind {
            BlobKind::WasmModule => CanisterSnapshotDataKind::WasmModule {
                offset,
                size: chunk_size,
            },
            BlobKind::WasmMemory => CanisterSnapshotDataKind::WasmMemory {
                offset,
                size: chunk_size,
            },
            BlobKind::StableMemory => CanisterSnapshotDataKind::StableMemory {
                offset,
                size: chunk_size,
            },
        };
        let data_args = ReadCanisterSnapshotDataArgs {
            canister_id: canister_id.into(),
            snapshot_id,
            kind,
        };
        let data = subnet
            .read_canister_snapshot_data(&data_args)
            .map_err(|e| e.description().to_string())?
            .chunk;
        file.write_all(&data)
            .map_err(|e| format!("Could not write {} file: {}", blob_kind.description(), e))?;
        offset += chunk_size;
    }
    Ok(())
}

impl Operation for CanisterSnapshotDownload {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let effective_principal = EffectivePrincipal::CanisterId(self.canister_id);
        let subnet = route(pic, effective_principal, false);
        match subnet {
            Ok(subnet) => {
                if let Err(e) = ensure_empty_dir(&self.snapshot_dir) {
                    return OpOut::Error(PocketIcError::InvalidCanisterSnapshotDirectory(e));
                }

                // Download snapshot metadata.
                let metadata_args = ReadCanisterSnapshotMetadataArgs {
                    canister_id: self.canister_id.into(),
                    snapshot_id: self.snapshot_id,
                };
                let metadata = match subnet.read_canister_snapshot_metadata(&metadata_args) {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        return OpOut::Error(PocketIcError::CanisterSnapshotError(
                            e.description().to_string(),
                        ));
                    }
                };
                let metadata_bytes = serde_json::to_string_pretty(&metadata).unwrap();
                let metadata_path = self.snapshot_dir.join("metadata.json");
                if let Err(e) = std::fs::write(metadata_path, metadata_bytes) {
                    return OpOut::Error(PocketIcError::CanisterSnapshotError(format!(
                        "Could not write metadata file: {}",
                        e
                    )));
                }

                // Download WASM binary.
                let wasm_module_path = self.snapshot_dir.join("wasm_module.bin");
                if let Err(e) = download_blob_to_file(
                    subnet.clone(),
                    self.canister_id,
                    self.snapshot_id,
                    BlobKind::WasmModule,
                    metadata.wasm_module_size,
                    wasm_module_path,
                ) {
                    return OpOut::Error(PocketIcError::CanisterSnapshotError(e));
                }

                // Download WASM memory.
                let wasm_memory_path = self.snapshot_dir.join("wasm_memory.bin");
                if let Err(e) = download_blob_to_file(
                    subnet.clone(),
                    self.canister_id,
                    self.snapshot_id,
                    BlobKind::WasmMemory,
                    metadata.wasm_memory_size,
                    wasm_memory_path,
                ) {
                    return OpOut::Error(PocketIcError::CanisterSnapshotError(e));
                }

                // Download stable memory.
                if metadata.stable_memory_size != 0 {
                    let stable_memory_path = self.snapshot_dir.join("stable_memory.bin");
                    if let Err(e) = download_blob_to_file(
                        subnet.clone(),
                        self.canister_id,
                        self.snapshot_id,
                        BlobKind::StableMemory,
                        metadata.stable_memory_size,
                        stable_memory_path,
                    ) {
                        return OpOut::Error(PocketIcError::CanisterSnapshotError(e));
                    }
                }

                // Download WASM chunk store.
                let chunk_store = match subnet.get_snapshot_chunk_store(&metadata_args) {
                    Ok(chunk_store) => chunk_store,
                    Err(e) => {
                        return OpOut::Error(PocketIcError::CanisterSnapshotError(
                            e.description().to_string(),
                        ));
                    }
                };
                if !chunk_store.is_empty() {
                    let chunk_store_path = self.snapshot_dir.join("wasm_chunk_store");
                    if let Err(e) = std::fs::create_dir_all(&chunk_store_path) {
                        return OpOut::Error(PocketIcError::CanisterSnapshotError(format!(
                            "Could not create WASM chunk store directory: {}",
                            e
                        )));
                    }
                    for (hash, chunk) in chunk_store {
                        let hash_str = hex::encode(hash);
                        let chunk_file = chunk_store_path.join(format!("{hash_str}.bin"));
                        if let Err(e) = std::fs::write(chunk_file, chunk) {
                            return OpOut::Error(PocketIcError::CanisterSnapshotError(format!(
                                "Could not write WASM chunk: {}",
                                e
                            )));
                        }
                    }
                }

                OpOut::NoOutput
            }
            Err(e) => OpOut::Error(PocketIcError::CanisterRequestRoutingError(e)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!(
            "canister_snapshot_download(sender={},canister_id={},snapshot_id={},snapshot_dir='{}')",
            self.sender,
            self.canister_id,
            self.snapshot_id,
            base64::encode_config(self.snapshot_dir.display().to_string(), base64::URL_SAFE)
        ))
    }
}

#[derive(Clone, Debug)]
pub struct CanisterSnapshotUpload {
    pub sender: PrincipalId,
    pub canister_id: CanisterId,
    pub replace_snapshot: Option<SnapshotId>,
    pub snapshot_dir: PathBuf,
}

fn upload_blob_from_file(
    subnet: Arc<StateMachine>,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
    blob_kind: BlobKind,
    length: u64,
    file: PathBuf,
) -> Result<(), String> {
    let mut offset = 0;
    let mut file = File::open(file)
        .map_err(|e| format!("Could not open {} file: {}", blob_kind.description(), e))?;
    while offset < length {
        let chunk_size = std::cmp::min(length - offset, MAX_CHUNK_SIZE);
        let mut chunk = vec![0u8; chunk_size as usize];
        file.read_exact(&mut chunk)
            .map_err(|e| format!("Could not read {} file: {}", blob_kind.description(), e))?;
        let kind = match blob_kind {
            BlobKind::WasmModule => CanisterSnapshotDataOffset::WasmModule { offset },
            BlobKind::WasmMemory => CanisterSnapshotDataOffset::WasmMemory { offset },
            BlobKind::StableMemory => CanisterSnapshotDataOffset::StableMemory { offset },
        };
        let data_args = UploadCanisterSnapshotDataArgs {
            canister_id: canister_id.into(),
            snapshot_id,
            kind,
            chunk,
        };
        subnet
            .upload_canister_snapshot_data(&data_args)
            .map_err(|e| e.description().to_string())?;
        offset += chunk_size;
    }
    Ok(())
}

impl Operation for CanisterSnapshotUpload {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let effective_principal = EffectivePrincipal::CanisterId(self.canister_id);
        let subnet = route(pic, effective_principal, false);
        match subnet {
            Ok(subnet) => {
                // Upload snapshot metadata.
                let metadata_path = self.snapshot_dir.join("metadata.json");
                let metadata_bytes = match std::fs::read(metadata_path) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return OpOut::Error(PocketIcError::CanisterSnapshotError(format!(
                            "Could not read metadata file: {}",
                            e
                        )));
                    }
                };
                let metadata: ReadCanisterSnapshotMetadataResponse =
                    match serde_json::from_slice(&metadata_bytes) {
                        Ok(metadata) => metadata,
                        Err(e) => {
                            return OpOut::Error(PocketIcError::CanisterSnapshotError(format!(
                                "Could not parse metadata file: {}",
                                e
                            )));
                        }
                    };
                let metadata_args = UploadCanisterSnapshotMetadataArgs {
                    canister_id: self.canister_id.into(),
                    replace_snapshot: self.replace_snapshot,
                    wasm_module_size: metadata.wasm_module_size,
                    globals: metadata.globals,
                    wasm_memory_size: metadata.wasm_memory_size,
                    stable_memory_size: metadata.stable_memory_size,
                    certified_data: metadata.certified_data,
                    global_timer: metadata.global_timer,
                    on_low_wasm_memory_hook_status: metadata.on_low_wasm_memory_hook_status,
                };
                let snapshot_id = match subnet.upload_canister_snapshot_metadata(&metadata_args) {
                    Ok(upload_response) => upload_response.snapshot_id,
                    Err(e) => {
                        return OpOut::Error(PocketIcError::CanisterSnapshotError(
                            e.description().to_string(),
                        ));
                    }
                };

                // Upload WASM binary.
                let wasm_module_path = self.snapshot_dir.join("wasm_module.bin");
                if let Err(e) = upload_blob_from_file(
                    subnet.clone(),
                    self.canister_id,
                    snapshot_id,
                    BlobKind::WasmModule,
                    metadata.wasm_module_size,
                    wasm_module_path,
                ) {
                    return OpOut::Error(PocketIcError::CanisterSnapshotError(e));
                }

                // Upload WASM memory.
                let wasm_memory_path = self.snapshot_dir.join("wasm_memory.bin");
                if let Err(e) = upload_blob_from_file(
                    subnet.clone(),
                    self.canister_id,
                    snapshot_id,
                    BlobKind::WasmMemory,
                    metadata.wasm_memory_size,
                    wasm_memory_path,
                ) {
                    return OpOut::Error(PocketIcError::CanisterSnapshotError(e));
                }

                // Upload stable memory.
                if metadata.stable_memory_size != 0 {
                    let stable_memory_path = self.snapshot_dir.join("stable_memory.bin");
                    if let Err(e) = upload_blob_from_file(
                        subnet.clone(),
                        self.canister_id,
                        snapshot_id,
                        BlobKind::StableMemory,
                        metadata.stable_memory_size,
                        stable_memory_path,
                    ) {
                        return OpOut::Error(PocketIcError::CanisterSnapshotError(e));
                    }
                }

                // Upload WASM chunk store.
                for hash in metadata.wasm_chunk_store {
                    let hash_str = hex::encode(hash.hash);
                    let chunk_store_path = self.snapshot_dir.join("wasm_chunk_store");
                    let chunk_file = chunk_store_path.join(format!("{hash_str}.bin"));
                    let chunk = match std::fs::read(chunk_file) {
                        Ok(chunk) => chunk,
                        Err(e) => {
                            return OpOut::Error(PocketIcError::CanisterSnapshotError(format!(
                                "Could not read WASM chunk: {}",
                                e
                            )));
                        }
                    };
                    let data_args = UploadCanisterSnapshotDataArgs {
                        canister_id: self.canister_id.into(),
                        snapshot_id,
                        kind: CanisterSnapshotDataOffset::WasmChunk,
                        chunk,
                    };
                    match subnet.upload_canister_snapshot_data(&data_args) {
                        Ok(_) => (),
                        Err(e) => {
                            return OpOut::Error(PocketIcError::CanisterSnapshotError(
                                e.description().to_string(),
                            ));
                        }
                    };
                }

                OpOut::CanisterSnapshotId(snapshot_id.to_vec())
            }
            Err(e) => OpOut::Error(PocketIcError::CanisterRequestRoutingError(e)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!(
            "canister_snapshot_upload(sender={},canister_id={},snapshot_dir='{}')",
            self.sender,
            self.canister_id,
            base64::encode_config(self.snapshot_dir.display().to_string(), base64::URL_SAFE)
        ))
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
                        eprintln!("Failed to submit ingress message: {e}");
                        OpOut::Error(PocketIcError::BadIngressMessage(e))
                    }
                    Err(SubmitIngressError::UserError(e)) => {
                        eprintln!("Failed to submit ingress message: {e:?}");
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
                });
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
                if let Some(caller) = self.caller
                    && let Some(actual_caller) = subnet.ingress_caller(&self.message_id.msg_id)
                    && caller != actual_caller.get().0
                {
                    return OpOut::Error(PocketIcError::Forbidden(
                        "The user tries to access Request ID not signed by the caller.".to_string(),
                    ));
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
                let delegation = pic
                    .get_nns_delegation_for_subnet(subnet.get_subnet_id())
                    .map(|delegation| {
                        (
                            delegation,
                            CertificateDelegationMetadata {
                                format: CertificateDelegationFormat::Flat,
                            },
                        )
                    });
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
                format!("Internal error: {e}"),
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
        OpId(format!("status({hash})",))
    }
}

pub enum CallRequestVersion {
    V2,
    V3,
    V4,
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
            Err(e) => OpOut::Error(PocketIcError::CanisterRequestRoutingError(e)),
            Ok(subnet) => {
                // Make sure the latest state is certified for the ingress filter to work.
                subnet.certify_latest_state();

                let node = &subnet.nodes[0];
                let (s, mut r) = mpsc::channel(MAX_P2P_IO_CHANNEL_SIZE);
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
                    CallRequestVersion::V2 => call_async::new_service(ingress_validator),
                    CallRequestVersion::V3 | CallRequestVersion::V4 => {
                        let subnet_id = subnet.get_subnet_id();
                        let delegation = pic.get_nns_delegation_for_subnet(subnet_id);
                        let builder = delegation.map(|delegation| {
                            NNSDelegationBuilder::try_new(
                                delegation.certificate,
                                subnet_id,
                                &subnet.replica_logger,
                            )
                            .unwrap()
                        });
                        let (_, delegation_rx) = watch::channel(builder);
                        let metrics_registry = MetricsRegistry::new();
                        let metrics = HttpHandlerMetrics::new(&metrics_registry);

                        call_sync::new_service(
                            ingress_validator,
                            subnet.ingress_watcher_handle.clone(),
                            metrics,
                            http_handler::Config::default()
                                .ingress_message_certificate_timeout_seconds,
                            NNSDelegationReader::new(delegation_rx, subnet.replica_logger.clone()),
                            subnet.state_manager.clone(),
                            match self.version {
                                CallRequestVersion::V2 => unreachable!(),
                                CallRequestVersion::V3 => call_sync::Version::V3,
                                CallRequestVersion::V4 => call_sync::Version::V4,
                            },
                        )
                    }
                };

                let api_version = match self.version {
                    CallRequestVersion::V2 => "v2",
                    CallRequestVersion::V3 => "v3",
                    CallRequestVersion::V4 => "v4",
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
    pub version: query::Version,
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
            Err(e) => OpOut::Error(PocketIcError::CanisterRequestRoutingError(e)),
            Ok(subnet) => {
                let subnet_id = subnet.get_subnet_id();
                let delegation = pic.get_nns_delegation_for_subnet(subnet_id);
                let builder = delegation.map(|delegation| {
                    NNSDelegationBuilder::try_new(
                        delegation.certificate,
                        subnet_id,
                        &subnet.replica_logger,
                    )
                    .unwrap()
                });
                let (_, delegation_rx) = watch::channel(builder);
                let node = &subnet.nodes[0];
                subnet.certify_latest_state();
                let query_handler = subnet.query_handler.lock().unwrap().clone();
                let svc = QueryServiceBuilder::builder(
                    subnet.replica_logger.clone(),
                    node.node_id,
                    Arc::new(PocketNodeSigner(node.node_signing_key.clone())),
                    subnet.registry_client.clone(),
                    Arc::new(StandaloneIngressSigVerifier),
                    NNSDelegationReader::new(delegation_rx, subnet.replica_logger.clone()),
                    query_handler,
                    self.version,
                )
                .with_time_source(subnet.time_source.clone())
                .build_service();

                let version_str = match self.version {
                    query::Version::V2 => "v2",
                    query::Version::V3 => "v3",
                };

                let request = axum::http::Request::builder()
                    .method(Method::POST)
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .uri(format!(
                        "/api/{version_str}/canister/{}/query",
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
    pub version: read_state::canister::Version,
}

impl Operation for CanisterReadStateRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        match route(
            pic,
            EffectivePrincipal::CanisterId(self.effective_canister_id),
            false,
        ) {
            Err(e) => OpOut::Error(PocketIcError::CanisterRequestRoutingError(e)),
            Ok(subnet) => {
                let subnet_id = subnet.get_subnet_id();
                let delegation = pic.get_nns_delegation_for_subnet(subnet_id);
                let nns_subnet_id = pic
                    .nns_subnet()
                    .map(|subnet| subnet.get_subnet_id())
                    .expect(
                        "The NNS subnet should already exist if we are already executing requests",
                    );
                let builder = delegation.map(|delegation| {
                    NNSDelegationBuilder::try_new(
                        delegation.certificate,
                        subnet_id,
                        &subnet.replica_logger,
                    )
                    .unwrap()
                });
                let (_, delegation_rx) = watch::channel(builder);
                subnet.certify_latest_state();
                let svc = CanisterReadStateServiceBuilder::builder(
                    subnet.replica_logger.clone(),
                    subnet.state_manager.clone(),
                    subnet.registry_client.clone(),
                    Arc::new(StandaloneIngressSigVerifier),
                    NNSDelegationReader::new(delegation_rx, subnet.replica_logger.clone()),
                    nns_subnet_id,
                    self.version,
                )
                .with_time_source(subnet.time_source.clone())
                .build_service();

                let version_str = match self.version {
                    read_state::canister::Version::V2 => "v2",
                    read_state::canister::Version::V3 => "v3",
                };

                let request = axum::http::Request::builder()
                    .method(Method::POST)
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .uri(format!(
                        "/api/{version_str}/canister/{}/read_state",
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
    pub version: read_state::subnet::Version,
}

impl Operation for SubnetReadStateRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        match route(pic, EffectivePrincipal::SubnetId(self.subnet_id), false) {
            Err(e) => OpOut::Error(PocketIcError::SubnetRequestRoutingError(e)),
            Ok(subnet) => {
                let subnet_id = subnet.get_subnet_id();
                let delegation = pic.get_nns_delegation_for_subnet(subnet_id);
                let builder = delegation.map(|delegation| {
                    NNSDelegationBuilder::try_new(
                        delegation.certificate,
                        subnet_id,
                        &subnet.replica_logger,
                    )
                    .unwrap()
                });
                let (_, delegation_rx) = watch::channel(builder);
                subnet.certify_latest_state();
                let nns_subnet_id = pic
                    .nns_subnet()
                    .map(|subnet| subnet.get_subnet_id())
                    .expect(
                        "The NNS subnet should already exist if we are already executing requests",
                    );
                let svc = SubnetReadStateServiceBuilder::builder(
                    NNSDelegationReader::new(delegation_rx, subnet.replica_logger.clone()),
                    subnet.state_manager.clone(),
                    nns_subnet_id,
                    self.version,
                )
                .build_service();

                let version_str = match self.version {
                    read_state::subnet::Version::V2 => "v2",
                    read_state::subnet::Version::V3 => "v3",
                };

                let request = axum::http::Request::builder()
                    .method(Method::POST)
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .uri(format!(
                        "/api/{version_str}/subnet/{}/read_state",
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
                });
            }
        };
        let canister_id = match CanisterId::try_from(canister_id) {
            Ok(canister_id) => canister_id,
            Err(_) => {
                return Err(ConversionError {
                    message: "Bad canister id".to_string(),
                });
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
        self.0.iter().try_for_each(|b| write!(f, "{b:02X}"))?;
        write!(f, ")")
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
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
                    // NNS subnet cannot be created at this point though because NNS is the root subnet
                    // and the root subnet cannot be changed after its PocketIC instance has already been created.
                    let subnet_id = match pic.mainnet_routing_table.lookup_entry(canister_id) {
                        Some((_, subnet_id)) => subnet_id,
                        None => {
                            return Err(format!(
                                "The effective canister ID {canister_id} does not belong to an existing subnet and it is not a mainnet canister ID."
                            ));
                        }
                    };
                    let subnet_kind =
                        subnet_kind_from_canister_id(&pic.mainnet_routing_table, canister_id);
                    if matches!(subnet_kind, SubnetKind::NNS) {
                        return Err(format!(
                            "The effective canister ID {canister_id} belongs to the NNS subnet on the IC mainnet for which PocketIC provides a `SubnetKind`: please set up your PocketIC instance with a subnet of that `SubnetKind`."
                        ));
                    }
                    let instruction_config = SubnetInstructionConfig::Production;
                    let ranges = pic
                        .mainnet_routing_table
                        .ranges(subnet_id)
                        .iter()
                        .cloned()
                        .collect();
                    // The canister allocation range must be disjoint from the canister ranges on the IC mainnet
                    // and all existing canister ranges within the PocketIC instance and thus we use
                    // `RangeGen::next_range()` to produce such a canister range.
                    let canister_allocation_range = pic.range_gen.next_range();
                    // This is a fresh subnet so we always update registry and system canisters.
                    let update_registry_and_system_canisters = true;
                    pic.subnets.create_subnet(
                        SubnetConfigInfo {
                            ranges,
                            alloc_range: Some(canister_allocation_range),
                            subnet_id: None,
                            subnet_state_dir: None,
                            subnet_kind,
                            instruction_config,
                            expected_state_time: None,
                        },
                        update_registry_and_system_canisters,
                    )?;
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
                    .map_err(|e| format!("Error decoding candid: {e:?}"))?;
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
                        .map_err(|e| format!("Error decoding candid: {e:?}"))?;
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
                RoutingTable::new(),
                0,
                ExtendedSubnetConfigSet {
                    application: vec![SubnetSpec::default()],
                    ..Default::default()
                },
                None,
                IcpConfig::default(),
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
            )
            .unwrap();
            let mut pic1 = PocketIc::try_new(
                runtime.clone(),
                RoutingTable::new(),
                1,
                ExtendedSubnetConfigSet {
                    application: vec![SubnetSpec::default()],
                    ..Default::default()
                },
                None,
                IcpConfig::default(),
                None,
                None,
                None,
                None,
                None,
                None,
                false,
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
