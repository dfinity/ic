use crate::async_trait;
use crate::state_api::state::{HasStateLabel, OpOut, PocketIcError, StateLabel};
use crate::OpId;
use crate::Operation;
use crate::{copy_dir, BlobStore};
use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Response as AxumResponse},
};
use candid::Decode;
use futures::future::BoxFuture;
use futures::FutureExt;
use hyper::body::Bytes;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{Method, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_socks2::SocksConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use ic_boundary::{Health, RootKey};
use ic_config::{
    execution_environment, flag_status::FlagStatus, http_handler, subnet_config::SubnetConfig,
};
use ic_crypto_sha2::Sha256;
use ic_http_endpoints_public::{
    call::{call_v2, call_v3},
    metrics::HttpHandlerMetrics,
    CanisterReadStateServiceBuilder, IngressValidatorBuilder, QueryServiceBuilder,
    SubnetReadStateServiceBuilder,
};
use ic_https_outcalls_adapter::{CanisterHttp, CanisterRequestBody};
use ic_https_outcalls_adapter_client::CanisterHttpAdapterClientImpl;
use ic_https_outcalls_service::canister_http_service_server::CanisterHttpService;
use ic_https_outcalls_service::canister_http_service_server::CanisterHttpServiceServer;
use ic_https_outcalls_service::CanisterHttpSendRequest;
use ic_https_outcalls_service::CanisterHttpSendResponse;
use ic_interfaces::{crypto::BasicSigner, ingress_pool::IngressPoolThrottler};
use ic_interfaces_adapter_client::NonBlockingChannel;
use ic_interfaces_state_manager::StateReader;
use ic_logger::ReplicaLogger;
use ic_management_canister_types::{
    CanisterIdRecord, CanisterInstallMode, EcdsaCurve, EcdsaKeyId, MasterPublicKeyId,
    Method as Ic00Method, ProvisionalCreateCanisterWithCyclesArgs,
};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::Level;
use ic_state_machine_tests::{
    finalize_registry, IngressState, IngressStatus, RejectCode, StateMachine, StateMachineBuilder,
    StateMachineConfig, StateMachineStateDir, SubmitIngressError, Time,
};
use ic_test_utilities_registry::add_subnet_list_record;
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    canister_http::{CanisterHttpReject, CanisterHttpRequestId, CanisterHttpResponseContent},
    crypto::{BasicSig, BasicSigOf, CryptoResult, Signable},
    messages::{
        CertificateDelegation, HttpCallContent, HttpRequestEnvelope, MessageId as OtherMessageId,
        QueryResponseHash, ReplicaHealthStatus, SignedIngress,
    },
    time::GENESIS,
    CanisterId, Height, NodeId, NumInstructions, PrincipalId, RegistryVersion, SubnetId,
};
use ic_validator_ingress_message::StandaloneIngressSigVerifier;
use itertools::Itertools;
use pocket_ic::common::rest::{
    self, BinaryBlob, BlobCompression, CanisterHttpHeader, CanisterHttpMethod, CanisterHttpRequest,
    CanisterHttpResponse, DtsFlag, ExtendedSubnetConfigSet, MockCanisterHttpResponse, RawAddCycles,
    RawCanisterCall, RawEffectivePrincipal, RawMessageId, RawSetStableMemory,
    SubnetInstructionConfig, SubnetKind, SubnetSpec, Topology,
};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::str::FromStr;
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufReader, Write},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime},
};
use tempfile::TempDir;
use tokio::sync::Mutex as TokioMutex;
use tokio::{runtime::Runtime, sync::mpsc};
use tonic::transport::{Channel, Server};
use tonic::transport::{Endpoint, Uri};
use tonic::{Code, Request, Response, Status};
use tower::{
    service_fn,
    util::{BoxCloneService, ServiceExt},
};

// See build.rs
include!(concat!(env!("OUT_DIR"), "/dashboard.rs"));

/// The response type for `/api/v2` and `/api/v3` IC endpoint operations.
pub(crate) type ApiResponse = BoxFuture<'static, (u16, BTreeMap<String, Vec<u8>>, Vec<u8>)>;

/// We assume that the maximum number of subnets on the mainnet is 1024.
/// Used for generating canister ID ranges that do not appear on mainnet.
pub const MAXIMUM_NUMBER_OF_SUBNETS_ON_MAINNET: u64 = 1024;

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
    ranges: Vec<CanisterIdRange>,
    alloc_range: Option<CanisterIdRange>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.write(format!("SubnetCanisterRanges({:?},{:?})", ranges, alloc_range).as_bytes());
    hasher.finish()
}

#[derive(Clone, Serialize, Deserialize)]
struct RawTopologyInternal(pub BTreeMap<String, RawSubnetConfigInternal>);

#[derive(Clone, Serialize, Deserialize)]
struct RawSubnetConfigInternal {
    pub subnet_config: SubnetConfigInternal,
    pub time: SystemTime,
}

#[derive(Clone)]
struct TopologyInternal(pub BTreeMap<[u8; 32], SubnetConfigInternal>);

#[derive(Clone, Serialize, Deserialize)]
struct SubnetConfigInternal {
    pub subnet_id: SubnetId,
    pub subnet_kind: SubnetKind,
    pub instruction_config: SubnetInstructionConfig,
    pub dts_flag: DtsFlag,
    pub ranges: Vec<CanisterIdRange>,
    pub alloc_range: Option<CanisterIdRange>,
}

pub(crate) type CanisterHttpAdapters = Arc<TokioMutex<HashMap<SubnetId, CanisterHttp>>>;

pub struct PocketIc {
    state_dir: Option<PathBuf>,
    subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>>,
    canister_http_adapters: CanisterHttpAdapters,
    routing_table: RoutingTable,
    /// Created on initialization and updated if a new subnet is created.
    topology: TopologyInternal,
    // Used for choosing a random subnet when the user does not specify
    // where a canister should be created. This value is seeded,
    // so reproducibility is maintained.
    randomness: StdRng,
    // The initial state hash used for computing the state label
    // to distinguish PocketIC instances with different initial configs.
    initial_state_hash: [u8; 32],
    // The following fields are used to create a new subnet.
    range_gen: RangeGen,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    runtime: Arc<Runtime>,
    nonmainnet_features: bool,
    log_level: Option<Level>,
}

impl Drop for PocketIc {
    fn drop(&mut self) {
        let subnets = self.subnets.read().unwrap();
        if let Some(ref state_dir) = self.state_dir {
            for subnet in subnets.values() {
                subnet.checkpointed_tick();
            }
            for subnet in subnets.values() {
                subnet.await_state_hash();
            }
            let mut topology_file = File::create(state_dir.join("topology.json")).unwrap();
            let raw_topology: RawTopologyInternal = RawTopologyInternal(
                self.topology
                    .0
                    .clone()
                    .into_iter()
                    .map(|(seed, config)| {
                        let time = subnets.get(&config.subnet_id).unwrap().time();
                        (
                            hex::encode(seed),
                            RawSubnetConfigInternal {
                                subnet_config: config,
                                time,
                            },
                        )
                    })
                    .collect(),
            );
            let topology_json = serde_json::to_string(&raw_topology).unwrap();
            topology_file.write_all(topology_json.as_bytes()).unwrap();
        }
        for subnet in subnets.values() {
            subnet.drop_payload_builder();
        }
    }
}

impl PocketIc {
    pub(crate) fn canister_http_adapters(&self) -> CanisterHttpAdapters {
        self.canister_http_adapters.clone()
    }

    pub(crate) fn topology(&self) -> Topology {
        let mut topology = Topology(BTreeMap::new());
        let subnets = self.subnets.read().unwrap();
        for (subnet_seed, config) in self.topology.0.iter() {
            // What will be returned to the client:
            let subnet_config = pocket_ic::common::rest::SubnetConfig {
                subnet_kind: config.subnet_kind,
                subnet_seed: *subnet_seed,
                node_ids: subnets
                    .get(&config.subnet_id)
                    .unwrap()
                    .nodes
                    .iter()
                    .map(|n| n.node_id.get().0.into())
                    .collect(),
                canister_ranges: config.ranges.iter().map(from_range).collect(),
                instruction_config: config.instruction_config.clone(),
            };
            topology
                .0
                .insert(config.subnet_id.get().into(), subnet_config);
        }
        topology
    }

    fn create_state_machine_state_dir(
        state_dir: &Option<PathBuf>,
        subnet_seed: &[u8; 32],
    ) -> Box<dyn StateMachineStateDir> {
        if let Some(ref state_dir) = state_dir {
            Box::new(state_dir.join(hex::encode(subnet_seed)))
        } else {
            Box::new(TempDir::new().unwrap())
        }
    }

    fn state_machine_builder(
        state_machine_state_dir: Box<dyn StateMachineStateDir>,
        runtime: Arc<Runtime>,
        subnet_kind: SubnetKind,
        subnet_seed: [u8; 32],
        instruction_config: SubnetInstructionConfig,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
        time: SystemTime,
        nonmainnet_features: bool,
        log_level: Option<Level>,
    ) -> StateMachineBuilder {
        let subnet_type = conv_type(subnet_kind);
        let subnet_size = subnet_size(subnet_kind);
        let mut subnet_config = SubnetConfig::new(subnet_type);
        let mut hypervisor_config = if nonmainnet_features {
            ic_starter::hypervisor_config(true)
        } else {
            execution_environment::Config::default()
        };
        if let SubnetInstructionConfig::Benchmarking = instruction_config {
            let instruction_limit = NumInstructions::new(99_999_999_999_999);
            if instruction_limit > subnet_config.scheduler_config.max_instructions_per_round {
                subnet_config.scheduler_config.max_instructions_per_round = instruction_limit;
            }
            subnet_config.scheduler_config.max_instructions_per_message = instruction_limit;
            subnet_config
                .scheduler_config
                .max_instructions_per_message_without_dts = instruction_limit;
            hypervisor_config.max_query_call_graph_instructions = instruction_limit;
        }
        // bound PocketIc resource consumption
        hypervisor_config.embedders_config.min_sandbox_count = 0;
        hypervisor_config.embedders_config.max_sandbox_count = 64;
        hypervisor_config.embedders_config.max_sandbox_idle_time = Duration::from_secs(30);
        // shorter query stats epoch length for faster query stats aggregation
        hypervisor_config.query_stats_epoch_length = 60;
        // enable canister debug prints
        hypervisor_config
            .embedders_config
            .feature_flags
            .rate_limiting_of_debug_prints = FlagStatus::Disabled;
        let state_machine_config = StateMachineConfig::new(subnet_config, hypervisor_config);
        let t = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let time = Time::from_nanos_since_unix_epoch(t);
        StateMachineBuilder::new()
            .with_runtime(runtime)
            .with_config(Some(state_machine_config))
            .with_subnet_seed(subnet_seed)
            .with_subnet_size(subnet_size.try_into().unwrap())
            .with_subnet_type(subnet_type)
            .with_time(time)
            .with_state_machine_state_dir(state_machine_state_dir)
            .with_registry_data_provider(registry_data_provider.clone())
            .with_log_level(log_level)
    }

    pub(crate) fn new(
        runtime: Arc<Runtime>,
        subnet_configs: ExtendedSubnetConfigSet,
        state_dir: Option<PathBuf>,
        nonmainnet_features: bool,
        log_level: Option<Level>,
    ) -> Self {
        let mut range_gen = RangeGen::new();
        let mut routing_table = RoutingTable::new();
        let mut nns_subnet_id = subnet_configs.nns.as_ref().and_then(|x| {
            x.get_subnet_id()
                .map(|y| SubnetId::new(PrincipalId(y.into())))
        });

        let topology: Option<RawTopologyInternal> = if let Some(ref state_dir) = state_dir {
            let topology_file_path = state_dir.join("topology.json");
            File::open(topology_file_path).ok().map(|file| {
                let reader = BufReader::new(file);
                serde_json::from_reader(reader).unwrap()
            })
        } else {
            None
        };

        let subnet_config_info: Vec<SubnetConfigInfo> = if let Some(topology) = topology {
            topology
                .0
                .into_iter()
                .map(|(subnet_seed, config)| SubnetConfigInfo {
                    state_machine_state_dir: Box::new(
                        state_dir.as_ref().unwrap().join(subnet_seed.clone()),
                    ),
                    subnet_id: Some(config.subnet_config.subnet_id),
                    ranges: config.subnet_config.ranges,
                    alloc_range: config.subnet_config.alloc_range,
                    subnet_kind: config.subnet_config.subnet_kind,
                    subnet_seed: hex::decode(subnet_seed).unwrap().try_into().unwrap(),
                    instruction_config: config.subnet_config.instruction_config,
                    dts_flag: config.subnet_config.dts_flag,
                    time: config.time,
                })
                .collect()
        } else {
            let fixed_range_subnets = subnet_configs.get_named();
            let flexible_subnets = {
                let sys = subnet_configs.system.iter().map(|spec| {
                    (
                        SubnetKind::System,
                        spec.get_state_path(),
                        spec.get_subnet_id(),
                        spec.get_instruction_config(),
                        spec.get_dts_flag(),
                    )
                });
                let app = subnet_configs.application.iter().map(|spec| {
                    (
                        SubnetKind::Application,
                        spec.get_state_path(),
                        spec.get_subnet_id(),
                        spec.get_instruction_config(),
                        spec.get_dts_flag(),
                    )
                });
                let verified_app = subnet_configs.verified_application.iter().map(|spec| {
                    (
                        SubnetKind::VerifiedApplication,
                        spec.get_state_path(),
                        spec.get_subnet_id(),
                        spec.get_instruction_config(),
                        spec.get_dts_flag(),
                    )
                });
                sys.chain(app).chain(verified_app)
            };

            let mut subnet_config_info: Vec<SubnetConfigInfo> = vec![];

            let ii_subnet_split = subnet_configs.ii.is_some();

            for (subnet_kind, subnet_state_dir, subnet_id, instruction_config, dts_flag) in
                fixed_range_subnets.into_iter().chain(flexible_subnets)
            {
                let RangeConfig {
                    canister_id_ranges: ranges,
                    canister_allocation_range: alloc_range,
                } = get_range_config(subnet_kind, &mut range_gen, ii_subnet_split);

                let subnet_seed = compute_subnet_seed(ranges.clone(), alloc_range);

                let state_machine_state_dir =
                    Self::create_state_machine_state_dir(&state_dir, &subnet_seed);

                if let Some(subnet_state_dir) = subnet_state_dir {
                    copy_dir(subnet_state_dir, state_machine_state_dir.path())
                        .expect("Failed to copy state directory");
                }

                subnet_config_info.push(SubnetConfigInfo {
                    state_machine_state_dir,
                    subnet_id: subnet_id.map(|raw| SubnetId::new(PrincipalId(raw.into()))),
                    ranges,
                    alloc_range,
                    subnet_kind,
                    subnet_seed,
                    instruction_config,
                    dts_flag,
                    time: GENESIS.into(),
                });
            }

            subnet_config_info
        };

        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let mut topology = TopologyInternal(BTreeMap::new());

        // Create all StateMachines and the topology from the subnet config infos.
        for SubnetConfigInfo {
            state_machine_state_dir,
            subnet_id,
            ranges,
            alloc_range,
            subnet_kind,
            subnet_seed,
            instruction_config,
            dts_flag,
            time,
        } in subnet_config_info.into_iter()
        {
            let mut builder = Self::state_machine_builder(
                state_machine_state_dir,
                runtime.clone(),
                subnet_kind,
                subnet_seed,
                instruction_config.clone(),
                registry_data_provider.clone(),
                time,
                nonmainnet_features,
                log_level,
            );

            if let DtsFlag::Disabled = dts_flag {
                builder = builder.no_dts();
            };

            if subnet_kind == SubnetKind::NNS {
                builder = builder.with_root_subnet_config();
            }

            if let Some(subnet_id) = subnet_id {
                builder = builder.with_subnet_id(subnet_id);
            }

            if subnet_kind == SubnetKind::II {
                builder = builder.with_idkg_key(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "dfx_test_key1".to_string(),
                }));
                builder = builder.with_idkg_key(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "test_key_1".to_string(),
                }));
                builder = builder.with_idkg_key(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "key_1".to_string(),
                }));
            }

            let sm = builder.build_with_subnets(subnets.clone());
            let subnet_id = sm.get_subnet_id();

            // Store the actual NNS subnet ID if none was provided by the client.
            if let (SubnetKind::NNS, None) = (subnet_kind, nns_subnet_id) {
                nns_subnet_id = Some(subnet_id);
            };

            // Insert ranges and allocation range into routing table
            for range in &ranges {
                routing_table.insert(*range, subnet_id).unwrap();
            }
            if let Some(alloc_range) = alloc_range {
                routing_table.insert(alloc_range, subnet_id).unwrap();
            }

            let subnet_config_internal = SubnetConfigInternal {
                subnet_id,
                subnet_kind,
                instruction_config,
                ranges,
                alloc_range,
                dts_flag,
            };
            topology.0.insert(subnet_seed, subnet_config_internal);
        }

        // Finalize registry with subnet IDs that are only available now that we created
        // all the StateMachines.
        let subnet_list = topology.0.values().map(|config| config.subnet_id).collect();
        finalize_registry(
            nns_subnet_id.unwrap_or(topology.0.values().next().unwrap().subnet_id),
            routing_table.clone(),
            subnet_list,
            registry_data_provider.clone(),
        );

        for subnet in subnets.read().unwrap().values() {
            // Reload registry on the state machines to make sure
            // all the state machines have a consistent view of the registry.
            subnet.reload_registry();
        }

        // Update the registry file on disk.
        if let Some(ref state_dir) = state_dir {
            let registry_proto_path = PathBuf::from(state_dir).join("registry.proto");
            registry_data_provider.write_to_file(registry_proto_path);
        }

        // Sync the time on the subnets (if only the NNS subnet is loaded
        // from a snapshot, then its time might diverge).
        // Since time must be monotone, we pick the maximum time.
        let mut max_time = GENESIS;
        for subnet in subnets.read().unwrap().values() {
            max_time = max(max_time, subnet.get_state_time());
        }
        for subnet in subnets.read().unwrap().values() {
            subnet.set_time(max_time.into());
        }

        // We execute a round on every subnet to make sure it has a state to certify.
        for subnet in subnets.read().unwrap().values() {
            subnet.execute_round();
        }

        let mut hasher = Sha256::new();
        let subnet_configs_string = format!("{:?}", subnet_configs);
        hasher.write(subnet_configs_string.as_bytes());
        let initial_state_hash = compute_state_label(
            &hasher.finish(),
            subnets.read().unwrap().values().cloned().collect(),
        )
        .0;

        let canister_http_adapters = Arc::new(TokioMutex::new(
            subnets
                .read()
                .unwrap()
                .iter()
                .map(|(subnet_id, sm)| {
                    (
                        *subnet_id,
                        new_canister_http_adapter(sm.replica_logger.clone(), &sm.metrics_registry),
                    )
                })
                .collect(),
        ));

        Self {
            state_dir,
            subnets,
            canister_http_adapters,
            routing_table,
            topology,
            randomness: StdRng::seed_from_u64(42),
            initial_state_hash,
            range_gen,
            registry_data_provider,
            runtime,
            nonmainnet_features,
            log_level,
        }
    }

    fn try_route_canister(&self, canister_id: CanisterId) -> Option<Arc<StateMachine>> {
        let subnet_id = self.routing_table.route(canister_id.into());
        subnet_id.map(|subnet_id| self.get_subnet_with_id(subnet_id).unwrap())
    }

    fn any_subnet(&self) -> Arc<StateMachine> {
        self.subnets
            .read()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone()
    }

    fn random_subnet(&mut self) -> Arc<StateMachine> {
        // A new canister should be created on an app subnet by default.
        // If there are no app subnets, fall back to system subnets.
        // If there are none of these, install it on any subnet.
        let random_app_subnet = self.get_random_subnet_of_type(rest::SubnetKind::Application);
        if let Some(subnet) = random_app_subnet {
            return subnet;
        }
        let random_verified_app_subnet =
            self.get_random_subnet_of_type(rest::SubnetKind::VerifiedApplication);
        if let Some(subnet) = random_verified_app_subnet {
            return subnet;
        }
        let random_system_subnet = self.get_random_subnet_of_type(rest::SubnetKind::System);
        if let Some(subnet) = random_system_subnet {
            return subnet;
        }
        // If there are no application or system subnets, return any subnet.
        self.any_subnet()
    }

    fn nns_subnet(&self) -> Option<Arc<StateMachine>> {
        self.topology().get_nns().map(|nns_subnet_id| {
            self.get_subnet_with_id(PrincipalId(nns_subnet_id).into())
                .unwrap()
        })
    }

    fn get_subnet_with_id(&self, subnet_id: SubnetId) -> Option<Arc<StateMachine>> {
        self.subnets
            .read()
            .expect("Failed to get read lock on subnets")
            .get(&subnet_id)
            .cloned()
    }

    fn get_random_subnet_of_type(
        &mut self,
        subnet_type: rest::SubnetKind,
    ) -> Option<Arc<StateMachine>> {
        let topology = self.topology();
        let subnets = topology
            .0
            .iter()
            .filter(|(_, config)| config.subnet_kind == subnet_type)
            .collect_vec();
        if !subnets.is_empty() {
            let n = subnets.len();
            let index = self.randomness.gen_range(0..n);
            let (subnet_principal, _) = subnets[index];
            let subnet_id = SubnetId::new(PrincipalId(*subnet_principal));
            self.get_subnet_with_id(subnet_id)
        } else {
            None
        }
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

impl Default for PocketIc {
    fn default() -> Self {
        Self::new(
            Runtime::new().unwrap().into(),
            ExtendedSubnetConfigSet {
                application: vec![SubnetSpec::default()],
                ..Default::default()
            },
            None,
            false,
            None,
        )
    }
}

fn compute_state_label(
    initial_state_hash: &[u8; 32],
    subnets: Vec<Arc<StateMachine>>,
) -> StateLabel {
    let mut hasher = Sha256::new();
    hasher.write(initial_state_hash);
    for subnet in subnets {
        let subnet_state_hash = subnet
            .state_manager
            .latest_state_certification_hash()
            .map(|(_, h)| h.0)
            .unwrap_or_else(|| [0u8; 32].to_vec());
        let nanos = systemtime_to_unix_epoch_nanos(subnet.time());
        hasher.write(&subnet_state_hash[..]);
        hasher.write(&nanos.to_be_bytes());
    }
    StateLabel(hasher.finish())
}

impl HasStateLabel for PocketIc {
    fn get_state_label(&self) -> StateLabel {
        compute_state_label(
            &self.initial_state_hash,
            self.subnets.read().unwrap().values().cloned().collect(),
        )
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
        Fiduciary => 28,
        SNS => 34,
        Bitcoin => 13,
        II => 28,
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
    ii_subnet_split: bool,
) -> RangeConfig {
    use rest::SubnetKind::*;
    if matches!(subnet_kind, NNS) && !ii_subnet_split {
        let range = gen_range("rwlgt-iiaaa-aaaaa-aaaaa-cai", "n5n4y-3aaaa-aaaaa-p777q-cai");
        let canister_id_ranges = vec![range];
        let canister_allocation_range = Some(range_gen.next_range());
        RangeConfig {
            canister_id_ranges,
            canister_allocation_range,
        }
    } else {
        let (canister_id_ranges, canister_allocation_range) =
            match subnet_kind_canister_range(subnet_kind) {
                Some(ranges) => (ranges, Some(range_gen.next_range())),
                None => (vec![range_gen.next_range()], None),
            };
        RangeConfig {
            canister_id_ranges,
            canister_allocation_range,
        }
    }
}

/// A stateful helper for finding available canister ranges.
#[derive(Default)]
struct RangeGen {
    range_offset: u64,
}

impl RangeGen {
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the next canister id range from the top
    pub fn next_range(&mut self) -> CanisterIdRange {
        let offset = (u64::MAX / CANISTER_IDS_PER_SUBNET) - 1 - self.range_offset;
        self.range_offset += 1;
        let start = offset * CANISTER_IDS_PER_SUBNET;
        let end = ((offset + 1) * CANISTER_IDS_PER_SUBNET) - 1;
        CanisterIdRange {
            start: CanisterId::from_u64(start),
            end: CanisterId::from_u64(end),
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
    pub state_machine_state_dir: Box<dyn StateMachineStateDir>,
    pub subnet_id: Option<SubnetId>,
    pub ranges: Vec<CanisterIdRange>,
    pub alloc_range: Option<CanisterIdRange>,
    pub subnet_kind: SubnetKind,
    pub subnet_seed: [u8; 32],
    pub instruction_config: SubnetInstructionConfig,
    pub dts_flag: DtsFlag,
    pub time: SystemTime,
}

// ---------------------------------------------------------------------------------------- //
// Operations on PocketIc

// When raw (rest) types are cast to operations, errors can occur.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConversionError {
    message: String,
}

#[derive(Clone, Debug)]
pub struct SetTime {
    pub time: Time,
}

impl Operation for SetTime {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        // Sets the time on all subnets.
        for subnet in pic.subnets.read().unwrap().values() {
            subnet.set_time(self.time.into());
        }
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId(format!("set_time_{}", self.time))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GetTopology;

impl Operation for GetTopology {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        OpOut::Topology(pic.topology().clone())
    }

    fn id(&self) -> OpId {
        OpId("get_topology".into())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GetTime;

impl Operation for GetTime {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        // Time is kept in sync across subnets, so one can take any subnet.
        let nanos = systemtime_to_unix_epoch_nanos(pic.any_subnet().time());
        OpOut::Time(nanos)
    }

    fn id(&self) -> OpId {
        OpId("get_time".into())
    }
}

#[derive(Clone, Copy, Debug)]
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
    let mut canister_http = vec![];
    for subnet in pic.subnets.read().unwrap().values() {
        let mut cur: Vec<_> = subnet
            .canister_http_request_contexts()
            .into_iter()
            .map(|(id, c)| CanisterHttpRequest {
                subnet_id: subnet.get_subnet_id().get().0,
                request_id: id.get(),
                http_method: http_method_from(&c.http_method),
                url: c.url,
                headers: c.headers.iter().map(http_header_from).collect(),
                body: c.body.unwrap_or_default(),
                max_response_bytes: c.max_response_bytes.map(|b| b.get()),
            })
            .collect();
        canister_http.append(&mut cur);
    }
    canister_http
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

// START COPY from rs/https_outcalls/client/src/client.rs

#[derive(Clone)]
pub struct SingleResponseAdapter {
    response: Result<CanisterHttpSendResponse, (Code, String)>,
}

impl SingleResponseAdapter {
    fn new(response: Result<CanisterHttpSendResponse, (Code, String)>) -> Self {
        Self { response }
    }
}

#[tonic::async_trait]
impl CanisterHttpService for SingleResponseAdapter {
    async fn canister_http_send(
        &self,
        _request: Request<CanisterHttpSendRequest>,
    ) -> Result<Response<CanisterHttpSendResponse>, Status> {
        match self.response.clone() {
            Ok(resp) => Ok(Response::new(resp)),
            Err((code, msg)) => Err(Status::new(code, msg)),
        }
    }
}

async fn setup_adapter_mock(
    adapter_response: Result<CanisterHttpSendResponse, (Code, String)>,
) -> Channel {
    let (client, server) = tokio::io::duplex(1024);
    let mock_adapter = SingleResponseAdapter::new(adapter_response);
    tokio::spawn(async move {
        Server::builder()
            .add_service(CanisterHttpServiceServer::new(mock_adapter))
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
                    Ok(client)
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
    let subnet_id =
        ic_types::SubnetId::new(ic_types::PrincipalId(mock_canister_http_response.subnet_id));
    let Some(subnet) = pic.get_subnet_with_id(subnet_id) else {
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
    let content = match &mock_canister_http_response.response {
        CanisterHttpResponse::CanisterHttpReply(reply) => {
            let grpc_channel =
                pic.runtime
                    .block_on(setup_adapter_mock(Ok(CanisterHttpSendResponse {
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
            let query_handler = subnet.query_handler.clone();
            let query_handler = BoxCloneService::new(service_fn(move |arg| {
                let query_handler = query_handler.clone();
                async {
                    let r = query_handler
                        .oneshot(arg)
                        .await
                        .expect("Inner service should be alive. I hope.");
                    Ok(r)
                }
            }));
            let mut client = CanisterHttpAdapterClientImpl::new(
                pic.runtime.handle().clone(),
                grpc_channel,
                query_handler.clone(),
                1,
                MetricsRegistry::new(),
                subnet.get_subnet_type(),
            );
            client
                .send(ic_types::canister_http::CanisterHttpRequest {
                    timeout,
                    id: canister_http_request_id,
                    context: context.clone(),
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
                reject_code: RejectCode::try_from(reject.reject_code).unwrap(),
                message: reject.message.clone(),
            })
        }
    };
    subnet.mock_canister_http_response(
        mock_canister_http_response.request_id,
        timeout,
        canister_id,
        content,
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

#[derive(Clone, Debug, Copy)]
pub struct PubKey {
    pub subnet_id: SubnetId,
}

impl Operation for PubKey {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = pic.get_subnet_with_id(self.subnet_id);
        match subnet {
            Some(subnet) => OpOut::Bytes(subnet.root_key_der()),
            None => OpOut::Error(PocketIcError::SubnetNotFound(self.subnet_id.get().0)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("root_key_{}", self.subnet_id))
    }
}

#[derive(Clone, Debug, Copy)]
pub struct Tick;

impl Operation for Tick {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        for subnet in pic.subnets.read().unwrap().values() {
            subnet.execute_round();
        }
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId("tick".to_string())
    }
}

#[derive(Clone, Debug, Copy)]
pub struct AdvanceTimeAndTick(pub Duration);

impl Operation for AdvanceTimeAndTick {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        for subnet in pic.subnets.read().unwrap().values() {
            subnet.advance_time(self.0);
            subnet.execute_round();
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
                        Err::<ic_state_machine_tests::WasmResult, ic_state_machine_tests::UserError>(e).into()
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
                        } => return Ok(result).into(),
                        IngressStatus::Known {
                            state: IngressState::Failed(error),
                            ..
                        } => {
                            return Err::<
                                ic_state_machine_tests::WasmResult,
                                ic_state_machine_tests::UserError,
                            >(error)
                            .into()
                        }
                        _ => {}
                    }
                    for subnet_ in pic.subnets.read().unwrap().values() {
                        subnet_.execute_round();
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
pub struct ExecuteIngressMessage(pub CanisterCall);

impl Operation for ExecuteIngressMessage {
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
                        Err::<ic_state_machine_tests::WasmResult, ic_state_machine_tests::UserError>(e).into()
                    }
                    Ok(msg_id) => {
                        // Now, we execute on all subnets until we have the result
                        let max_rounds = 100;
                        for _i in 0..max_rounds {
                            for subnet_ in pic.subnets.read().unwrap().values() {
                                subnet_.execute_round();
                            }
                            match subnet.ingress_status(&msg_id) {
                                IngressStatus::Known {
                                    state: IngressState::Completed(result),
                                    ..
                                } => return Ok(result).into(),
                                IngressStatus::Known {
                                    state: IngressState::Failed(error),
                                    ..
                                } => {
                                    return Err::<
                                        ic_state_machine_tests::WasmResult,
                                        ic_state_machine_tests::UserError,
                                    >(error)
                                    .into()
                                }
                                _ => {}
                            }
                        }
                        OpOut::Error(PocketIcError::BadIngressMessage(format!(
                            "Failed to answer to ingress {} after {} rounds.",
                            msg_id, max_rounds
                        )))
                    }
                }
            }
            Err(e) => OpOut::Error(PocketIcError::BadIngressMessage(e)),
        }
    }

    fn id(&self) -> OpId {
        let call_id = self.0.id();
        OpId(format!("canister_update_{}", call_id.0))
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
                subnet
                    .query_as_with_delegation(
                        self.0.sender,
                        self.0.canister_id,
                        self.0.method.clone(),
                        self.0.payload.clone(),
                        delegation,
                    )
                    .into()
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
        let subnets = pic.subnets.read().unwrap();

        // All PocketIC subnets have the same height and thus we fetch the height from an arbitrary subnet.
        let arbitrary_subnet = subnets.values().next().unwrap();
        let height = arbitrary_subnet.state_manager.latest_state_height();

        let states: Vec<_> = subnets
            .values()
            .map(|subnet| {
                (
                    subnet.state_manager.get_latest_state(),
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

#[async_trait]
impl Health for PocketHealth {
    async fn health(&self) -> ReplicaHealthStatus {
        ReplicaHealthStatus::Healthy
    }
}

struct PocketRootKey(pub Option<Vec<u8>>);

#[async_trait]
impl RootKey for PocketRootKey {
    async fn root_key(&self) -> Option<Vec<u8>> {
        self.0.clone()
    }
}

// START COPY from rs/boundary_node/ic_boundary/src/routes.rs
// TODO: reshare once ic_boundary upgrades to axum 0.7.

const IC_API_VERSION: &str = "0.18.0";
// Clippy complains that these are interior-mutable.
// We don't mutate them, so silence it.
// https://rust-lang.github.io/rust-clippy/master/index.html#/declare_interior_mutable_const
#[allow(clippy::declare_interior_mutable_const)]
const CONTENT_TYPE_CBOR: HeaderValue = HeaderValue::from_static("application/cbor");

pub async fn status(
    State((rk, h)): State<(Arc<dyn RootKey>, Arc<dyn Health>)>,
) -> impl IntoResponse {
    use ic_types::messages::HttpStatusResponse;

    let health = h.health().await;

    let status = HttpStatusResponse {
        ic_api_version: IC_API_VERSION.to_string(),
        root_key: rk.root_key().await.map(|x| x.into()),
        impl_version: None,
        impl_hash: None,
        replica_health_status: Some(health),
        certified_height: None,
    };

    // Serialize to CBOR
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    // These should not really fail, better to panic if something in serde changes which would cause them to fail
    ser.self_describe().unwrap();
    status.serialize(&mut ser).unwrap();
    let cbor = ser.into_inner();

    // Construct response and inject health status for middleware
    let mut response = cbor.into_response();
    response.extensions_mut().insert(health);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, CONTENT_TYPE_CBOR);

    response
}

// END COPY

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
                    Arc::new(Mutex::new(BoxCloneService::new(service_fn(move |arg| {
                        let ingress_filter = ingress_filter.clone();
                        async {
                            let r = ingress_filter
                                .oneshot(arg)
                                .await
                                .expect("Inner service should be alive. I hope.");
                            Ok(r)
                        }
                    })))),
                    Arc::new(RwLock::new(PocketIngressPoolThrottler)),
                    s,
                )
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
                        let metrics_registry = MetricsRegistry::new();
                        let metrics = HttpHandlerMetrics::new(&metrics_registry);

                        call_v3::new_service(
                            ingress_validator,
                            subnet.ingress_watcher_handle.clone(),
                            metrics,
                            http_handler::Config::default()
                                .ingress_message_certificate_timeout_seconds,
                            Arc::new(RwLock::new(delegation)),
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
struct PocketNodeSigner(pub ic_crypto_ed25519::PrivateKey);

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
                let node = &subnet.nodes[0];
                subnet.certify_latest_state();
                let query_handler = subnet.query_handler.clone();
                let svc = QueryServiceBuilder::builder(
                    subnet.replica_logger.clone(),
                    node.node_id,
                    Arc::new(PocketNodeSigner(node.node_signing_key.clone())),
                    subnet.registry_client.clone(),
                    Arc::new(StandaloneIngressSigVerifier),
                    Arc::new(RwLock::new(delegation)),
                    BoxCloneService::new(service_fn(move |arg| {
                        let query_handler = query_handler.clone();
                        async {
                            let r = query_handler
                                .oneshot(arg)
                                .await
                                .expect("Inner service should be alive. I hope.");
                            Ok(r)
                        }
                    })),
                )
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
                subnet.certify_latest_state();
                let svc = CanisterReadStateServiceBuilder::builder(
                    subnet.replica_logger.clone(),
                    subnet.state_manager.clone(),
                    subnet.registry_client.clone(),
                    Arc::new(StandaloneIngressSigVerifier),
                    Arc::new(RwLock::new(delegation)),
                )
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
                subnet.certify_latest_state();
                let svc = SubnetReadStateServiceBuilder::builder(
                    Arc::new(RwLock::new(delegation)),
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, PartialEq, Eq, Debug)]
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
        pocket_ic
            .try_route_canister(self.canister_id)
            .unwrap()
            .set_stable_memory(self.canister_id, &self.data);
        OpOut::NoOutput
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GetStableMemory {
    pub canister_id: CanisterId,
}

impl Operation for GetStableMemory {
    fn compute(&self, pocket_ic: &mut PocketIc) -> OpOut {
        OpOut::StableMemBytes(
            pocket_ic
                .try_route_canister(self.canister_id)
                .unwrap()
                .stable_memory(self.canister_id),
        )
    }

    fn id(&self) -> OpId {
        OpId(format!("get_stable_memory({})", self.canister_id))
    }
}

#[derive(Clone, Debug)]
pub struct GetCyclesBalance {
    pub canister_id: CanisterId,
}

impl Operation for GetCyclesBalance {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let result = pic
            .try_route_canister(self.canister_id)
            .unwrap()
            .cycle_balance(self.canister_id);
        OpOut::Cycles(result)
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
        let result = pic
            .try_route_canister(self.canister_id)
            .unwrap()
            .add_cycles(self.canister_id, self.amount);
        OpOut::Cycles(result)
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

// TODO: deprecate this as an Op; implement it as a client library convenience function

/// A convenience method that installs the given wasm module at the given canister id. The first
/// controller of the given canister is set as the sender. If the canister has no controller set,
/// the anynmous user is used.
pub struct InstallCanisterAsController {
    pub canister_id: CanisterId,
    pub mode: CanisterInstallMode,
    pub module: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Operation for InstallCanisterAsController {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        pic.try_route_canister(self.canister_id)
            .unwrap()
            .install_wasm_in_mode(
                self.canister_id,
                self.mode,
                self.module.clone(),
                self.payload.clone(),
            )
            .into()
    }

    fn id(&self) -> OpId {
        OpId("".into())
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
            .get_subnet_with_id(subnet_id)
            .ok_or(format!("Subnet with ID {subnet_id} not found")),
        EffectivePrincipal::CanisterId(canister_id) => match pic.try_route_canister(canister_id) {
            Some(subnet) => Ok(subnet),
            None => {
                if is_provisional_create_canister {
                    // We retrieve the PocketIC instace time (consistent across all subnets) from one subnet.
                    let time = pic.subnets.read().unwrap().values().next().unwrap().time();
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
                    let dts_flag = DtsFlag::Enabled;
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
                    // Compute the subnet seed.
                    let subnet_seed =
                        compute_subnet_seed(vec![range], Some(canister_allocation_range));
                    // We build the `StateMachine` of the new subnet.
                    let builder = PocketIc::state_machine_builder(
                        PocketIc::create_state_machine_state_dir(&pic.state_dir, &subnet_seed),
                        pic.runtime.clone(),
                        subnet_kind,
                        subnet_seed,
                        instruction_config.clone(),
                        pic.registry_data_provider.clone(),
                        time,
                        pic.nonmainnet_features,
                        pic.log_level,
                    );
                    let sm = builder.build_with_subnets(pic.subnets.clone());
                    // We insert the new subnet into the routing table.
                    let subnet_id = sm.get_subnet_id();
                    pic.routing_table.insert(range, subnet_id).unwrap();
                    pic.routing_table
                        .insert(canister_allocation_range, subnet_id)
                        .unwrap();
                    // We insert the new subnet into the topology.
                    let subnet_config_internal = SubnetConfigInternal {
                        subnet_id,
                        subnet_kind,
                        instruction_config,
                        ranges: vec![range],
                        alloc_range: Some(canister_allocation_range),
                        dts_flag,
                    };
                    pic.topology.0.insert(subnet_seed, subnet_config_internal);
                    // We update the registry by creating a new registry version
                    // and inserting new records at that new registry version.
                    let registry_version = pic.registry_data_provider.latest_version();
                    let pb_routing_table = PbRoutingTable::from(pic.routing_table.clone());
                    pic.registry_data_provider
                        .add(
                            &make_routing_table_record_key(),
                            registry_version,
                            Some(pb_routing_table),
                        )
                        .unwrap();
                    let subnet_list = pic
                        .topology()
                        .0
                        .keys()
                        .map(|p| PrincipalId(*p).into())
                        .collect();
                    add_subnet_list_record(
                        &pic.registry_data_provider,
                        registry_version.get(),
                        subnet_list,
                    );
                    for subnet in pic.subnets.read().unwrap().values() {
                        // Reload registry on the state machines to make sure
                        // all the state machines have a consistent view of the registry.
                        subnet.reload_registry();
                    }
                    // Update the registry file on disk.
                    if let Some(ref state_dir) = pic.state_dir {
                        let registry_proto_path = PathBuf::from(state_dir).join("registry.proto");
                        pic.registry_data_provider
                            .write_to_file(registry_proto_path);
                    }
                    // We need to execute a round on the new subnet to make its state certified.
                    // To keep the PocketIC instance time in sync, we execute a round on all subnets.
                    for subnet in pic.subnets.read().unwrap().values() {
                        subnet.execute_round();
                    }
                    // We update the canister http adapters.
                    pic.canister_http_adapters.blocking_lock().insert(
                        sm.get_subnet_id(),
                        new_canister_http_adapter(sm.replica_logger.clone(), &sm.metrics_registry),
                    );
                    Ok(sm)
                } else {
                    // If the request is not an update call to create a canister using the provisional API,
                    // we return an error (since such an update call to a newly created subnet would fail anyway).
                    Err(format!(
                        "Canister {canister_id} does not belong to any subnet."
                    ))
                }
            }
        },
        EffectivePrincipal::None => Ok(pic.random_subnet()),
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
                        EffectivePrincipal::CanisterId(specified_id.try_into().unwrap())
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

fn new_canister_http_adapter(
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
) -> CanisterHttp {
    // Socks client setup
    // We don't really use the Socks client in PocketIC as we set `socks_proxy_allowed: false` in the request,
    // but we still have to provide one when constructing the production `CanisterHttp` object
    // and thus we use a reserved (and invalid) proxy IP address.
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    http_connector.set_connect_timeout(Some(Duration::from_secs(2)));
    let proxy_connector = SocksConnector {
        proxy_addr: "http://240.0.0.0:8080"
            .parse()
            .expect("Failed to parse socks url."),
        auth: None,
        connector: http_connector.clone(),
    };
    let https_connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to set native roots.")
        .https_only()
        .enable_http1()
        .wrap_connector(proxy_connector);
    let socks_client =
        Client::builder(TokioExecutor::new()).build::<_, CanisterRequestBody>(https_connector);

    // Https client setup.
    let builder = HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to set native roots.")
        .https_or_http()
        .enable_http1();
    let https_client = Client::builder(TokioExecutor::new())
        .build::<_, CanisterRequestBody>(builder.wrap_connector(http_connector));

    CanisterHttp::new(https_client, socks_client, log, metrics_registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_label_test() {
        // State label changes.
        let pic = PocketIc::default();
        let state0 = pic.get_state_label();
        let canister_id = pic.any_subnet().create_canister(None);
        pic.any_subnet().add_cycles(canister_id, 2_000_000_000_000);
        let state1 = pic.get_state_label();
        pic.any_subnet().stop_canister(canister_id).unwrap();
        pic.any_subnet().delete_canister(canister_id).unwrap();
        let state2 = pic.get_state_label();

        assert_ne!(state0, state1);
        assert_ne!(state1, state2);
        assert_ne!(state0, state2);

        // Empyt IC.
        let pic = PocketIc::default();
        let state1 = pic.get_state_label();
        let pic = PocketIc::default();
        let state2 = pic.get_state_label();

        assert_eq!(state1, state2);

        // Two ICs with the same state.
        let pic = PocketIc::default();
        let cid = pic.any_subnet().create_canister(None);
        pic.any_subnet().add_cycles(cid, 2_000_000_000_000);
        pic.any_subnet().stop_canister(cid).unwrap();
        let state3 = pic.get_state_label();

        let pic = PocketIc::default();
        let cid = pic.any_subnet().create_canister(None);
        pic.any_subnet().add_cycles(cid, 2_000_000_000_000);
        pic.any_subnet().stop_canister(cid).unwrap();
        let state4 = pic.get_state_label();

        assert_eq!(state3, state4);
    }

    #[test]
    fn test_time() {
        let mut pic = PocketIc::default();

        let unix_time_ns = 1640995200000000000; // 1st Jan 2022
        let time = Time::from_nanos_since_unix_epoch(unix_time_ns);
        compute_assert_state_change(&mut pic, SetTime { time });
        let actual_time = compute_assert_state_immutable(&mut pic, GetTime {});

        match actual_time {
            OpOut::Time(actual_time_ns) => assert_eq!(unix_time_ns, actual_time_ns),
            _ => panic!("Unexpected OpOut: {:?}", actual_time),
        };
    }

    #[test]
    fn test_execute_message() {
        let (mut pic, canister_id) = new_pic_counter_installed();
        let amount: u128 = 20_000_000_000_000;
        let add_cycles = AddCycles {
            canister_id,
            amount,
        };
        add_cycles.compute(&mut pic);

        let update = ExecuteIngressMessage(CanisterCall {
            sender: PrincipalId::new_anonymous(),
            canister_id,
            method: "write".into(),
            payload: vec![],
            effective_principal: EffectivePrincipal::None,
        });

        compute_assert_state_change(&mut pic, update);
    }

    #[test]
    fn test_cycles_burn_app_subnet() {
        let (mut pic, canister_id) = new_pic_counter_installed();
        let (_, update) = query_update_constructors(canister_id);
        let cycles_balance = GetCyclesBalance { canister_id };
        let OpOut::Cycles(initial_balance) =
            compute_assert_state_immutable(&mut pic, cycles_balance.clone())
        else {
            unreachable!()
        };
        compute_assert_state_change(&mut pic, update("write"));
        let OpOut::Cycles(new_balance) = compute_assert_state_immutable(&mut pic, cycles_balance)
        else {
            unreachable!()
        };
        assert_ne!(initial_balance, new_balance);
    }

    #[test]
    fn test_cycles_burn_system_subnet() {
        let (mut pic, canister_id) = new_pic_counter_installed_system_subnet();
        let (_, update) = query_update_constructors(canister_id);

        let cycles_balance = GetCyclesBalance { canister_id };
        let OpOut::Cycles(initial_balance) =
            compute_assert_state_immutable(&mut pic, cycles_balance.clone())
        else {
            unreachable!()
        };
        compute_assert_state_change(&mut pic, update("write"));
        let OpOut::Cycles(new_balance) = compute_assert_state_immutable(&mut pic, cycles_balance)
        else {
            unreachable!()
        };
        assert_eq!(initial_balance, new_balance);
    }

    fn query_update_constructors(
        canister_id: CanisterId,
    ) -> (
        impl Fn(&str) -> Query,
        impl Fn(&str) -> ExecuteIngressMessage,
    ) {
        let call = move |method: &str| CanisterCall {
            sender: PrincipalId::new_anonymous(),
            canister_id,
            method: method.into(),
            payload: vec![],
            effective_principal: EffectivePrincipal::None,
        };

        let update = move |m: &str| ExecuteIngressMessage(call(m));
        let query = move |m: &str| Query(call(m));

        (query, update)
    }

    fn new_pic_counter_installed() -> (PocketIc, CanisterId) {
        let mut pic = PocketIc::default();
        let canister_id = pic.any_subnet().create_canister(None);

        let amount: u128 = 20_000_000_000_000;
        let add_cycles = AddCycles {
            canister_id,
            amount,
        };
        add_cycles.compute(&mut pic);

        let module = counter_wasm();
        let install_op = InstallCanisterAsController {
            canister_id,
            mode: CanisterInstallMode::Install,
            module,
            payload: vec![],
        };

        compute_assert_state_change(&mut pic, install_op);

        (pic, canister_id)
    }

    fn new_pic_counter_installed_system_subnet() -> (PocketIc, CanisterId) {
        let mut pic = PocketIc::new(
            Runtime::new().unwrap().into(),
            ExtendedSubnetConfigSet {
                ii: Some(SubnetSpec::default()),
                ..Default::default()
            },
            None,
            false,
            None,
        );
        let canister_id = pic.any_subnet().create_canister(None);

        let module = counter_wasm();
        let install_op = InstallCanisterAsController {
            canister_id,
            mode: CanisterInstallMode::Install,
            module,
            payload: vec![],
        };

        compute_assert_state_change(&mut pic, install_op);

        (pic, canister_id)
    }

    fn compute_assert_state_change(pic: &mut PocketIc, op: impl Operation) -> OpOut {
        let state0 = pic.get_state_label();
        let res = op.compute(pic);
        let state1 = pic.get_state_label();
        assert_ne!(state0, state1);
        res
    }

    fn compute_assert_state_immutable(pic: &mut PocketIc, op: impl Operation) -> OpOut {
        let state0 = pic.get_state_label();
        let res = op.compute(pic);
        let state1 = pic.get_state_label();
        assert_eq!(state0, state1);
        res
    }

    fn counter_wasm() -> Vec<u8> {
        wat::parse_str(COUNTER_WAT).unwrap().as_slice().to_vec()
    }

    const COUNTER_WAT: &str = r#"
;; Counter with global variable ;;
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))

  (func $read
    (i32.store
      (i32.const 0)
      (global.get 0)
    )
    (call $msg_reply_data_append
      (i32.const 0)
      (i32.const 4))
    (call $msg_reply))

  (func $write
    (global.set 0
      (i32.add
        (global.get 0)
        (i32.const 1)
      )
    )
    (call $read)
  )

  (memory $memory 1)
  (export "memory" (memory $memory))
  (global (export "counter_global") (mut i32) (i32.const 0))
  (export "canister_query read" (func $read))
  (export "canister_query inc_read" (func $write))
  (export "canister_update write" (func $write))
)
    "#;
}
