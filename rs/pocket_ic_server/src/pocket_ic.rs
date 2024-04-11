use crate::async_trait;
use crate::state_api::state::{HasStateLabel, OpOut, PocketIcError, StateLabel};
use crate::OpId;
use crate::Operation;
use crate::{copy_dir, BlobStore};
use axum::{extract::State, response::IntoResponse};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::Method;
use ic_boundary::{Health, RootKey};
use ic_config::execution_environment;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SubnetConfig;
use ic_crypto_sha2::Sha256;
use ic_http_endpoints_public::{
    CallServiceBuilder, CanisterReadStateServiceBuilder, QueryServiceBuilder,
};
use ic_interfaces::{crypto::BasicSigner, ingress_pool::IngressPoolThrottler};
use ic_management_canister_types::CanisterInstallMode;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    finalize_registry, IngressState, IngressStatus, StateMachine, StateMachineBuilder,
    StateMachineConfig, SubmitIngressError, Time,
};
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    artifact_kind::IngressArtifact,
    crypto::{BasicSig, BasicSigOf, CryptoResult, Signable},
    messages::{CertificateDelegation, QueryResponseHash, ReplicaHealthStatus},
    CanisterId, NodeId, NumInstructions, PrincipalId, RegistryVersion, SubnetId,
};
use ic_validator_ingress_message::StandaloneIngressSigVerifier;
use itertools::Itertools;
use pocket_ic::common::rest::{
    self, BinaryBlob, BlobCompression, DtsFlag, ExtendedSubnetConfigSet, RawAddCycles,
    RawCanisterCall, RawEffectivePrincipal, RawSetStableMemory, SubnetInstructionConfig,
    SubnetKind, SubnetSpec, Topology,
};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::str::FromStr;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tower::{
    service_fn,
    util::{BoxCloneService, ServiceExt},
};

/// We assume that the maximum number of subnets on the mainnet is 1024.
/// Used for generating canister ID ranges that do not appear on mainnet.
pub const MAXIMUM_NUMBER_OF_SUBNETS_ON_MAINNET: u64 = 1024;

pub struct PocketIc {
    subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>>,
    routing_table: RoutingTable,
    /// Constant, created on initialization.
    pub topology: Topology,
    // Used for choosing a random subnet when the user does not specify
    // where a canister should be created. This value is seeded,
    // so reproducibility is maintained.
    randomness: StdRng,
    // Used for computing the state label to distinguish PocketIC instances
    // with different initial configs.
    subnet_configs: ExtendedSubnetConfigSet,
}

impl PocketIc {
    pub fn new(runtime: Arc<Runtime>, subnet_configs: ExtendedSubnetConfigSet) -> Self {
        let fixed_range_subnets = subnet_configs.get_named();
        let flexible_subnets = {
            // note that for these, the subnet ids are currently ignored.
            let sys = subnet_configs.system.iter().map(|spec| {
                (
                    SubnetKind::System,
                    spec.get_state_path(),
                    spec.get_instruction_config(),
                    spec.get_dts_flag(),
                )
            });
            let app = subnet_configs.application.iter().map(|spec| {
                (
                    SubnetKind::Application,
                    spec.get_state_path(),
                    spec.get_instruction_config(),
                    spec.get_dts_flag(),
                )
            });
            sys.chain(app)
        };

        let mut range_gen = RangeGen::new();
        let mut subnet_config_info: Vec<SubnetConfigInfo> = vec![];
        let mut routing_table = RoutingTable::new();

        let mut nns_subnet_id = subnet_configs.nns.as_ref().and_then(|x| {
            x.get_subnet_id()
                .map(|y| SubnetId::new(PrincipalId(y.into())))
        });

        let ii_subnet_split = subnet_configs.ii.is_some();

        for (subnet_kind, subnet_state_dir, instruction_config, dts_flag) in
            fixed_range_subnets.into_iter().chain(flexible_subnets)
        {
            let RangeConfig {
                canister_id_ranges: ranges,
                canister_allocation_range: alloc_range,
            } = get_range_config(subnet_kind, &mut range_gen, ii_subnet_split);

            let state_dir = if let Some(subnet_state_dir) = subnet_state_dir {
                let tmp_dir = TempDir::new().expect("Failed to create temporary directory");
                copy_dir(subnet_state_dir, tmp_dir.path()).expect("Failed to copy state directory");
                Some(tmp_dir)
            } else {
                None
            };

            subnet_config_info.push(SubnetConfigInfo {
                ranges,
                alloc_range,
                subnet_kind,
                state_dir,
                instruction_config,
                dts_flag,
            });
        }

        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let mut topology = Topology(HashMap::new());

        // Create all StateMachines and the topology from the subnet config infos.
        for (
            subnet_seq_no,
            SubnetConfigInfo {
                ranges,
                alloc_range,
                subnet_kind,
                state_dir,
                instruction_config,
                dts_flag,
            },
        ) in subnet_config_info.into_iter().enumerate()
        {
            let subnet_type = conv_type(subnet_kind);
            let mut subnet_config = SubnetConfig::new(subnet_type);
            let mut hypervisor_config = execution_environment::Config::default();
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
            // enable canister debug prints
            hypervisor_config
                .embedders_config
                .feature_flags
                .rate_limiting_of_debug_prints = FlagStatus::Disabled;
            let sm_config = StateMachineConfig::new(subnet_config, hypervisor_config);
            let subnet_size = subnet_size(subnet_kind);
            let mut builder = StateMachineBuilder::new()
                .with_runtime(runtime.clone())
                .with_config(Some(sm_config))
                .with_subnet_seq_no(subnet_seq_no as u8)
                .with_subnet_size(subnet_size.try_into().unwrap())
                .with_subnet_type(subnet_type)
                .with_registry_data_provider(registry_data_provider.clone())
                .with_multisubnet_ecdsa_key()
                .with_use_cost_scaling_flag(true);

            if let DtsFlag::Enabled = dts_flag {
                builder = builder.with_dts();
            };

            if subnet_kind == SubnetKind::NNS {
                builder = builder.with_root_subnet_config();
                if let Some(nns_subnet_id) = nns_subnet_id {
                    builder = builder.with_subnet_id(nns_subnet_id);
                }
            }

            if let Some(state_dir) = state_dir {
                builder = builder.with_state_dir(state_dir);
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

            // What will be returned to the client:
            let subnet_config = pocket_ic::common::rest::SubnetConfig {
                subnet_kind,
                size: subnet_size,
                canister_ranges: ranges.iter().map(from_range).collect(),
                instruction_config,
            };
            topology.0.insert(subnet_id.get().0, subnet_config);
        }

        // Finalize registry with subnet IDs that are only available now that we created
        // all the StateMachines.
        let subnet_list = topology.0.keys().map(|p| PrincipalId(*p).into()).collect();
        finalize_registry(
            nns_subnet_id.unwrap_or(PrincipalId(*topology.0.keys().next().unwrap()).into()),
            routing_table.clone(),
            subnet_list,
            registry_data_provider,
        );

        for subnet in subnets.read().unwrap().values() {
            // Reload registry on the state machines to make sure
            // all the state machines have a consistent view of the registry.
            subnet.reload_registry();
        }

        Self {
            subnets,
            routing_table,
            topology,
            randomness: StdRng::seed_from_u64(42),
            subnet_configs,
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
        let random_system_subnet = self.get_random_subnet_of_type(rest::SubnetKind::System);
        if let Some(subnet) = random_system_subnet {
            return subnet;
        }
        // If there are no application or system subnets, return any subnet.
        self.any_subnet()
    }

    fn nns_subnet(&self) -> Option<Arc<StateMachine>> {
        self.topology.get_nns().map(|nns_subnet_id| {
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
        let subnets = self
            .topology
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
        )
    }
}

impl HasStateLabel for PocketIc {
    fn get_state_label(&self) -> StateLabel {
        let mut hasher = Sha256::new();
        let subnet_configs_string = format!("{:?}", self.subnet_configs);
        hasher.write(subnet_configs_string.as_bytes());
        for subnet in self.subnets.read().unwrap().values() {
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
}

fn conv_type(inp: rest::SubnetKind) -> SubnetType {
    use rest::SubnetKind::*;
    match inp {
        Application | Fiduciary | SNS => SubnetType::Application,
        Bitcoin | II | NNS | System => SubnetType::System,
    }
}

fn subnet_size(subnet: SubnetKind) -> u64 {
    use rest::SubnetKind::*;
    match subnet {
        Application => 13,
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

fn get_range_config(
    subnet_kind: rest::SubnetKind,
    range_gen: &mut RangeGen,
    ii_subnet_split: bool,
) -> RangeConfig {
    use rest::SubnetKind::*;
    match subnet_kind {
        Application | System => {
            let range = range_gen.next_range();
            RangeConfig {
                canister_id_ranges: vec![range],
                canister_allocation_range: None,
            }
        }
        Bitcoin => {
            let canister_allocation_range = range_gen.next_range();
            let range = gen_range("g3wsl-eqaaa-aaaan-aaaaa-cai", "2qqia-xyaaa-aaaan-p777q-cai");
            RangeConfig {
                canister_id_ranges: vec![range],
                canister_allocation_range: Some(canister_allocation_range),
            }
        }
        Fiduciary => {
            let canister_allocation_range = range_gen.next_range();
            let range = gen_range("mf7xa-laaaa-aaaar-qaaaa-cai", "qoznl-yiaaa-aaaar-7777q-cai");
            RangeConfig {
                canister_id_ranges: vec![range],
                canister_allocation_range: Some(canister_allocation_range),
            }
        }
        II => {
            let canister_allocation_range = range_gen.next_range();
            let range1 = gen_range("rdmx6-jaaaa-aaaaa-aaadq-cai", "rdmx6-jaaaa-aaaaa-aaadq-cai");
            let range2 = gen_range("uc7f6-kaaaa-aaaaq-qaaaa-cai", "ijz7v-ziaaa-aaaaq-7777q-cai");
            RangeConfig {
                canister_id_ranges: vec![range1, range2],
                canister_allocation_range: Some(canister_allocation_range),
            }
        }
        NNS => {
            let canister_allocation_range = range_gen.next_range();
            let canister_id_ranges = if ii_subnet_split {
                let range1 =
                    gen_range("rwlgt-iiaaa-aaaaa-aaaaa-cai", "renrk-eyaaa-aaaaa-aaada-cai");
                let range2 =
                    gen_range("qoctq-giaaa-aaaaa-aaaea-cai", "n5n4y-3aaaa-aaaaa-p777q-cai");
                vec![range1, range2]
            } else {
                let range = gen_range("rwlgt-iiaaa-aaaaa-aaaaa-cai", "n5n4y-3aaaa-aaaaa-p777q-cai");
                vec![range]
            };
            RangeConfig {
                canister_id_ranges,
                canister_allocation_range: Some(canister_allocation_range),
            }
        }
        SNS => {
            let canister_allocation_range = range_gen.next_range();
            let range = gen_range("ybpmr-kqaaa-aaaaq-aaaaa-cai", "ekjw2-zyaaa-aaaaq-p777q-cai");
            RangeConfig {
                canister_id_ranges: vec![range],
                canister_allocation_range: Some(canister_allocation_range),
            }
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
    pub ranges: Vec<CanisterIdRange>,
    pub alloc_range: Option<CanisterIdRange>,
    pub subnet_kind: SubnetKind,
    pub state_dir: Option<TempDir>,
    pub instruction_config: SubnetInstructionConfig,
    pub dts_flag: DtsFlag,
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

pub struct StatusRequest {
    pub bytes: Bytes,
    pub runtime: Arc<Runtime>,
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

        let resp = self
            .runtime
            .block_on(async { status(State((Arc::new(root_key), Arc::new(PocketHealth)))).await })
            .into_response();

        OpOut::ApiV2Response((
            resp.status().into(),
            resp.headers()
                .iter()
                .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
                .collect(),
            self.runtime
                .block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
                .unwrap()
                .to_vec(),
        ))
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

pub struct CallRequest {
    pub effective_canister_id: CanisterId,
    pub bytes: Bytes,
    pub runtime: Arc<Runtime>,
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
        let subnet = route(
            pic,
            EffectivePrincipal::CanisterId(self.effective_canister_id),
            None,
        );
        match subnet {
            Err(e) => OpOut::Error(PocketIcError::RequestRoutingError(e)),
            Ok(subnet) => {
                let node = &subnet.nodes[0];
                #[allow(clippy::disallowed_methods)]
                let (s, mut r) =
                    mpsc::unbounded_channel::<UnvalidatedArtifactMutation<IngressArtifact>>();
                let ingress_filter = subnet.ingress_filter.clone();

                let svc = CallServiceBuilder::builder(
                    node.node_id,
                    subnet.get_subnet_id(),
                    subnet.registry_client.clone(),
                    Arc::new(StandaloneIngressSigVerifier),
                    BoxCloneService::new(service_fn(move |arg| {
                        let ingress_filter = ingress_filter.clone();
                        async {
                            let r = ingress_filter
                                .oneshot(arg)
                                .await
                                .expect("Inner service should be alive. I hope.");
                            Ok(r)
                        }
                    })),
                    Arc::new(RwLock::new(PocketIngressPoolThrottler)),
                    s,
                )
                .build_service();

                let request = axum::http::Request::builder()
                    .method(Method::POST)
                    .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
                    .uri(format!(
                        "/api/v2/canister/{}/call",
                        PrincipalId(self.effective_canister_id.get().into())
                    ))
                    .body(self.bytes.clone().into())
                    .unwrap();
                let resp = self.runtime.block_on(svc.oneshot(request)).unwrap();

                if let Ok(UnvalidatedArtifactMutation::Insert((msg, _node_id))) = r.try_recv() {
                    subnet.push_signed_ingress(msg);
                }

                OpOut::ApiV2Response((
                    resp.status().into(),
                    resp.headers()
                        .iter()
                        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
                        .collect(),
                    self.runtime
                        .block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
                        .unwrap()
                        .to_vec(),
                ))
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
    pub runtime: Arc<Runtime>,
}

#[derive(Clone)]
struct PocketNodeSigner(pub ed25519_consensus::SigningKey);

impl BasicSigner<QueryResponseHash> for PocketNodeSigner {
    fn sign_basic(
        &self,
        message: &QueryResponseHash,
        _signer: NodeId,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<QueryResponseHash>> {
        Ok(BasicSigOf::new(BasicSig(
            self.0.sign(&message.as_signed_bytes()).to_bytes().to_vec(),
        )))
    }
}

impl Operation for QueryRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        let subnet = route(
            pic,
            EffectivePrincipal::CanisterId(self.effective_canister_id),
            None,
        );
        match subnet {
            Err(e) => OpOut::Error(PocketIcError::RequestRoutingError(e)),
            Ok(subnet) => {
                let delegation = pic.get_nns_delegation_for_subnet(subnet.get_subnet_id());
                let node = &subnet.nodes[0];
                subnet.certify_latest_state();
                let query_handler = subnet.query_handler.clone();
                let svc = QueryServiceBuilder::builder(
                    node.node_id,
                    Arc::new(PocketNodeSigner(node.signing_key.clone())),
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
                let resp = self.runtime.block_on(svc.oneshot(request)).unwrap();

                OpOut::ApiV2Response((
                    resp.status().into(),
                    resp.headers()
                        .iter()
                        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
                        .collect(),
                    self.runtime
                        .block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
                        .unwrap()
                        .to_vec(),
                ))
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
pub struct ReadStateRequest {
    pub effective_canister_id: CanisterId,
    pub bytes: Bytes,
    pub runtime: Arc<Runtime>,
}

impl Operation for ReadStateRequest {
    fn compute(&self, pic: &mut PocketIc) -> OpOut {
        match route(
            pic,
            EffectivePrincipal::CanisterId(self.effective_canister_id),
            None,
        ) {
            Err(e) => OpOut::Error(PocketIcError::RequestRoutingError(e)),
            Ok(subnet) => {
                let delegation = pic.get_nns_delegation_for_subnet(subnet.get_subnet_id());
                subnet.certify_latest_state();
                let svc = CanisterReadStateServiceBuilder::builder(
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
                let resp = self.runtime.block_on(svc.oneshot(request)).unwrap();

                OpOut::ApiV2Response((
                    resp.status().into(),
                    resp.headers()
                        .iter()
                        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
                        .collect(),
                    self.runtime
                        .block_on(axum::body::to_bytes(resp.into_body(), usize::MAX))
                        .unwrap()
                        .to_vec(),
                ))
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
            "read_state({},{})",
            self.effective_canister_id, hash,
        ))
    }
}

#[derive(Clone, Debug)]
pub enum EffectivePrincipal {
    None,
    SubnetId(SubnetId),
    CanisterId(CanisterId),
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
        let effective_principal = match effective_principal {
            RawEffectivePrincipal::SubnetId(subnet_id) => {
                let sid = PrincipalId::try_from(subnet_id);
                match sid {
                    Ok(sid) => EffectivePrincipal::SubnetId(SubnetId::new(sid)),
                    Err(_) => {
                        return Err(ConversionError {
                            message: "Bad subnet id".to_string(),
                        })
                    }
                }
            }
            RawEffectivePrincipal::CanisterId(canister_id) => {
                match CanisterId::try_from(canister_id) {
                    Ok(canister_id) => EffectivePrincipal::CanisterId(canister_id),
                    Err(_) => {
                        return Err(ConversionError {
                            message: "Bad effective canister id".to_string(),
                        })
                    }
                }
            }
            RawEffectivePrincipal::None => EffectivePrincipal::None,
        };
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
    canister_id: Option<CanisterId>,
) -> Result<Arc<StateMachine>, String> {
    match effective_principal {
        EffectivePrincipal::SubnetId(subnet_id) => pic
            .get_subnet_with_id(subnet_id)
            .ok_or(format!("Subnet with ID {subnet_id} not found")),
        EffectivePrincipal::CanisterId(effective_canister_id) => {
            pic.try_route_canister(effective_canister_id).ok_or(format!(
                "Desired canister ID {effective_canister_id} not contained on any subnet"
            ))
        }
        EffectivePrincipal::None => {
            if let Some(canister_id) = canister_id {
                if canister_id == CanisterId::ic_00() {
                    Ok(pic.random_subnet())
                } else {
                    pic.try_route_canister(canister_id)
                        .ok_or("Canister not found".into())
                }
            } else {
                Err("No effective principal and no canister id provided".to_string())
            }
        }
    }
}

fn route_call(
    pic: &mut PocketIc,
    canister_call: CanisterCall,
) -> Result<Arc<StateMachine>, String> {
    route(
        pic,
        canister_call.effective_principal.clone(),
        Some(canister_call.canister_id),
    )
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

        let time = Time::from_nanos_since_unix_epoch(21);
        compute_assert_state_change(&mut pic, SetTime { time });
        let expected_time = OpOut::Time(21);
        let actual_time = compute_assert_state_immutable(&mut pic, GetTime {});

        assert_eq!(expected_time, actual_time);
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
