use candid::Decode;
use core::sync::atomic::Ordering;
use ic_config::flag_status::FlagStatus;
use ic_config::{
    execution_environment::Config as HypervisorConfig, state_manager::LsmtConfig,
    subnet_config::SubnetConfig,
};
use ic_consensus::consensus::payload_builder::PayloadBuilderImpl;
use ic_constants::{MAX_INGRESS_TTL, PERMITTED_DRIFT, SMALL_APP_SUBNET_MAX_SIZE};
use ic_crypto_ecdsa_secp256k1::{PrivateKey, PublicKey};
use ic_crypto_extended_bip32::{DerivationIndex, DerivationPath};
use ic_crypto_test_utils_ni_dkg::{
    dummy_initial_dkg_transcript_with_master_key, sign_message, SecretKeyBytes,
};
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path as LabeledTreePath};
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_cycles_account_manager::CyclesAccountManager;
pub use ic_error_types::{ErrorCode, UserError};
use ic_execution_environment::{ExecutionServices, IngressHistoryReaderImpl};
use ic_ingress_manager::{IngressManager, RandomStateKind};
use ic_interfaces::ingress_pool::{
    IngressPool, PoolSection, UnvalidatedIngressArtifact, ValidatedIngressArtifact,
};
use ic_interfaces::{
    certification::{Verifier, VerifierError},
    consensus::PayloadBuilder as ConsensusPayloadBuilder,
    consensus_pool::ConsensusTime,
    execution_environment::{IngressFilterService, IngressHistoryReader, QueryExecutionService},
    validation::ValidationResult,
};
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, EncodeStreamError};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{CertificationScope, StateHashError, StateManager, StateReader};
use ic_logger::ReplicaLogger;
use ic_management_canister_types::{
    self as ic00, CanisterIdRecord, InstallCodeArgs, Method, Payload,
};
pub use ic_management_canister_types::{
    CanisterHttpResponsePayload, CanisterInstallMode, CanisterSettingsArgs, CanisterStatusResultV2,
    CanisterStatusType, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId, HttpHeader, HttpMethod,
    SignWithECDSAReply, UpdateSettingsArgs,
};
use ic_messaging::SyncMessageRouting;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_protobuf::registry::{
    crypto::v1::EcdsaSigningSubnetList,
    node::v1::{ConnectionEndpoint, NodeRecord},
    provisional_whitelist::v1::ProvisionalWhitelist as PbProvisionalWhitelist,
    routing_table::v1::CanisterMigrations as PbCanisterMigrations,
    routing_table::v1::RoutingTable as PbRoutingTable,
};
use ic_protobuf::types::v1::PrincipalId as PrincipalIdIdProto;
use ic_protobuf::types::v1::SubnetId as SubnetIdProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::provisional_whitelist::ProvisionalWhitelistRegistry;
use ic_registry_client_helpers::subnet::{SubnetListRegistry, SubnetRegistry};
use ic_registry_keys::{
    make_canister_migrations_record_key, make_catch_up_package_contents_key, make_crypto_node_key,
    make_ecdsa_signing_subnet_list_key, make_node_record_key,
    make_provisional_whitelist_record_key, make_routing_table_record_key, ROOT_SUBNET_ID_KEY,
};
use ic_registry_proto_data_provider::{ProtoRegistryDataProvider, INITIAL_REGISTRY_VERSION};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{
    routing_table_insert_subnet, CanisterIdRange, CanisterIdRanges, RoutingTable,
};
use ic_registry_subnet_features::{EcdsaConfig, SubnetFeatures, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_replicated_state::metadata_state::subnet_call_context_manager::SignWithEcdsaContext;
use ic_replicated_state::page_map::Buffer;
use ic_replicated_state::{
    canister_state::{NumWasmPages, WASM_PAGE_SIZE_IN_BYTES},
    Memory, PageMap, ReplicatedState,
};
use ic_state_layout::{CheckpointLayout, RwPolicy};
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::crypto::CryptoReturningOk;
use ic_test_utilities_metrics::{
    fetch_counter_vec, fetch_histogram_stats, fetch_int_counter, fetch_int_gauge,
    fetch_int_gauge_vec, Labels,
};
use ic_test_utilities_registry::{
    add_single_subnet_record, add_subnet_key_record, add_subnet_list_record, SubnetRecordBuilder,
};
use ic_test_utilities_time::FastForwardTimeSource;
use ic_types::artifact::IngressMessageId;
use ic_types::batch::{
    BlockmakerMetrics, ConsensusResponse, QueryStatsPayload, TotalQueryStats, ValidationContext,
};
pub use ic_types::canister_http::{CanisterHttpMethod, CanisterHttpRequestContext};
use ic_types::consensus::block_maker::SubnetRecords;
use ic_types::consensus::certification::CertificationContent;
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript,
};
pub use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{
    canister_threshold_sig::MasterPublicKey, AlgorithmId, CombinedThresholdSig,
    CombinedThresholdSigOf, KeyPurpose, Signable, Signed,
};
use ic_types::malicious_flags::MaliciousFlags;
use ic_types::signature::ThresholdSignature;
use ic_types::time::GENESIS;
use ic_types::xnet::CertifiedStreamSlice;
use ic_types::{
    batch::{Batch, BatchMessages, XNetPayload},
    consensus::certification::Certification,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpCallContent, HttpCanisterUpdate,
        HttpRequestEnvelope, Payload as MsgPayload, RejectContext, SignedIngress,
        SignedIngressContent, UserQuery, EXPECTED_MESSAGE_ID_LENGTH,
    },
    xnet::StreamIndex,
    CanisterLog, CountBytes, CryptoHashOfPartialState, Height, NodeId, Randomness, RegistryVersion,
};
pub use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{CallbackId, HttpRequestError, MessageId},
    time::Time,
    CanisterId, CryptoHashOfState, Cycles, PrincipalId, SubnetId, UserId,
};
use ic_xnet_payload_builder::{
    certified_slice_pool::{certified_slice_count_bytes, CertifiedSliceError},
    ExpectedIndices, RefillTaskHandle, XNetPayloadBuilderImpl, XNetPayloadBuilderMetrics,
    XNetSlicePool,
};
use serde::Deserialize;

pub use ic_error_types::RejectCode;
use maplit::btreemap;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::Serialize;
pub use slog::Level;
use std::io::stderr;
use std::path::Path;
use std::str::FromStr;
use std::string::ToString;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime};
use std::{collections::BTreeMap, convert::TryFrom};
use std::{fmt, io};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tower::buffer::Buffer as TowerBuffer;
use tower::ServiceExt;

#[cfg(test)]
mod tests;

#[derive(Debug, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum SubmitIngressError {
    HttpError(String),
    UserError(UserError),
}

struct FakeVerifier;

impl Verifier for FakeVerifier {
    fn validate(
        &self,
        _: SubnetId,
        _: &Certification,
        _: RegistryVersion,
    ) -> ValidationResult<VerifierError> {
        Ok(())
    }
}

/// Adds root subnet ID, routing table, subnet list,
/// and provisional whitelist to the registry.
pub fn finalize_registry(
    nns_subnet_id: SubnetId,
    routing_table: RoutingTable,
    subnet_list: Vec<SubnetId>,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
) {
    let registry_version = INITIAL_REGISTRY_VERSION;
    let root_subnet_id_proto = SubnetIdProto {
        principal_id: Some(PrincipalIdIdProto {
            raw: nns_subnet_id.get_ref().to_vec(),
        }),
    };
    registry_data_provider
        .add(
            ROOT_SUBNET_ID_KEY,
            registry_version,
            Some(root_subnet_id_proto),
        )
        .unwrap();
    let pb_routing_table = PbRoutingTable::from(routing_table.clone());
    registry_data_provider
        .add(
            &make_routing_table_record_key(),
            registry_version,
            Some(pb_routing_table),
        )
        .unwrap();
    add_subnet_list_record(&registry_data_provider, registry_version.get(), subnet_list);
    let pb_whitelist = PbProvisionalWhitelist::from(ProvisionalWhitelist::All);
    registry_data_provider
        .add(
            &make_provisional_whitelist_record_key(),
            registry_version,
            Some(pb_whitelist),
        )
        .unwrap();
}

/// Adds subnet-related records to registry.
/// Note: `finalize_registry` must be called with `routing_table` containing `subnet_id`
/// before any other public method of the `StateMachine` (except for `get_subnet_id`) is invoked.
fn make_nodes_registry(
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    ecdsa_keys: &[EcdsaKeyId],
    features: SubnetFeatures,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    nodes: &Vec<StateMachineNode>,
    is_root_subnet: bool,
    public_key: ThresholdSigPublicKey,
    ni_dkg_transcript: NiDkgTranscript,
) -> Arc<FakeRegistryClient> {
    let registry_version = INITIAL_REGISTRY_VERSION;
    // ECDSA subnet_id must be different from nns_subnet_id, otherwise
    // `sign_with_ecdsa` won't be charged.
    let subnet_id_proto = SubnetIdProto {
        principal_id: Some(PrincipalIdIdProto {
            raw: subnet_id.get_ref().to_vec(),
        }),
    };
    for key_id in ecdsa_keys {
        let id = make_ecdsa_signing_subnet_list_key(key_id);
        registry_data_provider
            .add(
                &id.clone(),
                registry_version,
                Some(EcdsaSigningSubnetList {
                    subnets: vec![subnet_id_proto.clone()],
                }),
            )
            .unwrap();
    }

    for node in nodes {
        let node_record = NodeRecord {
            node_operator_id: vec![0],
            xnet: None,
            http: Some(ConnectionEndpoint {
                ip_addr: "2a00:fb01:400:42:5000:22ff:fe5e:e3c4".into(),
                port: 1234,
            }),
            hostos_version_id: None,
            chip_id: None,
            public_ipv4_config: None,
            domain: None,
        };
        registry_data_provider
            .add(
                &make_node_record_key(node.node_id),
                registry_version,
                Some(node_record),
            )
            .unwrap();
        registry_data_provider
            .add(
                &make_crypto_node_key(node.node_id, KeyPurpose::NodeSigning),
                registry_version,
                Some(node.node_pk_proto.clone()),
            )
            .unwrap();
    }

    // The following constants were derived from the mainnet config
    // using `ic-admin --nns-url https://icp0.io get-topology`.
    // Note: The value of the constant `max_ingress_bytes_per_message`
    // does not match the corresponding values for the SNS and Bitcoin
    // subnets on the IC mainnet. This is because the input parameters
    // to this method do not allow to distinguish those two subnets.
    let max_ingress_bytes_per_message = match subnet_type {
        SubnetType::Application => 2 * 1024 * 1024,
        SubnetType::VerifiedApplication => 2 * 1024 * 1024,
        SubnetType::System => 3 * 1024 * 1024 + 512 * 1024,
    };
    let max_ingress_messages_per_block = if is_root_subnet { 400 } else { 1000 };
    let max_block_payload_size = 4 * 1024 * 1024;

    let node_ids: Vec<_> = nodes.iter().map(|n| n.node_id).collect();
    let record = SubnetRecordBuilder::from(&node_ids)
        .with_subnet_type(subnet_type)
        .with_max_ingress_bytes_per_message(max_ingress_bytes_per_message)
        .with_max_ingress_messages_per_block(max_ingress_messages_per_block)
        .with_max_block_payload_size(max_block_payload_size)
        .with_ecdsa_config(EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: ecdsa_keys.to_vec(),
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        })
        .with_features(features)
        .build();

    // Insert initial DKG transcripts
    let cup_contents = CatchUpPackageContents {
        initial_ni_dkg_transcript_high_threshold: Some(ni_dkg_transcript.clone().into()),
        initial_ni_dkg_transcript_low_threshold: Some(ni_dkg_transcript.into()),
        ..Default::default()
    };
    registry_data_provider
        .add(
            &make_catch_up_package_contents_key(subnet_id),
            INITIAL_REGISTRY_VERSION,
            Some(cup_contents),
        )
        .expect("Failed to add subnet record.");

    add_single_subnet_record(
        &registry_data_provider,
        registry_version.get(),
        subnet_id,
        record,
    );
    add_subnet_key_record(
        &registry_data_provider,
        registry_version.get(),
        subnet_id,
        public_key,
    );

    let registry_client = Arc::new(FakeRegistryClient::new(
        Arc::clone(&registry_data_provider) as _
    ));
    registry_client.update_to_latest_version();
    registry_client
}

/// Convert an object into CBOR binary.
fn into_cbor<R: Serialize>(r: &R) -> Vec<u8> {
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    ser.self_describe().expect("Could not write magic tag.");
    r.serialize(&mut ser).expect("Serialization failed.");
    ser.into_inner()
}

fn replica_logger() -> ReplicaLogger {
    use slog::Drain;
    let log_level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|level| Level::from_str(&level).ok())
        .unwrap_or(Level::Warning);

    let writer: Box<dyn io::Write + Sync + Send> = if std::env::var("LOG_TO_STDERR").is_ok() {
        Box::new(stderr())
    } else {
        Box::new(slog_term::TestStdoutWriter)
    };
    let decorator = slog_term::PlainSyncDecorator::new(writer);
    let drain = slog_term::FullFormat::new(decorator)
        .build()
        .filter_level(log_level)
        .fuse();
    let logger = slog::Logger::root(drain, slog::o!());
    logger.into()
}

/// Bundles the configuration of a `StateMachine`.
#[derive(Clone)]
pub struct StateMachineConfig {
    subnet_config: SubnetConfig,
    hypervisor_config: HypervisorConfig,
}

impl StateMachineConfig {
    pub fn new(subnet_config: SubnetConfig, hypervisor_config: HypervisorConfig) -> Self {
        Self {
            subnet_config,
            hypervisor_config,
        }
    }
}

/// Struct mocking consensus time required for instantiating `IngressManager`
/// in `StateMachine`.
struct PocketConsensusTime {
    t: RwLock<Time>,
}

impl PocketConsensusTime {
    fn new(t: Time) -> Self {
        Self { t: RwLock::new(t) }
    }
    /// We need to override the consensus time if the time in `StateMachine` changes.
    fn set(&self, t: Time) {
        *self.t.write().unwrap() = t;
    }
}

impl ConsensusTime for PocketConsensusTime {
    fn consensus_time(&self) -> Option<Time> {
        Some(*self.t.read().unwrap())
    }
}

/// Struct mocking the pool of received ingress messages required for
/// instantiating `IngressManager` in `StateMachine`.
struct PocketIngressPool {
    validated: BTreeMap<IngressMessageId, ValidatedIngressArtifact>,
}

impl IngressPool for PocketIngressPool {
    fn validated(&self) -> &dyn PoolSection<ValidatedIngressArtifact> {
        self
    }
    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedIngressArtifact> {
        unimplemented!("PocketIngressPool has no unvalidated pool")
    }
}

impl PoolSection<ValidatedIngressArtifact> for PocketIngressPool {
    fn get(&self, message_id: &IngressMessageId) -> Option<&ValidatedIngressArtifact> {
        self.validated.get(message_id)
    }

    fn get_all_by_expiry_range<'a>(
        &self,
        range: std::ops::RangeInclusive<Time>,
    ) -> Box<dyn Iterator<Item = &ValidatedIngressArtifact> + '_> {
        let (start, end) = range.into_inner();
        if end < start {
            return Box::new(std::iter::empty());
        }
        let min_bytes = [0; EXPECTED_MESSAGE_ID_LENGTH];
        let max_bytes = [0xff; EXPECTED_MESSAGE_ID_LENGTH];
        let range = std::ops::RangeInclusive::new(
            IngressMessageId::new(start, MessageId::from(min_bytes)),
            IngressMessageId::new(end, MessageId::from(max_bytes)),
        );
        Box::new(self.validated.range(range).map(|(_, v)| v))
    }

    fn get_timestamp(&self, message_id: &IngressMessageId) -> Option<Time> {
        self.validated.get(message_id).map(|x| x.timestamp)
    }

    fn size(&self) -> usize {
        self.validated.len()
    }
}

impl PocketIngressPool {
    fn new() -> Self {
        Self {
            validated: btreemap![],
        }
    }
    /// Pushes a received ingress message into the pool.
    fn push(&mut self, m: SignedIngress, timestamp: Time) {
        self.validated.insert(
            IngressMessageId::new(m.expiry_time(), m.id()),
            ValidatedIngressArtifact {
                msg: m.into(),
                timestamp,
            },
        );
    }
}

/// Struct mocking the pool of XNet messages required for
/// instantiating `XNetPayloadBuilderImpl` in `StateMachine`.
struct PocketXNetSlicePoolImpl {
    /// Association of subnet IDs to their corresponding `StateMachine`s
    /// from which the XNet messages are fetched.
    subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>>,
    /// Subnet ID of the `StateMachine` containing the pool.
    own_subnet_id: SubnetId,
}

impl PocketXNetSlicePoolImpl {
    fn new(
        subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>>,
        own_subnet_id: SubnetId,
    ) -> Self {
        Self {
            subnets,
            own_subnet_id,
        }
    }
}

impl XNetSlicePool for PocketXNetSlicePoolImpl {
    /// Obtains a certified slice of a stream from a `StateMachine`
    /// corresponding to a given subnet ID.
    fn take_slice(
        &self,
        subnet_id: SubnetId,
        begin: Option<&ExpectedIndices>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<Option<(CertifiedStreamSlice, usize)>, CertifiedSliceError> {
        let subnets = self.subnets.read().unwrap();
        let sm = subnets.get(&subnet_id).unwrap();
        let msg_begin = begin.map(|idx| idx.message_index);
        // We set `witness_begin` equal to `msg_begin` since all states are certified.
        let certified_stream = sm.generate_certified_stream_slice(
            self.own_subnet_id,
            msg_begin,
            msg_begin,
            msg_limit,
            byte_limit,
        );
        Ok(certified_stream
            .map(|certified_stream| {
                let num_bytes = certified_slice_count_bytes(&certified_stream).unwrap();
                (certified_stream, num_bytes)
            })
            .ok())
    }

    /// We do not collect any metrics here.
    fn observe_pool_size_bytes(&self) {}

    /// We do not cache XNet messages in this mock implementation
    /// and thus there is no need for garbage collection.
    fn garbage_collect(&self, _new_stream_positions: BTreeMap<SubnetId, ExpectedIndices>) {}

    /// We do not cache XNet messages in this mock implementation
    /// and thus there is no need for garbage collection.
    fn garbage_collect_slice(&self, _subnet_id: SubnetId, _stream_position: ExpectedIndices) {}
}

/// A replica node of the subnet with the corresponding `StateMachine`.
pub struct StateMachineNode {
    pub node_id: NodeId,
    pub node_pk_proto: PublicKeyProto,
    pub signing_key: ed25519_consensus::SigningKey,
}

impl From<u64> for StateMachineNode {
    fn from(i: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        let signing_key: ed25519_consensus::SigningKey = bytes.into();
        let node_pk_proto = PublicKeyProto {
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: signing_key.verification_key().to_bytes().to_vec(),
            version: 0,
            proof_data: None,
            timestamp: None,
        };
        Self {
            node_id: PrincipalId::new_self_authenticating(
                &signing_key.verification_key().to_bytes(),
            )
            .into(),
            node_pk_proto,
            signing_key,
        }
    }
}

/// Represents a replicated state machine detached from the network layer that
/// can be used to test this part of the stack in isolation.
pub struct StateMachine {
    subnet_id: SubnetId,
    public_key: ThresholdSigPublicKey,
    public_key_der: Vec<u8>,
    secret_key: SecretKeyBytes,
    ecdsa_secret_key: PrivateKey,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    pub registry_client: Arc<FakeRegistryClient>,
    pub state_manager: Arc<StateManagerImpl>,
    consensus_time: Arc<PocketConsensusTime>,
    ingress_pool: Arc<RwLock<PocketIngressPool>>,
    ingress_manager: Arc<IngressManager>,
    pub ingress_filter:
        tower::buffer::Buffer<IngressFilterService, (ProvisionalWhitelist, SignedIngressContent)>,
    payload_builder: Arc<RwLock<Option<PayloadBuilderImpl>>>,
    message_routing: SyncMessageRouting,
    metrics_registry: MetricsRegistry,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    pub query_handler:
        tower::buffer::Buffer<QueryExecutionService, (UserQuery, Option<CertificateDelegation>)>,
    runtime: Arc<Runtime>,
    pub state_dir: TempDir,
    checkpoints_enabled: std::sync::atomic::AtomicBool,
    nonce: std::sync::atomic::AtomicU64,
    time: std::sync::atomic::AtomicU64,
    ecdsa_subnet_public_keys: BTreeMap<EcdsaKeyId, MasterPublicKey>,
    replica_logger: ReplicaLogger,
    pub nodes: Vec<StateMachineNode>,
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StateMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateMachine")
            .field("state_dir", &self.state_dir.path().display())
            .field("nonce", &self.nonce.load(Ordering::Relaxed))
            .finish()
    }
}

pub struct StateMachineBuilder {
    state_dir: TempDir,
    nonce: u64,
    time: Time,
    config: Option<StateMachineConfig>,
    checkpoints_enabled: bool,
    subnet_type: SubnetType,
    subnet_size: usize,
    nns_subnet_id: Option<SubnetId>,
    subnet_id: Option<SubnetId>,
    routing_table: RoutingTable,
    use_cost_scaling_flag: bool,
    ecdsa_keys: Vec<EcdsaKeyId>,
    features: SubnetFeatures,
    runtime: Option<Arc<Runtime>>,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    lsmt_override: Option<LsmtConfig>,
    is_root_subnet: bool,
    seq_no: u8,
    with_extra_canister_range: Option<std::ops::RangeInclusive<CanisterId>>,
    dts: bool,
}

impl StateMachineBuilder {
    pub fn new() -> Self {
        Self {
            state_dir: TempDir::new().expect("failed to create a temporary directory"),
            nonce: 0,
            time: GENESIS,
            config: None,
            checkpoints_enabled: false,
            subnet_type: SubnetType::System,
            use_cost_scaling_flag: false,
            subnet_size: SMALL_APP_SUBNET_MAX_SIZE,
            nns_subnet_id: None,
            subnet_id: None,
            routing_table: RoutingTable::new(),
            ecdsa_keys: vec![EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "master_ecdsa_public_key".to_string(),
            }],
            features: SubnetFeatures {
                http_requests: true,
                ..SubnetFeatures::default()
            },
            runtime: None,
            registry_data_provider: Arc::new(ProtoRegistryDataProvider::new()),
            lsmt_override: None,
            is_root_subnet: false,
            seq_no: 0,
            with_extra_canister_range: None,
            dts: true,
        }
    }

    pub fn with_lsmt_override(self, lsmt_override: Option<LsmtConfig>) -> Self {
        Self {
            lsmt_override,
            ..self
        }
    }

    pub fn with_state_dir(self, state_dir: TempDir) -> Self {
        Self { state_dir, ..self }
    }

    fn with_nonce(self, nonce: u64) -> Self {
        Self { nonce, ..self }
    }

    pub fn with_time(self, time: Time) -> Self {
        Self { time, ..self }
    }

    pub fn with_config(self, config: Option<StateMachineConfig>) -> Self {
        Self { config, ..self }
    }

    pub fn with_checkpoints_enabled(self, checkpoints_enabled: bool) -> Self {
        Self {
            checkpoints_enabled,
            ..self
        }
    }

    pub fn with_current_time(self) -> Self {
        let time = Time::try_from(SystemTime::now()).expect("Current time conversion failed");
        Self { time, ..self }
    }

    pub fn with_subnet_type(self, subnet_type: SubnetType) -> Self {
        Self {
            subnet_type,
            ..self
        }
    }

    pub fn with_subnet_size(self, subnet_size: usize) -> Self {
        Self {
            subnet_size,
            ..self
        }
    }

    pub fn with_nns_subnet_id(self, nns_subnet_id: SubnetId) -> Self {
        Self {
            nns_subnet_id: Some(nns_subnet_id),
            ..self
        }
    }

    pub fn with_default_canister_range(self) -> Self {
        self // TODO: remove this pattern
    }

    pub fn with_extra_canister_range(self, id_range: std::ops::RangeInclusive<CanisterId>) -> Self {
        Self {
            with_extra_canister_range: Some(id_range),
            ..self
        }
    }

    pub fn with_routing_table(self, routing_table: RoutingTable) -> Self {
        Self {
            routing_table,
            ..self
        }
    }

    pub fn with_subnet_id(self, subnet_id: SubnetId) -> Self {
        Self {
            subnet_id: Some(subnet_id),
            ..self
        }
    }

    pub fn with_use_cost_scaling_flag(self, use_cost_scaling_flag: bool) -> Self {
        Self {
            use_cost_scaling_flag,
            ..self
        }
    }

    pub fn with_ecdsa_key(self, key: EcdsaKeyId) -> Self {
        let mut ecdsa_keys = self.ecdsa_keys;
        ecdsa_keys.push(key);
        Self { ecdsa_keys, ..self }
    }

    pub fn with_multisubnet_ecdsa_key(self) -> Self {
        Self {
            ecdsa_keys: vec![EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: format!("master_ecdsa_public_key_{}", self.seq_no),
            }],
            ..self
        }
    }

    pub fn with_features(self, features: SubnetFeatures) -> Self {
        Self { features, ..self }
    }

    pub fn with_runtime(self, runtime: Arc<Runtime>) -> Self {
        Self {
            runtime: Some(runtime),
            ..self
        }
    }

    pub fn with_registry_data_provider(
        self,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
    ) -> Self {
        Self {
            registry_data_provider,
            ..self
        }
    }

    pub fn with_subnet_seq_no(self, seq_no: u8) -> Self {
        Self { seq_no, ..self }
    }

    pub fn with_root_subnet_config(self) -> Self {
        Self {
            is_root_subnet: true,
            ..self
        }
    }

    /// Only use from pocket-ic-server binary.
    pub fn no_dts(self) -> Self {
        Self { dts: false, ..self }
    }

    pub fn build_internal(self) -> StateMachine {
        StateMachine::setup_from_dir(
            self.state_dir,
            self.nonce,
            self.time,
            self.config,
            self.checkpoints_enabled,
            self.subnet_type,
            self.subnet_size,
            self.subnet_id,
            self.use_cost_scaling_flag,
            self.ecdsa_keys,
            self.features,
            self.runtime.unwrap_or_else(|| {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("failed to create a tokio runtime")
                    .into()
            }),
            self.registry_data_provider,
            self.lsmt_override,
            self.is_root_subnet,
            self.seq_no,
            self.dts,
        )
    }

    pub fn build(self) -> StateMachine {
        let nns_subnet_id = self.nns_subnet_id;
        let mut routing_table = self.routing_table.clone();
        let registry_data_provider = self.registry_data_provider.clone();
        let extra_canister_range = self.with_extra_canister_range.clone();
        let sm = self.build_internal();
        let subnet_id = sm.get_subnet_id();
        if routing_table.is_empty() {
            routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
        }
        if let Some(id_range) = extra_canister_range {
            routing_table
                .assign_ranges(
                    CanisterIdRanges::try_from(vec![CanisterIdRange {
                        start: *id_range.start(),
                        end: *id_range.end(),
                    }])
                    .expect("invalid canister range"),
                    subnet_id,
                )
                .expect("failed to assign a canister range");
        }
        let subnet_list = vec![sm.get_subnet_id()];
        finalize_registry(
            nns_subnet_id.unwrap_or(subnet_id),
            routing_table,
            subnet_list,
            registry_data_provider,
        );
        sm.reload_registry();
        sm
    }

    /// Build a `StateMachine` and register it for multi-subnet testing
    /// in the provided association of subnet IDs and `StateMachine`s.
    pub fn build_with_subnets(
        self,
        subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>>,
    ) -> Arc<StateMachine> {
        // Build a `StateMachine` for the subnet with `self.subnet_id`.
        let sm = Arc::new(self.build_internal());
        let subnet_id = sm.get_subnet_id();

        // Register this new `StateMachine` in the *shared* association
        // of subnet IDs and their corresponding `StateMachine`s.
        subnets.write().unwrap().insert(subnet_id, sm.clone());

        // Create a dummny refill task handle to be used in `XNetPayloadBuilderImpl`.
        // It is fine that we do not pop any messages from the (bounded) channel
        // since errors are ignored in `RefillTaskHandle::trigger_refill()`.
        let (refill_trigger, _refill_receiver) = mpsc::channel(1);
        let refill_task_handle = RefillTaskHandle(Mutex::new(refill_trigger));

        // Instantiate a `XNetPayloadBuilderImpl`.
        // We need to use a deterministic PRNG - so we use an arbitrary fixed seed, e.g., 42.
        let rng = Arc::new(Some(Mutex::new(StdRng::seed_from_u64(42))));
        let xnet_slice_pool_impl = Box::new(PocketXNetSlicePoolImpl::new(subnets, subnet_id));
        let metrics = Arc::new(XNetPayloadBuilderMetrics::new(&sm.metrics_registry));
        let xnet_payload_builder = XNetPayloadBuilderImpl::new_from_components(
            sm.state_manager.clone(),
            sm.state_manager.clone(),
            sm.registry_client.clone(),
            rng,
            xnet_slice_pool_impl,
            refill_task_handle,
            metrics,
            sm.replica_logger.clone(),
        );

        // Instantiate a `PayloadBuilderImpl` and put it into `StateMachine`
        // which contains no `PayloadBuilderImpl` after creation.
        *sm.payload_builder.write().unwrap() = Some(PayloadBuilderImpl::new_for_testing(
            subnet_id,
            sm.nodes[0].node_id,
            sm.registry_client.clone(),
            sm.ingress_manager.clone(),
            Arc::new(xnet_payload_builder),
            sm.metrics_registry.clone(),
            sm.replica_logger.clone(),
        ));

        sm
    }
}

impl Default for StateMachineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachine {
    // TODO: cleanup, replace external calls with `StateMachineBuilder`.
    /// Constructs a new environment that uses a temporary directory for storing
    /// states.
    pub fn new() -> Self {
        StateMachineBuilder::new().build()
    }

    // TODO: cleanup, replace external calls with `StateMachineBuilder`.
    /// Constructs a new environment with the specified configuration.
    pub fn new_with_config(config: StateMachineConfig) -> Self {
        StateMachineBuilder::new().with_config(Some(config)).build()
    }

    /// Assemble a payload for a new round using `PayloadBuilderImpl`
    /// and execute a round with this payload.
    /// Note that only ingress messages submitted via `Self::submit_ingress`
    /// will be considered during payload building.
    pub fn execute_round(&self) {
        // Make sure the latest state is certified and fetch it from `StateManager`.
        self.certify_latest_state();
        let certified_height = self.state_manager.latest_certified_height();
        let state = self
            .state_manager
            .get_state_at(certified_height)
            .unwrap()
            .take();

        // Build a payload for the round using `PayloadBuilderImpl`.
        let registry_version = self.registry_client.get_latest_version();
        let validation_context = ValidationContext {
            time: self.get_time(),
            registry_version,
            certified_height,
        };
        let subnet_record = self
            .registry_client
            .get_subnet_record(self.subnet_id, registry_version)
            .unwrap()
            .unwrap();
        let subnet_records = SubnetRecords {
            membership_version: subnet_record.clone(),
            context_version: subnet_record,
        };
        let payload_builder = self.payload_builder.read().unwrap();
        let payload_builder = payload_builder.as_ref().unwrap();
        let batch_payload = payload_builder.get_payload(
            certified_height,
            &[], // Because the latest state is certified, we do not need to provide any `past_payloads`.
            &validation_context,
            &subnet_records,
        );

        // Convert payload produced by `PayloadBuilderImpl` into `PayloadBuilder`
        // used by the function `Self::execute_payload` of the `StateMachine`.
        let xnet_payload = batch_payload.xnet.clone();
        let ingress = &batch_payload.ingress;
        let ingress_messages = (0..ingress.message_count())
            .map(|i| ingress.get(i).unwrap().1)
            .collect();
        let mut payload = PayloadBuilder::new()
            .with_ingress_messages(ingress_messages)
            .with_xnet_payload(xnet_payload);

        // Push responses to ECDSA management canister calls into `PayloadBuilder`.
        let sign_with_ecdsa_contexts = state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .clone();
        for (callback, ecdsa_context) in sign_with_ecdsa_contexts {
            // The chain code is an additional input used during the key derivation process
            // to ensure deterministic generation of child keys from the master key.
            // We are using an array with 32 zeros by default.
            let derivation_path = DerivationPath::new(
                std::iter::once(ecdsa_context.request.sender.get().as_slice().to_vec())
                    .chain(ecdsa_context.derivation_path.clone().into_iter())
                    .map(DerivationIndex)
                    .collect::<Vec<_>>(),
            );
            let signature = sign_prehashed_message_with_derived_key(
                &self.ecdsa_secret_key,
                &ecdsa_context.message_hash,
                derivation_path,
            );

            let reply = SignWithECDSAReply { signature };

            payload.consensus_responses.push(ConsensusResponse::new(
                callback,
                MsgPayload::Data(reply.encode()),
            ));
        }

        // Finally execute the payload.
        self.execute_payload(payload);
    }

    /// Reload registry derived from a *shared* registry data provider
    /// to reflect changes in that shared registry data provider
    /// after this `StateMachine` has been built.
    pub fn reload_registry(&self) {
        self.registry_client.reload();
    }

    /// Constructs and initializes a new state machine that uses the specified
    /// directory for storing states.
    #[allow(clippy::too_many_arguments)]
    fn setup_from_dir(
        state_dir: TempDir,
        nonce: u64,
        time: Time,
        config: Option<StateMachineConfig>,
        checkpoints_enabled: bool,
        subnet_type: SubnetType,
        subnet_size: usize,
        subnet_id: Option<SubnetId>,
        use_cost_scaling_flag: bool,
        ecdsa_keys: Vec<EcdsaKeyId>,
        features: SubnetFeatures,
        runtime: Arc<Runtime>,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
        lsmt_override: Option<LsmtConfig>,
        is_root_subnet: bool,
        seq_no: u8,
        dts: bool,
    ) -> Self {
        let replica_logger = replica_logger();

        let metrics_registry = MetricsRegistry::new();

        let (subnet_config, mut hypervisor_config) = match config {
            Some(config) => (config.subnet_config, config.hypervisor_config),
            None => (SubnetConfig::new(subnet_type), HypervisorConfig::default()),
        };

        let node_offset: u64 = StdRng::seed_from_u64(seq_no.into()).gen();
        let nodes: Vec<StateMachineNode> = (0..subnet_size as u64)
            .map(|i| (node_offset + i).into())
            .collect();
        let (ni_dkg_transcript, secret_key) =
            dummy_initial_dkg_transcript_with_master_key(&mut StdRng::seed_from_u64(seq_no.into()));
        let public_key = (&ni_dkg_transcript).try_into().unwrap();
        let public_key_der = threshold_sig_public_key_to_der(public_key).unwrap();
        let subnet_id =
            subnet_id.unwrap_or(PrincipalId::new_self_authenticating(&public_key_der).into());
        let registry_client = make_nodes_registry(
            subnet_id,
            subnet_type,
            &ecdsa_keys,
            features,
            registry_data_provider.clone(),
            &nodes,
            is_root_subnet,
            public_key,
            ni_dkg_transcript,
        );

        let mut sm_config = ic_config::state_manager::Config::new(state_dir.path().to_path_buf());
        if let Some(lsmt_override) = lsmt_override {
            sm_config.lsmt_config = lsmt_override;
        }

        if !dts {
            hypervisor_config.canister_sandboxing_flag = FlagStatus::Disabled;
            hypervisor_config.deterministic_time_slicing = FlagStatus::Disabled;
        }

        // We are not interested in ingress signature validation.
        let malicious_flags = MaliciousFlags {
            maliciously_disable_ingress_validation: true,
            ..Default::default()
        };

        let mut cycles_account_manager = CyclesAccountManager::new(
            subnet_config.scheduler_config.max_instructions_per_message,
            subnet_type,
            subnet_id,
            subnet_config.cycles_account_manager_config,
        );
        cycles_account_manager.set_using_cost_scaling(use_cost_scaling_flag);
        let cycles_account_manager = Arc::new(cycles_account_manager);
        let state_manager = Arc::new(StateManagerImpl::new(
            Arc::new(FakeVerifier),
            subnet_id,
            subnet_type,
            replica_logger.clone(),
            &metrics_registry,
            &sm_config,
            None,
            malicious_flags.clone(),
        ));

        // NOTE: constructing execution services requires tokio context.
        //
        // We could have required the client to use [tokio::test] for state
        // machine tests, but this is error prone and leads to poor dev
        // experience.
        //
        // The API state machine provides is blocking anyway.
        let execution_services = runtime.block_on(async {
            ExecutionServices::setup_execution(
                replica_logger.clone(),
                &metrics_registry,
                subnet_id,
                subnet_type,
                subnet_config.scheduler_config.clone(),
                hypervisor_config.clone(),
                Arc::clone(&cycles_account_manager),
                Arc::clone(&state_manager) as Arc<_>,
                Arc::clone(&state_manager.get_fd_factory()),
            )
        });

        let message_routing = SyncMessageRouting::new(
            Arc::clone(&state_manager) as _,
            Arc::clone(&state_manager) as _,
            Arc::clone(&execution_services.ingress_history_writer) as _,
            execution_services.scheduler,
            hypervisor_config,
            cycles_account_manager.clone(),
            subnet_id,
            &metrics_registry,
            replica_logger.clone(),
            Arc::clone(&registry_client) as _,
            malicious_flags.clone(),
        );

        // The following key has been randomly generated using:
        // https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/crypto/ecdsa_secp256k1/src/lib.rs
        // It's the sec1 representation of the key in a hex string.
        // let private_key: PrivateKey = PrivateKey::generate();
        // let private_str = hex::encode(private_key.serialize_sec1());
        // We always set it to the same value to have deterministic results.
        // Please do not use this private key anywhere.
        let private_key_bytes =
            hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920")
                .unwrap();

        let ecdsa_secret_key: PrivateKey =
            PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();

        let mut ecdsa_subnet_public_keys = BTreeMap::new();

        for ecdsa_key in ecdsa_keys {
            ecdsa_subnet_public_keys.insert(
                ecdsa_key,
                MasterPublicKey {
                    algorithm_id: AlgorithmId::EcdsaSecp256k1,
                    public_key: ecdsa_secret_key.public_key().serialize_sec1(true),
                },
            );
        }

        ecdsa_subnet_public_keys.insert(
            EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: "master_ecdsa_public_key".to_string(),
            },
            MasterPublicKey {
                algorithm_id: AlgorithmId::EcdsaSecp256k1,
                public_key: ecdsa_secret_key.public_key().serialize_sec1(true),
            },
        );

        let time_source = FastForwardTimeSource::new();
        time_source.set_time(time).unwrap();
        let consensus_time = Arc::new(PocketConsensusTime::new(time));
        let ingress_pool = Arc::new(RwLock::new(PocketIngressPool::new()));
        // We are not interested in ingress signature validation
        // and thus use `CryptoReturningOk`.
        let ingress_verifier = Arc::new(CryptoReturningOk::default());
        let ingress_manager = Arc::new(IngressManager::new(
            time_source,
            consensus_time.clone(),
            Box::new(IngressHistoryReaderImpl::new(state_manager.clone())),
            ingress_pool.clone(),
            registry_client.clone(),
            ingress_verifier.clone(),
            metrics_registry.clone(),
            subnet_id,
            replica_logger.clone(),
            state_manager.clone(),
            cycles_account_manager,
            malicious_flags,
            RandomStateKind::Deterministic,
        ));

        Self {
            subnet_id,
            secret_key,
            public_key,
            public_key_der,
            ecdsa_secret_key,
            registry_data_provider,
            registry_client: registry_client.clone(),
            state_manager,
            consensus_time,
            ingress_pool,
            ingress_manager: ingress_manager.clone(),
            ingress_filter: runtime
                .block_on(async { TowerBuffer::new(execution_services.ingress_filter, 1) }),
            payload_builder: Arc::new(RwLock::new(None)), // set by `StateMachineBuilder::build_with_subnets`
            ingress_history_reader: execution_services.ingress_history_reader,
            message_routing,
            metrics_registry,
            query_handler: runtime.block_on(async {
                TowerBuffer::new(execution_services.query_execution_service, 1)
            }),
            runtime,
            state_dir,
            // Note: state machine tests are commonly used for testing
            // canisters, such tests usually don't rely on any persistence.
            checkpoints_enabled: std::sync::atomic::AtomicBool::new(checkpoints_enabled),
            nonce: std::sync::atomic::AtomicU64::new(nonce),
            time: std::sync::atomic::AtomicU64::new(time.as_nanos_since_unix_epoch()),
            ecdsa_subnet_public_keys,
            replica_logger,
            nodes,
        }
    }

    fn into_components(self) -> (TempDir, u64, Time, bool) {
        (
            self.state_dir,
            self.nonce.into_inner(),
            Time::from_nanos_since_unix_epoch(self.time.into_inner()),
            self.checkpoints_enabled.into_inner(),
        )
    }

    pub fn into_state_dir(self) -> TempDir {
        let (path, _, _, _) = self.into_components();
        path
    }

    /// Emulates a node restart, including checkpoint recovery.
    pub fn restart_node(self) -> Self {
        // We must drop self before setup_form_dir so that we don't have two StateManagers pointing
        // to the same root.
        let (state_dir, nonce, time, checkpoints_enabled) = self.into_components();

        StateMachineBuilder::new()
            .with_state_dir(state_dir)
            .with_nonce(nonce)
            .with_time(time)
            .with_checkpoints_enabled(checkpoints_enabled)
            .build()
    }

    /// Same as [restart_node], but allows overwriting the LSMT flag.
    pub fn restart_node_with_lsmt_override(self, lsmt_override: Option<LsmtConfig>) -> Self {
        // We must drop self before setup_form_dir so that we don't have two StateManagers pointing
        // to the same root.
        let (state_dir, nonce, time, checkpoints_enabled) = self.into_components();

        StateMachineBuilder::new()
            .with_state_dir(state_dir)
            .with_nonce(nonce)
            .with_time(time)
            .with_checkpoints_enabled(checkpoints_enabled)
            .with_lsmt_override(lsmt_override)
            .build()
    }

    /// Same as [restart_node], but the subnet will have the specified `config`
    /// after the restart.
    pub fn restart_node_with_config(self, config: StateMachineConfig) -> Self {
        // We must drop self before setup_form_dir so that we don't have two StateManagers pointing
        // to the same root.
        let (state_dir, nonce, time, checkpoints_enabled) = self.into_components();

        StateMachineBuilder::new()
            .with_state_dir(state_dir)
            .with_nonce(nonce)
            .with_time(time)
            .with_config(Some(config))
            .with_checkpoints_enabled(checkpoints_enabled)
            .build()
    }

    pub fn get_delegation_for_subnet(
        &self,
        subnet_id: SubnetId,
    ) -> Result<CertificateDelegation, String> {
        self.certify_latest_state();
        let certified_state_reader = match self.state_manager.get_certified_state_snapshot() {
            Some(reader) => reader,
            None => {
                return Err("No certified state available.".to_string());
            }
        };
        let paths = vec![
            LabeledTreePath::new(vec![
                b"subnet".into(),
                subnet_id.get().into(),
                b"public_key".into(),
            ]),
            LabeledTreePath::new(vec![
                b"subnet".into(),
                subnet_id.get().into(),
                b"canister_ranges".into(),
            ]),
            LabeledTreePath::from(Label::from("time")),
        ];
        let labeled_tree = sparse_labeled_tree_from_paths(&paths).unwrap();
        let (tree, certification) = match certified_state_reader.read_certified_state(&labeled_tree)
        {
            Some(r) => r,
            None => {
                return Err("Certified state could not be read.".to_string());
            }
        };
        let signature = certification.signed.signature.signature.get().0;
        Ok(CertificateDelegation {
            subnet_id: Blob(subnet_id.get().to_vec()),
            certificate: Blob(into_cbor(&Certificate {
                tree,
                signature: Blob(signature),
                delegation: None,
            })),
        })
    }

    /// If the argument is true, the state machine will create an on-disk
    /// checkpoint for each new state it creates.
    ///
    /// You have to call this function with `true` before you make any changes
    /// to the state machine if you want to use [restart_node] and
    /// [await_state_hash] functions.
    pub fn set_checkpoints_enabled(&self, enabled: bool) {
        self.checkpoints_enabled
            .store(enabled, core::sync::atomic::Ordering::Relaxed)
    }

    /// Returns the latest state.
    pub fn get_latest_state(&self) -> Arc<ReplicatedState> {
        self.state_manager.get_latest_state().take()
    }

    /// Generates a certified stream slice to a remote subnet.
    fn generate_certified_stream_slice(
        &self,
        remote_subnet_id: SubnetId,
        witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<CertifiedStreamSlice, EncodeStreamError> {
        self.certify_latest_state();
        self.state_manager.encode_certified_stream_slice(
            remote_subnet_id,
            witness_begin,
            msg_begin,
            msg_limit,
            byte_limit,
        )
    }

    /// Generates a Xnet payload to a remote subnet.
    pub fn generate_xnet_payload(
        &self,
        remote_subnet_id: SubnetId,
        witness_begin: Option<StreamIndex>,
        msg_begin: Option<StreamIndex>,
        msg_limit: Option<usize>,
        byte_limit: Option<usize>,
    ) -> Result<XNetPayload, EncodeStreamError> {
        self.generate_certified_stream_slice(
            remote_subnet_id,
            witness_begin,
            msg_begin,
            msg_limit,
            byte_limit,
        )
        .map(|certified_stream| XNetPayload {
            stream_slices: btreemap! { self.get_subnet_id() => certified_stream },
        })
    }

    /// Submit an ingress message into the ingress pool used by `PayloadBuilderImpl`
    /// in `Self::execute_round`.
    pub fn submit_ingress_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<MessageId, SubmitIngressError> {
        // Build `SignedIngress` with maximum ingress expiry and unique nonce,
        // omitting delegations and signatures.
        let ingress_expiry = (self.get_time() + MAX_INGRESS_TTL).as_nanos_since_unix_epoch();
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed) + 1;
        let nonce = Some(nonce.to_le_bytes().into());
        let msg = SignedIngress::try_from(HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(canister_id.get().into_vec()),
                    method_name: method.to_string(),
                    arg: Blob(payload.clone()),
                    sender: sender.into(),
                    ingress_expiry,
                    nonce: nonce.clone(),
                },
            },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        })
        .unwrap();
        self.submit_signed_ingress(msg)
    }

    /// Submit an ingress message into the ingress pool used by `PayloadBuilderImpl`
    /// in `Self::execute_round`.
    pub fn submit_signed_ingress(
        &self,
        msg: SignedIngress,
    ) -> Result<MessageId, SubmitIngressError> {
        // Make sure the latest state is certified and fetch it from `StateManager`.
        self.certify_latest_state();

        // Fetch ingress validation settings from the registry.
        let registry_version = self.registry_client.get_latest_version();
        let ingress_registry_settings = self
            .registry_client
            .get_ingress_message_settings(self.subnet_id, registry_version)
            .unwrap()
            .unwrap();
        let provisional_whitelist = self
            .registry_client
            .get_provisional_whitelist(registry_version)
            .unwrap()
            .unwrap();

        // Validate the size of the ingress message.
        if msg.count_bytes() > ingress_registry_settings.max_ingress_bytes_per_message {
            return Err(SubmitIngressError::HttpError(format!(
                "Request {} is too large. Message byte size {} is larger than the max allowed {}.",
                msg.id(),
                msg.count_bytes(),
                ingress_registry_settings.max_ingress_bytes_per_message
            )));
        }

        // Run `IngressFilter` on the ingress message.
        let ingress_filter = self.ingress_filter.clone();
        self.runtime
            .block_on(ingress_filter.oneshot((provisional_whitelist, msg.clone().into())))
            .unwrap()
            .map_err(SubmitIngressError::UserError)?;

        // All checks were successful at this point so we can push the ingress message to the ingress pool.
        let message_id = msg.id();
        self.ingress_pool
            .write()
            .unwrap()
            .push(msg, self.get_time());
        Ok(message_id)
    }

    /// Push an ingress message into the ingress pool used by `PayloadBuilderImpl`
    /// in `Self::execute_round`. This method does not perform any validation
    /// and thus it should only be called on already validated `SignedIngress`.
    pub fn push_signed_ingress(&self, msg: SignedIngress) {
        self.ingress_pool
            .write()
            .unwrap()
            .push(msg, self.get_time());
    }

    /// Triggers a single round of execution without any new inputs.  The state
    /// machine will invoke heartbeats and make progress on pending async calls.
    pub fn tick(&self) {
        let mut payload = PayloadBuilder::default();
        let state = self.state_manager.get_latest_state().take();
        let sign_with_ecdsa_contexts = state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .clone();
        for (callback, ecdsa_context) in sign_with_ecdsa_contexts {
            // The chain code is an additional input used during the key derivation process
            // to ensure deterministic generation of child keys from the master key.
            // We are using an array with 32 zeros by default.

            let derivation_path = DerivationPath::new(
                std::iter::once(ecdsa_context.request.sender.get().as_slice().to_vec())
                    .chain(ecdsa_context.derivation_path.clone().into_iter())
                    .map(DerivationIndex)
                    .collect::<Vec<_>>(),
            );
            let signature = sign_prehashed_message_with_derived_key(
                &self.ecdsa_secret_key,
                &ecdsa_context.message_hash,
                derivation_path,
            );

            let reply = SignWithECDSAReply { signature };

            payload.consensus_responses.push(ConsensusResponse::new(
                callback,
                MsgPayload::Data(reply.encode()),
            ));
        }
        self.execute_payload(payload);
    }

    /// Makes the state machine tick until there are no more messages in the system.
    /// This method is useful if you need to wait for asynchronous canister communication to
    /// complete.
    ///
    /// # Panics
    ///
    /// This function panics if the state machine did not process all messages within the
    /// `max_ticks` iterations.
    pub fn run_until_completion(&self, max_ticks: usize) {
        let mut reached_completion = false;
        for _tick in 0..max_ticks {
            let state = self.state_manager.get_latest_state().take();
            reached_completion = !state
                .canisters_iter()
                .any(|canister| canister.has_input() || canister.has_output())
                && !state.subnet_queues().has_input()
                && !state.subnet_queues().has_output();
            if reached_completion {
                break;
            }
            self.tick();
        }
        if !reached_completion {
            panic!(
                "The state machine did not reach completion after {} ticks",
                max_ticks
            );
        }
    }

    /// Checks critical error counters and panics if a critical error occurred.
    /// We ignore `execution_environment_unfiltered_ingress` for now.
    pub fn check_critical_errors(&self) {
        let error_counter_vec = fetch_counter_vec(&self.metrics_registry, "critical_errors");
        if let Some((metric, _)) = error_counter_vec.into_iter().find(|(_, v)| *v != 0.0) {
            let err: String = metric.get("error").unwrap().to_string();
            if err != *"execution_environment_unfiltered_ingress" {
                panic!("Critical error {} occurred.", err);
            }
        }
    }

    /// Advances time by 1ns (to make sure time is strictly monotone)
    /// and triggers a single round of execution with block payload as an input.
    pub fn execute_payload(&self, payload: PayloadBuilder) -> Height {
        self.advance_time(Duration::from_nanos(1));

        let batch_number = self.message_routing.expected_batch_height();

        let mut seed = [0u8; 32];
        // use the batch number to seed randomness
        seed[..8].copy_from_slice(batch_number.get().to_le_bytes().as_slice());

        let batch = Batch {
            batch_number,
            next_checkpoint_height: None,
            requires_full_state_hash: self.checkpoints_enabled.load(Ordering::Relaxed),
            messages: BatchMessages {
                signed_ingress_msgs: payload.ingress_messages,
                certified_stream_slices: payload.xnet_payload.stream_slices,
                bitcoin_adapter_responses: vec![],
                query_stats: payload.query_stats,
            },
            randomness: Randomness::from(seed),
            ecdsa_subnet_public_keys: self.ecdsa_subnet_public_keys.clone(),
            ecdsa_quadruple_ids: BTreeMap::new(),
            registry_version: self.registry_client.get_latest_version(),
            time: Time::from_nanos_since_unix_epoch(self.time.load(Ordering::Relaxed)),
            consensus_responses: payload.consensus_responses,
            blockmaker_metrics: BlockmakerMetrics::new_for_test(),
        };

        self.message_routing
            .process_batch(batch)
            .expect("Could not process batch");

        self.state_manager.remove_states_below(batch_number);
        assert_eq!(
            self.state_manager
                .latest_state_certification_hash()
                .unwrap()
                .0,
            batch_number
        );

        self.check_critical_errors();

        batch_number
    }

    pub fn execute_block_with_xnet_payload(&self, xnet_payload: XNetPayload) {
        self.execute_payload(PayloadBuilder::new().xnet_payload(xnet_payload));
    }

    /// Returns an immutable reference to the metrics registry.
    pub fn metrics_registry(&self) -> &MetricsRegistry {
        &self.metrics_registry
    }

    /// Returns the total number of Wasm instructions this state machine consumed in replicated
    /// message execution (ingress messages, inter-canister messages, and heartbeats).
    pub fn instructions_consumed(&self) -> f64 {
        fetch_histogram_stats(
            &self.metrics_registry,
            "scheduler_instructions_consumed_per_round",
        )
        .map(|stats| stats.sum)
        .unwrap_or(0.0)
    }

    /// Returns the total number of Wasm instructions executed when executing subnet
    /// messages (IC00 messages addressed to the subnet).
    pub fn subnet_message_instructions(&self) -> f64 {
        fetch_histogram_stats(
            &self.metrics_registry,
            "execution_round_subnet_queue_instructions",
        )
        .map(|stats| stats.sum)
        .unwrap_or(0.0)
    }

    /// Returns the number of canisters that were uninstalled due to being low
    /// on cycles.
    pub fn num_canisters_uninstalled_out_of_cycles(&self) -> u64 {
        fetch_int_counter(
            &self.metrics_registry,
            "scheduler_num_canisters_uninstalled_out_of_cycles",
        )
        .unwrap_or(0)
    }

    /// Total number of running canisters.
    pub fn num_running_canisters(&self) -> u64 {
        *fetch_int_gauge_vec(
            &self.metrics_registry,
            "replicated_state_registered_canisters",
        )
        .get(&Labels::from([("status".into(), "running".into())]))
        .unwrap_or(&0)
    }

    /// Total memory footprint of all canisters on this subnet.
    pub fn canister_memory_usage_bytes(&self) -> u64 {
        fetch_int_gauge(&self.metrics_registry, "canister_memory_usage_bytes").unwrap_or(0)
    }

    /// Sets the time that the state machine will use for executing next
    /// messages.
    pub fn set_time(&self, time: SystemTime) {
        let t = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        self.consensus_time
            .set(Time::from_nanos_since_unix_epoch(t));
        self.time.store(t, core::sync::atomic::Ordering::Relaxed);
    }

    /// Returns the current state machine time.
    pub fn time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(self.time.load(Ordering::Relaxed))
    }

    /// Returns the state machine time at the beginning of next round.
    pub fn time_of_next_round(&self) -> SystemTime {
        self.time() + Duration::from_nanos(1)
    }

    /// Returns the current state machine time.
    pub fn get_time(&self) -> Time {
        Time::from_nanos_since_unix_epoch(
            self.time()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        )
    }

    /// Returns the state machine time at the beginning of next round.
    pub fn get_time_of_next_round(&self) -> Time {
        Time::from_nanos_since_unix_epoch(
            self.time_of_next_round()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        )
    }

    /// Advances the state machine time by the given amount.
    pub fn advance_time(&self, amount: Duration) {
        self.set_time(self.time() + amount);
    }

    /// Returns the root key of the state machine.
    pub fn root_key(&self) -> ThresholdSigPublicKey {
        self.public_key
    }

    /// Returns the root key of the state machine.
    pub fn root_key_der(&self) -> Vec<u8> {
        self.public_key_der.clone()
    }

    /// Blocks until the hash of the latest state is computed.
    ///
    /// # Panics
    ///
    /// This function panics if the state hash computation takes more than a few
    /// seconds to complete.
    pub fn await_state_hash(&self) -> CryptoHashOfState {
        let h = self.state_manager.latest_state_height();
        let started_at = Instant::now();
        let mut tries = 0;
        while tries < 100 {
            match self.state_manager.get_state_hash_at(h) {
                Ok(hash) => return hash,
                Err(StateHashError::Transient(_)) => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e @ StateHashError::Permanent(_)) => {
                    panic!("Failed to compute state hash: {}", e)
                }
            }
        }
        panic!(
            "State hash computation took too long ({:?})",
            started_at.elapsed()
        )
    }

    /// Blocks until the result of the ingress message with the specified ID is
    /// available.
    ///
    /// # Panics
    ///
    /// This function panics if the result doesn't become available after the
    /// specified number of state machine ticks.
    pub fn await_ingress(
        &self,
        msg_id: MessageId,
        max_ticks: usize,
    ) -> Result<WasmResult, UserError> {
        let started_at = Instant::now();

        for _tick in 0..max_ticks {
            match self.ingress_status(&msg_id) {
                IngressStatus::Known {
                    state: IngressState::Completed(result),
                    ..
                } => return Ok(result),
                IngressStatus::Known {
                    state: IngressState::Failed(error),
                    ..
                } => return Err(error),
                _ => {
                    self.tick();
                }
            }
        }
        panic!(
            "Did not get answer to ingress {} after {} state machine ticks ({:?} elapsed)",
            msg_id,
            max_ticks,
            started_at.elapsed()
        )
    }

    /// Imports a directory containing a canister snapshot into the state machine.
    ///
    /// After you import the canister, you can execute methods on it and upgrade it.
    /// The original directory is not modified.
    ///
    /// The function is currently not used in code, but it is useful for local
    /// testing and debugging. Do not remove it.
    ///
    /// # Panics
    ///
    /// This function panics if loading the canister snapshot fails.
    pub fn import_canister_state<P: AsRef<Path>>(
        &self,
        canister_directory: P,
        canister_id: CanisterId,
    ) {
        let canister_directory = canister_directory.as_ref();
        assert!(
            canister_directory.is_dir(),
            "canister state at {} must be a directory",
            canister_directory.display()
        );

        let tip: CheckpointLayout<RwPolicy<()>> = CheckpointLayout::new_untracked(
            self.state_manager.state_layout().raw_path().join("tip"),
            ic_types::Height::new(0),
        )
        .expect("failed to obtain tip");
        let tip_canister_layout = tip
            .canister(&canister_id)
            .expect("failed to obtain writeable canister layout");

        fn copy_as_writeable(src: &Path, dst: &Path) {
            assert!(
                src.is_file(),
                "Canister layout contains only files, but {} is not a file.",
                src.display()
            );
            std::fs::copy(src, dst).expect("failed to copy file");
            let file = std::fs::File::open(dst).expect("failed to open file");
            let mut permissions = file
                .metadata()
                .expect("failed to get file permission")
                .permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            file.set_permissions(permissions)
                .expect("failed to set file persmission");
        }

        for entry in std::fs::read_dir(canister_directory).expect("failed to read_dir") {
            let entry = entry.expect("failed to get directory entry");
            copy_as_writeable(
                &entry.path(),
                &tip_canister_layout.raw_path().join(entry.file_name()),
            );
        }

        let canister_state = ic_state_manager::checkpoint::load_canister_state(
            &tip_canister_layout,
            &canister_id,
            ic_types::Height::new(0),
            self.state_manager.get_fd_factory(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "failed to load canister state from {}: {}",
                canister_directory.display(),
                e
            )
        })
        .0;

        let (h, mut state) = self.state_manager.take_tip();
        state.put_canister_state(canister_state);
        self.state_manager
            .commit_and_certify(state, h.increment(), CertificationScope::Full);
    }

    /// Replaces the canister state in this state machine with the canister
    /// state in given source replicated state.
    ///
    /// This is useful for emulating the state change due to a state sync.
    pub fn replace_canister_state(
        &self,
        source_state: Arc<ReplicatedState>,
        canister_id: CanisterId,
    ) {
        let (h, mut state) = self.state_manager.take_tip();
        state.put_canister_state(source_state.canister_state(&canister_id).unwrap().clone());
        self.state_manager
            .commit_and_certify(state, h.increment(), CertificationScope::Full);
        self.state_manager.remove_states_below(h.increment());
    }

    /// Removes states below the latest height.
    ///
    /// This is useful for testing behaviour after old states are dropped.
    pub fn remove_old_states(&self) {
        let h = self.state_manager.latest_state_height();
        self.state_manager.remove_states_below(h);
    }

    /// Removes a canister state from this state machine and migrates it to another state machine.
    /// This is done by writing a checkpoint and then removing the canister state from `self`;
    /// then importing the canister state into `other_env` from the checkpoint.
    pub fn move_canister_state_to(
        &self,
        other_env: &StateMachine,
        canister_id: CanisterId,
    ) -> Result<(), String> {
        // Enable checkpoints and make a tick to write a checkpoint.
        let cp_enabled = self.checkpoints_enabled.load(Ordering::Relaxed);
        self.set_checkpoints_enabled(true);
        self.tick();
        self.set_checkpoints_enabled(cp_enabled);

        let (height, mut state) = self.state_manager.take_tip();
        if state.take_canister_state(&canister_id).is_some() {
            self.state_manager.commit_and_certify(
                state,
                height.increment(),
                CertificationScope::Full,
            );

            other_env.import_canister_state(
                self.state_manager
                    .state_layout()
                    .checkpoint(height)
                    .unwrap()
                    .canister(&canister_id)
                    .unwrap()
                    .raw_path(),
                canister_id,
            );

            return Ok(());
        }
        Err(format!(
            "No canister state for canister id {}.",
            canister_id
        ))
    }

    pub fn install_wasm_in_mode(
        &self,
        canister_id: CanisterId,
        mode: CanisterInstallMode,
        wasm: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        let state = self.state_manager.get_latest_state().take();
        let sender = state
            .canister_state(&canister_id)
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous);
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::InstallCode,
            InstallCodeArgs::new(mode, canister_id, wasm, payload, None, None).encode(),
        )
        .map(|_| ())
    }

    /// Compiles specified WAT to Wasm and installs it for the canister using
    /// the specified ID in the provided install mode.
    fn install_wat_in_mode(
        &self,
        canister_id: CanisterId,
        mode: CanisterInstallMode,
        wat: &str,
        payload: Vec<u8>,
    ) {
        self.install_wasm_in_mode(
            canister_id,
            mode,
            wat::parse_str(wat).expect("invalid WAT"),
            payload,
        )
        .expect("failed to install canister");
    }

    /// Creates a new canister and returns the canister principal.
    pub fn create_canister(&self, settings: Option<CanisterSettingsArgs>) -> CanisterId {
        self.create_canister_with_cycles(None, Cycles::new(0), settings)
    }

    /// Creates a new canister with a cycles balance and returns the canister principal.
    pub fn create_canister_with_cycles(
        &self,
        specified_id: Option<PrincipalId>,
        cycles: Cycles,
        settings: Option<CanisterSettingsArgs>,
    ) -> CanisterId {
        let wasm_result = self
            .execute_ingress(
                ic00::IC_00,
                ic00::Method::ProvisionalCreateCanisterWithCycles,
                ic00::ProvisionalCreateCanisterWithCyclesArgs {
                    amount: Some(candid::Nat::from(cycles.get())),
                    settings,
                    specified_id,
                    sender_canister_version: None,
                }
                .encode(),
            )
            .expect("failed to create canister");
        match wasm_result {
            WasmResult::Reply(bytes) => CanisterIdRecord::decode(&bytes[..])
                .expect("failed to decode canister ID record")
                .get_canister_id(),
            WasmResult::Reject(reason) => panic!("create_canister call rejected: {}", reason),
        }
    }

    /// Creates a new canister and installs its code.
    /// Returns the ID of the newly created canister.
    ///
    /// This function is synchronous.
    pub fn install_canister(
        &self,
        module: Vec<u8>,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
    ) -> Result<CanisterId, UserError> {
        let canister_id = self.create_canister(settings);
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, module, payload)?;
        Ok(canister_id)
    }

    /// Installs the provided Wasm in an empty canister.
    ///
    /// This function is synchronous.
    pub fn install_existing_canister(
        &self,
        canister_id: CanisterId,
        module: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, module, payload)
    }

    /// Erases the previous state and code of the canister with the specified ID
    /// and replaces the code with the provided Wasm.
    ///
    /// This function is synchronous.
    pub fn reinstall_canister(
        &self,
        canister_id: CanisterId,
        module: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Reinstall, module, payload)
    }

    /// Creates a new canister with cycles and installs its code.
    /// Returns the ID of the newly created canister.
    ///
    /// This function is synchronous.
    pub fn install_canister_with_cycles(
        &self,
        module: Vec<u8>,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
        cycles: Cycles,
    ) -> Result<CanisterId, UserError> {
        let canister_id = self.create_canister_with_cycles(None, cycles, settings);
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, module, payload)?;
        Ok(canister_id)
    }

    /// Creates a new canister and installs its code specified by WAT string.
    /// Returns the ID of the newly created canister.
    ///
    /// This function is synchronous.
    ///
    /// # Panics
    ///
    /// Panicks if canister creation or the code install failed.
    pub fn install_canister_wat(
        &self,
        wat: &str,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
    ) -> CanisterId {
        let canister_id = self.create_canister(settings);
        self.install_wat_in_mode(canister_id, CanisterInstallMode::Install, wat, payload);
        canister_id
    }

    /// Erases the previous state and code of the canister with the specified ID
    /// and replaces the code with the compiled form of the provided WAT.
    pub fn reinstall_canister_wat(&self, canister_id: CanisterId, wat: &str, payload: Vec<u8>) {
        self.install_wat_in_mode(canister_id, CanisterInstallMode::Reinstall, wat, payload);
    }

    /// Performs upgrade of the canister with the specified ID to the
    /// code obtained by compiling the provided WAT.
    pub fn upgrade_canister_wat(&self, canister_id: CanisterId, wat: &str, payload: Vec<u8>) {
        self.install_wat_in_mode(canister_id, CanisterInstallMode::Upgrade, wat, payload);
    }

    /// Performs upgrade of the canister with the specified ID to the specified
    /// Wasm code.
    pub fn upgrade_canister(
        &self,
        canister_id: CanisterId,
        wasm: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Upgrade, wasm, payload)
    }

    /// Updates the settings of the given canister.
    ///
    /// This function is synchronous.
    pub fn update_settings(
        &self,
        canister_id: &CanisterId,
        settings: CanisterSettingsArgs,
    ) -> Result<(), UserError> {
        let state = self.state_manager.get_latest_state().take();
        let sender = state
            .canister_state(canister_id)
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous);
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::UpdateSettings,
            UpdateSettingsArgs {
                canister_id: canister_id.get(),
                settings,
                sender_canister_version: None,
            }
            .encode(),
        )
        .map(|_| ())
    }

    /// Returns true if the canister with the specified id exists.
    pub fn canister_exists(&self, canister: CanisterId) -> bool {
        self.state_manager
            .get_latest_state()
            .take()
            .canister_states
            .contains_key(&canister)
    }

    /// Queries the canister with the specified ID using the anonymous principal.
    pub fn query(
        &self,
        receiver: CanisterId,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.query_as(
            PrincipalId::new_anonymous(),
            receiver,
            method,
            method_payload,
        )
    }

    /// Queries the canister with the specified ID.
    pub fn query_as(
        &self,
        sender: PrincipalId,
        receiver: CanisterId,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.query_as_with_delegation(sender, receiver, method, method_payload, None)
    }

    /// Queries the canister with the specified ID and with an optional subnet delegation from the NNS.
    pub fn query_as_with_delegation(
        &self,
        sender: PrincipalId,
        receiver: CanisterId,
        method: impl ToString,
        method_payload: Vec<u8>,
        delegation: Option<CertificateDelegation>,
    ) -> Result<WasmResult, UserError> {
        self.certify_latest_state();
        let user_query = UserQuery {
            receiver,
            source: UserId::from(sender),
            method_name: method.to_string(),
            method_payload,
            ingress_expiry: 0,
            nonce: None,
        };
        if let Ok((result, _)) = self
            .runtime
            .block_on(self.query_handler.clone().oneshot((user_query, delegation)))
            .unwrap()
        {
            result
        } else {
            unreachable!()
        }
    }

    /// Returns the module hash of the specified canister.
    pub fn module_hash(&self, canister_id: CanisterId) -> Option<[u8; 32]> {
        let state = self.state_manager.get_latest_state().take();
        let canister_state = state.canister_state(&canister_id)?;
        Some(
            canister_state
                .execution_state
                .as_ref()?
                .wasm_binary
                .binary
                .module_hash(),
        )
    }

    /// Executes an ingress message on the canister with the specified ID.
    ///
    /// This function is synchronous, it blocks until the result of the ingress
    /// message is known. The function returns this result.
    ///
    /// # Panics
    ///
    /// This function panics if the status was not ready in a reasonable amount
    /// of time (typically, a few seconds).
    pub fn execute_ingress_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        const MAX_TICKS: usize = 100;
        let msg_id = self.send_ingress(sender, canister_id, method, payload);
        self.await_ingress(msg_id, MAX_TICKS)
    }

    pub fn execute_ingress(
        &self,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.execute_ingress_as(PrincipalId::new_anonymous(), canister_id, method, payload)
    }

    /// Sends an ingress message to the canister with the specified ID.
    ///
    /// This function is asynchronous. It returns the ID of the ingress message
    /// that can be awaited later with [await_ingress].
    pub fn send_ingress(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> MessageId {
        // increment the global nonce and use it as the current nonce.
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed) + 1;
        let builder = PayloadBuilder::new()
            .with_max_expiry_time_from_now(self.time())
            .with_nonce(nonce)
            .ingress(sender, canister_id, method, payload);

        let msg_id = builder.ingress_ids().pop().unwrap();
        self.execute_payload(builder);
        msg_id
    }

    /// Returns the status of the ingress message with the specified ID.
    pub fn ingress_status(&self, msg_id: &MessageId) -> IngressStatus {
        (self.ingress_history_reader.get_latest_status())(msg_id)
    }

    /// Starts the canister with the specified ID.
    pub fn start_canister(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.start_canister_as(PrincipalId::new_anonymous(), canister_id)
    }

    /// Starts the canister with the specified ID.
    /// Use this if the `canister_id`` is controlled by `sender``.
    pub fn start_canister_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
    ) -> Result<WasmResult, UserError> {
        self.execute_ingress_as(
            sender,
            CanisterId::ic_00(),
            "start_canister",
            (CanisterIdRecord::from(canister_id)).encode(),
        )
    }

    /// Stops the canister with the specified ID.
    pub fn stop_canister(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.stop_canister_as(PrincipalId::new_anonymous(), canister_id)
    }

    /// Stops the canister with the specified ID.
    /// Use this if the `canister_id`` is controlled by `sender``.
    pub fn stop_canister_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
    ) -> Result<WasmResult, UserError> {
        self.execute_ingress_as(
            sender,
            CanisterId::ic_00(),
            "stop_canister",
            (CanisterIdRecord::from(canister_id)).encode(),
        )
    }

    /// Stops the canister with the specified ID in a non-blocking way.
    ///
    /// This function is asynchronous. It returns the ID of the ingress message
    /// that can be awaited later with [await_ingress].
    /// This allows to do some clean-up between the time the canister is in the stopping state
    /// and the time it is actually stopped.
    pub fn stop_canister_non_blocking(&self, canister_id: CanisterId) -> MessageId {
        self.send_ingress(
            PrincipalId::new_anonymous(),
            CanisterId::ic_00(),
            "stop_canister",
            (CanisterIdRecord::from(canister_id)).encode(),
        )
    }

    /// Calls the `canister_status` endpoint on the management canister.
    pub fn canister_status(
        &self,
        canister_id: CanisterId,
    ) -> Result<Result<CanisterStatusResultV2, String>, UserError> {
        self.canister_status_as(PrincipalId::new_anonymous(), canister_id)
    }

    /// Calls the `canister_status` endpoint on the management canister of the specified sender.
    /// Use this if the `canister_id`` is controlled by `sender``.
    pub fn canister_status_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
    ) -> Result<Result<CanisterStatusResultV2, String>, UserError> {
        self.execute_ingress_as(
            sender,
            CanisterId::ic_00(),
            "canister_status",
            (CanisterIdRecord::from(canister_id)).encode(),
        )
        .map(|wasm_result| match wasm_result {
            WasmResult::Reply(reply) => Ok(Decode!(&reply, CanisterStatusResultV2).unwrap()),
            WasmResult::Reject(reject_msg) => Err(reject_msg),
        })
    }

    /// Deletes the canister with the specified ID.
    pub fn delete_canister(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.execute_ingress(
            CanisterId::ic_00(),
            "delete_canister",
            (CanisterIdRecord::from(canister_id)).encode(),
        )
    }

    /// Uninstalls the canister with the specified ID.
    pub fn uninstall_code(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.execute_ingress(
            CanisterId::ic_00(),
            "uninstall_code",
            (CanisterIdRecord::from(canister_id)).encode(),
        )
    }

    /// Updates the routing table so that a range of canisters is assigned to
    /// the specified destination subnet.
    pub fn reroute_canister_range(
        &self,
        canister_range: std::ops::RangeInclusive<CanisterId>,
        destination: SubnetId,
    ) {
        use ic_registry_client_helpers::routing_table::RoutingTableRegistry;

        let last_version = self.registry_client.get_latest_version();
        let next_version = last_version.increment();

        let mut routing_table = self
            .registry_client
            .get_routing_table(last_version)
            .expect("malformed routing table")
            .expect("missing routing table");

        routing_table
            .assign_ranges(
                CanisterIdRanges::try_from(vec![CanisterIdRange {
                    start: *canister_range.start(),
                    end: *canister_range.end(),
                }])
                .unwrap(),
                destination,
            )
            .expect("ranges are not well formed");

        self.registry_data_provider
            .add(
                &make_routing_table_record_key(),
                next_version,
                Some(PbRoutingTable::from(routing_table)),
            )
            .unwrap();
        self.registry_client.update_to_latest_version();

        assert_eq!(next_version, self.registry_client.get_latest_version());
    }

    /// Returns the subnet id of this state machine.
    pub fn get_subnet_id(&self) -> SubnetId {
        self.subnet_id
    }

    /// Marks canisters in the specified range as being migrated to another subnet.
    pub fn prepare_canister_migrations(
        &self,
        canister_range: std::ops::RangeInclusive<CanisterId>,
        source: SubnetId,
        destination: SubnetId,
    ) {
        use ic_registry_client_helpers::routing_table::RoutingTableRegistry;

        let last_version = self.registry_client.get_latest_version();
        let next_version = last_version.increment();

        let mut canister_migrations = self
            .registry_client
            .get_canister_migrations(last_version)
            .expect("malformed canister migrations")
            .unwrap_or_default();

        canister_migrations
            .insert_ranges(
                CanisterIdRanges::try_from(vec![CanisterIdRange {
                    start: *canister_range.start(),
                    end: *canister_range.end(),
                }])
                .unwrap(),
                source,
                destination,
            )
            .expect("ranges are not well formed");

        self.registry_data_provider
            .add(
                &make_canister_migrations_record_key(),
                next_version,
                Some(PbCanisterMigrations::from(canister_migrations)),
            )
            .unwrap();
        self.registry_client.update_to_latest_version();

        assert_eq!(next_version, self.registry_client.get_latest_version());
    }

    /// Marks canisters in the specified range as successfully migrated to another subnet.
    pub fn complete_canister_migrations(
        &self,
        canister_range: std::ops::RangeInclusive<CanisterId>,
        migration_trace: Vec<SubnetId>,
    ) {
        use ic_registry_client_helpers::routing_table::RoutingTableRegistry;

        let last_version = self.registry_client.get_latest_version();
        let next_version = last_version.increment();

        let mut canister_migrations = self
            .registry_client
            .get_canister_migrations(last_version)
            .expect("malformed canister migrations")
            .unwrap_or_default();

        canister_migrations
            .remove_ranges(
                CanisterIdRanges::try_from(vec![CanisterIdRange {
                    start: *canister_range.start(),
                    end: *canister_range.end(),
                }])
                .unwrap(),
                migration_trace,
            )
            .expect("ranges are not well formed");

        self.registry_data_provider
            .add(
                &make_canister_migrations_record_key(),
                next_version,
                Some(PbCanisterMigrations::from(canister_migrations)),
            )
            .unwrap();
        self.registry_client.update_to_latest_version();

        assert_eq!(next_version, self.registry_client.get_latest_version());
    }

    /// Return the subnet_ids from the internal RegistryClient
    pub fn get_subnet_ids(&self) -> Vec<SubnetId> {
        self.registry_client
            .get_subnet_ids(self.registry_client.get_latest_version())
            .unwrap()
            .unwrap()
    }

    /// Returns a stable memory snapshot of the specified canister.
    ///
    /// # Panics
    ///
    /// This function panics if:
    ///   * The specified canister does not exist.
    ///   * The specified canister does not have a module installed.
    pub fn stable_memory(&self, canister_id: CanisterId) -> Vec<u8> {
        let replicated_state = self.state_manager.get_latest_state().take();
        let memory = &replicated_state
            .canister_state(&canister_id)
            .unwrap_or_else(|| panic!("Canister {} does not exist", canister_id))
            .execution_state
            .as_ref()
            .unwrap_or_else(|| panic!("Canister {} has no module", canister_id))
            .stable_memory;

        let mut dst = vec![0u8; memory.size.get() * WASM_PAGE_SIZE_IN_BYTES];
        let buffer = Buffer::new(memory.page_map.clone());
        buffer.read(&mut dst, 0);
        dst
    }

    /// Returns the canister log of the specified canister.
    pub fn canister_log(&self, canister_id: CanisterId) -> CanisterLog {
        let replicated_state = self.state_manager.get_latest_state().take();
        let canister_state = replicated_state
            .canister_state(&canister_id)
            .unwrap_or_else(|| panic!("Canister {} does not exist", canister_id));
        canister_state.system_state.canister_log.clone()
    }

    /// Sets the content of the stable memory for the specified canister.
    ///
    /// If the `data` is not aligned to the Wasm page boundary, this function will extend the stable
    /// memory to have the minimum number of Wasm pages that fit all of the `data`.
    ///
    /// # Notes
    ///
    ///   * Avoid changing the stable memory of arbitrary canisters, they might be not prepared for
    ///     that. Consider upgrading the canister to an empty Wasm module, setting the stable
    ///     memory, and upgrading back to the original module instead.
    ///   * `set_stable_memory(ID, stable_memory(ID))` does not change the canister state.
    ///
    /// # Panics
    ///
    /// This function panics if:
    ///   * The specified canister does not exist.
    ///   * The specified canister does not have a module installed.
    pub fn set_stable_memory(&self, canister_id: CanisterId, data: &[u8]) {
        let (height, mut replicated_state) = self.state_manager.take_tip();
        let canister_state = replicated_state
            .canister_state_mut(&canister_id)
            .unwrap_or_else(|| panic!("Canister {} does not exist", canister_id));
        let size = (data.len() + WASM_PAGE_SIZE_IN_BYTES - 1) / WASM_PAGE_SIZE_IN_BYTES;
        let memory = Memory::new(PageMap::from(data), NumWasmPages::new(size));
        canister_state
            .execution_state
            .as_mut()
            .unwrap_or_else(|| panic!("Canister {} has no module", canister_id))
            .stable_memory = memory;
        self.state_manager.commit_and_certify(
            replicated_state,
            height.increment(),
            CertificationScope::Full,
        );
    }

    /// Returns the query stats of the specified canister.
    ///
    /// # Panics
    ///
    /// This function panics if the specified canister does not exist.
    pub fn query_stats(&self, canister_id: &CanisterId) -> TotalQueryStats {
        let state = self.state_manager.get_latest_state().take();
        state
            .canister_state(canister_id)
            .unwrap_or_else(|| panic!("Canister {} not found", canister_id))
            .scheduler_state
            .total_query_stats
            .clone()
    }

    /// Set query stats for the given canister to the specified value.
    pub fn set_query_stats(
        &mut self,
        canister_id: &CanisterId,
        total_query_stats: TotalQueryStats,
    ) {
        let (h, mut state) = self.state_manager.take_tip();
        state
            .canister_state_mut(canister_id)
            .unwrap_or_else(|| panic!("Canister {} not found", canister_id))
            .scheduler_state
            .total_query_stats = total_query_stats;

        self.state_manager
            .commit_and_certify(state, h.increment(), CertificationScope::Full);
    }

    /// Returns the cycle balance of the specified canister.
    ///
    /// # Panics
    ///
    /// This function panics if the specified canister does not exist.
    pub fn cycle_balance(&self, canister_id: CanisterId) -> u128 {
        let state = self.state_manager.get_latest_state().take();
        state
            .canister_state(&canister_id)
            .unwrap_or_else(|| panic!("Canister {} not found", canister_id))
            .system_state
            .balance()
            .get()
    }

    /// Tops up the specified canister with cycle amount and returns the resulting cycle balance.
    ///
    /// # Panics
    ///
    /// This function panics if the specified canister does not exist.
    pub fn add_cycles(&self, canister_id: CanisterId, amount: u128) -> u128 {
        let (height, mut state) = self.state_manager.take_tip();
        let canister_state = state
            .canister_state_mut(&canister_id)
            .unwrap_or_else(|| panic!("Canister {} not found", canister_id));
        canister_state
            .system_state
            .add_cycles(Cycles::from(amount), CyclesUseCase::NonConsumed);
        let balance = canister_state.system_state.balance().get();
        self.state_manager
            .commit_and_certify(state, height.increment(), CertificationScope::Full);
        balance
    }

    /// Returns sign with ECDSA contexts from internal subnet call context manager.
    pub fn sign_with_ecdsa_contexts(&self) -> BTreeMap<CallbackId, SignWithEcdsaContext> {
        let state = self.state_manager.get_latest_state().take();
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts
            .clone()
    }

    /// Returns canister HTTP request contexts from internal subnet call context manager.
    pub fn canister_http_request_contexts(
        &self,
    ) -> BTreeMap<CallbackId, CanisterHttpRequestContext> {
        let state = self.state_manager.get_latest_state().take();
        state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .clone()
    }

    /// Returns the size estimate of canisters heap delta in bytes.
    pub fn heap_delta_estimate_bytes(&self) -> u64 {
        let state = self.state_manager.get_latest_state().take();
        state.metadata.heap_delta_estimate.get()
    }

    pub fn deliver_query_stats(&self, query_stats: QueryStatsPayload) -> Height {
        self.execute_payload(PayloadBuilder::new().with_query_stats(Some(query_stats)))
    }

    /// Make sure the latest state is certified.
    pub fn certify_latest_state(&self) {
        certify_latest_state_helper(self.state_manager.clone(), &self.secret_key, self.subnet_id)
    }
}

/// Make sure the latest state is certified.
pub fn certify_latest_state_helper(
    state_manager: Arc<StateManagerImpl>,
    secret_key: &SecretKeyBytes,
    subnet_id: SubnetId,
) {
    if state_manager.latest_state_height() > state_manager.latest_certified_height() {
        let state_hashes = state_manager.list_state_hashes_to_certify();
        let (height, hash) = state_hashes.last().unwrap();
        state_manager
            .deliver_state_certification(certify_hash(secret_key, subnet_id, height, hash));
    }
}

fn certify_hash(
    secret_key: &SecretKeyBytes,
    subnet_id: SubnetId,
    height: &Height,
    hash: &CryptoHashOfPartialState,
) -> Certification {
    let signature = sign_message(
        CertificationContent::new(hash.clone())
            .as_signed_bytes()
            .as_slice(),
        secret_key,
    );
    let combined_sig =
        CombinedThresholdSigOf::from(CombinedThresholdSig(signature.as_ref().to_vec()));
    Certification {
        height: *height,
        signed: Signed {
            content: CertificationContent { hash: hash.clone() },
            signature: ThresholdSignature {
                signature: combined_sig,
                signer: NiDkgId {
                    dealer_subnet: subnet_id,
                    target_subnet: NiDkgTargetSubnet::Local,
                    start_block_height: *height,
                    dkg_tag: NiDkgTag::LowThreshold,
                },
            },
        },
    }
}

fn sign_prehashed_message_with_derived_key(
    ecdsa_secret_key: &PrivateKey,
    message_hash: &[u8],
    derivation_path: DerivationPath,
) -> Vec<u8> {
    const CHAIN_CODE: &[u8] = &[0; 32];

    let public_key = ecdsa_secret_key.public_key();
    let derived_public_key_bytes = derivation_path
        .public_key_derivation(&public_key.serialize_sec1(true), CHAIN_CODE)
        .expect("couldn't derive ecdsa public key");

    let derived_private_key_bytes = derivation_path
        .private_key_derivation(&ecdsa_secret_key.serialize_sec1(), CHAIN_CODE)
        .expect("couldn't derive ecdsa private key");
    let derived_private_key =
        PrivateKey::deserialize_sec1(&derived_private_key_bytes.derived_private_key)
            .expect("couldn't deserialize to sec1 ecdsa private key");
    let derived_public_key =
        PublicKey::deserialize_sec1(&derived_public_key_bytes.derived_public_key)
            .expect("couldn't deserialize sec1");

    assert_eq!(
        derived_private_key.public_key().serialize_sec1(true),
        derived_public_key_bytes.derived_public_key
    );
    let signature = derived_private_key
        .sign_digest(message_hash)
        .expect("failed to sign");

    assert!(derived_public_key.verify_signature_prehashed(message_hash, &signature));
    signature.to_vec()
}

#[derive(Clone)]
pub struct PayloadBuilder {
    expiry_time: Time,
    nonce: Option<u64>,
    ingress_messages: Vec<SignedIngress>,
    xnet_payload: XNetPayload,
    consensus_responses: Vec<ConsensusResponse>,
    query_stats: Option<QueryStatsPayload>,
}

impl Default for PayloadBuilder {
    fn default() -> Self {
        Self {
            expiry_time: GENESIS,
            nonce: Default::default(),
            ingress_messages: Default::default(),
            xnet_payload: Default::default(),
            consensus_responses: Default::default(),
            query_stats: Default::default(),
        }
        .with_max_expiry_time_from_now(GENESIS.into())
    }
}

impl PayloadBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_expiry_time_from_now(self, now: SystemTime) -> Self {
        self.with_expiry_time(now + MAX_INGRESS_TTL - PERMITTED_DRIFT)
    }

    pub fn with_expiry_time(self, expiry_time: SystemTime) -> Self {
        Self {
            expiry_time: expiry_time.try_into().unwrap(),
            ..self
        }
    }

    pub fn with_nonce(self, nonce: u64) -> Self {
        Self {
            nonce: Some(nonce),
            ..self
        }
    }

    pub fn with_ingress_messages(self, ingress_messages: Vec<SignedIngress>) -> Self {
        Self {
            ingress_messages,
            ..self
        }
    }
    pub fn with_xnet_payload(self, xnet_payload: XNetPayload) -> Self {
        Self {
            xnet_payload,
            ..self
        }
    }

    pub fn with_query_stats(self, query_stats: Option<QueryStatsPayload>) -> Self {
        Self {
            query_stats,
            ..self
        }
    }

    pub fn ingress(
        mut self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Self {
        let msg = SignedIngress::try_from(HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(canister_id.get().into_vec()),
                    method_name: method.to_string(),
                    arg: Blob(payload),
                    sender: Blob(sender.into_vec()),
                    ingress_expiry: self.expiry_time.as_nanos_since_unix_epoch(),
                    nonce: self.nonce.map(|n| Blob(n.to_be_bytes().to_vec())),
                },
            },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        })
        .unwrap();

        self.ingress_messages.push(msg);
        self.expiry_time += Duration::from_nanos(1);
        self.nonce = self.nonce.map(|n| n + 1);
        self
    }

    pub fn xnet_payload(mut self, xnet_payload: XNetPayload) -> Self {
        self.xnet_payload = xnet_payload;
        self
    }

    pub fn http_response(
        mut self,
        callback: CallbackId,
        payload: &CanisterHttpResponsePayload,
    ) -> Self {
        self.consensus_responses.push(ConsensusResponse::new(
            callback,
            MsgPayload::Data(payload.encode()),
        ));
        self
    }

    pub fn http_response_failure(
        mut self,
        callback: CallbackId,
        code: RejectCode,
        message: impl ToString,
    ) -> Self {
        self.consensus_responses.push(ConsensusResponse::new(
            callback,
            MsgPayload::Reject(RejectContext::new(code, message)),
        ));
        self
    }

    pub fn ingress_ids(&self) -> Vec<MessageId> {
        self.ingress_messages.iter().map(|i| i.id()).collect()
    }
}

// This test should panic on a critical error due to non-monotone timestamps.
#[should_panic]
#[test]
fn critical_error_test() {
    let sm = StateMachineBuilder::new().build();
    sm.set_time(SystemTime::UNIX_EPOCH);
    sm.tick();
    sm.set_time(SystemTime::UNIX_EPOCH);
    sm.tick();
}
