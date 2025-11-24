use candid::Decode;
use core::sync::atomic::Ordering;
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
use ic_btc_adapter_client::setup_bitcoin_adapter_clients;
use ic_btc_consensus::BitcoinPayloadBuilder;
use ic_config::{
    adapters::AdaptersConfig,
    bitcoin_payload_builder_config::Config as BitcoinPayloadBuilderConfig,
    execution_environment::Config as HypervisorConfig,
    flag_status::FlagStatus,
    message_routing::{MAX_STREAM_MESSAGES, TARGET_STREAM_SIZE_BYTES},
    state_manager::LsmtConfig,
    subnet_config::SubnetConfig,
};
use ic_consensus::consensus::payload_builder::PayloadBuilderImpl;
use ic_consensus_cup_utils::make_registry_cup_from_cup_contents;
use ic_consensus_utils::crypto::SignVerify;
use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
use ic_crypto_test_utils_ni_dkg::{
    SecretKeyBytes, dummy_initial_dkg_transcript_with_master_key, sign_message,
};
use ic_crypto_tree_hash::{Label, Path as LabeledTreePath, sparse_labeled_tree_from_paths};
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_cycles_account_manager::{CyclesAccountManager, IngressInductionCost};
pub use ic_error_types::{ErrorCode, UserError};
use ic_execution_environment::{ExecutionServices, IngressHistoryReaderImpl};
use ic_http_endpoints_public::{IngressWatcher, IngressWatcherHandle, metrics::HttpHandlerMetrics};
use ic_https_outcalls_consensus::payload_builder::CanisterHttpPayloadBuilderImpl;
use ic_ingress_manager::{IngressManager, RandomStateKind};
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, IntoMessages, PastPayload, ProposalContext},
    canister_http::{CanisterHttpChangeAction, CanisterHttpPool},
    certification::{Verifier, VerifierError},
    consensus::{PayloadBuilder as ConsensusPayloadBuilder, PayloadValidationError},
    consensus_pool::ConsensusTime,
    execution_environment::{
        IngressFilterService, IngressHistoryReader, QueryExecutionInput, QueryExecutionService,
        TransformExecutionService,
    },
    ingress_pool::{
        IngressPool, IngressPoolObject, PoolSection, UnvalidatedIngressArtifact,
        ValidatedIngressArtifact,
    },
    p2p::consensus::MutablePool,
    validation::ValidationResult,
};
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, EncodeStreamError};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{CertificationScope, StateHashError, StateManager, StateReader};
use ic_limits::{MAX_INGRESS_TTL, PERMITTED_DRIFT, SMALL_APP_SUBNET_MAX_SIZE};
use ic_logger::replica_logger::no_op_logger;
use ic_logger::{ReplicaLogger, error};
use ic_management_canister_types_private::{
    self as ic00, CanisterIdRecord, CanisterSnapshotDataKind, CanisterSnapshotDataOffset,
    InstallCodeArgs, MasterPublicKeyId, Method, Payload, ReadCanisterSnapshotDataArgs,
    ReadCanisterSnapshotDataResponse, ReadCanisterSnapshotMetadataArgs,
    ReadCanisterSnapshotMetadataResponse, UploadCanisterSnapshotDataArgs,
    UploadCanisterSnapshotMetadataArgs, UploadCanisterSnapshotMetadataResponse,
};
use ic_management_canister_types_private::{
    CanisterHttpResponsePayload, CanisterInstallMode, CanisterSettingsArgs,
    CanisterSnapshotResponse, CanisterStatusResultV2, ClearChunkStoreArgs, EcdsaCurve, EcdsaKeyId,
    InstallChunkedCodeArgs, LoadCanisterSnapshotArgs, SchnorrAlgorithm, SignWithECDSAReply,
    SignWithSchnorrReply, TakeCanisterSnapshotArgs, UpdateSettingsArgs, UploadChunkArgs,
    UploadChunkReply, VetKdDeriveKeyResult,
};
use ic_messaging::SyncMessageRouting;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_protobuf::{
    registry::{
        crypto::v1::{ChainKeyEnabledSubnetList, PublicKey as PublicKeyProto, X509PublicKeyCert},
        node::v1::{ConnectionEndpoint, NodeRecord},
        provisional_whitelist::v1::ProvisionalWhitelist as PbProvisionalWhitelist,
        replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
        routing_table::v1::{
            CanisterMigrations as PbCanisterMigrations, RoutingTable as PbRoutingTable,
        },
        subnet::v1::CatchUpPackageContents,
    },
    types::{
        v1 as pb,
        v1::{PrincipalId as PrincipalIdIdProto, SubnetId as SubnetIdProto},
    },
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::{
    provisional_whitelist::ProvisionalWhitelistRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_registry_keys::{
    NODE_REWARDS_TABLE_KEY, ROOT_SUBNET_ID_KEY, make_blessed_replica_versions_key,
    make_canister_migrations_record_key, make_canister_ranges_key,
    make_catch_up_package_contents_key, make_chain_key_enabled_subnet_list_key,
    make_crypto_node_key, make_crypto_tls_cert_key, make_node_record_key,
    make_provisional_whitelist_record_key, make_replica_version_key,
};
use ic_registry_proto_data_provider::{INITIAL_REGISTRY_VERSION, ProtoRegistryDataProvider};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{
    CanisterIdRange, CanisterIdRanges, RoutingTable, routing_table_insert_subnet,
};
use ic_registry_subnet_features::{
    ChainKeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE, KeyConfig, SubnetFeatures,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CheckpointLoadingMetrics, Memory, PageMap, ReplicatedState,
    canister_state::{
        NumWasmPages, WASM_PAGE_SIZE_IN_BYTES,
        system_state::{CanisterHistory, CyclesUseCase},
    },
    metadata_state::subnet_call_context_manager::{SignWithThresholdContext, ThresholdArguments},
    page_map::Buffer,
};
use ic_state_layout::{CheckpointLayout, ReadOnly};
use ic_state_manager::StateManagerImpl;
use ic_test_utilities_consensus::{FakeConsensusPoolCache, batch::MockBatchPayloadBuilder};
use ic_test_utilities_metrics::{
    Labels, fetch_counter_vec, fetch_histogram_stats, fetch_int_counter, fetch_int_gauge,
    fetch_int_gauge_vec,
};
use ic_test_utilities_registry::{
    SubnetRecordBuilder, add_single_subnet_record, add_subnet_key_record, add_subnet_list_record,
};
use ic_test_utilities_time::FastForwardTimeSource;
pub use ic_types::ingress::WasmResult;
use ic_types::{
    CanisterId, CryptoHashOfState, Cycles, NumBytes, PrincipalId, SubnetId, UserId,
    batch::BatchContent,
    canister_http::{
        CanisterHttpRequestContext, CanisterHttpRequestId, CanisterHttpResponseMetadata,
    },
    crypto::threshold_sig::ThresholdSigPublicKey,
    ingress::{IngressState, IngressStatus},
    messages::{CallbackId, MessageId},
    time::Time,
};
use ic_types::{
    CanisterLog, CountBytes, CryptoHashOfPartialState, Height, NodeId, Randomness, RegistryVersion,
    ReplicaVersion, SnapshotId,
    artifact::IngressMessageId,
    batch::{
        Batch, BatchMessages, BatchSummary, BlockmakerMetrics, CanisterCyclesCostSchedule,
        ChainKeyData, ConsensusResponse, QueryStatsPayload, SelfValidatingPayload, TotalQueryStats,
        ValidationContext, XNetPayload,
    },
    canister_http::{CanisterHttpResponse, CanisterHttpResponseContent},
    consensus::{
        block_maker::SubnetRecords,
        certification::{Certification, CertificationContent},
    },
    crypto::{
        AlgorithmId, CombinedThresholdSig, CombinedThresholdSigOf, KeyPurpose, Signable, Signed,
        canister_threshold_sig::MasterPublicKey,
        threshold_sig::ni_dkg::{
            NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript,
        },
    },
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, CertificateDelegationMetadata,
        EXPECTED_MESSAGE_ID_LENGTH, HttpCallContent, HttpCanisterUpdate, HttpRequestContent,
        HttpRequestEnvelope, Payload as MsgPayload, Query, QuerySource, RejectContext,
        SignedIngress, extract_effective_canister_id,
    },
    signature::ThresholdSignature,
    time::GENESIS,
    xnet::{CertifiedStreamSlice, StreamIndex},
};
use ic_xnet_payload_builder::{
    RefillTaskHandle, XNetPayloadBuilderImpl, XNetPayloadBuilderMetrics, XNetSlicePoolImpl,
    certified_slice_pool::CertifiedSlicePool, refill_stream_slice_indices,
};
use rcgen::{CertificateParams, KeyPair};
use serde::Deserialize;

use ic_error_types::RejectCode;
use maplit::btreemap;
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde::Serialize;
use slog::Level;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::TryFrom,
    fmt,
    io::{self, stderr},
    net::Ipv6Addr,
    path::{Path, PathBuf},
    str::FromStr,
    string::ToString,
    sync::{Arc, Mutex, RwLock, atomic::AtomicU64},
    time::{Duration, Instant, SystemTime},
};
use tempfile::TempDir;
use tokio::{
    runtime::Runtime,
    sync::{mpsc, watch},
};
use tower::ServiceExt;

/// The size of the channel used to communicate between the [`IngressWatcher`] and
/// execution. Mirrors the size used in production defined in `setup_ic_stack.rs`
const COMPLETED_EXECUTION_MESSAGES_BUFFER_SIZE: usize = 10_000;

const SNAPSHOT_DATA_CHUNK_SIZE: u64 = 2_000_000;

#[cfg(test)]
mod tests;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub enum SubmitIngressError {
    HttpError(String),
    UserError(UserError),
}

pub struct FakeVerifier;

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

/// Adds global registry records to the registry managed by the registry data provider:
/// - root subnet record;
/// - routing table record;
/// - subnet list record;
/// - chain key records;
/// - (empty) node rewards table.
pub fn add_global_registry_records(
    nns_subnet_id: SubnetId,
    routing_table: RoutingTable,
    subnet_list: Vec<SubnetId>,
    chain_keys: BTreeMap<MasterPublicKeyId, Vec<SubnetId>>,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
) {
    let registry_version = if registry_data_provider.is_empty() {
        INITIAL_REGISTRY_VERSION
    } else {
        registry_data_provider.latest_version()
    };

    // root subnet record
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

    // routing table record
    let pb_routing_table = PbRoutingTable::from(routing_table.clone());
    registry_data_provider
        .add(
            &make_canister_ranges_key(CanisterId::from_u64(0)),
            registry_version,
            Some(pb_routing_table.clone()),
        )
        .unwrap();

    // subnet list record
    add_subnet_list_record(&registry_data_provider, registry_version.get(), subnet_list);

    // chain key records
    for (key_id, subnets) in chain_keys {
        let subnets = subnets
            .into_iter()
            .map(|subnet_id| SubnetIdProto {
                principal_id: Some(PrincipalIdIdProto {
                    raw: subnet_id.get_ref().to_vec(),
                }),
            })
            .collect();
        registry_data_provider
            .add(
                &make_chain_key_enabled_subnet_list_key(&key_id),
                registry_version,
                Some(ChainKeyEnabledSubnetList { subnets }),
            )
            .unwrap();
    }

    // node rewards table
    registry_data_provider
        .add(
            NODE_REWARDS_TABLE_KEY,
            registry_version,
            Some(NodeRewardsTable {
                table: BTreeMap::new(),
            }),
        )
        .unwrap();
}

/// Adds initial registry records to the registry managed by the registry data provider:
/// - provisional whitelist record;
/// - blessed replica versions record;
/// - replica version record.
pub fn add_initial_registry_records(registry_data_provider: Arc<ProtoRegistryDataProvider>) {
    let registry_version = INITIAL_REGISTRY_VERSION;

    // provisional whitelist record
    let pb_whitelist = PbProvisionalWhitelist::from(ProvisionalWhitelist::All);
    registry_data_provider
        .add(
            &make_provisional_whitelist_record_key(),
            registry_version,
            Some(pb_whitelist),
        )
        .unwrap();

    // blessed replica versions record
    let replica_version = ReplicaVersion::default();
    let blessed_replica_version = BlessedReplicaVersions {
        blessed_version_ids: vec![replica_version.clone().into()],
    };
    registry_data_provider
        .add(
            &make_blessed_replica_versions_key(),
            registry_version,
            Some(blessed_replica_version),
        )
        .unwrap();

    // replica version record
    let replica_version_record = ReplicaVersionRecord {
        release_package_sha256_hex: "".to_string(),
        release_package_urls: vec![],
        guest_launch_measurements: None,
    };
    registry_data_provider
        .add(
            &make_replica_version_key(replica_version),
            registry_version,
            Some(replica_version_record),
        )
        .unwrap();
}

/// Adds subnet local registry records to the registry managed by the registry data provider:
/// - node records;
/// - node signing key records;
/// - node TLS key records;
/// - subnet CUP record;
/// - subnet record;
/// - subnet threshold key record.
///
/// Note: initial and global registry records must be added to the registry
/// (using the fuctions `add_initial_registry_records` and `add_global_registry_records`)
/// before any messages are executed on the `StateMachine`.
fn add_subnet_local_registry_records(
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    features: SubnetFeatures,
    nodes: &Vec<StateMachineNode>,
    public_key: ThresholdSigPublicKey,
    chain_keys_enabled_status: &BTreeMap<MasterPublicKeyId, bool>,
    ni_dkg_transcript: NiDkgTranscript,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    registry_version: RegistryVersion,
) {
    for node in nodes {
        let node_record = NodeRecord {
            node_operator_id: vec![0],
            xnet: Some(ConnectionEndpoint {
                ip_addr: node.xnet_ip_addr.to_string(),
                port: 2497,
            }),
            http: Some(ConnectionEndpoint {
                ip_addr: node.http_ip_addr.to_string(),
                port: 8080,
            }),
            hostos_version_id: None,
            chip_id: None,
            public_ipv4_config: None,
            domain: None,
            node_reward_type: None,
            ssh_node_state_write_access: vec![],
        };
        registry_data_provider
            .add(
                &make_node_record_key(node.node_id),
                registry_version,
                Some(node_record),
            )
            .unwrap();
        for (key, key_purpose) in [
            (node.node_signing_key.clone(), KeyPurpose::NodeSigning),
            (
                node.committee_signing_key.clone(),
                KeyPurpose::CommitteeSigning,
            ),
            (
                node.dkg_dealing_encryption_key.clone(),
                KeyPurpose::DkgDealingEncryption,
            ),
            (
                node.idkg_mega_encryption_key.clone(),
                KeyPurpose::IDkgMEGaEncryption,
            ),
        ] {
            let node_pk_proto = PublicKeyProto {
                algorithm: AlgorithmId::Ed25519 as i32,
                key_value: key.public_key().serialize_raw().to_vec(),
                version: 0,
                proof_data: None,
                timestamp: None,
            };
            registry_data_provider
                .add(
                    &make_crypto_node_key(node.node_id, key_purpose),
                    registry_version,
                    Some(node_pk_proto.clone()),
                )
                .unwrap();
        }

        let root_cert = CertificateParams::new(vec![node.node_id.to_string()])
            .unwrap()
            .self_signed(&node.root_key_pair)
            .unwrap();
        let tls_cert = X509PublicKeyCert {
            certificate_der: root_cert.der().to_vec(),
        };
        registry_data_provider
            .add(
                &make_crypto_tls_cert_key(node.node_id),
                registry_version,
                Some(tls_cert),
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
    let max_ingress_messages_per_block = 1000;
    let max_block_payload_size = 4 * 1024 * 1024;

    let node_ids: Vec<_> = nodes.iter().map(|n| n.node_id).collect();
    let record = SubnetRecordBuilder::from(&node_ids)
        .with_subnet_type(subnet_type)
        .with_max_ingress_bytes_per_message(max_ingress_bytes_per_message)
        .with_max_ingress_messages_per_block(max_ingress_messages_per_block)
        .with_max_block_payload_size(max_block_payload_size)
        .with_dkg_interval_length(u64::MAX / 2) // use the genesis CUP throughout the test
        .with_chain_key_config(ChainKeyConfig {
            key_configs: chain_keys_enabled_status
                .keys()
                .map(|key_id| KeyConfig {
                    key_id: key_id.clone(),
                    pre_signatures_to_create_in_advance: if key_id.requires_pre_signatures() {
                        1
                    } else {
                        0
                    },
                    max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                })
                .collect(),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        })
        .with_features(features)
        .build();

    // Insert initial DKG transcripts
    let mut high_threshold_transcript = ni_dkg_transcript.clone();
    high_threshold_transcript.dkg_id.dkg_tag = NiDkgTag::HighThreshold;
    let mut low_threshold_transcript = ni_dkg_transcript;
    low_threshold_transcript.dkg_id.dkg_tag = NiDkgTag::LowThreshold;
    let cup_contents = CatchUpPackageContents {
        initial_ni_dkg_transcript_high_threshold: Some(high_threshold_transcript.into()),
        initial_ni_dkg_transcript_low_threshold: Some(low_threshold_transcript.into()),
        ..Default::default()
    };
    registry_data_provider
        .add(
            &make_catch_up_package_contents_key(subnet_id),
            registry_version,
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
}

fn make_fresh_registry_cup(
    registry_client: Arc<FakeRegistryClient>,
    subnet_id: SubnetId,
    replica_logger: &ReplicaLogger,
) -> pb::CatchUpPackage {
    let registry_version = registry_client.get_latest_version();
    let cup_contents = registry_client
        .get_cup_contents(subnet_id, registry_version)
        .unwrap()
        .value
        .unwrap();
    let cup = make_registry_cup_from_cup_contents(
        registry_client.as_ref(),
        subnet_id,
        cup_contents,
        registry_version,
        replica_logger,
    )
    .unwrap();
    cup.into()
}

/// Convert an object into CBOR binary.
fn into_cbor<R: Serialize>(r: &R) -> Vec<u8> {
    let mut ser = serde_cbor::Serializer::new(Vec::new());
    ser.self_describe().expect("Could not write magic tag.");
    r.serialize(&mut ser).expect("Serialization failed.");
    ser.into_inner()
}

fn replica_logger(log_level: Option<Level>) -> ReplicaLogger {
    use slog::Drain;
    if let Some(log_level) = std::env::var("RUST_LOG")
        .ok()
        .and_then(|level| Level::from_str(&level).ok())
        .or(log_level)
    {
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
    } else {
        no_op_logger()
    }
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

    fn exceeds_limit(&self, _peer_id: &NodeId) -> bool {
        false
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
    fn push(&mut self, m: SignedIngress, timestamp: Time, peer_id: NodeId) {
        self.validated.insert(
            IngressMessageId::new(m.expiry_time(), m.id()),
            ValidatedIngressArtifact {
                msg: IngressPoolObject::new(peer_id, m),
                timestamp,
            },
        );
    }
}

pub trait Subnets: Send + Sync {
    fn insert(&self, state_machine: Arc<StateMachine>);
    fn get(&self, subnet_id: SubnetId) -> Option<Arc<StateMachine>>;
}

/// Struct mocking the XNet layer.
struct PocketXNetImpl {
    /// Pool of `StateMachine`s from which XNet messages are fetched.
    subnets: Arc<dyn Subnets>,
    /// The certified slice pool of the `StateMachine` for which the XNet layer is mocked.
    pool: Arc<Mutex<CertifiedSlicePool>>,
    /// The subnet ID of the `StateMachine` for which the XNet layer is mocked.
    own_subnet_id: SubnetId,
}

impl PocketXNetImpl {
    fn new(
        subnets: Arc<dyn Subnets>,
        pool: Arc<Mutex<CertifiedSlicePool>>,
        own_subnet_id: SubnetId,
    ) -> Self {
        Self {
            subnets,
            pool,
            own_subnet_id,
        }
    }

    fn refill(&self, registry_version: RegistryVersion, log: ReplicaLogger) {
        let refill_stream_slice_indices =
            refill_stream_slice_indices(self.pool.clone(), self.own_subnet_id);

        for (subnet_id, indices) in refill_stream_slice_indices {
            // When restoring a PocketIC instance from its state,
            // subnets are created sequentially and thus it is expected
            // that some subnets might not exist yet.
            if let Some(sm) = self.subnets.get(subnet_id) {
                match sm.generate_certified_stream_slice(
                    self.own_subnet_id,
                    Some(indices.witness_begin),
                    Some(indices.msg_begin),
                    None,
                    Some(indices.byte_limit),
                ) {
                    Ok(slice) => {
                        if indices.witness_begin != indices.msg_begin {
                            // Pulled a stream suffix, append to pooled slice.
                            self.pool
                                .lock()
                                .unwrap()
                                .append(subnet_id, slice, registry_version, log.clone())
                                .unwrap();
                        } else {
                            // Pulled a complete stream, replace pooled slice (if any).
                            self.pool
                                .lock()
                                .unwrap()
                                .put(subnet_id, slice, registry_version, log.clone())
                                .unwrap();
                        }
                    }
                    Err(EncodeStreamError::NoStreamForSubnet(_)) => (),
                    Err(err) => panic!("Unexpected XNetClient error: {err}"),
                }
            }
        }
    }

    fn subnets(&self) -> Arc<dyn Subnets> {
        self.subnets.clone()
    }
}

/// A custom `QueryStatsPayloadBuilderImpl` that uses a single
/// `QueryStatsPayloadBuilderImpl` to retrieve total query stats
/// and turns them into a collection of fractional query stats
/// for each node of the corresponding subnet.
/// Those fractional query stats are stored in the field `pending_payloads`
/// until they become part of a block and get `purge`d.
struct PocketQueryStatsPayloadBuilderImpl {
    query_stats_payload_builder: Box<dyn BatchPayloadBuilder>,
    node_ids: Vec<NodeId>,
    pending_payloads: RwLock<Vec<QueryStatsPayload>>,
}

impl PocketQueryStatsPayloadBuilderImpl {
    pub(crate) fn new(
        query_stats_payload_builder: Box<dyn BatchPayloadBuilder>,
        node_ids: Vec<NodeId>,
    ) -> Self {
        Self {
            query_stats_payload_builder,
            node_ids,
            pending_payloads: RwLock::new(Vec::new()),
        }
    }

    pub(crate) fn purge(&self, payload: &QueryStatsPayload) {
        assert!(self.pending_payloads.read().unwrap().contains(payload));
        self.pending_payloads
            .write()
            .unwrap()
            .retain(|p| p != payload);
    }
}

impl BatchPayloadBuilder for PocketQueryStatsPayloadBuilderImpl {
    fn build_payload(
        &self,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ValidationContext,
    ) -> Vec<u8> {
        if let Some(payload) = self.pending_payloads.read().unwrap().iter().next() {
            return payload.serialize_with_limit(max_size);
        }
        let serialized_payload = self.query_stats_payload_builder.build_payload(
            height,
            max_size,
            past_payloads,
            context,
        );
        let num_nodes = self.node_ids.len();
        if let Some(payload) = QueryStatsPayload::deserialize(&serialized_payload).unwrap() {
            assert!(self.node_ids.contains(&payload.proposer));
            *self.pending_payloads.write().unwrap() = self
                .node_ids
                .iter()
                .map(|node_id| {
                    let mut payload = payload.clone();
                    payload.proposer = *node_id;
                    // scale down the stats by the number of nodes
                    // since they'll be aggregated across all nodes
                    payload.stats = payload
                        .stats
                        .into_iter()
                        .map(|mut s| {
                            s.stats.num_calls /= num_nodes as u32;
                            s.stats.num_instructions /= num_nodes as u64;
                            s.stats.ingress_payload_size /= num_nodes as u64;
                            s.stats.egress_payload_size /= num_nodes as u64;
                            s
                        })
                        .collect();
                    payload
                })
                .collect();
        }
        if let Some(payload) = self.pending_payloads.read().unwrap().iter().next() {
            payload.serialize_with_limit(max_size)
        } else {
            vec![]
        }
    }

    fn validate_payload(
        &self,
        _height: Height,
        _proposal_context: &ProposalContext,
        _payload: &[u8],
        _past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        Ok(())
    }
}

/// A replica node of the subnet with the corresponding `StateMachine`.
pub struct StateMachineNode {
    pub node_id: NodeId,
    pub node_signing_key: ic_ed25519::PrivateKey,
    pub committee_signing_key: ic_ed25519::PrivateKey,
    pub dkg_dealing_encryption_key: ic_ed25519::PrivateKey,
    pub idkg_mega_encryption_key: ic_ed25519::PrivateKey,
    pub http_ip_addr: Ipv6Addr,
    pub xnet_ip_addr: Ipv6Addr,
    pub root_key_pair: KeyPair,
}

impl StateMachineNode {
    fn new(rng: &mut StdRng) -> Self {
        let node_signing_key = ic_ed25519::PrivateKey::deserialize_raw_32(&rng.r#gen());
        let committee_signing_key = ic_ed25519::PrivateKey::deserialize_raw_32(&rng.r#gen());
        let dkg_dealing_encryption_key = ic_ed25519::PrivateKey::deserialize_raw_32(&rng.r#gen());
        let idkg_mega_encryption_key = ic_ed25519::PrivateKey::deserialize_raw_32(&rng.r#gen());
        let mut http_ip_addr_bytes = rng.r#gen::<[u8; 16]>();
        http_ip_addr_bytes[0] = 0xe0; // make sure the ipv6 address has no special form
        let http_ip_addr = Ipv6Addr::from(http_ip_addr_bytes);
        let mut xnet_ip_addr_bytes = rng.r#gen::<[u8; 16]>();
        xnet_ip_addr_bytes[0] = 0xe0; // make sure the ipv6 address has no special form
        let xnet_ip_addr = Ipv6Addr::from(xnet_ip_addr_bytes);
        let seed = rng.r#gen::<[u8; 32]>();
        let signing_key = SigningKey::from_bytes(&seed);
        let pkcs8_bytes = signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let root_key_pair: KeyPair = pkcs8_bytes.try_into().unwrap();
        Self {
            node_id: PrincipalId::new_self_authenticating(
                &node_signing_key.public_key().serialize_rfc8410_der(),
            )
            .into(),
            node_signing_key,
            committee_signing_key,
            dkg_dealing_encryption_key,
            idkg_mega_encryption_key,
            http_ip_addr,
            xnet_ip_addr,
            root_key_pair,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum SignatureSecretKey {
    EcdsaSecp256k1(ic_secp256k1::PrivateKey),
    SchnorrBip340(ic_secp256k1::PrivateKey),
    Ed25519(ic_ed25519::DerivedPrivateKey),
    VetKD(ic_crypto_test_utils_vetkd::PrivateKey),
}

/// Represents a replicated state machine detached from the network layer that
/// can be used to test this part of the stack in isolation.
pub struct StateMachine {
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    public_key: ThresholdSigPublicKey,
    public_key_der: Vec<u8>,
    secret_key: SecretKeyBytes,
    is_ecdsa_signing_enabled: bool,
    is_schnorr_signing_enabled: bool,
    is_vetkd_enabled: bool,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    pub registry_client: Arc<FakeRegistryClient>,
    pub state_manager: Arc<StateManagerImpl>,
    consensus_time: Arc<PocketConsensusTime>,
    ingress_pool: Arc<RwLock<PocketIngressPool>>,
    ingress_manager: Arc<IngressManager>,
    pub ingress_filter: Arc<Mutex<IngressFilterService>>,
    pocket_xnet: Arc<RwLock<Option<PocketXNetImpl>>>,
    payload_builder: Arc<RwLock<Option<PayloadBuilderImpl>>>,
    message_routing: SyncMessageRouting,
    pub metrics_registry: MetricsRegistry,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    pub query_handler: Arc<Mutex<QueryExecutionService>>,
    pub transform_handler: Arc<Mutex<TransformExecutionService>>,
    pub runtime: Arc<Runtime>,
    // The atomicity is required for internal mutability and sending across threads.
    checkpoint_interval_length: AtomicU64,
    nonce: AtomicU64,
    // the time used to derive the time of the next round that is:
    //  - equal to `time` + 1ns if `time` = `time_of_last_round`;
    //  - equal to `time`       otherwise.
    time: AtomicU64,
    // the time of the last round
    // (equal to `time` when this `StateMachine` is initialized)
    time_of_last_round: RwLock<Time>,
    chain_key_subnet_public_keys: BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    chain_key_subnet_secret_keys: BTreeMap<MasterPublicKeyId, SignatureSecretKey>,
    ni_dkg_ids: BTreeMap<NiDkgMasterPublicKeyId, NiDkgId>,
    pub replica_logger: ReplicaLogger,
    pub log_level: Option<Level>,
    pub nodes: Vec<StateMachineNode>,
    pub batch_summary: Option<BatchSummary>,
    pub time_source: Arc<FastForwardTimeSource>,
    consensus_pool_cache: Arc<FakeConsensusPoolCache>,
    canister_http_pool: Arc<RwLock<CanisterHttpPoolImpl>>,
    canister_http_payload_builder: Arc<CanisterHttpPayloadBuilderImpl>,
    certified_height_tx: watch::Sender<Height>,
    pub ingress_watcher_handle: IngressWatcherHandle,
    /// A drop guard to gracefully cancel the ingress watcher task.
    _ingress_watcher_drop_guard: tokio_util::sync::DropGuard,
    query_stats_payload_builder: Arc<PocketQueryStatsPayloadBuilderImpl>,
    vetkd_payload_builder: Arc<dyn BatchPayloadBuilder>,
    remove_old_states: bool,
    cycles_account_manager: Arc<CyclesAccountManager>,
    cost_schedule: CanisterCyclesCostSchedule,
    // This field must be the last one so that the temporary directory is deleted at the very end.
    state_dir: Box<dyn StateMachineStateDir>,
    // DO NOT PUT ANY FIELDS AFTER `state_dir`!!!
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

/// A state directory for a `StateMachine` in which
/// the `StateMachine` maintains its state.
pub trait StateMachineStateDir: Send + Sync {
    fn path(&self) -> PathBuf;
}

/// A state directory based on a `TempDir` which
/// gets deleted once the `StateMachine` is dropped.
impl StateMachineStateDir for TempDir {
    fn path(&self) -> PathBuf {
        self.path().to_path_buf()
    }
}

/// A state directory based on a `PathBuf` which
/// is persisted once the `StateMachine` is dropped.
/// To reuse the state in another `StateMachine`,
/// you need to run `state_machine.checkpointed_tick()`
/// followed by `state_machine.await_state_hash()`
/// before dropping the `StateMachine`.
impl StateMachineStateDir for PathBuf {
    fn path(&self) -> PathBuf {
        self.clone()
    }
}

pub struct StateMachineBuilder {
    state_dir: Box<dyn StateMachineStateDir>,
    nonce: u64,
    time: Time,
    config: Option<StateMachineConfig>,
    // The default value `None` is to use 199/499 for system/app subnets.
    checkpoint_interval_length: Option<u64>,
    subnet_type: SubnetType,
    subnet_size: usize,
    nns_subnet_id: Option<SubnetId>,
    subnet_id: Option<SubnetId>,
    max_stream_messages: usize,
    target_stream_size_bytes: usize,
    routing_table: RoutingTable,
    chain_keys_enabled_status: BTreeMap<MasterPublicKeyId, bool>,
    ecdsa_signature_fee: Option<Cycles>,
    schnorr_signature_fee: Option<Cycles>,
    vetkd_derive_key_fee: Option<Cycles>,
    is_ecdsa_signing_enabled: bool,
    is_schnorr_signing_enabled: bool,
    is_vetkd_enabled: bool,
    is_snapshot_download_enabled: bool,
    is_snapshot_upload_enabled: bool,
    features: SubnetFeatures,
    runtime: Option<Arc<Runtime>>,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    lsmt_override: Option<LsmtConfig>,
    seed: [u8; 32],
    with_extra_canister_range: Option<std::ops::RangeInclusive<CanisterId>>,
    log_level: Option<Level>,
    bitcoin_testnet_uds_path: Option<PathBuf>,
    dogecoin_testnet_uds_path: Option<PathBuf>,
    remove_old_states: bool,
    /// If a registry version is provided, then new registry records are created for the `StateMachine`
    /// at the provided registry version.
    /// Otherwise, no new registry records are created.
    create_at_registry_version: Option<RegistryVersion>,
    cost_schedule: CanisterCyclesCostSchedule,
}

impl StateMachineBuilder {
    pub fn new() -> Self {
        Self {
            state_dir: Box::new(TempDir::new().expect("failed to create a temporary directory")),
            nonce: 0,
            time: GENESIS,
            config: None,
            checkpoint_interval_length: None,
            subnet_type: SubnetType::System,
            subnet_size: SMALL_APP_SUBNET_MAX_SIZE,
            nns_subnet_id: None,
            subnet_id: None,
            max_stream_messages: MAX_STREAM_MESSAGES,
            target_stream_size_bytes: TARGET_STREAM_SIZE_BYTES,
            routing_table: RoutingTable::new(),
            chain_keys_enabled_status: Default::default(),
            ecdsa_signature_fee: None,
            schnorr_signature_fee: None,
            vetkd_derive_key_fee: None,
            is_ecdsa_signing_enabled: true,
            is_schnorr_signing_enabled: true,
            is_vetkd_enabled: true,
            is_snapshot_download_enabled: false,
            is_snapshot_upload_enabled: false,
            features: SubnetFeatures {
                http_requests: true,
                ..SubnetFeatures::default()
            },
            runtime: None,
            registry_data_provider: Arc::new(ProtoRegistryDataProvider::new()),
            lsmt_override: None,
            seed: [42; 32],
            with_extra_canister_range: None,
            log_level: Some(Level::Warning),
            bitcoin_testnet_uds_path: None,
            dogecoin_testnet_uds_path: None,
            remove_old_states: true,
            create_at_registry_version: Some(INITIAL_REGISTRY_VERSION),
            cost_schedule: CanisterCyclesCostSchedule::Normal,
        }
    }

    pub fn with_cost_schedule(self, cost_schedule: CanisterCyclesCostSchedule) -> Self {
        Self {
            cost_schedule,
            ..self
        }
    }

    pub fn with_lsmt_override(self, lsmt_override: Option<LsmtConfig>) -> Self {
        Self {
            lsmt_override,
            ..self
        }
    }

    pub fn with_state_machine_state_dir(self, state_dir: Box<dyn StateMachineStateDir>) -> Self {
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
        let checkpoint_interval_length = if checkpoints_enabled { 0 } else { u64::MAX };
        Self {
            checkpoint_interval_length: Some(checkpoint_interval_length),
            ..self
        }
    }

    pub fn with_checkpoint_interval_length(self, checkpoint_interval_length: u64) -> Self {
        Self {
            checkpoint_interval_length: Some(checkpoint_interval_length),
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

    pub fn with_max_stream_messages(self, max_stream_messages: usize) -> Self {
        Self {
            max_stream_messages,
            ..self
        }
    }

    pub fn with_target_stream_size_bytes(self, target_stream_size_bytes: usize) -> Self {
        Self {
            target_stream_size_bytes,
            ..self
        }
    }

    pub fn with_master_ecdsa_public_key(self) -> Self {
        self.with_chain_key(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "master_ecdsa_public_key".to_string(),
        }))
    }

    pub fn with_chain_key(mut self, key_id: MasterPublicKeyId) -> Self {
        self.chain_keys_enabled_status.insert(key_id, true);
        self
    }

    pub fn with_disabled_chain_key(mut self, key_id: MasterPublicKeyId) -> Self {
        self.chain_keys_enabled_status.insert(key_id, false);
        self
    }

    pub fn with_ecdsa_signature_fee(self, ecdsa_signing_fee: u128) -> Self {
        Self {
            ecdsa_signature_fee: Some(Cycles::new(ecdsa_signing_fee)),
            ..self
        }
    }

    pub fn with_schnorr_signature_fee(self, schnorr_signature_fee: u128) -> Self {
        Self {
            schnorr_signature_fee: Some(Cycles::new(schnorr_signature_fee)),
            ..self
        }
    }

    pub fn with_vetkd_derive_key_fee(self, fee: u128) -> Self {
        Self {
            vetkd_derive_key_fee: Some(Cycles::new(fee)),
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

    pub fn with_subnet_seed(self, seed: [u8; 32]) -> Self {
        Self { seed, ..self }
    }

    pub fn with_ecdsa_signing_enabled(self, is_ecdsa_signing_enabled: bool) -> Self {
        Self {
            is_ecdsa_signing_enabled,
            ..self
        }
    }

    pub fn with_schnorr_signing_enabled(self, is_schnorr_signing_enabled: bool) -> Self {
        Self {
            is_schnorr_signing_enabled,
            ..self
        }
    }

    pub fn with_vetkd_enabled(self, is_vetkd_enabled: bool) -> Self {
        Self {
            is_vetkd_enabled,
            ..self
        }
    }

    pub fn with_snapshot_download_enabled(self, is_snapshot_download_enabled: bool) -> Self {
        Self {
            is_snapshot_download_enabled,
            ..self
        }
    }

    pub fn with_snapshot_upload_enabled(self, is_snapshot_upload_enabled: bool) -> Self {
        Self {
            is_snapshot_upload_enabled,
            ..self
        }
    }

    pub fn with_log_level(self, log_level: Option<Level>) -> Self {
        Self { log_level, ..self }
    }

    pub fn with_bitcoin_testnet_uds_path(self, bitcoin_testnet_uds_path: Option<PathBuf>) -> Self {
        Self {
            bitcoin_testnet_uds_path,
            ..self
        }
    }

    pub fn with_dogecoin_testnet_uds_path(
        self,
        dogecoin_testnet_uds_path: Option<PathBuf>,
    ) -> Self {
        Self {
            dogecoin_testnet_uds_path,
            ..self
        }
    }

    pub fn with_remove_old_states(self, remove_old_states: bool) -> Self {
        Self {
            remove_old_states,
            ..self
        }
    }

    /// If a registry version is provided, then new registry records are created for the `StateMachine`
    /// at the provided registry version.
    /// Otherwise, no new registry records are created.
    pub fn create_at_registry_version(self, registry_version: Option<RegistryVersion>) -> Self {
        Self {
            create_at_registry_version: registry_version,
            ..self
        }
    }

    pub fn build_internal(self) -> StateMachine {
        StateMachine::setup_from_dir(
            self.state_dir,
            self.nonce,
            self.time,
            self.config,
            self.checkpoint_interval_length,
            self.subnet_type,
            self.subnet_size,
            self.subnet_id,
            self.max_stream_messages,
            self.target_stream_size_bytes,
            self.chain_keys_enabled_status,
            self.ecdsa_signature_fee,
            self.schnorr_signature_fee,
            self.vetkd_derive_key_fee,
            self.is_ecdsa_signing_enabled,
            self.is_schnorr_signing_enabled,
            self.is_vetkd_enabled,
            self.is_snapshot_download_enabled,
            self.is_snapshot_upload_enabled,
            self.features,
            self.runtime.unwrap_or_else(|| {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("failed to create a tokio runtime")
                    .into()
            }),
            self.registry_data_provider,
            self.lsmt_override,
            self.seed,
            self.log_level,
            self.remove_old_states,
            self.create_at_registry_version,
            self.cost_schedule,
        )
    }

    pub fn build(self) -> StateMachine {
        let nns_subnet_id = self.nns_subnet_id;
        let mut routing_table = self.routing_table.clone();
        let registry_data_provider = self.registry_data_provider.clone();
        let extra_canister_range = self.with_extra_canister_range.clone();
        let chain_keys_enabled_status = self.chain_keys_enabled_status.clone();
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
        let chain_keys = chain_keys_enabled_status
            .into_iter()
            .filter_map(|(key_id, is_enabled)| {
                if is_enabled {
                    Some((key_id, vec![subnet_id]))
                } else {
                    None
                }
            })
            .collect();
        add_initial_registry_records(registry_data_provider.clone());
        add_global_registry_records(
            nns_subnet_id.unwrap_or(subnet_id),
            routing_table,
            subnet_list,
            chain_keys,
            registry_data_provider,
        );
        sm.reload_registry();
        sm
    }

    /// Build a `StateMachine` and register it for multi-subnet testing
    /// in the provided association of subnet IDs and `StateMachine`s.
    pub fn build_with_subnets(self, subnets: Arc<dyn Subnets>) -> Arc<StateMachine> {
        let bitcoin_testnet_uds_path = self.bitcoin_testnet_uds_path.clone();
        let dogecoin_testnet_uds_path = self.dogecoin_testnet_uds_path.clone();

        // Build a `StateMachine` for the subnet with `self.subnet_id`.
        let sm = Arc::new(self.build_internal());
        let subnet_id = sm.get_subnet_id();

        // Register this new `StateMachine` in the *shared* pool of `StateMachine`s.
        subnets.insert(sm.clone());

        // Create a dummny refill task handle to be used in `XNetPayloadBuilderImpl`.
        // It is fine that we do not pop any messages from the (bounded) channel
        // since errors are ignored in `RefillTaskHandle::trigger_refill()`.
        let (refill_trigger, _refill_receiver) = mpsc::channel(1);
        let refill_task_handle = RefillTaskHandle(Mutex::new(refill_trigger));

        // Instantiate a `XNetPayloadBuilderImpl`.
        // We need to use a deterministic PRNG - so we use an arbitrary fixed seed, e.g., 42.
        let rng = Arc::new(Some(Mutex::new(StdRng::seed_from_u64(42))));
        let certified_stream_store: Arc<dyn CertifiedStreamStore> = sm.state_manager.clone();
        let certified_slice_pool = Arc::new(Mutex::new(CertifiedSlicePool::new(
            certified_stream_store,
            &sm.metrics_registry,
        )));
        let xnet_slice_pool_impl = Box::new(XNetSlicePoolImpl::new(certified_slice_pool.clone()));
        let metrics = Arc::new(XNetPayloadBuilderMetrics::new(&sm.metrics_registry));
        let xnet_payload_builder = Arc::new(XNetPayloadBuilderImpl::new_from_components(
            sm.state_manager.clone(),
            sm.state_manager.clone(),
            sm.registry_client.clone(),
            rng,
            None,
            xnet_slice_pool_impl,
            refill_task_handle,
            metrics,
            sm.replica_logger.clone(),
        ));

        let adapters_config = AdaptersConfig {
            bitcoin_mainnet_uds_path: None,
            bitcoin_mainnet_uds_metrics_path: None,
            bitcoin_testnet_uds_path,
            bitcoin_testnet_uds_metrics_path: None,
            dogecoin_mainnet_uds_path: None,
            dogecoin_mainnet_uds_metrics_path: None,
            dogecoin_testnet_uds_path,
            dogecoin_testnet_uds_metrics_path: None,
            https_outcalls_uds_path: None,
            https_outcalls_uds_metrics_path: None,
        };
        let bitcoin_clients = setup_bitcoin_adapter_clients(
            sm.replica_logger.clone(),
            &sm.metrics_registry,
            sm.runtime.handle().clone(),
            adapters_config,
        );
        let self_validating_payload_builder = Arc::new(BitcoinPayloadBuilder::new(
            sm.state_manager.clone(),
            &sm.metrics_registry,
            bitcoin_clients.btc_mainnet_client,
            bitcoin_clients.btc_testnet_client,
            bitcoin_clients.doge_mainnet_client,
            bitcoin_clients.doge_testnet_client,
            sm.subnet_id,
            sm.registry_client.clone(),
            BitcoinPayloadBuilderConfig::default(),
            sm.replica_logger.clone(),
        ));

        // Put `PocketXNetImpl` into `StateMachine`
        // which contains no `PocketXNetImpl` after creation.
        let pocket_xnet_impl = PocketXNetImpl::new(subnets, certified_slice_pool, subnet_id);
        *sm.pocket_xnet.write().unwrap() = Some(pocket_xnet_impl);
        // Instantiate a `PayloadBuilderImpl` and put it into `StateMachine`
        // which contains no `PayloadBuilderImpl` after creation.
        *sm.payload_builder.write().unwrap() = Some(PayloadBuilderImpl::new(
            subnet_id,
            sm.nodes[0].node_id,
            sm.registry_client.clone(),
            sm.ingress_manager.clone(),
            xnet_payload_builder,
            self_validating_payload_builder,
            sm.canister_http_payload_builder.clone(),
            sm.query_stats_payload_builder.clone(),
            sm.vetkd_payload_builder.clone(),
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
    /// Provides the implicit time increment for a single round of execution
    /// if time does not advance between consecutive rounds.
    pub const EXECUTE_ROUND_TIME_INCREMENT: Duration = Duration::from_nanos(1);

    // TODO: cleanup, replace external calls with `StateMachineBuilder`.
    /// Constructs a new environment that uses a temporary directory for storing
    /// states.
    pub fn new() -> Self {
        StateMachineBuilder::new().build()
    }

    /// Drops the payload builder of this `StateMachine`.
    /// This function should be called when this `StateMachine` is supposed to be dropped
    /// if this `StateMachine` was created using `StateMachineBuilder::build_with_subnets`
    /// because the payload builder contains an `Arc` of this `StateMachine`
    /// which creates a circular dependency preventing this `StateMachine`s from being dropped.
    pub fn drop_payload_builder(&self) {
        self.pocket_xnet.write().unwrap().take();
        self.payload_builder.write().unwrap().take();
    }

    // TODO: cleanup, replace external calls with `StateMachineBuilder`.
    /// Constructs a new environment with the specified configuration.
    pub fn new_with_config(config: StateMachineConfig) -> Self {
        StateMachineBuilder::new().with_config(Some(config)).build()
    }

    pub fn execute_round(&self) {
        self.do_execute_round(None);
    }

    pub fn execute_round_with_blockmaker_metrics(&self, blockmaker_metrics: BlockmakerMetrics) {
        self.do_execute_round(Some(blockmaker_metrics));
    }

    /// Assemble a payload for a new round using `PayloadBuilderImpl`
    /// and execute a round with this payload.
    /// Note that only ingress messages submitted via `Self::submit_ingress`
    /// will be considered during payload building.
    pub fn do_execute_round(&self, blockmaker_metrics: Option<BlockmakerMetrics>) {
        // Make sure the latest state is certified and fetch it from `StateManager`.
        self.certify_latest_state();
        let certified_height = self.state_manager.latest_certified_height();

        self.certified_height_tx
            .send(certified_height)
            .expect("Ingress watcher is running");

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
        self.pocket_xnet
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .refill(registry_version, self.replica_logger.clone());
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
        let ingress_messages = ingress.clone().try_into().unwrap();
        let (http_responses, _) =
            CanisterHttpPayloadBuilderImpl::into_messages(&batch_payload.canister_http);
        let inducted: Vec<_> = http_responses
            .clone()
            .into_iter()
            .map(|r| r.callback)
            .collect();
        let changeset = self
            .canister_http_pool
            .read()
            .unwrap()
            .get_validated_shares()
            .filter_map(|share| {
                if inducted.contains(&share.content.id) {
                    Some(CanisterHttpChangeAction::RemoveValidated(share.clone()))
                } else {
                    None
                }
            })
            .collect();
        self.canister_http_pool.write().unwrap().apply(changeset);
        let query_stats = QueryStatsPayload::deserialize(&batch_payload.query_stats).unwrap();
        if let Some(ref query_stats) = query_stats {
            self.query_stats_payload_builder.purge(query_stats);
        }
        let self_validating = Some(batch_payload.self_validating);
        let mut payload = PayloadBuilder::new()
            .with_ingress_messages(ingress_messages)
            .with_xnet_payload(xnet_payload)
            .with_consensus_responses(http_responses)
            .with_query_stats(query_stats)
            .with_self_validating(self_validating);
        if let Some(blockmaker_metrics) = blockmaker_metrics {
            payload = payload.with_blockmaker_metrics(blockmaker_metrics);
        }

        // Process threshold signing requests.
        for (id, context) in &state
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts
        {
            self.process_threshold_signing_request(id, context, &mut payload);
        }

        // Finally execute the payload.
        self.execute_payload(payload);
    }

    /// Reload registry derived from a *shared* registry data provider
    /// to reflect changes in that shared registry data provider
    /// after this `StateMachine` has been built.
    pub fn reload_registry(&self) {
        self.registry_client.reload();
        // Since the latest registry version could have changed,
        // we update the CUP in `FakeConsensusPoolCache` to refer
        // to the latest registry version.
        let cup_proto = make_fresh_registry_cup(
            self.registry_client.clone(),
            self.subnet_id,
            &self.replica_logger,
        );
        self.consensus_pool_cache.update_cup(cup_proto);
    }

    /// Constructs and initializes a new state machine that uses the specified
    /// directory for storing states.
    #[allow(clippy::too_many_arguments)]
    fn setup_from_dir(
        state_dir: Box<dyn StateMachineStateDir>,
        nonce: u64,
        time: Time,
        config: Option<StateMachineConfig>,
        checkpoint_interval_length: Option<u64>,
        subnet_type: SubnetType,
        subnet_size: usize,
        subnet_id: Option<SubnetId>,
        max_stream_messages: usize,
        target_stream_size_bytes: usize,
        chain_keys_enabled_status: BTreeMap<MasterPublicKeyId, bool>,
        ecdsa_signature_fee: Option<Cycles>,
        schnorr_signature_fee: Option<Cycles>,
        vetkd_derive_key_fee: Option<Cycles>,
        is_ecdsa_signing_enabled: bool,
        is_schnorr_signing_enabled: bool,
        is_vetkd_enabled: bool,
        is_snapshot_download_enabled: bool,
        is_snapshot_upload_enabled: bool,
        features: SubnetFeatures,
        runtime: Arc<Runtime>,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
        lsmt_override: Option<LsmtConfig>,
        seed: [u8; 32],
        log_level: Option<Level>,
        remove_old_states: bool,
        create_at_registry_version: Option<RegistryVersion>,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Self {
        let checkpoint_interval_length = checkpoint_interval_length.unwrap_or(match subnet_type {
            SubnetType::Application | SubnetType::VerifiedApplication => 499,
            SubnetType::System => 199,
        });
        let replica_logger = replica_logger(log_level);

        let metrics_registry = MetricsRegistry::new();

        let (mut subnet_config, mut hypervisor_config) = match config {
            Some(config) => (config.subnet_config, config.hypervisor_config),
            None => (SubnetConfig::new(subnet_type), HypervisorConfig::default()),
        };
        if is_snapshot_download_enabled {
            hypervisor_config.canister_snapshot_download = FlagStatus::Enabled;
        }
        if is_snapshot_upload_enabled {
            hypervisor_config.canister_snapshot_upload = FlagStatus::Enabled;
        }
        if let Some(ecdsa_signature_fee) = ecdsa_signature_fee {
            subnet_config
                .cycles_account_manager_config
                .ecdsa_signature_fee = ecdsa_signature_fee;
        }
        if let Some(schnorr_signature_fee) = schnorr_signature_fee {
            subnet_config
                .cycles_account_manager_config
                .schnorr_signature_fee = schnorr_signature_fee;
        }
        if let Some(vetkd_derive_key_fee) = vetkd_derive_key_fee {
            subnet_config.cycles_account_manager_config.vetkd_fee = vetkd_derive_key_fee;
        }

        let mut node_rng = StdRng::from_seed(seed);
        let nodes: Vec<StateMachineNode> = (0..subnet_size)
            .map(|_| StateMachineNode::new(&mut node_rng))
            .collect();
        let (ni_dkg_transcript, secret_key) =
            dummy_initial_dkg_transcript_with_master_key(&mut StdRng::from_seed(seed));
        let public_key = (&ni_dkg_transcript).try_into().unwrap();
        let public_key_der = threshold_sig_public_key_to_der(public_key).unwrap();
        let subnet_id =
            subnet_id.unwrap_or(PrincipalId::new_self_authenticating(&public_key_der).into());

        let mut sm_config = ic_config::state_manager::Config::new(state_dir.path().to_path_buf());
        if let Some(lsmt_override) = lsmt_override {
            sm_config.lsmt_config = lsmt_override;
        }

        // We are not interested in ingress signature validation.
        let malicious_flags = MaliciousFlags {
            maliciously_disable_ingress_validation: true,
            ..Default::default()
        };

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

        if let Some(create_registry_version) = create_at_registry_version {
            add_subnet_local_registry_records(
                subnet_id,
                subnet_type,
                features,
                &nodes,
                public_key,
                &chain_keys_enabled_status,
                ni_dkg_transcript,
                registry_data_provider.clone(),
                create_registry_version,
            );
        }

        let registry_client = FakeRegistryClient::new(Arc::clone(&registry_data_provider) as _);
        registry_client.update_to_latest_version();
        let registry_client = Arc::new(registry_client);

        let canister_http_pool = Arc::new(RwLock::new(CanisterHttpPoolImpl::new(
            metrics_registry.clone(),
            replica_logger.clone(),
        )));
        let cup_proto =
            make_fresh_registry_cup(registry_client.clone(), subnet_id, &replica_logger);
        let consensus_pool_cache = Arc::new(FakeConsensusPoolCache::new(cup_proto));
        let crypto = CryptoReturningOk::default();
        let canister_http_payload_builder = Arc::new(CanisterHttpPayloadBuilderImpl::new(
            canister_http_pool.clone(),
            consensus_pool_cache.clone(),
            Arc::new(crypto),
            state_manager.clone(),
            subnet_id,
            registry_client.clone(),
            &metrics_registry,
            replica_logger.clone(),
        ));

        let vetkd_payload_builder = Arc::new(MockBatchPayloadBuilder::new().expect_noop());

        // Setup ingress watcher for synchronous call endpoint.
        let (completed_execution_messages_tx, completed_execution_messages_rx) =
            mpsc::channel(COMPLETED_EXECUTION_MESSAGES_BUFFER_SIZE);
        let (certified_height_tx, certified_height_rx) = watch::channel(Height::from(0));

        let cancellation_token = tokio_util::sync::CancellationToken::new();
        let cancellation_token_clone = cancellation_token.clone();
        let ingress_watcher_drop_guard = cancellation_token.drop_guard();
        let (ingress_watcher_handle, _join_handle) = IngressWatcher::start(
            runtime.handle().clone(),
            replica_logger.clone(),
            HttpHandlerMetrics::new(&metrics_registry),
            certified_height_rx,
            completed_execution_messages_rx,
            cancellation_token_clone,
        );

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
                hypervisor_config.clone(),
                subnet_config.clone(),
                Arc::clone(&state_manager) as Arc<_>,
                Arc::clone(&state_manager.get_fd_factory()),
                completed_execution_messages_tx,
                &state_manager.state_layout().tmp(),
            )
        });

        let message_routing = SyncMessageRouting::new(
            Arc::clone(&state_manager) as _,
            Arc::clone(&state_manager) as _,
            Arc::clone(&execution_services.ingress_history_writer) as _,
            execution_services.scheduler,
            hypervisor_config,
            Arc::clone(&execution_services.cycles_account_manager),
            subnet_id,
            max_stream_messages,
            target_stream_size_bytes,
            &metrics_registry,
            replica_logger.clone(),
            Arc::clone(&registry_client) as _,
            malicious_flags.clone(),
        );

        let master_ecdsa_public_key = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "master_ecdsa_public_key".to_string(),
        };

        let mut chain_key_subnet_public_keys = BTreeMap::new();
        let mut chain_key_subnet_secret_keys = BTreeMap::new();
        let mut ni_dkg_ids = BTreeMap::new();

        for key_id in chain_keys_enabled_status.keys() {
            let (public_key, private_key) = match key_id {
                MasterPublicKeyId::Ecdsa(id) if *id == master_ecdsa_public_key => {
                    // ckETH tests rely on using the hard-coded ecdsa_secret_key

                    // The following key has been randomly generated using:
                    // https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/crypto/ecdsa_secp256k1/src/lib.rs
                    // It's the sec1 representation of the key in a hex string.
                    // let private_key: PrivateKey = PrivateKey::generate();
                    // let private_str = hex::encode(private_key.serialize_sec1());
                    // We always set it to the same value to have deterministic results.
                    // Please do not use this private key anywhere.
                    let private_key_bytes = hex::decode(
                        "fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920",
                    )
                    .unwrap();

                    let private_key =
                        ic_secp256k1::PrivateKey::deserialize_sec1(private_key_bytes.as_slice())
                            .unwrap();

                    let public_key = MasterPublicKey {
                        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                        public_key: private_key.public_key().serialize_sec1(true),
                    };

                    let private_key = SignatureSecretKey::EcdsaSecp256k1(private_key);

                    (public_key, private_key)
                }
                MasterPublicKeyId::Ecdsa(id) => {
                    use ic_secp256k1::{DerivationIndex, DerivationPath, PrivateKey};

                    let path =
                        DerivationPath::new(vec![DerivationIndex(id.name.as_bytes().to_vec())]);

                    // We use a fixed seed here so that all subnets in PocketIC share the same keys.
                    let private_key = PrivateKey::generate_from_seed(&[42; 32])
                        .derive_subkey(&path)
                        .0;

                    let public_key = MasterPublicKey {
                        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                        public_key: private_key.public_key().serialize_sec1(true),
                    };

                    let private_key = SignatureSecretKey::EcdsaSecp256k1(private_key);

                    (public_key, private_key)
                }
                MasterPublicKeyId::Schnorr(id) => match id.algorithm {
                    SchnorrAlgorithm::Bip340Secp256k1 => {
                        use ic_secp256k1::{DerivationIndex, DerivationPath, PrivateKey};

                        let path =
                            DerivationPath::new(vec![DerivationIndex(id.name.as_bytes().to_vec())]);

                        // We use a fixed seed here so that all subnets in PocketIC share the same keys.
                        let private_key = PrivateKey::generate_from_seed(&[42; 32])
                            .derive_subkey(&path)
                            .0;

                        let public_key = MasterPublicKey {
                            algorithm_id: AlgorithmId::ThresholdSchnorrBip340,
                            public_key: private_key.public_key().serialize_sec1(true),
                        };

                        let private_key = SignatureSecretKey::SchnorrBip340(private_key);

                        (public_key, private_key)
                    }
                    SchnorrAlgorithm::Ed25519 => {
                        use ic_ed25519::{DerivationIndex, DerivationPath, PrivateKey};

                        let path =
                            DerivationPath::new(vec![DerivationIndex(id.name.as_bytes().to_vec())]);

                        // We use a fixed seed here so that all subnets in PocketIC share the same keys.
                        let private_key = PrivateKey::generate_from_seed(&[42; 32])
                            .derive_subkey(&path)
                            .0;

                        let public_key = MasterPublicKey {
                            algorithm_id: AlgorithmId::ThresholdEd25519,
                            public_key: private_key.public_key().serialize_raw().to_vec(),
                        };

                        let private_key = SignatureSecretKey::Ed25519(private_key);

                        (public_key, private_key)
                    }
                },
                MasterPublicKeyId::VetKd(id) => {
                    use ic_crypto_test_utils_vetkd::PrivateKey;

                    let private_key = PrivateKey::generate(id.name.as_bytes());

                    let public_key = MasterPublicKey {
                        algorithm_id: AlgorithmId::VetKD,
                        public_key: private_key.public_key_bytes(),
                    };

                    let private_key = SignatureSecretKey::VetKD(private_key);

                    let nidkg_id = NiDkgId {
                        start_block_height: Height::new(0),
                        dealer_subnet: subnet_id,
                        dkg_tag: NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(
                            id.clone(),
                        )),
                        target_subnet: NiDkgTargetSubnet::Local,
                    };

                    ni_dkg_ids.insert(NiDkgMasterPublicKeyId::VetKd(id.clone()), nidkg_id);

                    (public_key, private_key)
                }
            };

            chain_key_subnet_secret_keys.insert(key_id.clone(), private_key);
            chain_key_subnet_public_keys.insert(key_id.clone(), public_key);
        }

        let time_source = FastForwardTimeSource::new();
        time_source.set_time(time).unwrap();
        let consensus_time = Arc::new(PocketConsensusTime::new(time));
        let ingress_pool = Arc::new(RwLock::new(PocketIngressPool::new()));
        // We are not interested in ingress signature validation
        // and thus use `CryptoReturningOk`.
        let ingress_verifier = Arc::new(CryptoReturningOk::default());
        let ingress_manager = Arc::new(IngressManager::new(
            time_source.clone(),
            consensus_time.clone(),
            Box::new(IngressHistoryReaderImpl::new(state_manager.clone())),
            ingress_pool.clone(),
            registry_client.clone(),
            ingress_verifier.clone(),
            metrics_registry.clone(),
            subnet_id,
            replica_logger.clone(),
            state_manager.clone(),
            Arc::clone(&execution_services.cycles_account_manager),
            malicious_flags,
            RandomStateKind::Deterministic,
        ));

        let query_stats_payload_builder = execution_services
            .query_stats_payload_builder
            .into_payload_builder(
                state_manager.clone(),
                nodes[0].node_id,
                replica_logger.clone(),
            );
        let pocket_query_stats_payload_builder = Arc::new(PocketQueryStatsPayloadBuilderImpl::new(
            query_stats_payload_builder,
            nodes.iter().map(|n| n.node_id).collect(),
        ));

        Self {
            subnet_id,
            subnet_type,
            secret_key,
            public_key,
            public_key_der,
            is_ecdsa_signing_enabled,
            is_schnorr_signing_enabled,
            is_vetkd_enabled,
            registry_data_provider,
            registry_client: registry_client.clone(),
            state_manager,
            consensus_time,
            ingress_pool,
            ingress_manager: ingress_manager.clone(),
            ingress_filter: Arc::new(Mutex::new(execution_services.ingress_filter)),
            pocket_xnet: Arc::new(RwLock::new(None)), // set by `StateMachineBuilder::build_with_subnets`
            payload_builder: Arc::new(RwLock::new(None)), // set by `StateMachineBuilder::build_with_subnets`
            ingress_history_reader: execution_services.ingress_history_reader,
            message_routing,
            metrics_registry: metrics_registry.clone(),
            query_handler: Arc::new(Mutex::new(execution_services.query_execution_service)),
            transform_handler: Arc::new(Mutex::new(execution_services.transform_execution_service)),
            ingress_watcher_handle,
            _ingress_watcher_drop_guard: ingress_watcher_drop_guard,
            certified_height_tx,
            runtime,
            state_dir,
            // Note: state machine tests are commonly used for testing
            // canisters, such tests usually don't rely on any persistence.
            checkpoint_interval_length: checkpoint_interval_length.into(),
            nonce: AtomicU64::new(nonce),
            time: AtomicU64::new(time.as_nanos_since_unix_epoch()),
            time_of_last_round: RwLock::new(time),
            chain_key_subnet_public_keys,
            chain_key_subnet_secret_keys,
            ni_dkg_ids,
            replica_logger: replica_logger.clone(),
            log_level,
            nodes,
            batch_summary: None,
            time_source,
            consensus_pool_cache,
            canister_http_pool,
            canister_http_payload_builder,
            query_stats_payload_builder: pocket_query_stats_payload_builder,
            vetkd_payload_builder,
            remove_old_states,
            cycles_account_manager: execution_services.cycles_account_manager,
            cost_schedule,
        }
    }

    fn into_components_inner(self) -> (Box<dyn StateMachineStateDir>, u64, Time, u64) {
        (
            self.state_dir,
            self.nonce.into_inner(),
            Time::from_nanos_since_unix_epoch(self.time.into_inner()),
            self.checkpoint_interval_length.load(Ordering::Relaxed),
        )
    }

    fn into_components(self) -> (Box<dyn StateMachineStateDir>, u64, Time, u64) {
        // Finish any asynchronous state manager operations first.
        self.state_manager.flush_tip_channel();
        self.state_manager
            .state_layout()
            .flush_checkpoint_removal_channel();

        let state_manager = Arc::downgrade(&self.state_manager);
        let result = self.into_components_inner();
        // StateManager is owned by an Arc, that is cloned into multiple components and different
        // threads. If we return before all the asynchronous components release the Arc, we may
        // end up with to StateManagers writing to the same directory, resulting in a crash.
        let start = std::time::Instant::now();
        while state_manager.upgrade().is_some() {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if start.elapsed() > std::time::Duration::from_secs(5 * 60) {
                panic!("Timed out while dropping StateMachine.");
            }
        }
        result
    }

    /// Safely drops this `StateMachine`. We cannot achieve this functionality by implementing `Drop`
    /// since we have to wait until there are no more `Arc`s for the state manager and
    /// this is infeasible in a `Drop` implementation.
    pub fn drop(self) {
        let _ = self.into_components();
    }

    /// Emulates a node restart, including checkpoint recovery.
    pub fn restart_node(self) -> Self {
        // We must drop self before setup_form_dir so that we don't have two StateManagers pointing
        // to the same root.
        let (state_dir, nonce, time, checkpoint_interval_length) = self.into_components();

        StateMachineBuilder::new()
            .with_state_machine_state_dir(state_dir)
            .with_nonce(nonce)
            .with_time(time)
            .with_checkpoint_interval_length(checkpoint_interval_length)
            .build()
    }

    /// Same as [restart_node], but allows overwriting the LSMT flag.
    pub fn restart_node_with_lsmt_override(self, lsmt_override: Option<LsmtConfig>) -> Self {
        // We must drop self before setup_form_dir so that we don't have two StateManagers pointing
        // to the same root.
        let (state_dir, nonce, time, checkpoint_interval_length) = self.into_components();

        StateMachineBuilder::new()
            .with_state_machine_state_dir(state_dir)
            .with_nonce(nonce)
            .with_time(time)
            .with_checkpoint_interval_length(checkpoint_interval_length)
            .with_lsmt_override(lsmt_override)
            .build()
    }

    /// Same as [restart_node], but enables snapshot downloading.
    pub fn restart_node_with_snapshot_download_enabled(self) -> Self {
        // We must drop self before setup_form_dir so that we don't have two StateManagers pointing
        // to the same root.
        let (state_dir, nonce, time, checkpoint_interval_length) = self.into_components();

        StateMachineBuilder::new()
            .with_state_machine_state_dir(state_dir)
            .with_nonce(nonce)
            .with_time(time)
            .with_checkpoint_interval_length(checkpoint_interval_length)
            .with_snapshot_download_enabled(true)
            .build()
    }

    /// Same as [restart_node], but the subnet will have the specified `config`
    /// after the restart.
    pub fn restart_node_with_config(self, config: StateMachineConfig) -> Self {
        // We must drop self before setup_form_dir so that we don't have two StateManagers pointing
        // to the same root.
        let (state_dir, nonce, time, checkpoint_interval_length) = self.into_components();

        StateMachineBuilder::new()
            .with_state_machine_state_dir(state_dir)
            .with_nonce(nonce)
            .with_time(time)
            .with_config(Some(config))
            .with_checkpoint_interval_length(checkpoint_interval_length)
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
        // TODO(CON-1487): return the `canister_ranges/{subnet_id}` path as well
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
        let checkpoint_interval_length = if enabled { 0 } else { u64::MAX };
        self.set_checkpoint_interval_length(checkpoint_interval_length);
    }

    /// Set current interval length. The typical interval length
    /// for application subnets is 499.
    pub fn set_checkpoint_interval_length(&self, checkpoint_interval_length: u64) {
        self.checkpoint_interval_length
            .store(checkpoint_interval_length, Ordering::Relaxed);
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
        let msg = self.ingress_message(sender, canister_id, method, payload);
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
        let ingress_filter = self.ingress_filter.lock().unwrap().clone();
        self.runtime
            .block_on(ingress_filter.oneshot((provisional_whitelist, msg.clone())))
            .unwrap()
            .map_err(SubmitIngressError::UserError)?;

        // All checks were successful at this point so we can push the ingress message to the ingress pool.
        let message_id = msg.id();
        self.ingress_pool
            .write()
            .unwrap()
            .push(msg, self.get_time(), self.nodes[0].node_id);
        Ok(message_id)
    }

    /// Push an ingress message into the ingress pool used by `PayloadBuilderImpl`
    /// in `Self::execute_round`. This method does not perform any validation
    /// and thus it should only be called on already validated `SignedIngress`.
    pub fn push_signed_ingress(&self, msg: SignedIngress) {
        self.ingress_pool
            .write()
            .unwrap()
            .push(msg, self.get_time(), self.nodes[0].node_id);
    }

    pub fn mock_canister_http_response(
        &self,
        request_id: u64,
        timeout: Time,
        canister_id: CanisterId,
        contents: Vec<CanisterHttpResponseContent>,
    ) {
        assert_eq!(contents.len(), self.nodes.len());
        for (node, content) in std::iter::zip(self.nodes.iter(), contents.into_iter()) {
            let registry_version = self.registry_client.get_latest_version();
            let response = CanisterHttpResponse {
                id: CanisterHttpRequestId::from(request_id),
                timeout,
                canister_id,
                content: content.clone(),
            };
            let response_metadata = CanisterHttpResponseMetadata {
                id: CallbackId::from(request_id),
                timeout,
                registry_version,
                content_hash: ic_types::crypto::crypto_hash(&response),
                replica_version: ReplicaVersion::default(),
            };
            let signature = CryptoReturningOk::default()
                .sign(&response_metadata, node.node_id, registry_version)
                .unwrap();
            let share = Signed {
                content: response_metadata,
                signature,
            };
            self.canister_http_pool.write().unwrap().apply(vec![
                CanisterHttpChangeAction::AddToValidated(share.clone(), response.clone()),
            ]);
        }
    }

    /// Handles all the HTTP requests with provided closure,
    /// adds responses to the consensus responses queue and executes that payload.
    pub fn handle_http_call(
        &self,
        name: &str,
        mut f: impl FnMut(&CanisterHttpRequestContext) -> CanisterHttpResponsePayload,
    ) {
        let mut payload = PayloadBuilder::new();
        let contexts = self.canister_http_request_contexts();
        assert!(!contexts.is_empty(), "expected '{name}' HTTP request");
        for (id, context) in &contexts {
            let response = f(context);
            payload = payload.http_response(*id, &response);
        }
        self.execute_payload(payload);
    }

    fn build_sign_with_ecdsa_reply(
        &self,
        context: &SignWithThresholdContext,
    ) -> Result<SignWithECDSAReply, UserError> {
        assert!(context.is_ecdsa());

        if let Some(SignatureSecretKey::EcdsaSecp256k1(k)) =
            self.chain_key_subnet_secret_keys.get(&context.key_id())
        {
            let path = ic_secp256k1::DerivationPath::from_canister_id_and_path(
                context.request.sender.get().as_slice(),
                &context.derivation_path,
            );
            let dk = k.derive_subkey(&path).0;
            let signature = dk
                .sign_digest_with_ecdsa(&context.ecdsa_args().message_hash)
                .to_vec();
            Ok(SignWithECDSAReply { signature })
        } else {
            Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Subnet {} does not hold threshold key {}.",
                    self.subnet_id,
                    context.key_id()
                ),
            ))
        }
    }

    fn build_sign_with_schnorr_reply(
        &self,
        context: &SignWithThresholdContext,
    ) -> Result<SignWithSchnorrReply, UserError> {
        assert!(context.is_schnorr());

        let signature = match self.chain_key_subnet_secret_keys.get(&context.key_id()) {
            Some(SignatureSecretKey::SchnorrBip340(k)) => {
                let path = ic_secp256k1::DerivationPath::from_canister_id_and_path(
                    context.request.sender.get().as_slice(),
                    &context.derivation_path[..],
                );
                let (dk, _cc) = k.derive_subkey(&path);

                if let Some(ref aux) = context.schnorr_args().taproot_tree_root {
                    dk.sign_message_with_bip341_no_rng(&context.schnorr_args().message, aux)
                        .map(|v| v.to_vec())
                        .map_err(|_| {
                            UserError::new(
                                ErrorCode::CanisterRejectedMessage,
                                format!(
                                    "Invalid inputs for BIP341 signature with key {}",
                                    context.key_id()
                                ),
                            )
                        })?
                } else {
                    dk.sign_message_with_bip340_no_rng(&context.schnorr_args().message)
                        .to_vec()
                }
            }
            Some(SignatureSecretKey::Ed25519(k)) => {
                let path = ic_ed25519::DerivationPath::from_canister_id_and_path(
                    context.request.sender.get().as_slice(),
                    &context.derivation_path[..],
                );
                let (dk, _cc) = k.derive_subkey(&path);

                if context.schnorr_args().taproot_tree_root.is_some() {
                    return Err(UserError::new(
                        ErrorCode::CanisterRejectedMessage,
                        "Ed25519 does not use BIP341 aux parameter".to_string(),
                    ));
                }

                dk.sign_message(&context.schnorr_args().message).to_vec()
            }
            _ => {
                return Err(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    format!(
                        "Subnet {} does not hold threshold key {}.",
                        self.subnet_id,
                        context.key_id()
                    ),
                ));
            }
        };

        Ok(SignWithSchnorrReply { signature })
    }

    fn build_vetkd_derive_key_reply(
        &self,
        context: &SignWithThresholdContext,
    ) -> Result<VetKdDeriveKeyResult, UserError> {
        assert!(context.is_vetkd());

        if let Some(SignatureSecretKey::VetKD(k)) =
            self.chain_key_subnet_secret_keys.get(&context.key_id())
        {
            let vetkd_context: Vec<u8> =
                context.derivation_path.iter().flatten().cloned().collect();
            let encrypted_key = k.vetkd_protocol(
                context.request.sender.get().as_slice(),
                &vetkd_context,
                context.vetkd_args().input.as_ref(),
                &context.vetkd_args().transport_public_key,
                &[42; 32],
            );

            Ok(VetKdDeriveKeyResult { encrypted_key })
        } else {
            Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Subnet {} does not hold threshold key {}.",
                    self.subnet_id,
                    context.key_id()
                ),
            ))
        }
    }

    fn process_threshold_signing_request(
        &self,
        id: &CallbackId,
        context: &SignWithThresholdContext,
        payload: &mut PayloadBuilder,
    ) {
        match context.args {
            ThresholdArguments::Ecdsa(_) if self.is_ecdsa_signing_enabled => {
                match self.build_sign_with_ecdsa_reply(context) {
                    Ok(response) => {
                        payload.consensus_responses.push(ConsensusResponse::new(
                            *id,
                            MsgPayload::Data(response.encode()),
                        ));
                    }
                    Err(user_error) => {
                        payload.consensus_responses.push(ConsensusResponse::new(
                            *id,
                            MsgPayload::Reject(RejectContext::from(user_error)),
                        ));
                    }
                }
            }
            ThresholdArguments::Schnorr(_) if self.is_schnorr_signing_enabled => {
                match self.build_sign_with_schnorr_reply(context) {
                    Ok(response) => {
                        payload.consensus_responses.push(ConsensusResponse::new(
                            *id,
                            MsgPayload::Data(response.encode()),
                        ));
                    }
                    Err(user_error) => {
                        payload.consensus_responses.push(ConsensusResponse::new(
                            *id,
                            MsgPayload::Reject(RejectContext::from(user_error)),
                        ));
                    }
                }
            }
            ThresholdArguments::VetKd(_) if self.is_vetkd_enabled => {
                match self.build_vetkd_derive_key_reply(context) {
                    Ok(response) => {
                        payload.consensus_responses.push(ConsensusResponse::new(
                            *id,
                            MsgPayload::Data(response.encode()),
                        ));
                    }
                    Err(user_error) => {
                        payload.consensus_responses.push(ConsensusResponse::new(
                            *id,
                            MsgPayload::Reject(RejectContext::from(user_error)),
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    /// If set to true, the state machine will handle sign_with_ecdsa calls during `tick()`.
    pub fn set_ecdsa_signing_enabled(&mut self, value: bool) {
        self.is_ecdsa_signing_enabled = value;
    }

    /// If set to true, the state machine will handle sign_with_schnorr calls during `tick()`.
    pub fn set_schnorr_signing_enabled(&mut self, value: bool) {
        self.is_schnorr_signing_enabled = value;
    }

    /// If set to true, the state machine will handle vetkd_derive_key calls during `tick()`.
    pub fn set_vetkd_enabled(&mut self, value: bool) {
        self.is_vetkd_enabled = value;
    }

    /// Triggers a single round of execution without any new inputs.  The state
    /// machine will invoke heartbeats and make progress on pending async calls.
    pub fn tick(&self) {
        let mut payload = PayloadBuilder::default();
        let state = self.state_manager.get_latest_state().take();

        // Process threshold signing requests.
        for (id, context) in &state
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts
        {
            self.process_threshold_signing_request(id, context, &mut payload);
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
            panic!("The state machine did not reach completion after {max_ticks} ticks");
        }
    }

    /// Checks critical error counters and panics if a critical error occurred.
    pub fn check_critical_errors(&self) {
        let error_counter_vec = fetch_counter_vec(&self.metrics_registry, "critical_errors");
        if let Some((metric, _)) = error_counter_vec.into_iter().find(|(_, v)| *v != 0.0) {
            let err: String = metric.get("error").unwrap().to_string();
            panic!("Critical error {err} occurred.");
        }
    }

    /// Advances time by 1ns (to make sure time is strictly monotone)
    /// and triggers a single round of execution with block payload as an input.
    pub fn execute_payload(&self, payload: PayloadBuilder) -> Height {
        let batch_number = self.message_routing.expected_batch_height();

        let mut seed = [0u8; 32];
        // use the batch number to seed randomness
        seed[..8].copy_from_slice(batch_number.get().to_le_bytes().as_slice());

        // Use the `batch_summary` explicitly set, or create a new one based
        // on the `checkpoint_interval_length`.
        let checkpoint_interval_length = self.checkpoint_interval_length.load(Ordering::Relaxed);
        let checkpoint_interval_length_plus_one = checkpoint_interval_length.saturating_add(1);
        let full_intervals: u64 = batch_number.get() / checkpoint_interval_length_plus_one;
        let next_checkpoint_height = (full_intervals + 1) * checkpoint_interval_length_plus_one;
        let batch_summary = self.batch_summary.clone().or(Some(BatchSummary {
            next_checkpoint_height: next_checkpoint_height.into(),
            current_interval_length: checkpoint_interval_length.into(),
        }));
        let requires_full_state_hash = batch_number
            .get()
            .is_multiple_of(checkpoint_interval_length_plus_one);

        let current_time = self.get_time();
        let time_of_next_round = if current_time == *self.time_of_last_round.read().unwrap() {
            current_time + Self::EXECUTE_ROUND_TIME_INCREMENT
        } else {
            current_time
        };

        let blockmaker_metrics = payload
            .blockmaker_metrics
            .unwrap_or(BlockmakerMetrics::new_for_test());

        let batch = Batch {
            batch_number,
            batch_summary,
            requires_full_state_hash,
            blockmaker_metrics,
            content: BatchContent::Data(BatchMessages {
                signed_ingress_msgs: payload.ingress_messages,
                certified_stream_slices: payload.xnet_payload.stream_slices,
                bitcoin_adapter_responses: payload
                    .self_validating
                    .map(|p| p.get().to_vec())
                    .unwrap_or_default(),
                query_stats: payload.query_stats,
            }),
            randomness: Randomness::from(seed),
            chain_key_data: ChainKeyData {
                master_public_keys: self.chain_key_subnet_public_keys.clone(),
                idkg_pre_signatures: BTreeMap::new(),
                nidkg_ids: self.ni_dkg_ids.clone(),
            },
            registry_version: self.registry_client.get_latest_version(),
            time: time_of_next_round,
            consensus_responses: payload.consensus_responses,
            replica_version: ReplicaVersion::default(),
        };

        self.message_routing
            .process_batch(batch)
            .expect("Could not process batch");

        if self.remove_old_states {
            self.state_manager.remove_states_below(batch_number);
        }
        assert_eq!(self.state_manager.latest_state_height(), batch_number);

        self.check_critical_errors();

        self.set_time(time_of_next_round.into());
        *self.time_of_last_round.write().unwrap() = time_of_next_round;

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

    /// Get the time stored in the latest state. This is useful when starting
    /// the `StateMachine` on an already existing state since time
    /// must be monotone and thus the time of the `StateMachine`
    /// which is used when executing rounds must be set to be
    /// no smaller than the time stored in the latest state.
    pub fn get_state_time(&self) -> Time {
        let replicated_state = self.state_manager.get_latest_state().take();
        replicated_state.metadata.batch_time
    }

    /// Sets the time that the state machine will use for executing next
    /// messages.
    pub fn set_time(&self, time: SystemTime) {
        let t = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let time = Time::from_nanos_since_unix_epoch(t);
        self.consensus_time.set(time);
        self.time.store(t, Ordering::Relaxed);
        self.time_source
            .set_time(time)
            .unwrap_or_else(|_| error!(self.replica_logger, "Time went backwards."));
    }

    /// Certifies the specified time by modifying the time in the replicated state
    /// and certifying that new state.
    pub fn set_certified_time(&self, time: SystemTime) {
        let t = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let time = Time::from_nanos_since_unix_epoch(t);
        let (height, mut replicated_state) = self.state_manager.take_tip();
        replicated_state.metadata.batch_time = time;
        self.state_manager.commit_and_certify(
            replicated_state,
            height.increment(),
            CertificationScope::Metadata,
            None,
        );
        self.set_time(time.into());
        *self.time_of_last_round.write().unwrap() = time;
    }

    /// Returns the current state machine time.
    /// The time of a round executed by this state machine equals its current time
    /// if its current time increased since the last round.
    /// Otherwise, the current time is implicitly increased by `StateMachine::EXECUTE_ROUND_TIME_INCREMENT` (1ns)
    /// before executing the next round.
    pub fn time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(self.time.load(Ordering::Relaxed))
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
        self.state_manager.flush_tip_channel();
        let h = self.state_manager.latest_state_height();
        let started_at = Instant::now();
        loop {
            let elapsed = started_at.elapsed();
            if elapsed > Duration::from_secs(5 * 60) {
                panic!("State hash computation took too long ({elapsed:?})");
            }
            match self.state_manager.get_state_hash_at(h) {
                Ok(hash) => return hash,
                Err(StateHashError::Transient(_)) => {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e @ StateHashError::Permanent(_)) => {
                    panic!("Failed to compute state hash: {e}")
                }
            }
        }
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
    /// This function is useful for local testing and debugging. Do not remove it.
    ///
    /// # Panics
    ///
    /// This function panics if loading the canister snapshot fails.
    pub fn import_canister_state<P: AsRef<Path>>(
        &self,
        canister_directory: P,
        canister_id: CanisterId,
    ) {
        use ic_replicated_state::testing::SystemStateTesting;

        let canister_directory = canister_directory.as_ref();
        assert!(
            canister_directory.is_dir(),
            "canister state at {} must be a directory",
            canister_directory.display()
        );

        let tip: CheckpointLayout<ReadOnly> = CheckpointLayout::new_untracked(
            self.state_manager.state_layout().raw_path().join("tip"),
            ic_types::Height::new(0),
        )
        .expect("failed to obtain tip");
        let tip_canister_layout = tip
            .canister(&canister_id)
            .expect("failed to obtain canister layout");
        std::fs::create_dir_all(tip_canister_layout.raw_path())
            .expect("Failed to create checkpoint dir");

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

        // A `CheckpointLoadingMetrics` that panics on broken soft invariants.
        struct StrictCheckpointLoadingMetrics;
        impl CheckpointLoadingMetrics for StrictCheckpointLoadingMetrics {
            fn observe_broken_soft_invariant(&self, msg: String) {
                panic!("{}", msg);
            }
        }

        let mut canister_state = ic_state_manager::checkpoint::load_canister_state(
            &tip_canister_layout,
            &canister_id,
            ic_types::Height::new(0),
            self.state_manager.get_fd_factory(),
            &StrictCheckpointLoadingMetrics,
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

        // Repartition input schedules; Required step for migrating canisters.
        canister_state
            .system_state
            .split_input_schedules(&canister_id, &state.canister_states);

        state.put_canister_state(canister_state);

        self.state_manager.commit_and_certify(
            state,
            h.increment(),
            CertificationScope::Metadata,
            None,
        );
    }

    // Enable checkpoints and make a tick to write a checkpoint.
    pub fn checkpointed_tick(&self) {
        let checkpoint_interval_length = self.checkpoint_interval_length.load(Ordering::Relaxed);
        self.set_checkpoints_enabled(true);
        self.tick();
        self.set_checkpoint_interval_length(checkpoint_interval_length);
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
        self.checkpointed_tick();
        let (h, mut state) = self.state_manager.take_tip();
        state.put_canister_state(source_state.canister_state(&canister_id).unwrap().clone());
        self.state_manager
            .commit_and_certify(state, h.increment(), CertificationScope::Full, None);
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
        self.checkpointed_tick();

        let (height, mut state) = self.state_manager.take_tip();
        if state.take_canister_state(&canister_id).is_some() {
            self.state_manager.commit_and_certify(
                state,
                height.increment(),
                CertificationScope::Full,
                None,
            );
            self.state_manager.flush_tip_channel();

            other_env.import_canister_state(
                self.state_manager
                    .state_layout()
                    .checkpoint_verified(height)
                    .unwrap()
                    .canister(&canister_id)
                    .unwrap()
                    .raw_path(),
                canister_id,
            );

            return Ok(());
        }
        Err(format!("No canister state for canister id {canister_id}."))
    }

    /// Produces a routing table, a canister migrations list and a subnet list record that reflects
    /// splitting this subnet; then passes them to the registry data provider.
    ///
    /// Does not update the registry client on this subnet.
    ///
    /// This is intended to be used before calling `split` simulating a split of this subnet. Having
    /// this as a separate step allows for other subnets to observe this update before this subnet
    /// undergoes the split, which is a highly likely situation in a real subnet split.
    ///
    /// Note: An actual observation is done only after updating the registry client to the newest version.
    ///       Since this functions does not update the registry client, this can be done at any point on
    ///       any subnet in the same subnet pool as this one, i.e. before, at or after the actual split.
    pub fn make_registry_entries_for_subnet_split(
        &self,
        seed: [u8; 32],
        canister_range: std::ops::RangeInclusive<CanisterId>,
    ) {
        use ic_registry_client_helpers::routing_table::RoutingTableRegistry;
        use ic_registry_client_helpers::subnet::SubnetListRegistry;

        // Generate new subnet Id from `seed`.
        let (ni_dkg_transcript, _) =
            dummy_initial_dkg_transcript_with_master_key(&mut StdRng::from_seed(seed));
        let public_key = (&ni_dkg_transcript).try_into().unwrap();
        let public_key_der = threshold_sig_public_key_to_der(public_key).unwrap();
        let subnet_id = PrincipalId::new_self_authenticating(&public_key_der).into();

        // Generate the ranges to be added to the routing table and canister migrations list.
        let ranges = CanisterIdRanges::try_from(vec![CanisterIdRange {
            start: *canister_range.start(),
            end: *canister_range.end(),
        }])
        .unwrap();

        let last_version = self.registry_client.get_latest_version();
        let next_version = last_version.increment();

        // Adapt the routing table and add it to the registry data provider.
        let mut routing_table = self
            .registry_client
            .get_routing_table(last_version)
            .expect("malformed routing table")
            .expect("missing routing table");

        routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
        routing_table
            .assign_ranges(ranges.clone(), subnet_id)
            .expect("ranges are not well formed");

        let pb_routing_table = PbRoutingTable::from(routing_table);
        self.registry_data_provider
            .add(
                &make_canister_ranges_key(CanisterId::from_u64(0)),
                next_version,
                Some(pb_routing_table),
            )
            .unwrap();

        // Adapt the canister migrations list.
        let mut canister_migrations = self
            .registry_client
            .get_canister_migrations(last_version)
            .expect("malformed canister migrations")
            .unwrap_or_default();

        canister_migrations
            .insert_ranges(ranges, self.get_subnet_id(), subnet_id)
            .expect("ranges are not well formed");

        self.registry_data_provider
            .add(
                &make_canister_migrations_record_key(),
                next_version,
                Some(PbCanisterMigrations::from(canister_migrations)),
            )
            .unwrap();

        // Extend subnet list record.
        let mut subnet_ids = self
            .registry_client
            .get_subnet_ids(last_version)
            .expect("malformed subnet list")
            .unwrap_or_default();

        let initial_len = subnet_ids.len();
        subnet_ids.push(subnet_id);
        subnet_ids.sort();
        subnet_ids.dedup();
        assert!(subnet_ids.len() > initial_len);

        add_subnet_list_record(&self.registry_data_provider, next_version.get(), subnet_ids);

        // Add subnet initial records for the new subnet that will be created at the split.
        let features = SubnetFeatures {
            http_requests: true,
            ..SubnetFeatures::default()
        };
        let subnet_size = self.nodes.len();
        let mut node_rng = StdRng::from_seed(seed);
        let nodes: Vec<StateMachineNode> = (0..subnet_size)
            .map(|_| StateMachineNode::new(&mut node_rng))
            .collect();

        let chain_keys_enabled_status = Default::default();

        add_subnet_local_registry_records(
            subnet_id,
            self.subnet_type,
            features,
            &nodes,
            public_key,
            &chain_keys_enabled_status,
            ni_dkg_transcript,
            self.registry_data_provider.clone(),
            next_version,
        );
    }

    /// Simulates a subnet split where the corresponding registry entries are assumed to be done
    /// beforehand, i.e. `make_registry_entries_for_subnet_split` should be called first using the
    /// same `seed`.
    ///
    /// The process has the following steps:
    /// - Write a checkpoint on `self`.
    /// - Clone its enire state directory into a new `state_dir`.
    /// - Create a new `StateMachine` using this `state_dir` and the provided `seed`.
    /// - Reloads the registry und updates it to the latest version.
    /// - Get the routing table from the registry and use it to perform the split.
    ///
    /// Returns an error if the routing table does not contain the subnet Id of the new `env` that
    /// was just created or if the split itself fails.
    pub fn split(&self, seed: [u8; 32]) -> Result<Arc<StateMachine>, String> {
        use ic_registry_client_helpers::routing_table::RoutingTableRegistry;

        // Write a checkpoint.
        self.checkpointed_tick();
        self.state_manager.flush_tip_channel();

        // Create a state dir for the new env; then clone the contents of the entire state directory.
        let state_dir = Box::new(TempDir::new().expect("failed to create a temporary directory"));
        fs_extra::dir::copy(
            self.state_manager.state_layout().raw_path(),
            state_dir.path(),
            &fs_extra::dir::CopyOptions {
                content_only: true,
                ..fs_extra::dir::CopyOptions::new()
            },
        )
        .expect("failed to clone state directory.");

        // Create a new `StateMachine` using the same XNet pool.
        let env = StateMachineBuilder::new()
            .with_state_machine_state_dir(state_dir)
            .with_nonce(self.nonce.load(Ordering::Relaxed))
            .with_time(Time::from_nanos_since_unix_epoch(
                self.time.load(Ordering::Relaxed),
            ))
            .with_checkpoint_interval_length(
                self.checkpoint_interval_length.load(Ordering::Relaxed),
            )
            .with_subnet_size(self.nodes.len())
            .with_subnet_seed(seed)
            .with_subnet_type(self.subnet_type)
            .with_registry_data_provider(self.registry_data_provider.clone())
            .build_with_subnets(
                (*self.pocket_xnet.read().unwrap())
                    .as_ref()
                    .ok_or("no XNet layer found")?
                    .subnets(),
            );

        // Get the newest registry version.
        self.reload_registry();
        self.registry_client.update_to_latest_version();

        // Get the routing table.
        let last_version = self.registry_client.get_latest_version();
        let routing_table = self
            .registry_client
            .get_routing_table(last_version)
            .expect("malformed routing table")
            .expect("missing routing table");

        // Check the new subnet is in this routing table.
        if routing_table.ranges(env.get_subnet_id()).is_empty() {
            return Err("Routing table does not contain the new subnet".to_string());
        }

        // Perform the split on `self`.
        let (height, state) = self.state_manager.take_tip();
        let mut state = state.split(self.get_subnet_id(), &routing_table, None)?;
        state.after_split();

        self.state_manager.commit_and_certify(
            state,
            height.increment(),
            CertificationScope::Full,
            None,
        );

        // Perform the split on `env`, which requires preserving the `prev_state_hash`
        // (as opposed to MVP subnet splitting where it is adjusted manually).
        let (height, state) = env.state_manager.take_tip();
        let prev_state_hash = state.metadata.prev_state_hash.clone();
        let mut state = state.split(env.get_subnet_id(), &routing_table, None)?;
        state.metadata.prev_state_hash = prev_state_hash;
        state.after_split();

        env.state_manager.commit_and_certify(
            state,
            height.increment(),
            CertificationScope::Full,
            None,
        );

        Ok(env)
    }

    /// Returns the controllers of a canister or `None` if the canister does not exist.
    pub fn get_controllers(&self, canister_id: CanisterId) -> Option<Vec<PrincipalId>> {
        let state = self.state_manager.get_latest_state().take();
        state
            .canister_state(&canister_id)
            .map(|s| s.controllers().iter().cloned().collect())
    }

    pub fn install_wasm_in_mode(
        &self,
        canister_id: CanisterId,
        mode: CanisterInstallMode,
        wasm: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        let sender = self
            .get_controllers(canister_id)
            .map(|controllers| {
                controllers
                    .into_iter()
                    .next()
                    .unwrap_or(PrincipalId::new_anonymous())
            })
            .unwrap_or(PrincipalId::new_anonymous());
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::InstallCode,
            InstallCodeArgs::new(mode, canister_id, wasm, payload).encode(),
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

    /// Creates a new canister and returns the canister principal.
    pub fn create_canister_with_cycles(
        &self,
        specified_id: Option<PrincipalId>,
        cycles: Cycles,
        settings: Option<CanisterSettingsArgs>,
    ) -> CanisterId {
        let wasm_result = self
            .create_canister_with_cycles_impl(specified_id, cycles, settings)
            .expect("failed to create canister");
        match wasm_result {
            WasmResult::Reply(bytes) => CanisterIdRecord::decode(&bytes[..])
                .expect("failed to decode canister ID record")
                .get_canister_id(),
            WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
        }
    }

    /// Creates a new canister.
    pub fn create_canister_with_cycles_impl(
        &self,
        specified_id: Option<PrincipalId>,
        cycles: Cycles,
        settings: Option<CanisterSettingsArgs>,
    ) -> Result<WasmResult, UserError> {
        self.execute_ingress(
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

    fn get_controller(&self, canister_id: &CanisterId) -> PrincipalId {
        let state = self.state_manager.get_latest_state().take();
        state
            .canister_state(canister_id)
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous)
    }

    /// Create a canister snapshot.
    pub fn take_canister_snapshot(
        &self,
        args: TakeCanisterSnapshotArgs,
    ) -> Result<CanisterSnapshotResponse, UserError> {
        let sender = self.get_controller(&args.get_canister_id());
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::TakeCanisterSnapshot,
            args.encode(),
        )
        .map(|res| match res {
            WasmResult::Reply(data) => CanisterSnapshotResponse::decode(&data),
            WasmResult::Reject(reason) => {
                panic!("take_canister_snapshot call rejected: {reason}")
            }
        })?
    }

    /// Load the canister state from a canister snapshot.
    pub fn load_canister_snapshot(
        &self,
        args: LoadCanisterSnapshotArgs,
    ) -> Result<Vec<u8>, UserError> {
        let sender = self.get_controller(&args.get_canister_id());
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::LoadCanisterSnapshot,
            args.encode(),
        )
        .map(|res| match res {
            WasmResult::Reply(data) => Ok(data),
            WasmResult::Reject(reason) => {
                panic!("load_canister_snapshot call rejected: {reason}")
            }
        })?
    }

    pub fn read_canister_snapshot_metadata(
        &self,
        args: &ReadCanisterSnapshotMetadataArgs,
    ) -> Result<ReadCanisterSnapshotMetadataResponse, UserError> {
        let sender = self.get_controller(&args.get_canister_id());
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::ReadCanisterSnapshotMetadata,
            args.encode(),
        )
        .map(|res| match res {
            WasmResult::Reply(data) => ReadCanisterSnapshotMetadataResponse::decode(&data),
            WasmResult::Reject(reason) => {
                panic!("read_canister_snapshot_metadata call rejected: {reason}")
            }
        })?
    }

    pub fn read_canister_snapshot_data(
        &self,
        args: &ReadCanisterSnapshotDataArgs,
    ) -> Result<ReadCanisterSnapshotDataResponse, UserError> {
        let sender = self.get_controller(&args.get_canister_id());
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::ReadCanisterSnapshotData,
            args.encode(),
        )
        .map(|res| match res {
            WasmResult::Reply(data) => ReadCanisterSnapshotDataResponse::decode(&data),
            WasmResult::Reject(reason) => {
                panic!("read_canister_snapshot_data call rejected: {reason}")
            }
        })?
    }

    /// Helper to download the whole snapshot chunk store.
    pub fn get_snapshot_chunk_store(
        &self,
        args: &ReadCanisterSnapshotMetadataArgs,
    ) -> Result<HashMap<Vec<u8>, Vec<u8>>, UserError> {
        let md = self.read_canister_snapshot_metadata(args)?;
        let chunk_hashes = md.wasm_chunk_store;
        let mut res = HashMap::new();
        for hash in chunk_hashes.into_iter() {
            let ReadCanisterSnapshotDataResponse { chunk } =
                self.read_canister_snapshot_data(&ReadCanisterSnapshotDataArgs {
                    canister_id: args.canister_id,
                    snapshot_id: args.snapshot_id,
                    kind: CanisterSnapshotDataKind::WasmChunk {
                        hash: hash.hash.clone(),
                    },
                })?;
            res.insert(hash.hash, chunk);
        }
        Ok(res)
    }

    /// Helper to download the whole snapshot canister module.
    pub fn get_snapshot_module(
        &self,
        args: &ReadCanisterSnapshotMetadataArgs,
    ) -> Result<Vec<u8>, UserError> {
        self.get_snapshot_blob(
            args,
            |md: &ReadCanisterSnapshotMetadataResponse| md.wasm_module_size,
            |offset, size| CanisterSnapshotDataKind::WasmModule { offset, size },
        )
    }

    /// Helper to download the whole snapshot canister heap.
    pub fn get_snapshot_heap(
        &self,
        args: &ReadCanisterSnapshotMetadataArgs,
    ) -> Result<Vec<u8>, UserError> {
        self.get_snapshot_blob(
            args,
            |md: &ReadCanisterSnapshotMetadataResponse| md.wasm_memory_size,
            |offset, size| CanisterSnapshotDataKind::WasmMemory { offset, size },
        )
    }

    /// Helper to download the whole snapshot canister stable memory.
    pub fn get_snapshot_stable_memory(
        &self,
        args: &ReadCanisterSnapshotMetadataArgs,
    ) -> Result<Vec<u8>, UserError> {
        self.get_snapshot_blob(
            args,
            |md: &ReadCanisterSnapshotMetadataResponse| md.stable_memory_size,
            |offset, size| CanisterSnapshotDataKind::StableMemory { offset, size },
        )
    }

    /// Downloads one of the snapshot blobs as a whole.
    /// Takes two selector closures that determine which blob to target:
    /// Canister module, heap or stable memory.
    fn get_snapshot_blob(
        &self,
        args: &ReadCanisterSnapshotMetadataArgs,
        size_extractor: impl Fn(&ReadCanisterSnapshotMetadataResponse) -> u64,
        kind_gen: impl Fn(u64, u64) -> CanisterSnapshotDataKind,
    ) -> Result<Vec<u8>, UserError> {
        let md = self.read_canister_snapshot_metadata(args)?;
        let mut res = vec![];
        let module_size = size_extractor(&md);
        let mut start = 0;
        while start < module_size {
            let size = u64::min(SNAPSHOT_DATA_CHUNK_SIZE, module_size - start);
            let args = ReadCanisterSnapshotDataArgs {
                canister_id: args.canister_id,
                snapshot_id: args.snapshot_id,
                kind: kind_gen(start, size),
            };
            start += size;
            let mut bytes = self.read_canister_snapshot_data(&args)?.chunk;
            res.append(&mut bytes);
        }
        Ok(res)
    }

    pub fn upload_canister_snapshot_metadata(
        &self,
        args: &UploadCanisterSnapshotMetadataArgs,
    ) -> Result<UploadCanisterSnapshotMetadataResponse, UserError> {
        let sender = self.get_controller(&args.get_canister_id());
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::UploadCanisterSnapshotMetadata,
            args.encode(),
        )
        .map(|res| match res {
            WasmResult::Reply(data) => UploadCanisterSnapshotMetadataResponse::decode(&data),
            WasmResult::Reject(reason) => {
                panic!("upload_canister_snapshot_metadata call rejected: {reason}")
            }
        })?
    }

    pub fn upload_canister_snapshot_data(
        &self,
        args: &UploadCanisterSnapshotDataArgs,
    ) -> Result<(), UserError> {
        let sender = self.get_controller(&args.get_canister_id());
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::UploadCanisterSnapshotData,
            args.encode(),
        )
        .map(|res| match res {
            WasmResult::Reply(data) => Decode!(&data, ()).unwrap(),
            WasmResult::Reject(reason) => {
                panic!("upload_canister_snapshot_data call rejected: {reason}")
            }
        })
    }

    /// Uploads `data` to a canister snapshot's module by calling `upload_canister_snapshot_data`
    /// as often as necessary with chunks of size `SNAPSHOT_DATA_CHUNK_SIZE`.
    ///
    /// If given, skips `start_chunk` number of chunks.
    /// If given, only uploads until `end_chunk` (or until complete, whichever happens earlier).
    pub fn upload_snapshot_module(
        &self,
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        data: impl AsRef<[u8]>,
        start_chunk: Option<usize>,
        end_chunk: Option<usize>,
    ) -> Result<(), UserError> {
        self.upload_snapshot_blob(
            canister_id,
            snapshot_id,
            data,
            start_chunk,
            end_chunk,
            |x| CanisterSnapshotDataOffset::WasmModule { offset: x },
        )
    }

    /// Uploads `data` to a canister snapshot's heap by calling `upload_canister_snapshot_data`
    /// as often as necessary with chunks of size `SNAPSHOT_DATA_CHUNK_SIZE`.
    ///
    /// If given, skips `start_chunk` number of chunks.
    /// If given, only uploads until `end_chunk` (or until complete, whichever happens earlier).
    pub fn upload_snapshot_heap(
        &self,
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        data: impl AsRef<[u8]>,
        start_chunk: Option<usize>,
        end_chunk: Option<usize>,
    ) -> Result<(), UserError> {
        self.upload_snapshot_blob(
            canister_id,
            snapshot_id,
            data,
            start_chunk,
            end_chunk,
            |x| CanisterSnapshotDataOffset::WasmMemory { offset: x },
        )
    }

    /// Uploads `data` to a canister snapshot's stable memory by calling `upload_canister_snapshot_data`
    /// as often as necessary with chunks of size `SNAPSHOT_DATA_CHUNK_SIZE`.
    ///
    /// If given, skips `start_chunk` number of chunks.
    /// If given, only uploads until `end_chunk` (or until complete, whichever happens earlier).
    pub fn upload_snapshot_stable_memory(
        &self,
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        data: impl AsRef<[u8]>,
        start_chunk: Option<usize>,
        end_chunk: Option<usize>,
    ) -> Result<(), UserError> {
        self.upload_snapshot_blob(
            canister_id,
            snapshot_id,
            data,
            start_chunk,
            end_chunk,
            |x| CanisterSnapshotDataOffset::StableMemory { offset: x },
        )
    }

    /// Uploads `data` to one of the canister snapshot's blobs (wasm module, heap, stable memory)
    /// by calling `upload_canister_snapshot_data` as often as necessary with chunks of size
    /// `SNAPSHOT_DATA_CHUNK_SIZE`.
    /// The targeted blob is determined by the `kind_gen` selector closure.
    ///
    /// If given, skips `start_chunk` number of chunks.
    /// If given, only uploads until `end_chunk` (or until complete, whichever happens earlier).
    fn upload_snapshot_blob(
        &self,
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        data: impl AsRef<[u8]>,
        start_chunk: Option<usize>,
        end_chunk: Option<usize>,
        kind_gen: impl Fn(u64) -> CanisterSnapshotDataOffset,
    ) -> Result<(), UserError> {
        let data_size = data.as_ref().len() as u64;
        let mut cnt = 0;
        let mut start = 0;
        while start < data_size {
            let size = u64::min(SNAPSHOT_DATA_CHUNK_SIZE, data_size - start);
            if start_chunk.is_some() && cnt < *start_chunk.as_ref().unwrap()
                || end_chunk.is_some() && cnt >= *end_chunk.as_ref().unwrap()
            {
                start += size;
                cnt += 1;
                continue;
            }
            let kind = kind_gen(start);
            let chunk = data.as_ref()[start as usize..(start + size) as usize].to_vec();
            let args = UploadCanisterSnapshotDataArgs {
                canister_id: canister_id.into(),
                snapshot_id,
                kind,
                chunk,
            };
            self.upload_canister_snapshot_data(&args)?;
            start += size;
            cnt += 1;
        }
        Ok(())
    }

    /// Upload a chunk to the wasm chunk store.
    pub fn upload_chunk(&self, args: UploadChunkArgs) -> Result<UploadChunkReply, UserError> {
        let state = self.state_manager.get_latest_state().take();
        let sender = state
            .canister_state(&args.get_canister_id())
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous);
        self.execute_ingress_as(sender, ic00::IC_00, Method::UploadChunk, args.encode())
            .map(|res| match res {
                WasmResult::Reply(data) => UploadChunkReply::decode(&data),
                WasmResult::Reject(reason) => {
                    panic!("upload_chunk call rejected: {reason}")
                }
            })?
    }

    /// Install code from the wasm chunk store.
    pub fn install_chunked_code(&self, args: InstallChunkedCodeArgs) -> Result<(), UserError> {
        let state = self.state_manager.get_latest_state().take();
        let sender = state
            .canister_state(&args.target_canister_id())
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous);
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::InstallChunkedCode,
            args.encode(),
        )
        .map(|_| ())
    }

    /// Clear the wasm chunk store.
    pub fn clear_chunk_store(&self, canister_id: CanisterId) -> Result<(), UserError> {
        let state = self.state_manager.get_latest_state().take();
        let sender = state
            .canister_state(&canister_id)
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous);
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::ClearChunkStore,
            ClearChunkStoreArgs {
                canister_id: canister_id.into(),
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

    /// Returns all the canister ids.
    pub fn get_canister_ids(&self) -> Vec<CanisterId> {
        self.state_manager
            .get_latest_state()
            .take()
            .canister_states
            .keys()
            .cloned()
            .collect()
    }

    /// Returns true if the canister with the specified id exists and is not empty.
    pub fn canister_not_empty(&self, canister: CanisterId) -> bool {
        self.state_manager
            .get_latest_state()
            .take()
            .canister_states
            .get(&canister)
            .map(|canister| canister.execution_state.is_some())
            .unwrap_or_default()
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
        delegation: Option<(CertificateDelegation, CertificateDelegationMetadata)>,
    ) -> Result<WasmResult, UserError> {
        self.certify_latest_state();
        let user_query = Query {
            source: QuerySource::User {
                user_id: UserId::from(sender),
                ingress_expiry: 0,
                nonce: None,
            },
            receiver,
            method_name: method.to_string(),
            method_payload,
        };
        let query_svc = self.query_handler.lock().unwrap().clone();
        let input = QueryExecutionInput {
            query: user_query,
            certificate_delegation_with_metadata: delegation,
        };
        if let Ok((result, _)) = self.runtime.block_on(query_svc.oneshot(input)).unwrap() {
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
        // Largest single message is 1T for system subnet install messages
        // Considered with 2B instruction slices, this gives us 500 ticks
        const MAX_TICKS: usize = 500;
        let msg_id = self.send_ingress_safe(sender, canister_id, method, payload)?;
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

    fn ingress_message(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> SignedIngress {
        // Build `SignedIngress` with maximum ingress expiry and unique nonce,
        // omitting delegations and signatures.
        let ingress_expiry = (self.get_time() + MAX_INGRESS_TTL).as_nanos_since_unix_epoch();
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);
        let nonce_blob = Some(nonce.to_le_bytes().into());
        SignedIngress::try_from(HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(canister_id.get().into_vec()),
                    method_name: method.to_string(),
                    arg: Blob(payload.clone()),
                    sender: sender.into(),
                    ingress_expiry,
                    nonce: nonce_blob,
                },
            },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        })
        .unwrap()
    }

    pub fn ingress_message_cost(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> IngressInductionCost {
        let msg = self.ingress_message(sender, canister_id, method, payload);
        let effective_canister_id = extract_effective_canister_id(msg.content()).unwrap();
        let subnet_size = self.nodes.len();
        self.cycles_account_manager.ingress_induction_cost(
            &msg,
            effective_canister_id,
            subnet_size,
            self.cost_schedule,
        )
    }

    /// Sends an ingress message to the canister with the specified ID.
    ///
    /// This function is asynchronous. It returns the ID of the ingress message
    /// that can be awaited later with [await_ingress].
    pub fn send_ingress_safe(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<MessageId, UserError> {
        let msg = self.ingress_message(sender, canister_id, method, payload);

        // Fetch ingress validation settings from the registry.
        let registry_version = self.registry_client.get_latest_version();
        let provisional_whitelist = self
            .registry_client
            .get_provisional_whitelist(registry_version)
            .unwrap()
            .unwrap();

        // Run `IngressFilter` on the ingress message.
        let ingress_filter = self.ingress_filter.lock().unwrap().clone();
        self.runtime
            .block_on(ingress_filter.oneshot((provisional_whitelist, msg.clone())))
            .unwrap()?;

        let msg_id = msg.content().id();
        let builder = PayloadBuilder::new().signed_ingress(msg);
        self.execute_payload(builder);
        Ok(msg_id)
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
        self.send_ingress_safe(sender, canister_id, method, payload)
            .unwrap()
    }

    /// Returns the status of the ingress message with the specified ID.
    pub fn ingress_status(&self, msg_id: &MessageId) -> IngressStatus {
        (self.ingress_history_reader.get_latest_status())(msg_id)
    }

    /// Returns the caller of the ingress message with the specified ID if available.
    pub fn ingress_caller(&self, msg_id: &MessageId) -> Option<UserId> {
        self.get_latest_state().get_ingress_status(msg_id).user_id()
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

        let pb_routing_table = PbRoutingTable::from(routing_table);
        self.registry_data_provider
            .add(
                &make_canister_ranges_key(CanisterId::from_u64(0)),
                next_version,
                Some(pb_routing_table.clone()),
            )
            .unwrap();
        self.registry_client.update_to_latest_version();

        assert_eq!(next_version, self.registry_client.get_latest_version());
    }

    /// Returns the subnet type of this state machine.
    pub fn get_subnet_type(&self) -> SubnetType {
        self.subnet_type
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
            .unwrap_or_else(|| panic!("Canister {canister_id} does not exist"))
            .execution_state
            .as_ref()
            .unwrap_or_else(|| panic!("Canister {canister_id} has no module"))
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
            .unwrap_or_else(|| panic!("Canister {canister_id} does not exist"));
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
            .unwrap_or_else(|| panic!("Canister {canister_id} does not exist"));
        let size = data.len().div_ceil(WASM_PAGE_SIZE_IN_BYTES);
        let memory = Memory::new(PageMap::from(data), NumWasmPages::new(size));
        canister_state
            .execution_state
            .as_mut()
            .unwrap_or_else(|| panic!("Canister {canister_id} has no module"))
            .stable_memory = memory;
        self.state_manager.commit_and_certify(
            replicated_state,
            height.increment(),
            CertificationScope::Metadata,
            None,
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
            .unwrap_or_else(|| panic!("Canister {canister_id} not found"))
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
            .unwrap_or_else(|| panic!("Canister {canister_id} not found"))
            .scheduler_state
            .total_query_stats = total_query_stats;

        self.state_manager.commit_and_certify(
            state,
            h.increment(),
            CertificationScope::Metadata,
            None,
        );
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
            .unwrap_or_else(|| panic!("Canister {canister_id} not found"))
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
            .unwrap_or_else(|| panic!("Canister {canister_id} not found"));
        canister_state
            .system_state
            .add_cycles(Cycles::from(amount), CyclesUseCase::NonConsumed);
        let balance = canister_state.system_state.balance().get();
        self.state_manager.commit_and_certify(
            state,
            height.increment(),
            CertificationScope::Metadata,
            None,
        );
        balance
    }

    /// Returns `sign_with_ecdsa` contexts from internal subnet call context manager.
    pub fn sign_with_ecdsa_contexts(&self) -> BTreeMap<CallbackId, SignWithThresholdContext> {
        let state = self.state_manager.get_latest_state().take();
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_ecdsa_contexts()
    }

    /// Returns `sign_with_schnorr` contexts from internal subnet call context manager.
    pub fn sign_with_schnorr_contexts(&self) -> BTreeMap<CallbackId, SignWithThresholdContext> {
        let state = self.state_manager.get_latest_state().take();
        state
            .metadata
            .subnet_call_context_manager
            .sign_with_schnorr_contexts()
    }

    /// Returns `vetkd_derive_key` contexts from internal subnet call context manager.
    pub fn vetkd_derive_key_contexts(&self) -> BTreeMap<CallbackId, SignWithThresholdContext> {
        let state = self.state_manager.get_latest_state().take();
        state
            .metadata
            .subnet_call_context_manager
            .vetkd_derive_key_contexts()
    }

    /// Returns canister HTTP request contexts from internal subnet call context manager.
    pub fn canister_http_request_contexts(
        &self,
    ) -> BTreeMap<CallbackId, CanisterHttpRequestContext> {
        let request_ids_already_made: BTreeSet<_> = self
            .canister_http_pool
            .read()
            .unwrap()
            .get_validated_shares()
            .map(|share| share.content.id)
            .collect();
        let state = self.state_manager.get_latest_state().take();
        state
            .metadata
            .subnet_call_context_manager
            .canister_http_request_contexts
            .clone()
            .into_iter()
            .filter(|(id, _)| !request_ids_already_made.contains(id))
            .collect()
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

    /// Execute a block containing the latest xnet payload.
    /// This function assumes the `StateMachine` was built with `StatMachineBuilder::build_with_subnets`.
    pub fn execute_xnet(&self) {
        self.certify_latest_state();
        let certified_height = self.state_manager.latest_certified_height();
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
        self.pocket_xnet
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .refill(registry_version, self.replica_logger.clone());
        let payload_builder = self.payload_builder.read().unwrap();
        let payload_builder = payload_builder.as_ref().unwrap();
        let batch_payload = payload_builder.get_payload(
            certified_height,
            &[], // Because the latest state is certified, we do not need to provide any `past_payloads`.
            &validation_context,
            &subnet_records,
        );

        let xnet_payload = batch_payload.xnet.clone();
        let payload = PayloadBuilder::new().with_xnet_payload(xnet_payload);

        self.execute_payload(payload);
    }

    /// Returns the history of the given canister_id.
    ///
    /// # Panics
    /// Panics if the canister_id does not exist in the replicated state.
    pub fn get_canister_history(&self, canister_id: CanisterId) -> CanisterHistory {
        self.get_latest_state()
            .canister_state(&canister_id)
            .unwrap()
            .system_state
            .get_canister_history()
            .clone()
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

#[derive(Clone)]
pub struct PayloadBuilder {
    expiry_time: Time,
    nonce: Option<u64>,
    ingress_messages: Vec<SignedIngress>,
    xnet_payload: XNetPayload,
    consensus_responses: Vec<ConsensusResponse>,
    query_stats: Option<QueryStatsPayload>,
    self_validating: Option<SelfValidatingPayload>,
    blockmaker_metrics: Option<BlockmakerMetrics>,
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
            self_validating: Default::default(),
            blockmaker_metrics: Default::default(),
        }
        .with_max_expiry_time_from_now(GENESIS.into())
    }
}

impl PayloadBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_blockmaker_metrics(self, blockmaker_metrics: BlockmakerMetrics) -> Self {
        Self {
            blockmaker_metrics: Some(blockmaker_metrics),
            ..self
        }
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
    pub fn with_consensus_responses(self, consensus_responses: Vec<ConsensusResponse>) -> Self {
        Self {
            consensus_responses,
            ..self
        }
    }

    pub fn with_query_stats(self, query_stats: Option<QueryStatsPayload>) -> Self {
        Self {
            query_stats,
            ..self
        }
    }

    pub fn with_self_validating(self, self_validating: Option<SelfValidatingPayload>) -> Self {
        Self {
            self_validating,
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
        self.nonce = self.nonce.map(|n| n + 1);
        self
    }

    pub fn signed_ingress(mut self, msg: SignedIngress) -> Self {
        self.ingress_messages.push(msg);
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

struct SubnetsImpl {
    subnets: Arc<RwLock<BTreeMap<SubnetId, Arc<StateMachine>>>>,
}

impl SubnetsImpl {
    fn new() -> Self {
        Self {
            subnets: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
}

impl Subnets for SubnetsImpl {
    fn insert(&self, state_machine: Arc<StateMachine>) {
        self.subnets
            .write()
            .unwrap()
            .insert(state_machine.get_subnet_id(), state_machine);
    }
    fn get(&self, subnet_id: SubnetId) -> Option<Arc<StateMachine>> {
        self.subnets.read().unwrap().get(&subnet_id).cloned()
    }
}

fn multi_subnet_setup(
    subnets: Arc<dyn Subnets>,
    subnet_seed: u8,
    config: StateMachineConfig,
    subnet_type: SubnetType,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
) -> Arc<StateMachine> {
    StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_seed([subnet_seed; 32])
        .with_subnet_type(subnet_type)
        .with_registry_data_provider(registry_data_provider)
        .build_with_subnets(subnets)
}

/// Sets up two `StateMachine` as application subnets and configured with a
/// `StateMachineConfig` that can communicate with each other.
pub fn two_subnets_with_config(
    config1: StateMachineConfig,
    config2: StateMachineConfig,
) -> (Arc<StateMachine>, Arc<StateMachine>) {
    // Set up registry data provider.
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());

    // Set up the two state machines for the two (app) subnets.
    let subnets = Arc::new(SubnetsImpl::new());
    let env1 = multi_subnet_setup(
        subnets.clone(),
        1,
        config1,
        SubnetType::Application,
        registry_data_provider.clone(),
    );
    let env2 = multi_subnet_setup(
        subnets.clone(),
        2,
        config2,
        SubnetType::Application,
        registry_data_provider.clone(),
    );

    // Set up routing table with two subnets.
    let subnet_id1 = env1.get_subnet_id();
    let subnet_id2 = env2.get_subnet_id();

    let mut routing_table = RoutingTable::new();
    routing_table_insert_subnet(&mut routing_table, subnet_id1).unwrap();
    routing_table_insert_subnet(&mut routing_table, subnet_id2).unwrap();

    // Set up subnet list for registry.
    let subnet_list = vec![subnet_id1, subnet_id2];

    // Add initial and global registry records.
    add_initial_registry_records(registry_data_provider.clone());
    add_global_registry_records(
        subnet_id1,
        routing_table,
        subnet_list,
        BTreeMap::new(),
        registry_data_provider,
    );

    // Reload registry on the two state machines to make sure that
    // both the state machines have a consistent view of the registry.
    env1.reload_registry();
    env2.reload_registry();

    (env1, env2)
}

/// Sets up two `StateMachine` that can communicate with each other.
pub fn two_subnets_simple() -> (Arc<StateMachine>, Arc<StateMachine>) {
    let config = StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        HypervisorConfig::default(),
    );
    two_subnets_with_config(config.clone(), config)
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
