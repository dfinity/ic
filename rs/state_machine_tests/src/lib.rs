use candid::Decode;
use core::sync::atomic::Ordering;
use ic_artifact_pool::canister_http_pool::CanisterHttpPoolImpl;
use ic_config::{
    execution_environment::Config as HypervisorConfig, flag_status::FlagStatus,
    state_manager::LsmtConfig, subnet_config::SubnetConfig,
};
use ic_consensus::consensus::payload_builder::PayloadBuilderImpl;
use ic_consensus::dkg::{make_registry_cup, make_registry_cup_from_cup_contents};
use ic_consensus_utils::crypto::SignVerify;
use ic_crypto_test_utils_ni_dkg::{
    dummy_initial_dkg_transcript_with_master_key, sign_message, SecretKeyBytes,
};
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path as LabeledTreePath};
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_cycles_account_manager::CyclesAccountManager;
pub use ic_error_types::{ErrorCode, UserError};
use ic_execution_environment::{ExecutionServices, IngressHistoryReaderImpl};
use ic_http_endpoints_public::{metrics::HttpHandlerMetrics, IngressWatcher, IngressWatcherHandle};
use ic_https_outcalls_consensus::payload_builder::CanisterHttpPayloadBuilderImpl;
use ic_ingress_manager::{IngressManager, RandomStateKind};
use ic_interfaces::batch_payload::BatchPayloadBuilder;
use ic_interfaces::ingress_pool::IngressPoolObject;
use ic_interfaces::{
    batch_payload::{IntoMessages, PastPayload, ProposalContext},
    canister_http::{CanisterHttpChangeAction, CanisterHttpPool},
    certification::{Verifier, VerifierError},
    consensus::{PayloadBuilder as ConsensusPayloadBuilder, PayloadValidationError},
    consensus_pool::ConsensusTime,
    execution_environment::{IngressFilterService, IngressHistoryReader, QueryExecutionService},
    ingress_pool::{
        IngressPool, PoolSection, UnvalidatedIngressArtifact, ValidatedIngressArtifact,
    },
    p2p::consensus::MutablePool,
    validation::ValidationResult,
};
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, EncodeStreamError};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::{CertificationScope, StateHashError, StateManager, StateReader};
use ic_limits::{MAX_INGRESS_TTL, PERMITTED_DRIFT, SMALL_APP_SUBNET_MAX_SIZE};
use ic_logger::{error, ReplicaLogger};
use ic_management_canister_types::{
    self as ic00, CanisterIdRecord, InstallCodeArgs, MasterPublicKeyId, Method, Payload,
};
pub use ic_management_canister_types::{
    CanisterHttpResponsePayload, CanisterInstallMode, CanisterSettingsArgs,
    CanisterSettingsArgsBuilder, CanisterSnapshotResponse, CanisterStatusResultV2,
    CanisterStatusType, ClearChunkStoreArgs, EcdsaCurve, EcdsaKeyId, HttpHeader, HttpMethod,
    InstallChunkedCodeArgs, LoadCanisterSnapshotArgs, SchnorrAlgorithm, SignWithECDSAReply,
    SignWithSchnorrReply, TakeCanisterSnapshotArgs, UpdateSettingsArgs, UploadChunkArgs,
    UploadChunkReply,
};
use ic_messaging::SyncMessageRouting;
use ic_metrics::MetricsRegistry;
use ic_protobuf::types::v1 as pb;
use ic_protobuf::{
    registry::{
        crypto::v1::{ChainKeySigningSubnetList, PublicKey as PublicKeyProto, X509PublicKeyCert},
        node::v1::{ConnectionEndpoint, NodeRecord},
        provisional_whitelist::v1::ProvisionalWhitelist as PbProvisionalWhitelist,
        replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
        routing_table::v1::{
            CanisterMigrations as PbCanisterMigrations, RoutingTable as PbRoutingTable,
        },
        subnet::v1::CatchUpPackageContents,
    },
    types::v1::{PrincipalId as PrincipalIdIdProto, SubnetId as SubnetIdProto},
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_client_helpers::{
    provisional_whitelist::ProvisionalWhitelistRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_registry_keys::{
    make_blessed_replica_versions_key, make_canister_migrations_record_key,
    make_catch_up_package_contents_key, make_chain_key_signing_subnet_list_key,
    make_crypto_node_key, make_crypto_tls_cert_key, make_node_record_key,
    make_provisional_whitelist_record_key, make_replica_version_key, make_routing_table_record_key,
    ROOT_SUBNET_ID_KEY,
};
use ic_registry_proto_data_provider::{ProtoRegistryDataProvider, INITIAL_REGISTRY_VERSION};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{
    routing_table_insert_subnet, CanisterIdRange, CanisterIdRanges, RoutingTable,
};
use ic_registry_subnet_features::{
    ChainKeyConfig, KeyConfig, SubnetFeatures, DEFAULT_ECDSA_MAX_QUEUE_SIZE,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::{system_state::CyclesUseCase, NumWasmPages, WASM_PAGE_SIZE_IN_BYTES},
    metadata_state::subnet_call_context_manager::{SignWithThresholdContext, ThresholdArguments},
    page_map::Buffer,
    CheckpointLoadingMetrics, Memory, PageMap, ReplicatedState,
};
use ic_state_layout::{CheckpointLayout, ReadOnly};
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::crypto::CryptoReturningOk;
use ic_test_utilities_consensus::FakeConsensusPoolCache;
use ic_test_utilities_metrics::{
    fetch_counter_vec, fetch_histogram_stats, fetch_int_counter, fetch_int_gauge,
    fetch_int_gauge_vec, Labels,
};
use ic_test_utilities_registry::{
    add_single_subnet_record, add_subnet_key_record, add_subnet_list_record, SubnetRecordBuilder,
};
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::ids::NODE_1;
use ic_types::{
    artifact::IngressMessageId,
    batch::{
        Batch, BatchMessages, BatchSummary, BlockmakerMetrics, ConsensusResponse,
        QueryStatsPayload, TotalQueryStats, ValidationContext, XNetPayload,
    },
    canister_http::{CanisterHttpResponse, CanisterHttpResponseContent},
    consensus::{
        block_maker::SubnetRecords,
        certification::{Certification, CertificationContent},
        CatchUpPackage,
    },
    crypto::{
        canister_threshold_sig::MasterPublicKey,
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript},
        AlgorithmId, CombinedThresholdSig, CombinedThresholdSigOf, KeyPurpose, Signable, Signed,
    },
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpCallContent, HttpCanisterUpdate,
        HttpRequestEnvelope, Payload as MsgPayload, Query, QuerySource, RejectContext,
        SignedIngress, SignedIngressContent, EXPECTED_MESSAGE_ID_LENGTH,
    },
    signature::ThresholdSignature,
    time::GENESIS,
    xnet::{CertifiedStreamSlice, StreamIndex},
    CanisterLog, CountBytes, CryptoHashOfPartialState, Height, NodeId, Randomness, RegistryVersion,
    ReplicaVersion,
};
pub use ic_types::{
    canister_http::{
        CanisterHttpMethod, CanisterHttpRequestContext, CanisterHttpRequestId,
        CanisterHttpResponseMetadata,
    },
    crypto::threshold_sig::ThresholdSigPublicKey,
    crypto::{CryptoHash, CryptoHashOf},
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{CallbackId, HttpRequestError, MessageId},
    signature::BasicSignature,
    time::Time,
    CanisterId, CryptoHashOfState, Cycles, NumBytes, PrincipalId, SubnetId, UserId,
};
use ic_xnet_payload_builder::{
    certified_slice_pool::{certified_slice_count_bytes, CertifiedSliceError},
    ExpectedIndices, RefillTaskHandle, XNetPayloadBuilderImpl, XNetPayloadBuilderMetrics,
    XNetSlicePool,
};
use rcgen::{CertificateParams, KeyPair};
use serde::Deserialize;

pub use ic_error_types::RejectCode;
use maplit::btreemap;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::Serialize;
pub use slog::Level;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt,
    io::{self, stderr},
    net::Ipv6Addr,
    path::{Path, PathBuf},
    str::FromStr,
    string::ToString,
    sync::{atomic::AtomicU64, Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime},
};
use tempfile::TempDir;
use tokio::{
    runtime::Runtime,
    sync::{mpsc, watch},
};
use tower::{buffer::Buffer as TowerBuffer, ServiceExt};

/// The size of the channel used to communicate between the [`IngressWatcher`] and
/// execution. Mirrors the size used in production defined in `setup_ic_stack.rs`
const COMPLETED_EXECUTION_MESSAGES_BUFFER_SIZE: usize = 10_000;

#[cfg(test)]
mod tests;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
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
    let replica_version_record = ReplicaVersionRecord {
        release_package_sha256_hex: "".to_string(),
        release_package_urls: vec![],
        guest_launch_measurement_sha256_hex: None,
    };
    registry_data_provider
        .add(
            &make_replica_version_key(replica_version),
            registry_version,
            Some(replica_version_record),
        )
        .unwrap();
}

/// Adds subnet-related records to registry.
/// Note: `finalize_registry` must be called with `routing_table` containing `subnet_id`
/// before any other public method of the `StateMachine` (except for `get_subnet_id`) is invoked.
fn make_nodes_registry(
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    idkg_keys_signing_enabled_status: &BTreeMap<MasterPublicKeyId, bool>,
    features: SubnetFeatures,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    nodes: &Vec<StateMachineNode>,
    is_root_subnet: bool,
    public_key: ThresholdSigPublicKey,
    ni_dkg_transcript: NiDkgTranscript,
) -> FakeRegistryClient {
    let registry_version = if registry_data_provider.is_empty() {
        INITIAL_REGISTRY_VERSION
    } else {
        let latest_registry_version = registry_data_provider.latest_version();
        RegistryVersion::from(latest_registry_version.get() + 1)
    };
    // ECDSA subnet_id must be different from nns_subnet_id, otherwise
    // `sign_with_ecdsa` won't be charged.
    let subnet_id_proto = SubnetIdProto {
        principal_id: Some(PrincipalIdIdProto {
            raw: subnet_id.get_ref().to_vec(),
        }),
    };
    for (key_id, is_signing_enabled) in idkg_keys_signing_enabled_status {
        if !*is_signing_enabled {
            continue;
        }
        registry_data_provider
            .add(
                &make_chain_key_signing_subnet_list_key(key_id),
                registry_version,
                Some(ChainKeySigningSubnetList {
                    subnets: vec![subnet_id_proto.clone()],
                }),
            )
            .unwrap();
    }

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
        let root_key_pair = KeyPair::generate().unwrap();
        let root_cert = CertificateParams::new(vec![node.node_id.to_string()])
            .unwrap()
            .self_signed(&root_key_pair)
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
    let max_ingress_messages_per_block = if is_root_subnet { 400 } else { 1000 };
    let max_block_payload_size = 4 * 1024 * 1024;

    let node_ids: Vec<_> = nodes.iter().map(|n| n.node_id).collect();
    let record = SubnetRecordBuilder::from(&node_ids)
        .with_subnet_type(subnet_type)
        .with_max_ingress_bytes_per_message(max_ingress_bytes_per_message)
        .with_max_ingress_messages_per_block(max_ingress_messages_per_block)
        .with_max_block_payload_size(max_block_payload_size)
        .with_dkg_interval_length(u64::MAX / 2) // use the genesis CUP throughout the test
        .with_chain_key_config(ChainKeyConfig {
            key_configs: idkg_keys_signing_enabled_status
                .iter()
                .map(|(key_id, _)| KeyConfig {
                    key_id: key_id.clone(),
                    pre_signatures_to_create_in_advance: 1,
                    max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
                })
                .collect(),
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

    let registry_client = FakeRegistryClient::new(Arc::clone(&registry_data_provider) as _);
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

fn replica_logger(log_level: Option<Level>) -> ReplicaLogger {
    use slog::Drain;
    let log_level = log_level
        .or(std::env::var("RUST_LOG")
            .ok()
            .and_then(|level| Level::from_str(&level).ok()))
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
    fn push(&mut self, m: SignedIngress, timestamp: Time) {
        self.validated.insert(
            IngressMessageId::new(m.expiry_time(), m.id()),
            ValidatedIngressArtifact {
                msg: IngressPoolObject::new(NODE_1, m),
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
                let mut num_bytes = certified_slice_count_bytes(&certified_stream).unwrap();
                // Because `StateMachine::generate_certified_stream_slice` only uses a size estimate
                // when constructing a slice (this estimate can be off by at most a few KB),
                // we fake the reported slice size if it exceeds the specified size limit to make sure the payload builder will accept the slice as valid and include it into the block.
                // This is fine since we don't actually validate the payload in the context of Pocket IC, and so blocks containing
                // a XNet slice exceeding the byte limit won't be rejected as invalid.
                if let Some(byte_limit) = byte_limit {
                    if num_bytes > byte_limit {
                        num_bytes = byte_limit;
                    }
                }
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
    pub node_signing_key: ic_crypto_ed25519::PrivateKey,
    pub committee_signing_key: ic_crypto_ed25519::PrivateKey,
    pub dkg_dealing_encryption_key: ic_crypto_ed25519::PrivateKey,
    pub idkg_mega_encryption_key: ic_crypto_ed25519::PrivateKey,
    pub http_ip_addr: Ipv6Addr,
    pub xnet_ip_addr: Ipv6Addr,
}

impl StateMachineNode {
    fn new(rng: &mut StdRng) -> Self {
        let node_signing_key = ic_crypto_ed25519::PrivateKey::deserialize_raw_32(&rng.gen());
        let committee_signing_key = ic_crypto_ed25519::PrivateKey::deserialize_raw_32(&rng.gen());
        let dkg_dealing_encryption_key =
            ic_crypto_ed25519::PrivateKey::deserialize_raw_32(&rng.gen());
        let idkg_mega_encryption_key =
            ic_crypto_ed25519::PrivateKey::deserialize_raw_32(&rng.gen());
        let http_ip_addr = Ipv6Addr::from(rng.gen::<[u16; 8]>());
        let xnet_ip_addr = Ipv6Addr::from(rng.gen::<[u16; 8]>());
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
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum SignatureSecretKey {
    EcdsaSecp256k1(ic_crypto_secp256k1::PrivateKey),
    SchnorrBip340(ic_crypto_secp256k1::PrivateKey),
    Ed25519(ic_crypto_ed25519::DerivedPrivateKey),
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
    pub metrics_registry: MetricsRegistry,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    pub query_handler:
        tower::buffer::Buffer<QueryExecutionService, (Query, Option<CertificateDelegation>)>,
    runtime: Arc<Runtime>,
    // The atomicity is required for internal mutability and sending across threads.
    checkpoint_interval_length: AtomicU64,
    nonce: AtomicU64,
    time: AtomicU64,
    idkg_subnet_public_keys: BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    idkg_subnet_secret_keys: BTreeMap<MasterPublicKeyId, SignatureSecretKey>,
    pub replica_logger: ReplicaLogger,
    pub nodes: Vec<StateMachineNode>,
    pub batch_summary: Option<BatchSummary>,
    time_source: Arc<FastForwardTimeSource>,
    consensus_pool_cache: Arc<FakeConsensusPoolCache>,
    canister_http_pool: Arc<RwLock<CanisterHttpPoolImpl>>,
    canister_http_payload_builder: Arc<CanisterHttpPayloadBuilderImpl>,
    certified_height_tx: watch::Sender<Height>,
    pub ingress_watcher_handle: IngressWatcherHandle,
    /// A drop guard to gracefully cancel the ingress watcher task.
    _ingress_watcher_drop_guard: tokio_util::sync::DropGuard,
    query_stats_payload_builder: Arc<PocketQueryStatsPayloadBuilderImpl>,
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
    routing_table: RoutingTable,
    enable_canister_snapshots: bool,
    idkg_keys_signing_enabled_status: BTreeMap<MasterPublicKeyId, bool>,
    ecdsa_signature_fee: Option<Cycles>,
    schnorr_signature_fee: Option<Cycles>,
    is_ecdsa_signing_enabled: bool,
    is_schnorr_signing_enabled: bool,
    features: SubnetFeatures,
    runtime: Option<Arc<Runtime>>,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    lsmt_override: Option<LsmtConfig>,
    is_root_subnet: bool,
    seed: [u8; 32],
    with_extra_canister_range: Option<std::ops::RangeInclusive<CanisterId>>,
    dts: bool,
    log_level: Option<Level>,
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
            enable_canister_snapshots: false,
            subnet_size: SMALL_APP_SUBNET_MAX_SIZE,
            nns_subnet_id: None,
            subnet_id: None,
            routing_table: RoutingTable::new(),
            idkg_keys_signing_enabled_status: Default::default(),
            ecdsa_signature_fee: None,
            schnorr_signature_fee: None,
            is_ecdsa_signing_enabled: true,
            is_schnorr_signing_enabled: true,
            features: SubnetFeatures {
                http_requests: true,
                ..SubnetFeatures::default()
            },
            runtime: None,
            registry_data_provider: Arc::new(ProtoRegistryDataProvider::new()),
            lsmt_override: None,
            is_root_subnet: false,
            seed: [42; 32],
            with_extra_canister_range: None,
            dts: true,
            log_level: None,
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

    pub fn with_canister_snapshots(self, enable_canister_snapshots: bool) -> Self {
        Self {
            enable_canister_snapshots,
            ..self
        }
    }

    pub fn with_master_ecdsa_public_key(self) -> Self {
        self.with_idkg_key(MasterPublicKeyId::Ecdsa(EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "master_ecdsa_public_key".to_string(),
        }))
    }

    pub fn with_idkg_key(mut self, key_id: MasterPublicKeyId) -> Self {
        self.idkg_keys_signing_enabled_status.insert(key_id, true);
        self
    }

    pub fn with_signing_disabled_idkg_key(mut self, key_id: MasterPublicKeyId) -> Self {
        self.idkg_keys_signing_enabled_status.insert(key_id, false);
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

    pub fn with_root_subnet_config(self) -> Self {
        Self {
            is_root_subnet: true,
            ..self
        }
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

    /// Only use from pocket-ic-server binary.
    pub fn no_dts(self) -> Self {
        Self { dts: false, ..self }
    }

    pub fn with_log_level(self, log_level: Option<Level>) -> Self {
        Self { log_level, ..self }
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
            self.enable_canister_snapshots,
            self.idkg_keys_signing_enabled_status,
            self.ecdsa_signature_fee,
            self.schnorr_signature_fee,
            self.is_ecdsa_signing_enabled,
            self.is_schnorr_signing_enabled,
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
            self.seed,
            self.dts,
            self.log_level,
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
            sm.canister_http_payload_builder.clone(),
            sm.query_stats_payload_builder.clone(),
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
    /// Provides the time increment for a single round of execution.
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
        self.payload_builder.write().unwrap().take();
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
        let mut payload = PayloadBuilder::new()
            .with_ingress_messages(ingress_messages)
            .with_xnet_payload(xnet_payload)
            .with_consensus_responses(http_responses)
            .with_query_stats(query_stats);

        // Process threshold signing requests.
        for (id, context) in &state
            .metadata
            .subnet_call_context_manager
            .sign_with_threshold_contexts
        {
            match context.args {
                ThresholdArguments::Ecdsa(_) if self.is_ecdsa_signing_enabled => {
                    let response = self.build_sign_with_ecdsa_reply(context);
                    payload.consensus_responses.push(ConsensusResponse::new(
                        *id,
                        MsgPayload::Data(response.encode()),
                    ));
                }
                ThresholdArguments::Schnorr(_) if self.is_schnorr_signing_enabled => {
                    if let Some(response) = self.build_sign_with_schnorr_reply(context) {
                        payload.consensus_responses.push(ConsensusResponse::new(
                            *id,
                            MsgPayload::Data(response.encode()),
                        ));
                    }
                }
                _ => {}
            }
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
        let registry_version = self.registry_client.get_latest_version();
        let cup_contents = self
            .registry_client
            .get_cup_contents(self.subnet_id, registry_version)
            .unwrap()
            .value
            .unwrap();
        let cup = make_registry_cup_from_cup_contents(
            self.registry_client.as_ref(),
            self.subnet_id,
            cup_contents,
            registry_version,
            &self.replica_logger,
        )
        .unwrap();
        let cup_proto: pb::CatchUpPackage = cup.into();
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
        enable_canister_snapshots: bool,
        idkg_keys_signing_enabled_status: BTreeMap<MasterPublicKeyId, bool>,
        ecdsa_signature_fee: Option<Cycles>,
        schnorr_signature_fee: Option<Cycles>,
        is_ecdsa_signing_enabled: bool,
        is_schnorr_signing_enabled: bool,
        features: SubnetFeatures,
        runtime: Arc<Runtime>,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
        lsmt_override: Option<LsmtConfig>,
        is_root_subnet: bool,
        seed: [u8; 32],
        dts: bool,
        log_level: Option<Level>,
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
        let registry_client = make_nodes_registry(
            subnet_id,
            subnet_type,
            &idkg_keys_signing_enabled_status,
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

        if enable_canister_snapshots {
            hypervisor_config.canister_snapshots = FlagStatus::Enabled;
        }

        // We are not interested in ingress signature validation.
        let malicious_flags = MaliciousFlags {
            maliciously_disable_ingress_validation: true,
            ..Default::default()
        };

        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            subnet_config.scheduler_config.max_instructions_per_message,
            subnet_type,
            subnet_id,
            subnet_config.cycles_account_manager_config,
        ));
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

        // get the CUP from the registry
        let cup: CatchUpPackage =
            make_registry_cup(&registry_client, subnet_id, &replica_logger).unwrap();
        let cup_proto: pb::CatchUpPackage = cup.into();
        // now we can wrap the registry client into an Arc
        let registry_client = Arc::new(registry_client);

        let canister_http_pool = Arc::new(RwLock::new(CanisterHttpPoolImpl::new(
            metrics_registry.clone(),
            replica_logger.clone(),
        )));
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
                subnet_config.scheduler_config.clone(),
                hypervisor_config.clone(),
                Arc::clone(&cycles_account_manager),
                Arc::clone(&state_manager) as Arc<_>,
                Arc::clone(&state_manager.get_fd_factory()),
                completed_execution_messages_tx,
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

        let master_ecdsa_public_key = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "master_ecdsa_public_key".to_string(),
        };

        let mut idkg_subnet_public_keys = BTreeMap::new();
        let mut idkg_subnet_secret_keys = BTreeMap::new();

        for key_id in idkg_keys_signing_enabled_status.keys() {
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

                    let private_key = ic_crypto_secp256k1::PrivateKey::deserialize_sec1(
                        private_key_bytes.as_slice(),
                    )
                    .unwrap();

                    let public_key = MasterPublicKey {
                        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                        public_key: private_key.public_key().serialize_sec1(true),
                    };

                    let private_key = SignatureSecretKey::EcdsaSecp256k1(private_key);

                    (public_key, private_key)
                }
                MasterPublicKeyId::Ecdsa(id) => {
                    use ic_crypto_secp256k1::{DerivationIndex, DerivationPath, PrivateKey};

                    let path =
                        DerivationPath::new(vec![DerivationIndex(id.name.as_bytes().to_vec())]);

                    let private_key = PrivateKey::generate_from_seed(&seed).derive_subkey(&path).0;

                    let public_key = MasterPublicKey {
                        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
                        public_key: private_key.public_key().serialize_sec1(true),
                    };

                    let private_key = SignatureSecretKey::EcdsaSecp256k1(private_key);

                    (public_key, private_key)
                }
                MasterPublicKeyId::Schnorr(id) => match id.algorithm {
                    SchnorrAlgorithm::Bip340Secp256k1 => {
                        use ic_crypto_secp256k1::{DerivationIndex, DerivationPath, PrivateKey};

                        let path =
                            DerivationPath::new(vec![DerivationIndex(id.name.as_bytes().to_vec())]);

                        let private_key =
                            PrivateKey::generate_from_seed(&seed).derive_subkey(&path).0;

                        let public_key = MasterPublicKey {
                            algorithm_id: AlgorithmId::ThresholdSchnorrBip340,
                            public_key: private_key.public_key().serialize_sec1(true),
                        };

                        let private_key = SignatureSecretKey::SchnorrBip340(private_key);

                        (public_key, private_key)
                    }
                    SchnorrAlgorithm::Ed25519 => {
                        use ic_crypto_ed25519::{DerivationIndex, DerivationPath, PrivateKey};

                        let path =
                            DerivationPath::new(vec![DerivationIndex(id.name.as_bytes().to_vec())]);

                        let private_key =
                            PrivateKey::generate_from_seed(&seed).derive_subkey(&path).0;

                        let public_key = MasterPublicKey {
                            algorithm_id: AlgorithmId::ThresholdEd25519,
                            public_key: private_key.public_key().serialize_raw().to_vec(),
                        };

                        let private_key = SignatureSecretKey::Ed25519(private_key);

                        (public_key, private_key)
                    }
                },
            };

            idkg_subnet_secret_keys.insert(key_id.clone(), private_key);

            idkg_subnet_public_keys.insert(key_id.clone(), public_key);
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
            cycles_account_manager,
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
            metrics_registry: metrics_registry.clone(),
            query_handler: runtime.block_on(async {
                TowerBuffer::new(execution_services.query_execution_service, 1)
            }),
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
            idkg_subnet_public_keys,
            idkg_subnet_secret_keys,
            replica_logger: replica_logger.clone(),
            nodes,
            batch_summary: None,
            time_source,
            consensus_pool_cache,
            canister_http_pool,
            canister_http_payload_builder,
            query_stats_payload_builder: pocket_query_stats_payload_builder,
        }
    }

    fn into_components(self) -> (Box<dyn StateMachineStateDir>, u64, Time, u64) {
        (
            self.state_dir,
            self.nonce.into_inner(),
            Time::from_nanos_since_unix_epoch(self.time.into_inner()),
            self.checkpoint_interval_length.load(Ordering::Relaxed),
        )
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
        assert!(!contexts.is_empty(), "expected '{}' HTTP request", name);
        for (id, context) in &contexts {
            let response = f(context);
            payload = payload.http_response(*id, &response);
        }
        self.execute_payload(payload);
    }

    fn build_sign_with_ecdsa_reply(
        &self,
        context: &SignWithThresholdContext,
    ) -> SignWithECDSAReply {
        assert!(context.is_ecdsa());

        if let Some(SignatureSecretKey::EcdsaSecp256k1(k)) =
            self.idkg_subnet_secret_keys.get(&context.key_id())
        {
            let path = ic_crypto_secp256k1::DerivationPath::from_canister_id_and_path(
                context.request.sender.get().as_slice(),
                &context.derivation_path,
            );
            let dk = k.derive_subkey(&path).0;
            let signature = dk
                .sign_digest_with_ecdsa(&context.ecdsa_args().message_hash)
                .to_vec();
            SignWithECDSAReply { signature }
        } else {
            panic!("No ECDSA key with key id {} found", context.key_id());
        }
    }

    fn build_sign_with_schnorr_reply(
        &self,
        context: &SignWithThresholdContext,
    ) -> Option<SignWithSchnorrReply> {
        assert!(context.is_schnorr());

        let signature = match self.idkg_subnet_secret_keys.get(&context.key_id()) {
            Some(SignatureSecretKey::SchnorrBip340(k)) => {
                let path = ic_crypto_secp256k1::DerivationPath::from_canister_id_and_path(
                    context.request.sender.get().as_slice(),
                    &context.derivation_path[..],
                );
                let (dk, _cc) = k.derive_subkey(&path);

                let message = {
                    if context.schnorr_args().message.len() == 32 {
                        let mut message = [0u8; 32];
                        message.copy_from_slice(&context.schnorr_args().message);
                        message
                    } else {
                        error!(
                            self.replica_logger,
                            "Currently BIP340 signing of messages != 32 bytes not supported"
                        );
                        return None;
                    }
                };

                dk.sign_message_with_bip340_no_rng(&message).to_vec()
            }
            Some(SignatureSecretKey::Ed25519(k)) => {
                let path = ic_crypto_ed25519::DerivationPath::from_canister_id_and_path(
                    context.request.sender.get().as_slice(),
                    &context.derivation_path[..],
                );
                let (dk, _cc) = k.derive_subkey(&path);

                dk.sign_message(&context.schnorr_args().message).to_vec()
            }
            _ => {
                panic!("No Schnorr key with specified key id found");
            }
        };

        Some(SignWithSchnorrReply { signature })
    }

    /// If set to true, the state machine will handle sign_with_ecdsa calls during `tick()`.
    pub fn set_ecdsa_signing_enabled(&mut self, value: bool) {
        self.is_ecdsa_signing_enabled = value;
    }

    /// If set to true, the state machine will handle sign_with_schnorr calls during `tick()`.
    pub fn set_schnorr_signing_enabled(&mut self, value: bool) {
        self.is_schnorr_signing_enabled = value;
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
            match context.args {
                ThresholdArguments::Ecdsa(_) if self.is_ecdsa_signing_enabled => {
                    let response = self.build_sign_with_ecdsa_reply(context);
                    payload.consensus_responses.push(ConsensusResponse::new(
                        *id,
                        MsgPayload::Data(response.encode()),
                    ));
                }
                ThresholdArguments::Schnorr(_) if self.is_schnorr_signing_enabled => {
                    if let Some(response) = self.build_sign_with_schnorr_reply(context) {
                        payload.consensus_responses.push(ConsensusResponse::new(
                            *id,
                            MsgPayload::Data(response.encode()),
                        ));
                    }
                }
                _ => {}
            }
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
    pub fn check_critical_errors(&self) {
        let error_counter_vec = fetch_counter_vec(&self.metrics_registry, "critical_errors");
        if let Some((metric, _)) = error_counter_vec.into_iter().find(|(_, v)| *v != 0.0) {
            let err: String = metric.get("error").unwrap().to_string();
            panic!("Critical error {} occurred.", err);
        }
    }

    /// Advances time by 1ns (to make sure time is strictly monotone)
    /// and triggers a single round of execution with block payload as an input.
    pub fn execute_payload(&self, payload: PayloadBuilder) -> Height {
        self.advance_time(Self::EXECUTE_ROUND_TIME_INCREMENT);

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
        let requires_full_state_hash =
            batch_number.get() % checkpoint_interval_length_plus_one == 0;

        let batch = Batch {
            batch_number,
            batch_summary,
            requires_full_state_hash,
            messages: BatchMessages {
                signed_ingress_msgs: payload.ingress_messages,
                certified_stream_slices: payload.xnet_payload.stream_slices,
                bitcoin_adapter_responses: vec![],
                query_stats: payload.query_stats,
            },
            randomness: Randomness::from(seed),
            idkg_subnet_public_keys: self.idkg_subnet_public_keys.clone(),
            idkg_pre_signature_ids: BTreeMap::new(),
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

    /// Returns the current state machine time.
    pub fn time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(self.time.load(Ordering::Relaxed))
    }

    /// Returns the state machine time at the beginning of next round.
    pub fn time_of_next_round(&self) -> SystemTime {
        self.time() + Self::EXECUTE_ROUND_TIME_INCREMENT
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

        let canister_state = ic_state_manager::checkpoint::load_canister_state(
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

    /// Create a canister snapshot.
    pub fn take_canister_snapshot(
        &self,
        args: TakeCanisterSnapshotArgs,
    ) -> Result<CanisterSnapshotResponse, UserError> {
        let state = self.state_manager.get_latest_state().take();
        let sender = state
            .canister_state(&args.get_canister_id())
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous);
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::TakeCanisterSnapshot,
            args.encode(),
        )
        .map(|res| match res {
            WasmResult::Reply(data) => CanisterSnapshotResponse::decode(&data),
            WasmResult::Reject(reason) => {
                panic!("take_canister_snapshot call rejected: {}", reason)
            }
        })?
    }

    /// Load the canister state from a canister snapshot.
    pub fn load_canister_snapshot(
        &self,
        args: LoadCanisterSnapshotArgs,
    ) -> Result<Vec<u8>, UserError> {
        let state = self.state_manager.get_latest_state().take();
        let sender = state
            .canister_state(&args.get_canister_id())
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous);
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::LoadCanisterSnapshot,
            args.encode(),
        )
        .map(|res| match res {
            WasmResult::Reply(data) => Ok(data),
            WasmResult::Reject(reason) => {
                panic!("load_canister_snapshot call rejected: {}", reason)
            }
        })?
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
                    panic!("upload_chunk call rejected: {}", reason)
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
        // Build `SignedIngress` with maximum ingress expiry and unique nonce,
        // omitting delegations and signatures.
        let ingress_expiry = (self.get_time() + MAX_INGRESS_TTL).as_nanos_since_unix_epoch();
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed) + 1;
        let nonce_blob = Some(nonce.to_le_bytes().into());
        let msg = SignedIngress::try_from(HttpRequestEnvelope::<HttpCallContent> {
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
        .unwrap();

        // Fetch ingress validation settings from the registry.
        let registry_version = self.registry_client.get_latest_version();
        let provisional_whitelist = self
            .registry_client
            .get_provisional_whitelist(registry_version)
            .unwrap()
            .unwrap();

        // Run `IngressFilter` on the ingress message.
        let ingress_filter = self.ingress_filter.clone();
        self.runtime
            .block_on(ingress_filter.oneshot((provisional_whitelist, msg.clone().into())))
            .unwrap()?;

        let builder = PayloadBuilder::new()
            .with_max_expiry_time_from_now(self.time())
            .with_nonce(nonce)
            .ingress(sender, canister_id, method, payload);
        let msg_id = builder.ingress_ids().pop().unwrap();
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
        self.expiry_time += StateMachine::EXECUTE_ROUND_TIME_INCREMENT;
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
