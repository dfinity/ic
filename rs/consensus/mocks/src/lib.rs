//! Contains mocks for traits internal to consensus
use ic_artifact_pool::{
    canister_http_pool::CanisterHttpPoolImpl, dkg_pool::DkgPoolImpl, idkg_pool::IDkgPoolImpl,
};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus_utils::membership::Membership;
use ic_interfaces::{
    batch_payload::ProposalContext,
    consensus::{PayloadBuilder, PayloadValidationError},
    validation::ValidationResult,
};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::ROOT_SUBNET_ID_KEY;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
use ic_test_utilities::{crypto::CryptoReturningOk, state_manager::RefMockStateManager};
use ic_test_utilities_consensus::IDkgStatsNoOp;
use ic_test_utilities_registry::{setup_registry_non_final, SubnetRecordBuilder};
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::{block_maker::SubnetRecords, Payload},
    replica_config::ReplicaConfig,
    Height, RegistryVersion, SubnetId, Time,
};
use mockall::predicate::*;
use mockall::*;
use std::sync::{Arc, RwLock};

mock! {
    pub PayloadBuilder {}

    impl PayloadBuilder for PayloadBuilder {
        fn get_payload<'a>(
            &self,
            height: Height,
            past_payloads: &[(Height, Time, Payload)],
            context: &ValidationContext,
            subnet_records: &SubnetRecords,
        ) -> BatchPayload;

        fn validate_payload<'a>(
            &self,
            height: Height,
            proposal_context: &ProposalContext<'a>,
            payload: &Payload,
            past_payloads: &[(Height, Time, Payload)],
        ) -> ValidationResult<PayloadValidationError>;
    }
}

/// Sync wrapper to allow shared modification. See [`RefMockStateManager`].
#[derive(Default)]
pub struct RefMockPayloadBuilder {
    pub mock: RwLock<MockPayloadBuilder>,
}

impl RefMockPayloadBuilder {
    pub fn get_mut(&self) -> std::sync::RwLockWriteGuard<'_, MockPayloadBuilder> {
        self.mock.write().unwrap()
    }
}

impl PayloadBuilder for RefMockPayloadBuilder {
    fn get_payload(
        &self,
        height: Height,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
        subnet_records: &SubnetRecords,
    ) -> BatchPayload {
        self.mock
            .read()
            .unwrap()
            .get_payload(height, past_payloads, context, subnet_records)
    }
    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &Payload,
        past_payloads: &[(Height, Time, Payload)],
    ) -> ValidationResult<PayloadValidationError> {
        self.mock
            .read()
            .unwrap()
            .validate_payload(height, proposal_context, payload, past_payloads)
    }
}

pub struct Dependencies {
    pub crypto: Arc<CryptoReturningOk>,
    pub registry: Arc<FakeRegistryClient>,
    pub registry_data_provider: Arc<ProtoRegistryDataProvider>,
    pub membership: Arc<Membership>,
    pub time_source: Arc<FastForwardTimeSource>,
    pub pool: TestConsensusPool,
    pub replica_config: ReplicaConfig,
    pub state_manager: Arc<RefMockStateManager>,
    pub dkg_pool: Arc<RwLock<DkgPoolImpl>>,
    pub idkg_pool: Arc<RwLock<IDkgPoolImpl>>,
    pub canister_http_pool: Arc<RwLock<CanisterHttpPoolImpl>>,
}

/// Creates most common consensus components used for testing. All components
/// share the same mocked registry with the provided records, so they refer to
/// the identical registry content at any time. The MockStateManager instance
/// that is returned contains no expectations.
pub fn dependencies_with_subnet_records_with_raw_state_manager(
    pool_config: ArtifactPoolConfig,
    subnet_id: SubnetId,
    records: Vec<(u64, SubnetRecord)>,
) -> Dependencies {
    let time_source = FastForwardTimeSource::new();
    let registry_version = RegistryVersion::from(records[0].clone().0);
    let (registry_data_provider, registry) = setup_registry_non_final(subnet_id, records);
    registry_data_provider
        .add(
            ROOT_SUBNET_ID_KEY,
            registry_version,
            Some(ic_types::subnet_id_into_protobuf(subnet_test_id(0))),
        )
        .unwrap();
    registry.update_to_latest_version();
    let replica_config = ReplicaConfig {
        subnet_id,
        node_id: node_test_id(0),
    };
    let crypto = Arc::new(CryptoReturningOk::default());
    let state_manager = Arc::new(RefMockStateManager::default());
    let log = ic_logger::replica_logger::no_op_logger();
    let dkg_pool = Arc::new(RwLock::new(DkgPoolImpl::new(
        ic_metrics::MetricsRegistry::new(),
        log.clone(),
    )));
    let idkg_pool = Arc::new(RwLock::new(IDkgPoolImpl::new(
        pool_config.clone(),
        log.clone(),
        ic_metrics::MetricsRegistry::new(),
        Box::new(IDkgStatsNoOp {}),
    )));
    let canister_http_pool = Arc::new(RwLock::new(CanisterHttpPoolImpl::new(
        ic_metrics::MetricsRegistry::new(),
        log,
    )));
    let pool = TestConsensusPool::new(
        replica_config.node_id,
        subnet_id,
        pool_config,
        time_source.clone(),
        registry.clone(),
        crypto.clone(),
        state_manager.clone(),
        Some(dkg_pool.clone()),
    );
    let membership = Arc::new(Membership::new(
        pool.get_cache(),
        registry.clone(),
        subnet_id,
    ));
    Dependencies {
        crypto,
        registry,
        registry_data_provider,
        membership,
        time_source,
        pool,
        replica_config,
        state_manager,
        dkg_pool,
        idkg_pool,
        canister_http_pool,
    }
}

/// Creates most common consensus components used for testing. All components
/// share the same mocked registry with the provided records, so they refer to
/// the identical registry content at any time. This constructor should be used,
/// if specific subnet parameters are required.
pub fn dependencies_with_subnet_params(
    pool_config: ArtifactPoolConfig,
    subnet_id: SubnetId,
    records: Vec<(u64, SubnetRecord)>,
) -> Dependencies {
    let Dependencies {
        time_source,
        registry_data_provider,
        registry,
        membership,
        crypto,
        pool,
        replica_config,
        state_manager,
        dkg_pool,
        idkg_pool,
        canister_http_pool,
        ..
    } = dependencies_with_subnet_records_with_raw_state_manager(pool_config, subnet_id, records);

    state_manager
        .get_mut()
        .expect_get_state_at()
        .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
            Height::new(0),
            Arc::new(ic_test_utilities_state::get_initial_state(0, 0)),
        )));

    Dependencies {
        crypto,
        registry,
        registry_data_provider,
        membership,
        time_source,
        pool,
        replica_config,
        state_manager,
        dkg_pool,
        idkg_pool,
        canister_http_pool,
    }
}

/// Creates most common consensus components used for testing. All components
/// share the same mocked registry with one registry version holding the subnet
/// record for the specified number of nodes with all other parameters set to
/// their default values.
pub fn dependencies(pool_config: ArtifactPoolConfig, nodes: u64) -> Dependencies {
    let committee = (0..nodes).map(node_test_id).collect::<Vec<_>>();
    dependencies_with_subnet_params(
        pool_config,
        subnet_test_id(0),
        vec![(1, SubnetRecordBuilder::from(&committee).build())],
    )
}
