//! Contains mocks for traits internal to consensus
use ic_artifact_pool::{
    canister_http_pool::CanisterHttpPoolImpl, dkg_pool::DkgPoolImpl, idkg_pool::IDkgPoolImpl,
};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus_utils::membership::Membership;
use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
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
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_consensus::IDkgStatsNoOp;
use ic_test_utilities_registry::{
    SubnetRecordBuilder, add_single_subnet_record, add_subnet_list_record,
    insert_initial_dkg_transcript,
};
use ic_test_utilities_time::FastForwardTimeSource;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{
    Height, RegistryVersion, SubnetId, Time,
    batch::{BatchPayload, ValidationContext},
    consensus::{Payload, block_maker::SubnetRecords},
    replica_config::ReplicaConfig,
};
use mockall::predicate::*;
use mockall::*;
use std::{
    collections::BTreeSet,
    sync::{Arc, RwLock},
};

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

pub struct DependenciesBuilder {
    pool_config: ArtifactPoolConfig,
    records: Vec<(u64, SubnetId, SubnetRecord)>,
    replica_config: ReplicaConfig,
    mocked_state_manager: bool,
    #[allow(clippy::type_complexity)]
    additional_registry_mutations: Vec<Box<dyn Fn(&Arc<ProtoRegistryDataProvider>)>>,
}

impl DependenciesBuilder {
    pub fn new(
        pool_config: ArtifactPoolConfig,
        records: Vec<(u64, SubnetId, SubnetRecord)>,
    ) -> Self {
        Self {
            pool_config,
            replica_config: ReplicaConfig {
                node_id: node_test_id(0),
                subnet_id: records[0].1,
            },
            records,
            mocked_state_manager: false,
            additional_registry_mutations: Vec::new(),
        }
    }

    pub fn with_replica_config(mut self, replica_config: ReplicaConfig) -> Self {
        self.replica_config = replica_config;

        self
    }

    pub fn with_mocked_state_manager(mut self) -> Self {
        self.mocked_state_manager = true;

        self
    }

    pub fn add_additional_registry_mutation(
        mut self,
        mutation: impl Fn(&Arc<ProtoRegistryDataProvider>) + 'static,
    ) -> Self {
        self.additional_registry_mutations.push(Box::new(mutation));

        self
    }

    pub fn build(self) -> Dependencies {
        let time_source = FastForwardTimeSource::new();
        let initial_registry_version = RegistryVersion::from(self.records[0].clone().0);
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());
        assert!(
            !self.records.is_empty(),
            "Cannot setup a registry without records."
        );
        let mut subnet_ids: BTreeSet<SubnetId> = BTreeSet::default();
        let mut last_version = None;

        for (version, subnet_id, record) in self.records {
            if let Some(last_version) = last_version
                && last_version != version
            {
                add_subnet_list_record(
                    &registry_data_provider,
                    last_version,
                    Vec::from_iter(subnet_ids.clone()),
                );
            }

            if subnet_ids.insert(subnet_id) {
                insert_initial_dkg_transcript(version, subnet_id, &record, &registry_data_provider);
            }

            add_single_subnet_record(&registry_data_provider, version, subnet_id, record);

            last_version = Some(version);
        }

        if let Some(last_version) = last_version {
            add_subnet_list_record(
                &registry_data_provider,
                last_version,
                Vec::from_iter(subnet_ids),
            );
        }

        for registry_mutation in self.additional_registry_mutations {
            registry_mutation(&registry_data_provider);
        }

        let registry = Arc::new(FakeRegistryClient::new(
            Arc::clone(&registry_data_provider) as Arc<_>
        ));

        registry_data_provider
            .add(
                ROOT_SUBNET_ID_KEY,
                initial_registry_version,
                Some(ic_types::subnet_id_into_protobuf(subnet_test_id(0))),
            )
            .unwrap();
        registry.update_to_latest_version();
        let crypto = Arc::new(CryptoReturningOk::default());
        let state_manager = Arc::new(RefMockStateManager::default());
        let log = ic_logger::replica_logger::no_op_logger();
        let dkg_pool = Arc::new(RwLock::new(DkgPoolImpl::new(
            ic_metrics::MetricsRegistry::new(),
            log.clone(),
        )));
        let idkg_pool = Arc::new(RwLock::new(IDkgPoolImpl::new(
            self.pool_config.clone(),
            log.clone(),
            ic_metrics::MetricsRegistry::new(),
            Box::new(IDkgStatsNoOp {}),
        )));
        let canister_http_pool = Arc::new(RwLock::new(CanisterHttpPoolImpl::new(
            ic_metrics::MetricsRegistry::new(),
            log,
        )));
        let pool = TestConsensusPool::new(
            self.replica_config.node_id,
            self.replica_config.subnet_id,
            self.pool_config,
            time_source.clone(),
            registry.clone(),
            crypto.clone(),
            state_manager.clone(),
            Some(dkg_pool.clone()),
        );
        let membership = Arc::new(Membership::new(
            pool.get_cache(),
            registry.clone(),
            self.replica_config.subnet_id,
        ));

        if self.mocked_state_manager {
            state_manager
                .get_mut()
                .expect_get_state_at()
                .return_const(Ok(ic_interfaces_state_manager::Labeled::new(
                    Height::new(0),
                    Arc::new(ic_test_utilities_state::get_initial_state(0, 0)),
                )));
        }

        Dependencies {
            crypto,
            registry,
            registry_data_provider,
            membership,
            time_source,
            pool,
            replica_config: self.replica_config,
            state_manager,
            dkg_pool,
            idkg_pool,
            canister_http_pool,
        }
    }
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
    DependenciesBuilder::new(
        pool_config,
        records
            .into_iter()
            .map(|(version, record)| (version, subnet_id, record))
            .collect(),
    )
    .build()
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
    DependenciesBuilder::new(
        pool_config,
        records
            .into_iter()
            .map(|(version, record)| (version, subnet_id, record))
            .collect(),
    )
    .with_mocked_state_manager()
    .build()
}

/// Creates most common consensus components used for testing. All components
/// share the same mocked registry with one registry version holding the subnet
/// record for the specified number of nodes with all other parameters set to
/// their default values.
pub fn dependencies(pool_config: ArtifactPoolConfig, nodes: u64) -> Dependencies {
    let committee = (0..nodes).map(node_test_id).collect::<Vec<_>>();
    DependenciesBuilder::new(
        pool_config,
        vec![(
            1,
            subnet_test_id(0),
            SubnetRecordBuilder::from(&committee).build(),
        )],
    )
    .with_mocked_state_manager()
    .build()
}
