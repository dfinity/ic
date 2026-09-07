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
use ic_interfaces_mocks::messaging::RefMockMessageRouting;
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
    Height, RegistryVersion, ReplicaVersion, SubnetId, Time,
    batch::{BatchPayload, ValidationContext},
    consensus::{Payload, block_maker::SubnetRecords},
    replica_config::ReplicaConfig,
};
use mockall::*;
use std::str::FromStr;
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
    mock: RwLock<MockPayloadBuilder>,
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

#[non_exhaustive]
pub struct Dependencies {
    pub crypto: Arc<CryptoReturningOk>,
    pub registry: Arc<FakeRegistryClient>,
    pub registry_data_provider: Arc<ProtoRegistryDataProvider>,
    pub membership: Arc<Membership>,
    pub time_source: Arc<FastForwardTimeSource>,
    pub pool: TestConsensusPool,
    pub replica_config: ReplicaConfig,
    pub state_manager: Arc<RefMockStateManager>,
    pub payload_builder: Arc<RefMockPayloadBuilder>,
    pub message_routing: Arc<RefMockMessageRouting>,
    pub dkg_pool: Arc<RwLock<DkgPoolImpl>>,
    pub idkg_pool: Arc<RwLock<IDkgPoolImpl>>,
    pub canister_http_pool: Arc<RwLock<CanisterHttpPoolImpl>>,
}

pub struct DependenciesBuilder {
    pool_config: ArtifactPoolConfig,
    sorted_subnet_records: Vec<(u64, SubnetId, SubnetRecord)>,
    replica_config: ReplicaConfig,
    with_state_manager_expectations: bool,
}

impl DependenciesBuilder {
    /// Creates a builder for the most common consensus components used for
    /// testing. All components share the same mocked registry with one
    /// registry version holding the subnet record for the specified number of
    /// nodes with all other parameters set to their default values.
    pub fn new(pool_config: ArtifactPoolConfig, nodes: u64) -> Self {
        let committee = (0..nodes).map(node_test_id).collect::<Vec<_>>();
        Self::single_subnet(
            pool_config,
            subnet_test_id(0),
            vec![(1, SubnetRecordBuilder::from(&committee).build())],
        )
    }

    /// Creates a builder for the most common consensus components used for
    /// testing. All components share the same mocked registry with the
    /// provided records, so they refer to the identical registry content at
    /// any time. This constructor should be used, if specific subnet
    /// parameters are required.
    pub fn single_subnet(
        pool_config: ArtifactPoolConfig,
        subnet_id: SubnetId,
        subnet_records: Vec<(u64, SubnetRecord)>,
    ) -> Self {
        Self::multiple_subnets(
            pool_config,
            subnet_records
                .into_iter()
                .map(|(version, record)| (version, subnet_id, record))
                .collect(),
        )
    }

    /// Creates a builder for the most common consensus components used for
    /// testing. All components share the same mocked registry with the
    /// provided records, so they refer to the identical registry content at
    /// any time. This constructor should be used, if records for multiple
    /// subnets are required.
    pub fn multiple_subnets(
        pool_config: ArtifactPoolConfig,
        mut subnet_records: Vec<(u64, SubnetId, SubnetRecord)>,
    ) -> Self {
        assert!(
            !subnet_records.is_empty(),
            "Cannot setup a registry without records."
        );

        // Sort the records by registry version to ensure we are iterating on them in the correct
        // order when inserting them into the registry.
        subnet_records.sort_by_key(|(version, _, _)| *version);

        Self {
            pool_config,
            replica_config: ReplicaConfig {
                node_id: node_test_id(0),
                subnet_id: subnet_records[0].1,
                replica_version: ReplicaVersion::from_str(&subnet_records[0].2.replica_version_id)
                    .expect("Invalid replica_version_id"),
            },
            sorted_subnet_records: subnet_records,
            with_state_manager_expectations: true,
        }
    }

    pub fn with_replica_config(mut self, replica_config: ReplicaConfig) -> Self {
        self.replica_config = replica_config;
        self
    }

    /// Sets the DKG interval length on every subnet record passed to the
    /// builder.
    pub fn with_dkg_interval_length(mut self, length: u64) -> Self {
        for (_, _, record) in self.sorted_subnet_records.iter_mut() {
            record.dkg_interval_length = length;
        }
        self
    }

    /// Leaves the returned `RefMockStateManager` without any expectations, so
    /// that the test can set up its own `get_state_at` behavior.
    pub fn without_state_manager_expectations(mut self) -> Self {
        self.with_state_manager_expectations = false;
        self
    }

    pub fn build(self) -> Dependencies {
        let time_source = FastForwardTimeSource::new();
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());

        registry_data_provider
            .add(
                ROOT_SUBNET_ID_KEY,
                RegistryVersion::from(self.sorted_subnet_records[0].0),
                Some(ic_types::subnet_id_into_protobuf(subnet_test_id(0))),
            )
            .unwrap();

        let mut subnet_ids: BTreeSet<SubnetId> = BTreeSet::default();
        let mut last_version = None;
        for (version, subnet_id, record) in self.sorted_subnet_records {
            // Update the subnet list record for the previous version when the version changes.
            // This ensures that the subnet list record is updated only once per version, even if
            // there are multiple subnet records for that version (we assume the records are
            // sorted).
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
        // The last iterated version never had its subnet list record updated, so we need to do it
        // here.
        if let Some(last_version) = last_version {
            add_subnet_list_record(
                &registry_data_provider,
                last_version,
                Vec::from_iter(subnet_ids),
            );
        }

        let registry = Arc::new(FakeRegistryClient::new(
            Arc::clone(&registry_data_provider) as Arc<_>
        ));

        registry.update_to_latest_version();

        let crypto = Arc::new(CryptoReturningOk::default());
        let state_manager = Arc::new(RefMockStateManager::default());
        let log = ic_logger::replica_logger::no_op_logger();
        let dkg_pool = Arc::new(RwLock::new(DkgPoolImpl::new(
            ic_metrics::MetricsRegistry::new(),
            log.clone(),
            Height::from(0),
        )));
        let idkg_pool = Arc::new(RwLock::new(IDkgPoolImpl::new(
            self.replica_config.node_id,
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
            self.replica_config.replica_version.clone(),
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

        if self.with_state_manager_expectations {
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
            payload_builder: Arc::new(RefMockPayloadBuilder::default()),
            message_routing: Arc::new(RefMockMessageRouting::default()),
            dkg_pool,
            idkg_pool,
            canister_http_pool,
        }
    }
}
