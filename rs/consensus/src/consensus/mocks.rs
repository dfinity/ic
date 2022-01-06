//! Contains mocks for traits internal to consensus
use crate::consensus::{membership::Membership, payload_builder::PayloadBuilder};
use ic_artifact_pool::{dkg_pool::DkgPoolImpl, ecdsa_pool::EcdsaPoolImpl};
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_interfaces::{
    consensus::PayloadValidationError, ingress_pool::IngressPoolSelect,
    validation::ValidationResult,
};
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_keys::ROOT_SUBNET_ID_KEY;
use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
use ic_test_utilities::{
    crypto::CryptoReturningOk,
    registry::{setup_registry_non_final, SubnetRecordBuilder},
    state_manager::RefMockStateManager,
    types::ids::{node_test_id, subnet_test_id},
    FastForwardTimeSource,
};
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::Payload,
    replica_config::ReplicaConfig,
    Height, RegistryVersion, SubnetId, Time,
};
use mockall::predicate::*;
use mockall::*;
use std::sync::{Arc, RwLock};

use super::block_maker::SubnetRecords;

mock! {
    pub PayloadBuilder {}

    pub trait PayloadBuilder {
        fn get_payload<'a>(
            &self,
            height: Height,
            ingress_pool: &'a (dyn IngressPoolSelect + 'a),
            past_payloads: &[(Height, Time, Payload)],
            context: &ValidationContext,
            subnet_records: &SubnetRecords,
        ) -> BatchPayload;

        fn validate_payload(
            &self,
            payload: &Payload,
            past_payloads: &[(Height, Time, Payload)],
            context: &ValidationContext,
        ) -> ValidationResult<PayloadValidationError>;
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
    pub ecdsa_pool: Arc<RwLock<EcdsaPoolImpl>>,
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
    let dkg_pool = Arc::new(RwLock::new(DkgPoolImpl::new(
        ic_metrics::MetricsRegistry::new(),
    )));
    let ecdsa_pool = Arc::new(RwLock::new(EcdsaPoolImpl::new(
        ic_logger::replica_logger::no_op_logger(),
        ic_metrics::MetricsRegistry::new(),
    )));
    let pool = TestConsensusPool::new(
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
        ecdsa_pool,
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
        ecdsa_pool,
        ..
    } = dependencies_with_subnet_records_with_raw_state_manager(pool_config, subnet_id, records);

    state_manager
        .get_mut()
        .expect_get_state_at()
        .return_const(Ok(ic_interfaces::state_manager::Labeled::new(
            Height::new(0),
            Arc::new(ic_test_utilities::state::get_initial_state(0, 0)),
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
        ecdsa_pool,
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
