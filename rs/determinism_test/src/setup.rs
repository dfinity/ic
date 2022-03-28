use ic_config::{
    subnet_config::{SubnetConfig, SubnetConfigs},
    Config,
};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_execution_environment::ExecutionServices;
use ic_interfaces::execution_environment::IngressHistoryReader;
use ic_messaging::MessageRoutingImpl;
use ic_metrics::MetricsRegistry;
use ic_metrics_exporter::MetricsRuntimeImpl;
use ic_protobuf::registry::{
    provisional_whitelist::v1::ProvisionalWhitelist as PbProvisionalWhitelist,
    routing_table::v1::RoutingTable as PbRoutingTable,
};
use ic_protobuf::types::v1::PrincipalId as PrincipalIdIdProto;
use ic_protobuf::types::v1::SubnetId as SubnetIdProto;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_keys::{
    make_provisional_whitelist_record_key, make_routing_table_record_key, ROOT_SUBNET_ID_KEY,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::{
    consensus::fake::FakeVerifier,
    registry::{add_subnet_record, insert_initial_dkg_transcript, SubnetRecordBuilder},
    types::ids::subnet_test_id,
};
use ic_types::{replica_config::ReplicaConfig, NodeId, PrincipalId, RegistryVersion, SubnetId};
use std::sync::Arc;

fn get_registry(
    metrics_registry: &MetricsRegistry,
    subnet_id: SubnetId,
    root_subnet_id: SubnetId,
    subnet_type: SubnetType,
    node_ids: &[NodeId],
) -> Arc<RegistryClientImpl> {
    let registry_version = RegistryVersion::from(1);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());

    let root_subnet_id_proto = SubnetIdProto {
        principal_id: Some(PrincipalIdIdProto {
            raw: root_subnet_id.get_ref().to_vec(),
        }),
    };
    data_provider
        .add(
            ROOT_SUBNET_ID_KEY,
            registry_version,
            Some(root_subnet_id_proto),
        )
        .unwrap();
    let mut routing_table = RoutingTable::new();
    routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
    let pb_routing_table = PbRoutingTable::from(routing_table);
    data_provider
        .add(
            &make_routing_table_record_key(),
            registry_version,
            Some(pb_routing_table),
        )
        .unwrap();
    let pb_whitelist = PbProvisionalWhitelist::from(ProvisionalWhitelist::All);
    data_provider
        .add(
            &make_provisional_whitelist_record_key(),
            registry_version,
            Some(pb_whitelist),
        )
        .unwrap();

    // Set subnetwork list(needed for filling network_topology.nns_subnet_id)
    let mut record = SubnetRecordBuilder::from(node_ids).build();
    record.subnet_type = i32::from(subnet_type);

    insert_initial_dkg_transcript(registry_version.get(), subnet_id, &record, &data_provider);
    add_subnet_record(&data_provider, registry_version.get(), subnet_id, record);

    let registry_client = Arc::new(RegistryClientImpl::new(
        data_provider,
        Some(metrics_registry),
    ));
    registry_client.fetch_and_start_polling().unwrap();
    registry_client
}

pub(crate) fn setup() -> (
    MessageRoutingImpl,
    Arc<StateManagerImpl>,
    Box<dyn IngressHistoryReader>,
    Config,
    SubnetConfig,
) {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let subnet_type = SubnetType::System;
    let subnet_id = subnet_test_id(1);
    let root_subnet_id = subnet_test_id(2);
    let (config, _) = Config::temp_config();
    let subnet_config = SubnetConfigs::default().own_subnet_config(subnet_type);
    let replica_config = ReplicaConfig {
        node_id: NodeId::from(PrincipalId::new_node_test_id(27)),
        subnet_id,
    };

    let metrics_registry = MetricsRegistry::new();
    let registry = get_registry(
        &metrics_registry,
        subnet_id,
        root_subnet_id,
        subnet_type,
        &[replica_config.node_id],
    );

    let cycles_account_manager = Arc::new(CyclesAccountManager::new(
        subnet_config.scheduler_config.max_instructions_per_message,
        subnet_type,
        subnet_id,
        subnet_config.cycles_account_manager_config,
    ));
    let state_manager = Arc::new(StateManagerImpl::new(
        Arc::new(FakeVerifier::new()),
        replica_config.subnet_id,
        subnet_type,
        log.clone().into(),
        &metrics_registry,
        &config.state_manager,
        None,
        ic_types::malicious_flags::MaliciousFlags::default(),
    ));

    let execution_services = ExecutionServices::setup_execution(
        log.clone().into(),
        &metrics_registry,
        replica_config.subnet_id,
        subnet_type,
        subnet_config.scheduler_config.clone(),
        config.hypervisor.clone(),
        Arc::clone(&cycles_account_manager),
        Arc::clone(&state_manager) as Arc<_>,
    );
    let _metrics_runtime = MetricsRuntimeImpl::new_insecure(
        tokio::runtime::Handle::current(),
        config.metrics.clone(),
        metrics_registry.clone(),
        &log,
    );

    let message_routing = MessageRoutingImpl::new(
        Arc::clone(&state_manager) as _,
        Arc::clone(&state_manager) as _,
        Arc::clone(&execution_services.ingress_history_writer) as _,
        execution_services.scheduler,
        config.hypervisor.clone(),
        cycles_account_manager,
        replica_config.subnet_id,
        &metrics_registry,
        log.clone().into(),
        Arc::clone(&registry) as _,
    );

    (
        message_routing,
        state_manager,
        execution_services.ingress_history_reader,
        config,
        subnet_config,
    )
}
