use ic_config::execution_environment::Config;
use ic_config::subnet_config::SubnetConfigs;
use ic_execution_environment::setup_execution;
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    state_manager::FakeStateManager,
    types::ids::{subnet_test_id, user_test_id},
    with_test_replica_logger,
};
use ic_types::{messages::UserQuery, user_error::ErrorCode, CanisterId, SubnetId};
use maplit::btreemap;
use std::{path::Path, sync::Arc};

fn initial_state(path: &Path, subnet_id: SubnetId) -> ReplicatedState {
    let routing_table = RoutingTable::new(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
    });
    let mut state =
        ReplicatedState::new_rooted_at(subnet_id, SubnetType::Application, path.to_path_buf());
    state.metadata.network_topology.routing_table = routing_table;
    state
}

#[test]
fn query_non_existent() {
    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let subnet_type = SubnetType::Application;
        let subnet_config = SubnetConfigs::default().own_subnet_config(subnet_type);
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let state = initial_state(tmpdir.path(), subnet_id);
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let state_manager = Arc::new(FakeStateManager::new());

        let (_, _, query_handler, _, _) = setup_execution(
            log,
            &metrics_registry,
            subnet_id,
            subnet_type,
            subnet_config.scheduler_config,
            Config::default(),
            cycles_account_manager,
            state_manager,
        );

        let receiver = CanisterId::from(1234);
        match query_handler.query(
            UserQuery {
                source: user_test_id(2),
                receiver,
                method_name: "read".to_string(),
                method_payload: b"Hello".to_vec(),
                ingress_expiry: 0,
                nonce: None,
            },
            Arc::new(state),
            vec![],
        ) {
            Err(ref e) if e.code() == ErrorCode::CanisterNotFound => (),
            e => panic!("expected NotFound error, got {:?}", e),
        }
    });
}
