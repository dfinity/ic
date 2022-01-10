use crate::{
    canister_manager::{CanisterManager, CanisterMgrConfig},
    canister_settings::CanisterSettings,
    hypervisor::Hypervisor,
    IngressHistoryWriterImpl, InternalHttpQueryHandler,
};
use ic_base_types::NumSeconds;
use ic_config::execution_environment::Config;
use ic_interfaces::execution_environment::{
    ExecutionMode, ExecutionParameters, QueryHandler, SubnetAvailableMemory,
};
use ic_metrics::MetricsRegistry;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    types::{
        ids::{canister_test_id, subnet_test_id, user_test_id},
        messages::InstallCodeContextBuilder,
    },
    universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM},
    with_test_replica_logger,
};
use ic_types::{
    ingress::WasmResult, messages::UserQuery, user_error::ErrorCode, ComputeAllocation,
};
use ic_types::{CanisterId, Cycles, NumBytes, NumInstructions, SubnetId};
use maplit::btreemap;
use std::{convert::TryFrom, path::Path, sync::Arc};

const CYCLE_BALANCE: Cycles = Cycles::new(100_000_000_000_000);
const INSTRUCTION_LIMIT: NumInstructions = NumInstructions::new(1_000_000_000);
const MEMORY_CAPACITY: NumBytes = NumBytes::new(1_000_000_000);
const MAX_NUMBER_OF_CANISTERS: u64 = 0;

fn with_setup<F>(subnet_type: SubnetType, f: F)
where
    F: FnOnce(InternalHttpQueryHandler, CanisterManager, ReplicatedState),
{
    fn canister_manager_config(subnet_id: SubnetId, subnet_type: SubnetType) -> CanisterMgrConfig {
        CanisterMgrConfig::new(
            MEMORY_CAPACITY,
            Some(CYCLE_BALANCE),
            CYCLE_BALANCE,
            NumSeconds::from(100_000),
            subnet_id,
            subnet_type,
            1000,
            1,
        )
    }

    fn initial_state(path: &Path, subnet_id: SubnetId, subnet_type: SubnetType) -> ReplicatedState {
        let routing_table = Arc::new(RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0), end: CanisterId::from(0xff) } => subnet_id,
        }).unwrap());
        let mut state = ReplicatedState::new_rooted_at(subnet_id, subnet_type, path.to_path_buf());
        state.metadata.network_topology.routing_table = routing_table;
        state.metadata.network_topology.nns_subnet_id = subnet_id;
        state
    }

    with_test_replica_logger(|log| {
        let subnet_id = subnet_test_id(1);
        let metrics_registry = MetricsRegistry::new();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        let hypervisor = Hypervisor::new(
            Config::default(),
            &metrics_registry,
            subnet_id,
            subnet_type,
            log.clone(),
            Arc::clone(&cycles_account_manager),
        );
        let hypervisor = Arc::new(hypervisor);
        let ingress_history_writer = Arc::new(IngressHistoryWriterImpl::new(
            log.clone(),
            &metrics_registry,
        ));
        let canister_manager = CanisterManager::new(
            Arc::clone(&hypervisor) as Arc<_>,
            log.clone(),
            canister_manager_config(subnet_id, subnet_type),
            cycles_account_manager,
            ingress_history_writer,
        );
        let tmpdir = tempfile::Builder::new().prefix("test").tempdir().unwrap();
        let state = initial_state(tmpdir.path(), subnet_id, subnet_type);
        let query_handler = InternalHttpQueryHandler::new(
            log,
            hypervisor,
            subnet_id,
            subnet_type,
            Config::default(),
            &metrics_registry,
            INSTRUCTION_LIMIT,
        );
        f(query_handler, canister_manager, state);
    });
}

fn universal_canister(
    canister_manager: &CanisterManager,
    state: &mut ReplicatedState,
) -> CanisterId {
    let sender = canister_test_id(1).get();
    let sender_subnet_id = subnet_test_id(1);
    let canister_id = canister_manager
        .create_canister(
            sender,
            sender_subnet_id,
            CYCLE_BALANCE,
            CanisterSettings::default(),
            MAX_NUMBER_OF_CANISTERS,
            state,
        )
        .0
        .unwrap();

    canister_manager
        .install_code(
            InstallCodeContextBuilder::default()
                .sender(sender)
                .canister_id(canister_id)
                .wasm_module(UNIVERSAL_CANISTER_WASM.to_vec())
                .build(),
            state,
            ExecutionParameters {
                instruction_limit: INSTRUCTION_LIMIT,
                canister_memory_limit: MEMORY_CAPACITY,
                subnet_available_memory: SubnetAvailableMemory::new(MEMORY_CAPACITY.get() as i64),
                compute_allocation: ComputeAllocation::default(),
                subnet_type: SubnetType::Application,
                execution_mode: ExecutionMode::Replicated,
            },
        )
        .1
        .unwrap();
    canister_id
}

#[test]
fn query_metrics_are_reported() {
    with_setup(
        SubnetType::VerifiedApplication,
        |query_handler, canister_manager, mut state| {
            // In this test we have two canisters A and B.
            // Canister A handles the user query by calling canister B.

            let canister_a = universal_canister(&canister_manager, &mut state);
            let canister_b = universal_canister(&canister_manager, &mut state);
            let output = query_handler.query(
                UserQuery {
                    source: user_test_id(2),
                    receiver: canister_a,
                    method_name: "query".to_string(),
                    method_payload: wasm()
                        .inter_query(
                            canister_b,
                            call_args().other_side(wasm().reply_data(&b"pong".to_vec())),
                        )
                        .build(),
                    ingress_expiry: 0,
                    nonce: None,
                },
                Arc::new(state),
                vec![],
            );
            assert_eq!(output, Ok(WasmResult::Reply(b"pong".to_vec())));
            assert_eq!(1, query_handler.metrics.query.duration.get_sample_count());
            assert_eq!(
                1,
                query_handler.metrics.query.instructions.get_sample_count()
            );
            assert!(0 < query_handler.metrics.query.instructions.get_sample_sum() as u64);
            assert_eq!(1, query_handler.metrics.query.messages.get_sample_count());
            // We expect four messages:
            // - canister_a.query() as pure
            // - canister_a.query() as stateful
            // - canister_b.query() as stateful
            // - canister_a.on_reply()
            assert_eq!(
                4,
                query_handler.metrics.query.messages.get_sample_sum() as u64
            );
            assert_eq!(
                1,
                query_handler
                    .metrics
                    .query_initial_call
                    .duration
                    .get_sample_count()
            );
            assert!(
                0 < query_handler
                    .metrics
                    .query_initial_call
                    .instructions
                    .get_sample_sum() as u64
            );
            assert_eq!(
                1,
                query_handler
                    .metrics
                    .query_initial_call
                    .instructions
                    .get_sample_count()
            );
            assert_eq!(
                1,
                query_handler
                    .metrics
                    .query_initial_call
                    .messages
                    .get_sample_count()
            );
            assert_eq!(
                1,
                query_handler
                    .metrics
                    .query_initial_call
                    .messages
                    .get_sample_sum() as u64
            );
            assert_eq!(
                1,
                query_handler
                    .metrics
                    .query_retry_call
                    .duration
                    .get_sample_count()
            );
            assert_eq!(
                1,
                query_handler
                    .metrics
                    .query_spawned_calls
                    .duration
                    .get_sample_count()
            );
            assert_eq!(
                1,
                query_handler
                    .metrics
                    .query_spawned_calls
                    .instructions
                    .get_sample_count()
            );
            assert!(
                0 < query_handler
                    .metrics
                    .query_spawned_calls
                    .instructions
                    .get_sample_sum() as u64
            );
            assert_eq!(
                1,
                query_handler
                    .metrics
                    .query_spawned_calls
                    .messages
                    .get_sample_count()
            );
            assert_eq!(
                2,
                query_handler
                    .metrics
                    .query_spawned_calls
                    .messages
                    .get_sample_sum() as u64
            );
            assert_eq!(
                query_handler.metrics.query.instructions.get_sample_sum() as u64,
                query_handler
                    .metrics
                    .query_initial_call
                    .instructions
                    .get_sample_sum() as u64
                    + query_handler
                        .metrics
                        .query_retry_call
                        .instructions
                        .get_sample_sum() as u64
                    + query_handler
                        .metrics
                        .query_spawned_calls
                        .instructions
                        .get_sample_sum() as u64
            )
        },
    );
}

#[test]
fn query_call_with_side_effects() {
    with_setup(
        SubnetType::System,
        |query_handler, canister_manager, mut state| {
            // In this test we have two canisters A and B.
            // Canister A does a side-effectful operation (stable_grow) and then
            // calls canister B. The side effect must happen once and only once.

            let canister_a = universal_canister(&canister_manager, &mut state);
            let canister_b = universal_canister(&canister_manager, &mut state);
            let output = query_handler.query(
                UserQuery {
                    source: user_test_id(2),
                    receiver: canister_a,
                    method_name: "query".to_string(),
                    method_payload: wasm()
                        .stable_grow(10)
                        .inter_query(
                            canister_b,
                            call_args()
                                .other_side(wasm().reply_data(&b"ignore".to_vec()))
                                .on_reply(wasm().stable_size().reply_int()),
                        )
                        .build(),
                    ingress_expiry: 0,
                    nonce: None,
                },
                Arc::new(state),
                vec![],
            );
            assert_eq!(output, Ok(WasmResult::Reply(10_i32.to_le_bytes().to_vec())));
        },
    );
}

#[test]
fn query_calls_disabled_for_application_subnet() {
    with_setup(
        SubnetType::Application,
        |query_handler, canister_manager, mut state| {
            // In this test we have two canisters A and B.
            // Canister A does a side-effectful operation (stable_grow) and then
            // calls canister B. The side effect must happen once and only once.

            let canister_a = universal_canister(&canister_manager, &mut state);
            let canister_b = universal_canister(&canister_manager, &mut state);
            let output = query_handler.query(
                UserQuery {
                    source: user_test_id(2),
                    receiver: canister_a,
                    method_name: "query".to_string(),
                    method_payload: wasm()
                        .stable_grow(10)
                        .inter_query(
                            canister_b,
                            call_args()
                                .other_side(wasm().reply_data(&b"ignore".to_vec()))
                                .on_reply(wasm().stable_size().reply_int()),
                        )
                        .build(),
                    ingress_expiry: 0,
                    nonce: None,
                },
                Arc::new(state),
                vec![],
            );
            match output {
                Ok(_) => unreachable!("The query was expected to fail, but it succeeded."),
                Err(err) => assert_eq!(err.code(), ErrorCode::CanisterContractViolation),
            }
        },
    );
}

#[test]
fn query_compilied_once() {
    with_setup(
        SubnetType::Application,
        |query_handler, canister_manager, mut state| {
            let canister_id = universal_canister(&canister_manager, &mut state);
            let canister = state.canister_state_mut(&canister_id).unwrap();
            // The canister was compiled during installation.
            assert_eq!(1, query_handler.hypervisor.compile_count());
            // Drop the embedder cache to force compilation during query handling.
            canister
                .execution_state
                .as_mut()
                .unwrap()
                .wasm_binary
                .clear_compilation_cache();

            let result = query_handler.query(
                UserQuery {
                    source: user_test_id(2),
                    receiver: canister_id,
                    method_name: "query".to_string(),
                    method_payload: wasm().reply().build(),
                    ingress_expiry: 0,
                    nonce: None,
                },
                Arc::new(state.clone()),
                vec![],
            );
            assert!(result.is_ok());

            // Now we expect the compilation counter to increase because the query
            // had to compile.
            assert_eq!(2, query_handler.hypervisor.compile_count());

            let result = query_handler.query(
                UserQuery {
                    source: user_test_id(2),
                    receiver: canister_id,
                    method_name: "query".to_string(),
                    method_payload: wasm().reply().build(),
                    ingress_expiry: 0,
                    nonce: None,
                },
                Arc::new(state),
                vec![],
            );
            assert!(result.is_ok());

            // The last query should have reused the compiled code.
            assert_eq!(2, query_handler.hypervisor.compile_count());
        },
    );
}
