mod hypervisor;
use hypervisor::{execution_parameters, test_network_topology, with_hypervisor};
use ic_base_types::NumSeconds;
use ic_execution_environment::execution::heartbeat;
use ic_execution_environment::CanisterHeartbeatError;
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::{HypervisorError, TrapCode};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{page_map::PAGE_SIZE, CanisterState};
use ic_test_utilities::{
    cycles_account_manager::CyclesAccountManagerBuilder,
    mock_time,
    state::SystemStateBuilder,
    state::{get_stopped_canister_on_system_subnet, get_stopping_canister_on_nns},
    types::ids::canister_test_id,
};
use ic_types::{methods::SystemMethod, Cycles, NumBytes, NumInstructions};

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const INITIAL_CYCLES: Cycles = Cycles::new(5_000_000_000_000);

// Tests that canister heartbeat is executed.
#[test]
fn canister_heartbeat() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
            (module
              (func (export "canister_heartbeat")
                    unreachable)
              (memory (export "memory") 1))"#,
        )
        .unwrap();

        let subnet_type = SubnetType::Application;
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = CanisterState {
            system_state: SystemStateBuilder::new()
                .memory_allocation(NumBytes::new(8 * 1024 * 1024 * 1024)) // 8GiB
                .canister_id(canister_id)
                .initial_cycles(INITIAL_CYCLES)
                .freeze_threshold(NumSeconds::new(0))
                .build(),
            execution_state: Some(execution_state),
            scheduler_state: Default::default(),
        };
        let network_topology = test_network_topology();
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let heartbeat_result = heartbeat::execute_heartbeat(
            canister,
            network_topology,
            execution_parameters,
            subnet_type,
            mock_time(),
            &hypervisor,
            &CyclesAccountManagerBuilder::new().build(),
        );
        assert_eq!(
            heartbeat_result.heap_delta_result,
            Err(CanisterHeartbeatError::CanisterExecutionFailed(
                HypervisorError::Trapped(TrapCode::Unreachable)
            ))
        );
    });
}

// Tests that execute_canister_heartbeat produces a heap delta.
#[test]
fn execute_canister_heartbeat_produces_heap_delta() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wasm = wabt::wat2wasm(
            r#"
            (module
              (func (export "canister_heartbeat")
                (i32.store (i32.const 10) (i32.const 10))
              )
              (memory (export "memory") 1))"#,
        )
        .unwrap();

        let subnet_type = SubnetType::Application;
        let canister_id = canister_test_id(42);
        let execution_state = hypervisor
            .create_execution_state(wasm, tmp_path, canister_id)
            .unwrap();
        let canister = CanisterState {
            system_state: SystemStateBuilder::new()
                .memory_allocation(NumBytes::new(8 * 1024 * 1024 * 1024)) // 8GiB
                .canister_id(canister_id)
                .initial_cycles(INITIAL_CYCLES)
                .freeze_threshold(NumSeconds::new(0))
                .build(),
            execution_state: Some(execution_state),
            scheduler_state: Default::default(),
        };
        let network_topology = test_network_topology();
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let heartbeat_result = heartbeat::execute_heartbeat(
            canister,
            network_topology,
            execution_parameters,
            subnet_type,
            mock_time(),
            &hypervisor,
            &CyclesAccountManagerBuilder::new().build(),
        );
        let heap_delta = heartbeat_result.heap_delta_result.unwrap();
        // the wasm module touched one memory location so that should produce one page
        // of delta.
        assert_eq!(heap_delta.get(), (PAGE_SIZE) as u64);
    });
}

#[test]
fn test_non_existing_canister_heartbeat() {
    with_hypervisor(|hypervisor, tmp_path| {
        let wat = "(module)";
        let binary = wabt::wat2wasm(wat).unwrap();
        let subnet_type = SubnetType::Application;
        let canister_id = canister_test_id(42);
        let system_method = SystemMethod::CanisterStart;

        let execution_state = hypervisor
            .create_execution_state(binary, tmp_path, canister_id)
            .unwrap();
        let canister = CanisterState {
            system_state: SystemStateBuilder::new()
                .memory_allocation(NumBytes::new(8 * 1024 * 1024 * 1024)) // 8GiB
                .canister_id(canister_id)
                .initial_cycles(INITIAL_CYCLES)
                .freeze_threshold(NumSeconds::new(0))
                .build(),
            execution_state: Some(execution_state),
            scheduler_state: Default::default(),
        };
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);
        let network_topology = test_network_topology();
        // Run the non-existing system method.

        let heartbeat_result = heartbeat::execute_heartbeat(
            canister,
            network_topology,
            execution_parameters,
            subnet_type,
            mock_time(),
            &hypervisor,
            &CyclesAccountManagerBuilder::new().build(),
        );

        assert!(
            heartbeat_result.heap_delta_result.is_ok(),
            "{} should return gracefully if it isn't exported.",
            system_method
        );
        assert_eq!(
            heartbeat_result.instructions_left, MAX_NUM_INSTRUCTIONS,
            "Calling {} should not cost cycles if it doesn't exist.",
            system_method
        );
    });
}

#[test]
fn canister_heartbeat_doesnt_run_when_canister_is_stopped() {
    with_hypervisor(|hypervisor, _| {
        let network_topology = test_network_topology();
        let canister = get_stopped_canister_on_system_subnet(canister_test_id(0));
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let result = heartbeat::execute_heartbeat(
            canister,
            network_topology,
            execution_parameters,
            SubnetType::System,
            mock_time(),
            &hypervisor,
            &CyclesAccountManagerBuilder::new().build(),
        );

        assert_eq!(
            result.heap_delta_result,
            Err(CanisterHeartbeatError::CanisterNotRunning {
                status: CanisterStatusType::Stopped,
            })
        );
    });
}

#[test]
fn canister_heartbeat_doesnt_run_when_canister_is_stopping() {
    with_hypervisor(|hypervisor, _| {
        let network_topology = test_network_topology();
        let canister = get_stopping_canister_on_nns(canister_test_id(0));
        let execution_parameters = execution_parameters(&canister, MAX_NUM_INSTRUCTIONS);

        let result = heartbeat::execute_heartbeat(
            canister,
            network_topology,
            execution_parameters,
            SubnetType::System,
            mock_time(),
            &hypervisor,
            &CyclesAccountManagerBuilder::new().build(),
        );

        assert_eq!(
            result.heap_delta_result,
            Err(CanisterHeartbeatError::CanisterNotRunning {
                status: CanisterStatusType::Stopping,
            })
        );
    });
}
