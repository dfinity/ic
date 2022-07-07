use crate::Hypervisor;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{ExecutionParameters, SubnetAvailableMemory};
use ic_logger::{fatal, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, NetworkTopology};
use ic_system_api::ApiType;
use ic_types::messages::SignedIngressContent;
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{NumInstructions, Time};

/// Executes the system method `canister_inspect_message`.
///
/// This method is called pre-consensus to let the canister decide if it
/// wants to accept the message or not.
pub fn execute_inspect_message(
    time: Time,
    canister: CanisterState,
    ingress: &SignedIngressContent,
    own_subnet_type: SubnetType,
    execution_parameters: ExecutionParameters,
    subnet_available_memory: SubnetAvailableMemory,
    hypervisor: &Hypervisor,
    network_topology: &NetworkTopology,
    logger: &ReplicaLogger,
) -> (NumInstructions, Result<(), UserError>) {
    let canister_id = canister.canister_id();
    let memory_usage = canister.memory_usage(own_subnet_type);
    let method = WasmMethod::System(SystemMethod::CanisterInspectMessage);
    let (execution_state, system_state, _) = canister.into_parts();

    // Validate that the Wasm module is present.
    let execution_state = match execution_state {
        None => {
            return (
                execution_parameters.total_instruction_limit,
                Err(UserError::new(
                    ErrorCode::CanisterWasmModuleNotFound,
                    "Requested canister has no wasm module",
                )),
            );
        }
        Some(execution_state) => execution_state,
    };

    // If the Wasm module does not export the method, then this execution
    // succeeds as a no-op.
    if !execution_state.exports_method(&method) {
        return (execution_parameters.total_instruction_limit, Ok(()));
    }

    let system_api = ApiType::inspect_message(
        ingress.sender().get(),
        ingress.method_name().to_string(),
        ingress.arg().to_vec(),
        time,
    );
    let (output, _output_execution_state, _system_state_accessor) = hypervisor.execute(
        system_api,
        system_state,
        memory_usage,
        execution_parameters,
        subnet_available_memory,
        FuncRef::Method(method),
        execution_state,
        network_topology,
    );
    match output.wasm_result {
        Ok(maybe_wasm_result) => match maybe_wasm_result {
            None => (output.num_instructions_left, Ok(())),
            Some(_result) => fatal!(
                logger,
                "SystemApi should guarantee that the canister does not reply"
            ),
        },
        Err(err) => (
            output.num_instructions_left,
            Err(err.into_user_error(&canister_id)),
        ),
    }
}
