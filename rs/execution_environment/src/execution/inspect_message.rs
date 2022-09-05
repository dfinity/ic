use crate::execution_environment::{as_round_instructions, RoundLimits};
use crate::Hypervisor;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_logger::{fatal, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, NetworkTopology};
use ic_system_api::{ApiType, ExecutionParameters};
use ic_types::messages::SignedIngressContent;
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{NumInstructions, Time};

/// Executes the system method `canister_inspect_message`.
///
/// This method is called pre-consensus to let the canister decide if it
/// wants to accept the message or not.
#[allow(clippy::too_many_arguments)]
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
    let message_instruction_limit = execution_parameters.instruction_limits.message();

    // Validate that the Wasm module is present.
    let execution_state = match execution_state {
        None => {
            return (
                message_instruction_limit,
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
        return (message_instruction_limit, Ok(()));
    }

    let system_api = ApiType::inspect_message(
        ingress.sender().get(),
        ingress.method_name().to_string(),
        ingress.arg().to_vec(),
        time,
    );
    let mut round_limits = RoundLimits {
        instructions: as_round_instructions(message_instruction_limit),
        subnet_available_memory,
        // Ignore compute allocation
        compute_allocation_used: 0,
    };
    let (output, _output_execution_state, _system_state_accessor) = hypervisor.execute(
        system_api,
        time,
        system_state,
        memory_usage,
        execution_parameters,
        FuncRef::Method(method),
        execution_state,
        network_topology,
        &mut round_limits,
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
