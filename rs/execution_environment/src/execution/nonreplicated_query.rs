// This module defines how non-replicated query messages are executed.
// See https://smartcontracts.org/docs/interface-spec/index.html#http-query.
//
// Note that execution of replicated queries (queries in the update context)
// is defined in the `call` module.
//

use crate::execution::common::{validate_canister, validate_method};
use crate::{Hypervisor, NonReplicatedQueryKind};
use ic_base_types::PrincipalId;
use ic_error_types::UserError;
use ic_interfaces::execution_environment::ExecutionParameters;
use ic_replicated_state::{CanisterState, NetworkTopology};
use ic_system_api::ApiType;
use ic_types::ingress::WasmResult;
use ic_types::methods::{FuncRef, WasmMethod};
use ic_types::{Cycles, NumInstructions, Time};

// Execute non replicated query.
#[allow(clippy::too_many_arguments)]
pub fn execute_non_replicated_query(
    query_kind: NonReplicatedQueryKind,
    method: &str,
    payload: &[u8],
    caller: PrincipalId,
    mut canister: CanisterState,
    data_certificate: Option<Vec<u8>>,
    time: Time,
    execution_parameters: ExecutionParameters,
    network_topology: &NetworkTopology,
    hypervisor: &Hypervisor,
) -> (
    CanisterState,
    NumInstructions,
    Result<Option<WasmResult>, UserError>,
) {
    // Validate that the canister is running.
    if let Err(err) = validate_canister(&canister) {
        return (
            canister,
            execution_parameters.total_instruction_limit,
            Err(err),
        );
    }

    let method = WasmMethod::Query(method.to_string());
    let memory_usage = canister.memory_usage(hypervisor.subnet_type());

    // Validate that the Wasm module is present and exports the method
    if let Err(err) = validate_method(&method, &canister) {
        let canister_id = canister.canister_id();
        return (
            canister,
            execution_parameters.total_instruction_limit,
            Err(err.into_user_error(&canister_id)),
        );
    }

    let mut preserve_changes = false;
    let non_replicated_query_kind = match query_kind {
        NonReplicatedQueryKind::Pure => ic_system_api::NonReplicatedQueryKind::Pure,
        NonReplicatedQueryKind::Stateful { call_origin } => {
            preserve_changes = true;
            let call_context_id = canister
                .system_state
                .call_context_manager_mut()
                .unwrap()
                .new_call_context(call_origin, Cycles::from(0), time);
            ic_system_api::NonReplicatedQueryKind::Stateful {
                call_context_id,
                outgoing_request: None,
            }
        }
    };

    let api_type = ApiType::non_replicated_query(
        time,
        caller,
        hypervisor.subnet_id(),
        payload.to_vec(),
        data_certificate,
        non_replicated_query_kind,
    );
    // As we are executing the query in non-replicated mode, we can
    // modify the canister as the caller is not going to be able to
    // commit modifications to the canister anyway.
    let (output, output_execution_state, output_system_state) = hypervisor.execute(
        api_type,
        canister.system_state,
        memory_usage,
        execution_parameters,
        FuncRef::Method(method),
        canister.execution_state.clone().unwrap(),
        network_topology,
    );
    canister.system_state = output_system_state;
    if preserve_changes {
        canister.execution_state = Some(output_execution_state);
    }

    let result = output
        .wasm_result
        .map_err(|err| err.into_user_error(&canister.canister_id()));
    (canister, output.num_instructions_left, result)
}
