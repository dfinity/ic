// This module defines how non-replicated query messages are executed.
// See https://internetcomputer.org/docs/interface-spec/index.html#http-query
//
// Note that execution of replicated queries (queries in the update context)
// is defined in the `call` module.
//

use crate::execution::common::{validate_canister, validate_method};
use crate::execution_environment::RoundLimits;
use crate::{Hypervisor, NonReplicatedQueryKind, metrics::CallTreeMetricsNoOp};
use ic_embedders::wasmtime_embedder::system_api::{ApiType, ExecutionParameters};
use ic_error_types::UserError;
use ic_interfaces::execution_environment::SystemApiCallCounters;
use ic_replicated_state::{CallOrigin, CanisterState, NetworkTopology};
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::ingress::WasmResult;
use ic_types::messages::{CallContextId, RequestMetadata};
use ic_types::methods::{FuncRef, WasmMethod};
use ic_types::{Cycles, NumInstructions, Time};
use prometheus::IntCounter;

// Execute non replicated query.
#[allow(clippy::too_many_arguments)]
pub fn execute_non_replicated_query(
    query_kind: NonReplicatedQueryKind,
    method: WasmMethod,
    payload: &[u8],
    mut canister: CanisterState,
    data_certificate: Option<Vec<u8>>,
    time: Time,
    execution_parameters: ExecutionParameters,
    network_topology: &NetworkTopology,
    hypervisor: &Hypervisor,
    round_limits: &mut RoundLimits,
    state_changes_error: &IntCounter,
    cost_schedule: CanisterCyclesCostSchedule,
) -> (
    CanisterState,
    NumInstructions,
    Result<Option<WasmResult>, UserError>,
    Option<CallContextId>,
    SystemApiCallCounters,
) {
    // Validate that the canister is running.
    if let Err(err) = validate_canister(&canister) {
        return (
            canister,
            execution_parameters.instruction_limits.message(),
            Err(err),
            None,
            SystemApiCallCounters::default(),
        );
    }

    let memory_usage = canister.memory_usage();
    let message_memory_usage = canister.message_memory_usage();

    // Validate that the Wasm module is present and exports the method
    if let Err(err) = validate_method(&method, &canister) {
        let canister_id = canister.canister_id();
        return (
            canister,
            execution_parameters.instruction_limits.message(),
            Err(err.into_user_error(&canister_id)),
            None,
            SystemApiCallCounters::default(),
        );
    }

    let mut preserve_changes = false;
    let (api_type, call_context_id) = match query_kind {
        NonReplicatedQueryKind::Pure { caller } => (
            ApiType::non_replicated_query(
                time,
                caller,
                hypervisor.subnet_id(),
                payload.to_vec(),
                data_certificate,
            ),
            None,
        ),
        NonReplicatedQueryKind::Stateful { call_origin } => {
            preserve_changes = true;
            let caller = match call_origin {
                CallOrigin::Query(source, ..) => source.get(),
                CallOrigin::CanisterQuery(sender, ..) => sender.get(),
                _ => panic!("Unexpected call origin for execute_non_replicated_query"),
            };
            let call_context_id = canister
                .system_state
                .new_call_context(
                    call_origin,
                    Cycles::zero(),
                    time,
                    RequestMetadata::for_new_call_tree(time),
                )
                .unwrap();
            (
                ApiType::composite_query(
                    time,
                    caller,
                    hypervisor.subnet_id(),
                    payload.to_vec(),
                    data_certificate,
                    call_context_id,
                ),
                Some(call_context_id),
            )
        }
    };

    // As we are executing the query in non-replicated mode, we can
    // modify the canister as the caller is not going to be able to
    // commit modifications to the canister anyway.
    let (output, output_execution_state, output_system_state) = hypervisor.execute(
        api_type,
        time,
        canister.system_state,
        memory_usage,
        message_memory_usage,
        execution_parameters,
        FuncRef::Method(method),
        canister.execution_state.clone().unwrap(),
        network_topology,
        round_limits,
        state_changes_error,
        &CallTreeMetricsNoOp,
        time,
        cost_schedule,
    );
    canister.system_state = output_system_state;
    if preserve_changes {
        canister.execution_state = Some(output_execution_state);
    }

    let result = output
        .wasm_result
        .map_err(|err| err.into_user_error(&canister.canister_id()));
    (
        canister,
        output.num_instructions_left,
        result,
        call_context_id,
        output.system_api_call_counters,
    )
}
