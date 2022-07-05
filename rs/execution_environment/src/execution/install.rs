// This module defines how the `install_code` IC method in mode
// `install`/`reinstall` is executed.
// See https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-install_code
use crate::canister_manager::PausedInstallCodeExecution;
use crate::canister_manager::{
    canister_layout, CanisterManagerError, DtsInstallCodeResult, InstallCodeContext,
    InstallCodeResponse, InstallCodeResult,
};
use crate::execution::common::deduct_compilation_instructions;
use crate::Hypervisor;
use ic_base_types::{NumBytes, PrincipalId, SubnetId};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_embedders::wasm_executor::{PausedWasmExecution, WasmExecutionResult};
use ic_interfaces::execution_environment::{
    ExecutionParameters, SubnetAvailableMemory, WasmExecutionOutput,
};
use ic_logger::{fatal, info, ReplicaLogger};
use ic_replicated_state::{CanisterState, NetworkTopology, SystemState};
use ic_sys::PAGE_SIZE;
use ic_system_api::sandbox_safe_system_state::SystemStateChanges;
use ic_system_api::ApiType;
use ic_types::methods::{FuncRef, SystemMethod, WasmMethod};
use ic_types::{MemoryAllocation, NumInstructions, Time};
use std::path::PathBuf;

/// Installs a new code in canister. The algorithm consists of three stages:
/// - Stage 1: create a new execution state based on the new Wasm code.
/// - Stage 2: invoke the `start()` method (if present).
/// - Stage 3: invoke the `canister_init()` method (if present).
///
/// With deterministic time slicing stages 2 and 3 may require multiple rounds
/// to complete. In order to support that, the algorithm is implemented as a
/// state machine:
/// ```text
/// [begin]
///   │
///   ▼
/// [create new execution state]
///   │
///   │
///   │                   exceeded slice
///   ▼                  instruction limit
/// [execute start()] ───────────────────────► PausedStartExecutionDuringInstall
///   │                                          │    │         ▲
///   │                                          │    └─────────┘
///   │            finished execution            │    exceeded slice
///   │◄─────────────────────────────────────────┘   instruction limit
///   │
///   │
///   │                        exceeded slice
///   ▼                       instruction limit
/// [execute canister_init()]───────────────────► PausedInitExecution
///   │                                              │    │        ▲
///   │                                              │    └────────┘
///   │             finished execution               │   exceeded slice
///   │◄─────────────────────────────────────────────┘  instruction limit
///   │
///   │
///   ▼
/// [end]
///```
///
/// Note that currently `PausedStartExecutionDuringInstall` does not exist in
/// code because it is not implemented yet.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_install(
    context: InstallCodeContext,
    old_canister: CanisterState,
    time: Time,
    canister_layout_path: PathBuf,
    mut execution_parameters: ExecutionParameters,
    network_topology: &NetworkTopology,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> DtsInstallCodeResult {
    // Stage 1: create a new execution state based on the new Wasm binary.

    let canister_id = context.canister_id;
    let layout = canister_layout(&canister_layout_path, &canister_id);

    let (instructions_from_compilation, execution_state) = match hypervisor.create_execution_state(
        context.wasm_module,
        layout.raw_path(),
        canister_id,
    ) {
        Ok(result) => result,
        Err(err) => {
            return DtsInstallCodeResult {
                old_canister,
                response: InstallCodeResponse::Result((
                    execution_parameters.total_instruction_limit,
                    Err((canister_id, err).into()),
                )),
            };
        }
    };

    let instructions_left = deduct_compilation_instructions(
        execution_parameters.total_instruction_limit,
        instructions_from_compilation,
    );
    execution_parameters.total_instruction_limit = instructions_left;
    execution_parameters.slice_instruction_limit = instructions_left;

    let system_state = old_canister.system_state.clone();
    let scheduler_state = old_canister.scheduler_state.clone();
    let mut new_canister = CanisterState::new(system_state, Some(execution_state), scheduler_state);

    // Update allocations.  This must happen after we have created the new
    // execution state so that we fairly account for the memory requirements
    // of the new wasm module.
    if let Some(compute_allocation) = context.compute_allocation {
        new_canister.scheduler_state.compute_allocation = compute_allocation;
        execution_parameters.compute_allocation = compute_allocation;
    }

    // While the memory allocation can still be included in the context, we need to
    // try to take it from there. Otherwise, we should use the current memory
    // allocation of the canister.
    let desired_memory_allocation = match context.memory_allocation {
        Some(allocation) => allocation,
        None => new_canister.system_state.memory_allocation,
    };
    if let MemoryAllocation::Reserved(bytes) = desired_memory_allocation {
        if bytes < new_canister.memory_usage(hypervisor.subnet_type()) {
            return DtsInstallCodeResult {
                old_canister,
                response: InstallCodeResponse::Result((
                    execution_parameters.total_instruction_limit,
                    Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                        canister_id,
                        memory_allocation_given: desired_memory_allocation,
                        memory_usage_needed: new_canister.memory_usage(hypervisor.subnet_type()),
                    }),
                )),
            };
        }
        execution_parameters.canister_memory_limit = bytes;
    }
    new_canister.system_state.memory_allocation = desired_memory_allocation;

    let total_heap_delta = NumBytes::from(0);

    // Stage 2: invoke the `start()` method of the Wasm module (if present).

    let method = WasmMethod::System(SystemMethod::CanisterStart);
    let memory_usage = new_canister.memory_usage(hypervisor.subnet_type());
    let canister_id = new_canister.canister_id();

    // The execution state is present because we just put it there.
    let execution_state = new_canister.execution_state.take().unwrap();

    // If the Wasm module does not export the method, then this execution
    // succeeds as a no-op.
    if !execution_state.exports_method(&method) {
        info!(
            log,
            "Executing (start) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.total_instruction_limit - instructions_left,
            instructions_left
        );
        new_canister.execution_state = Some(execution_state);
        install_stage_2b_continue_install_after_start(
            context.sender,
            context.arg,
            new_canister,
            old_canister,
            execution_parameters,
            instructions_left,
            total_heap_delta,
            time,
            network_topology,
            hypervisor,
            log,
        )
    } else {
        let (output_execution_state, wasm_execution_result) = hypervisor.execute_dts(
            ApiType::start(),
            SystemState::new_for_start(canister_id),
            memory_usage,
            execution_parameters.clone(),
            FuncRef::Method(method),
            execution_state,
        );
        new_canister.execution_state = Some(output_execution_state);

        match wasm_execution_result {
            WasmExecutionResult::Finished(output, _system_state_changes) => {
                install_stage_2a_process_start_result(
                    output,
                    context.sender,
                    context.arg,
                    new_canister,
                    old_canister,
                    execution_parameters,
                    total_heap_delta,
                    time,
                    network_topology,
                    hypervisor,
                    log,
                )
            }
            WasmExecutionResult::Paused(paused_wasm_execution) => {
                let paused_execution = Box::new(PausedStartExecutionDuringInstall {
                    paused_wasm_execution,
                    new_canister,
                    execution_parameters,
                    total_heap_delta,
                    context_sender: context.sender,
                    context_arg: context.arg,
                    time,
                });
                DtsInstallCodeResult {
                    old_canister,
                    response: InstallCodeResponse::Paused(paused_execution),
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn install_stage_2a_process_start_result(
    output: WasmExecutionOutput,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    new_canister: CanisterState,
    old_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    mut total_heap_delta: NumBytes,
    time: Time,
    network_topology: &NetworkTopology,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> DtsInstallCodeResult {
    let canister_id = new_canister.canister_id();
    let instructions_left = output.num_instructions_left;
    match output.wasm_result {
        Ok(opt_result) => {
            if opt_result.is_some() {
                fatal!(log, "[EXC-BUG] System methods cannot use msg_reply.");
            }
            total_heap_delta +=
                NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);
        }
        Err(err) => {
            return DtsInstallCodeResult {
                old_canister,
                response: InstallCodeResponse::Result((
                    instructions_left,
                    Err((canister_id, err).into()),
                )),
            }
        }
    };

    install_stage_2b_continue_install_after_start(
        context_sender,
        context_arg,
        new_canister,
        old_canister,
        execution_parameters,
        instructions_left,
        total_heap_delta,
        time,
        network_topology,
        hypervisor,
        log,
    )
}

#[allow(clippy::too_many_arguments)]
fn install_stage_2b_continue_install_after_start(
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    mut new_canister: CanisterState,
    old_canister: CanisterState,
    mut execution_parameters: ExecutionParameters,
    instructions_left: NumInstructions,
    total_heap_delta: NumBytes,
    time: Time,
    network_topology: &NetworkTopology,
    hypervisor: &Hypervisor,
    log: &ReplicaLogger,
) -> DtsInstallCodeResult {
    let canister_id = new_canister.canister_id();
    info!(
        log,
        "Executing (start) on canister {} consumed {} instructions.  {} instructions are left.",
        canister_id,
        execution_parameters.total_instruction_limit - instructions_left,
        instructions_left
    );
    execution_parameters.total_instruction_limit = instructions_left;
    execution_parameters.slice_instruction_limit = instructions_left;

    // Stage 3: invoke the `canister_init()` method of the Wasm module (if present).

    let method = WasmMethod::System(SystemMethod::CanisterInit);

    // If the Wasm module does not export the method, then this execution
    // succeeds as a no-op.
    if !new_canister
        .execution_state
        .as_ref()
        .unwrap()
        .exports_method(&method)
    {
        info!(
            log,
            "Executing (canister_init) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.total_instruction_limit - instructions_left,
            instructions_left
        );
        return DtsInstallCodeResult {
            old_canister,
            response: InstallCodeResponse::Result((
                instructions_left,
                Ok((
                    InstallCodeResult {
                        heap_delta: total_heap_delta,
                        old_wasm_hash: None,
                        new_wasm_hash: None,
                    },
                    new_canister,
                )),
            )),
        };
    }

    let memory_usage = new_canister.memory_usage(hypervisor.subnet_type());
    let (output_execution_state, wasm_execution_result) = hypervisor.execute_dts(
        ApiType::init(time, context_arg, context_sender),
        new_canister.system_state.clone(),
        memory_usage,
        execution_parameters.clone(),
        FuncRef::Method(method),
        new_canister.execution_state.unwrap(),
    );
    new_canister.execution_state = Some(output_execution_state);
    match wasm_execution_result {
        WasmExecutionResult::Finished(output, system_state_changes) => {
            install_stage_3_process_init_result(
                old_canister,
                new_canister,
                output,
                system_state_changes,
                execution_parameters,
                total_heap_delta,
                hypervisor.subnet_id(),
                network_topology,
                log,
            )
        }
        WasmExecutionResult::Paused(paused_wasm_execution) => {
            let paused_execution = Box::new(PausedInitExecution {
                new_canister,
                paused_wasm_execution,
                execution_parameters,
                total_heap_delta,
            });
            DtsInstallCodeResult {
                old_canister,
                response: InstallCodeResponse::Paused(paused_execution),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn install_stage_3_process_init_result(
    old_canister: CanisterState,
    mut new_canister: CanisterState,
    output: WasmExecutionOutput,
    system_state_changes: SystemStateChanges,
    execution_parameters: ExecutionParameters,
    mut total_heap_delta: NumBytes,
    subnet_id: SubnetId,
    network_topology: &NetworkTopology,
    log: &ReplicaLogger,
) -> DtsInstallCodeResult {
    let canister_id = new_canister.canister_id();
    info!(
        log,
        "Executing (canister_init) on canister {} consumed {} instructions.  {} instructions are left.",
        canister_id,
        execution_parameters.total_instruction_limit - output.num_instructions_left,
        output.num_instructions_left
    );

    match output.wasm_result {
        Ok(opt_result) => {
            if opt_result.is_some() {
                fatal!(log, "[EXC-BUG] System methods cannot use msg_reply.");
            }
            system_state_changes.apply_changes(
                &mut new_canister.system_state,
                network_topology,
                subnet_id,
                log,
            );

            total_heap_delta +=
                NumBytes::from((output.instance_stats.dirty_pages * PAGE_SIZE) as u64);

            DtsInstallCodeResult {
                old_canister,
                response: InstallCodeResponse::Result((
                    output.num_instructions_left,
                    Ok((
                        InstallCodeResult {
                            heap_delta: total_heap_delta,
                            old_wasm_hash: None,
                            new_wasm_hash: None,
                        },
                        new_canister,
                    )),
                )),
            }
        }
        Err(err) => DtsInstallCodeResult {
            old_canister,
            response: InstallCodeResponse::Result((
                output.num_instructions_left,
                Err((canister_id, err).into()),
            )),
        },
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister install.
#[derive(Debug)]
struct PausedInitExecution {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    total_heap_delta: NumBytes,
}

impl PausedInstallCodeExecution for PausedInitExecution {
    fn resume(
        self: Box<Self>,
        old_canister: CanisterState,
        subnet_available_memory: SubnetAvailableMemory,
        network_topology: &NetworkTopology,
        hypervisor: &Hypervisor,
        _cycles_account_manager: &CyclesAccountManager,
        log: &ReplicaLogger,
    ) -> DtsInstallCodeResult {
        let mut new_canister = self.new_canister;
        let execution_state = new_canister.execution_state.take().unwrap();
        let (execution_state, wasm_execution_result) = self
            .paused_wasm_execution
            .resume(execution_state, subnet_available_memory);
        new_canister.execution_state = Some(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(output, system_state_changes) => {
                install_stage_3_process_init_result(
                    old_canister,
                    new_canister,
                    output,
                    system_state_changes,
                    self.execution_parameters,
                    self.total_heap_delta,
                    hypervisor.subnet_id(),
                    network_topology,
                    log,
                )
            }
            WasmExecutionResult::Paused(paused_wasm_execution) => {
                let paused_execution = Box::new(PausedInitExecution {
                    new_canister,
                    paused_wasm_execution,
                    ..*self
                });
                DtsInstallCodeResult {
                    old_canister,
                    response: InstallCodeResponse::Paused(paused_execution),
                }
            }
        }
    }

    fn abort(self: Box<Self>) {
        todo!()
    }
}

/// Struct used to hold necessary information for the
/// deterministic time slicing execution of canister install.
#[derive(Debug)]
struct PausedStartExecutionDuringInstall {
    paused_wasm_execution: Box<dyn PausedWasmExecution>,
    new_canister: CanisterState,
    execution_parameters: ExecutionParameters,
    total_heap_delta: NumBytes,
    context_sender: PrincipalId,
    context_arg: Vec<u8>,
    time: Time,
}

impl PausedInstallCodeExecution for PausedStartExecutionDuringInstall {
    fn resume(
        self: Box<Self>,
        old_canister: CanisterState,
        subnet_available_memory: SubnetAvailableMemory,
        network_topology: &NetworkTopology,
        hypervisor: &Hypervisor,
        _cycles_account_manager: &CyclesAccountManager,
        log: &ReplicaLogger,
    ) -> DtsInstallCodeResult {
        let mut new_canister = self.new_canister;
        let execution_state = new_canister.execution_state.take().unwrap();
        let (execution_state, wasm_execution_result) = self
            .paused_wasm_execution
            .resume(execution_state, subnet_available_memory);
        new_canister.execution_state = Some(execution_state);
        match wasm_execution_result {
            WasmExecutionResult::Finished(output, _system_state_changes) => {
                install_stage_2a_process_start_result(
                    output,
                    self.context_sender,
                    self.context_arg,
                    new_canister,
                    old_canister,
                    self.execution_parameters,
                    self.total_heap_delta,
                    self.time,
                    network_topology,
                    hypervisor,
                    log,
                )
            }
            WasmExecutionResult::Paused(paused_wasm_execution) => {
                let paused_execution = Box::new(PausedStartExecutionDuringInstall {
                    new_canister,
                    paused_wasm_execution,
                    ..*self
                });
                DtsInstallCodeResult {
                    old_canister,
                    response: InstallCodeResponse::Paused(paused_execution),
                }
            }
        }
    }

    fn abort(self: Box<Self>) {
        todo!()
    }
}
