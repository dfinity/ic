use crate::wasmtime_embedder::{system_api_complexity, StoreData};

use ic_config::flag_status::FlagStatus;
use ic_interfaces::execution_environment::{
    ExecutionComplexity, HypervisorError, HypervisorResult, PerformanceCounterType, SystemApi,
};
use ic_logger::{error, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_sys::PAGE_SIZE;
use ic_types::{CanisterId, Cycles, NumBytes, NumInstructions, NumPages, Time};

use wasmtime::{AsContextMut, Caller, Global, Linker, Store, Trap, Val};

use std::convert::TryFrom;

fn process_err<S: SystemApi>(
    store: &mut impl AsContextMut<Data = StoreData<S>>,
    e: HypervisorError,
) -> wasmtime::Trap {
    let t = wasmtime::Trap::new(format! {"{}", e});
    store
        .as_context_mut()
        .data_mut()
        .system_api
        .set_execution_error(e);
    t
}

/// Gets the global variable that stores the number of instructions from `caller`.
#[inline(always)]
fn get_num_instructions_global<S: SystemApi>(
    caller: &mut Caller<'_, StoreData<S>>,
    log: &ReplicaLogger,
    canister_id: CanisterId,
) -> Result<Global, Trap> {
    match caller.data().num_instructions_global {
        None => {
            error!(
                log,
                "[EXC-BUG] Canister {}: instructions counter is set to None.", canister_id,
            );
            Err(process_err(
                caller,
                HypervisorError::InstructionLimitExceeded,
            ))
        }
        Some(global) => Ok(global),
    }
}

#[inline(always)]
fn load_value<S: SystemApi>(
    global: &Global,
    mut caller: &mut Caller<'_, StoreData<S>>,
    log: &ReplicaLogger,
    canister_id: CanisterId,
) -> Result<i64, Trap> {
    match global.get(&mut caller) {
        Val::I64(instructions) => Ok(instructions),
        others => {
            error!(
                log,
                "[EXC-BUG] Canister {}: expected value of type I64 instead got {:?}",
                canister_id,
                others,
            );
            Err(process_err(
                caller,
                HypervisorError::InstructionLimitExceeded,
            ))
        }
    }
}

#[inline(always)]
fn store_value<S: SystemApi>(
    global: &Global,
    num_instructions: i64,
    mut caller: &mut Caller<'_, StoreData<S>>,
    log: &ReplicaLogger,
    canister_id: CanisterId,
) -> Result<(), Trap> {
    if let Err(err) = global.set(&mut caller, Val::I64(num_instructions)) {
        error!(
            log,
            "[EXC-BUG] Canister {}: Setting instructions to {} failed with {}",
            canister_id,
            num_instructions,
            err
        );
        return Err(process_err(
            caller,
            HypervisorError::InstructionLimitExceeded,
        ));
    }
    Ok(())
}

/// Charges a canister (in instructions) for system API call overhead (exit,
/// accessing state, etc) and for using `num_bytes` bytes of memory. If
/// the canister has run out instructions or there are unexpected bugs, return
/// an error.
///
/// There are a number of scenarios that this function must handle where due
/// to potential bugs, the expected information is not available. In more
/// classical systems, we could just panic in such cases. However, for us
/// that has the danger of putting the subnet in a crash loop. So instead,
/// we emit a error log message and continue execution. We intentionally do
/// not introduce new error types in these paths as these error paths should
/// be extremely rare and we do not want to increase the complexity of the
/// code to handle hypothetical bugs.
//
// Note: marked not for inlining as we don't want to spill this code into every system API call.
#[inline(never)]
fn charge_for_system_api_call<S: SystemApi>(
    log: &ReplicaLogger,
    canister_id: CanisterId,
    caller: &mut Caller<'_, StoreData<S>>,
    system_api_overhead: NumInstructions,
    num_bytes: u32,
    complexity: &ExecutionComplexity,
    dirty_page_cost: NumInstructions,
    stable_memory_dirty_page_limit: NumPages,
) -> Result<(), Trap> {
    observe_execution_complexity(
        log,
        canister_id,
        caller,
        complexity,
        stable_memory_dirty_page_limit,
    )?;
    let num_instructions_from_bytes = caller
        .data()
        .system_api
        .get_num_instructions_from_bytes(NumBytes::from(num_bytes as u64));
    let (num_instructions1, overflow1) = num_instructions_from_bytes
        .get()
        .overflowing_add(dirty_page_cost.get());
    let (num_instructions, overflow2) =
        num_instructions1.overflowing_add(system_api_overhead.get());
    if overflow1 || overflow2 {
        error!(
            log,
            "Canister {}: Overflow while calculating charge for System API Call: overhead: {}, num_bytes: {}, dirty_page_cost: {}",
            canister_id,
            system_api_overhead,
            num_bytes,
            dirty_page_cost,
        );
        return Err(process_err(
            caller,
            HypervisorError::ContractViolation(
                "Overflow while calculating charge for a system call".to_string(),
            ),
        ));
    }
    charge_direct_fee(
        log,
        canister_id,
        caller,
        NumInstructions::from(num_instructions),
    )
}

fn charge_direct_fee<S: SystemApi>(
    log: &ReplicaLogger,
    canister_id: CanisterId,
    caller: &mut Caller<'_, StoreData<S>>,
    num_instructions: NumInstructions,
) -> Result<(), Trap> {
    if num_instructions == NumInstructions::from(0) {
        return Ok(());
    }

    let num_instructions_global = get_num_instructions_global(caller, log, canister_id)?;
    let mut instruction_counter = load_value(&num_instructions_global, caller, log, canister_id)?;
    // Assert the current instruction counter is sane
    let system_api = &mut caller.data_mut().system_api;
    let instruction_limit = system_api.slice_instruction_limit().get() as i64;
    if instruction_counter > instruction_limit {
        error!(
            log,
            "[EXC-BUG] Canister {}: current instructions counter {} is greater than the limit {}",
            canister_id,
            instruction_counter,
            instruction_limit
        );
        // Continue execution
    }

    // We are going to substract a potentially large fee from the instruction
    // counter. To avoid underflows, we need to first ensure that the
    // instruction counter is not negative.
    if instruction_counter < 0 {
        // Note we cannot use `map_err()` here because `caller` is needed later on in `store_value`.
        instruction_counter = match system_api.out_of_instructions(instruction_counter) {
            Ok(instruction_counter) => instruction_counter,
            Err(err) => {
                return Err(process_err(caller, err));
            }
        };
    }

    // Now we can subtract the fee and store the new instruction counter.
    let fee = num_instructions.get() as i64;
    instruction_counter -= fee;
    store_value(
        &num_instructions_global,
        instruction_counter,
        caller,
        log,
        canister_id,
    )?;

    // If the instruction counter became negative after subtracting the fee,
    // then we need to call the out-of-instructins handler again and store the
    // returned new counter value.
    if instruction_counter < 0 {
        let system_api = &mut caller.data_mut().system_api;
        // Note we cannot use `map_err()` here because `caller` is needed later on in `store_value`.
        instruction_counter = match system_api.out_of_instructions(instruction_counter) {
            Ok(instruction_counter) => instruction_counter,
            Err(err) => {
                return Err(process_err(caller, err));
            }
        };
        store_value(
            &num_instructions_global,
            instruction_counter,
            caller,
            log,
            canister_id,
        )?;
    }
    Ok(())
}

/// Returns the number of new stable dirty pages and their cost for a potential
/// write to stable memory.
fn get_new_stable_dirty_pages<S: SystemApi>(
    caller: &mut Caller<'_, StoreData<S>>,
    offset: u64,
    size: u64,
) -> Result<(NumPages, NumInstructions), Trap> {
    match caller
        .data()
        .system_api
        .dirty_pages_from_stable_write(offset, size)
    {
        Err(e) => Err(process_err(caller, e)),
        Ok(result) => Ok(result),
    }
}

/// Observe execution complexity.
fn observe_execution_complexity<S: SystemApi>(
    log: &ReplicaLogger,
    canister_id: CanisterId,
    caller: &mut Caller<'_, StoreData<S>>,
    complexity: &ExecutionComplexity,
    stable_memory_dirty_page_limit: NumPages,
) -> Result<(), Trap> {
    #[allow(non_upper_case_globals)]
    const KiB: u64 = 1024;

    let system_api = &mut caller.data_mut().system_api;
    let total_complexity = system_api.get_total_execution_complexity() + complexity;
    if system_api.subnet_type() != SubnetType::System {
        // TODO: RUN-126: Implement per-round complexity that combines complexities of
        //       multiple messages.
        // Note: for install messages the CPU Limit will be > 1s, but it will be addressed with DTS
        let message_instruction_limit = system_api.message_instruction_limit();
        if total_complexity.cpu > message_instruction_limit {
            error!(
                log,
                "Canister {}: Error exceeding CPU complexity limit: (observed:{}, limit:{})",
                canister_id,
                total_complexity.cpu,
                message_instruction_limit,
            );
            return Err(process_err(
                caller,
                HypervisorError::InstructionLimitExceeded,
            ));
        } else if total_complexity.stable_dirty_pages > stable_memory_dirty_page_limit {
            let error = HypervisorError::MemoryAccessLimitExceeded(
                format!("Exceeded the limit for the number of modified pages in the stable memory in a single message execution: limit: {} KB, modified: {} KB.",
                    stable_memory_dirty_page_limit * (PAGE_SIZE as u64 / KiB),
                    total_complexity.stable_dirty_pages.get() * (PAGE_SIZE as u64 / KiB),
                ),
            );
            return Err(process_err(caller, error));
        }
    }
    system_api.set_total_execution_complexity(total_complexity);
    Ok(())
}

/// A helper to pass wasmtime counters to the System API
fn ic0_performance_counter_helper<S: SystemApi>(
    log: &ReplicaLogger,
    canister_id: CanisterId,
    caller: &mut Caller<'_, StoreData<S>>,
    counter_type: u32,
) -> Result<u64, Trap> {
    match counter_type {
        0 => {
            let num_instructions_global = get_num_instructions_global(caller, log, canister_id)?;
            let instruction_counter =
                load_value(&num_instructions_global, caller, log, canister_id)?;
            caller
                .data()
                .system_api
                .ic0_performance_counter(PerformanceCounterType::Instructions(instruction_counter))
                .map_err(|e| process_err(caller, e))
        }
        _ => Err(process_err(
            caller,
            HypervisorError::ContractViolation(format!(
                "Error getting performance counter type {}",
                counter_type
            )),
        )),
    }
}

pub(crate) fn syscalls<S: SystemApi>(
    log: ReplicaLogger,
    canister_id: CanisterId,
    store: &Store<StoreData<S>>,
    rate_limiting_of_debug_prints: FlagStatus,
    stable_memory_dirty_page_limit: NumPages,
) -> Linker<StoreData<S>> {
    fn with_system_api<S, T>(caller: &mut Caller<'_, StoreData<S>>, f: impl Fn(&mut S) -> T) -> T {
        f(&mut caller.as_context_mut().data_mut().system_api)
    }

    fn with_memory_and_system_api<S: SystemApi, T>(
        mut caller: &mut Caller<'_, StoreData<S>>,
        f: impl Fn(&mut S, &mut [u8]) -> HypervisorResult<T>,
    ) -> Result<T, wasmtime::Trap> {
        let result = caller
            .get_export("memory")
            .ok_or_else(|| {
                HypervisorError::ContractViolation(
                    "WebAssembly module must define memory".to_string(),
                )
            })
            .and_then(|ext| {
                ext.into_memory().ok_or_else(|| {
                    HypervisorError::ContractViolation(
                        "export 'memory' is not a memory".to_string(),
                    )
                })
            })
            .and_then(|mem| {
                let (mem, store) = mem.data_and_store_mut(&mut caller);
                f(&mut store.system_api, mem)
            });

        match result {
            Err(e) => Err(process_err(caller, e)),
            Ok(r) => Ok(r),
        }
    }

    let mut linker = Linker::new(store.engine());

    linker
        .func_wrap("ic0", "msg_caller_copy", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_CALLER_COPY,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_caller_copy(dst as u32, offset as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_caller_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_caller_size())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0::msg_caller_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_arg_data_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_arg_data_size())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0::msg_arg_data_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_arg_data_copy", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::MSG_ARG_DATA_COPY,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_ARG_DATA_COPY,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, mem| {
                    system_api.ic0_msg_arg_data_copy(dst as u32, offset as u32, size as u32, mem)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_method_name_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_method_name_size())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0::msg_metohd_name_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_method_name_copy", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::MSG_METHOD_NAME_COPY,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_METHOD_NAME_COPY,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_method_name_copy(
                        dst as u32,
                        offset as u32,
                        size as u32,
                        memory,
                    )
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "accept_message", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_accept_message())
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reply_data_append", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: i32, size: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::MSG_REPLY_DATA_APPEND,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_REPLY_DATA_APPEND,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reply_data_append(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reply", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_reply())
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_code", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_reject_code())
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: i32, size: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::MSG_REJECT,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_REJECT,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reject(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_msg_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_reject_msg_size())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_msg_reject_msg_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_msg_copy", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::MSG_REJECT_MSG_COPY,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_REJECT_MSG_COPY,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reject_msg_copy(
                        dst as u32,
                        offset as u32,
                        size as u32,
                        memory,
                    )
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_self_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_canister_self_size())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_canister_self_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_self_copy", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::CANISTER_SELF_COPY,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_canister_self_copy(
                        dst as u32,
                        offset as u32,
                        size as u32,
                        memory,
                    )
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "controller_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_controller_size())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_controller_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "controller_copy", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::CONTROLLER_COPY,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_controller_copy(dst as u32, offset as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "debug_print", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, offset: i32, length: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::DEBUG_PRINT,
                    length as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::DEBUG_PRINT,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                match (
                    caller.data().system_api.subnet_type(),
                    rate_limiting_of_debug_prints,
                ) {
                    // Debug print is a no-op on non-system subnets with rate limiting.
                    (SubnetType::Application, FlagStatus::Enabled) => Ok(()),
                    (SubnetType::VerifiedApplication, FlagStatus::Enabled) => Ok(()),
                    // If rate limiting is disabled or the subnet is a system subnet, then
                    // debug print produces output.
                    (_, FlagStatus::Disabled) | (SubnetType::System, FlagStatus::Enabled) => {
                        with_memory_and_system_api(&mut caller, |system_api, memory| {
                            system_api.ic0_debug_print(offset as u32, length as u32, memory)
                        })
                    }
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "trap", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, offset: i32, length: i32| -> Result<(), _> {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::TRAP,
                    length as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::TRAP,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_trap(offset as u32, length as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_simple", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>,
                  callee_src: i32,
                  callee_size: i32,
                  name_src: i32,
                  name_len: i32,
                  reply_fun: i32,
                  reply_env: i32,
                  reject_fun: i32,
                  reject_env: i32,
                  src: i32,
                  len: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::CALL_SIMPLE,
                    len as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::CALL_SIMPLE,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_call_simple(
                        callee_src as u32,
                        callee_size as u32,
                        name_src as u32,
                        name_len as u32,
                        reply_fun as u32,
                        reply_env as u32,
                        reject_fun as u32,
                        reject_env as u32,
                        src as u32,
                        len as u32,
                        memory,
                    )
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_new", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>,
                  callee_src: i32,
                  callee_size: i32,
                  name_src: i32,
                  name_len: i32,
                  reply_fun: i32,
                  reply_env: i32,
                  reject_fun: i32,
                  reject_env: i32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::CALL_NEW,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_call_new(
                        callee_src as u32,
                        callee_size as u32,
                        name_src as u32,
                        name_len as u32,
                        reply_fun as u32,
                        reply_env as u32,
                        reject_fun as u32,
                        reject_env as u32,
                        memory,
                    )
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_data_append", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: i32, size: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::CALL_DATA_APPEND,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::CALL_DATA_APPEND,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_call_data_append(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_on_cleanup", {
            move |mut caller: Caller<'_, StoreData<S>>, fun: i32, env: i32| {
                with_system_api(&mut caller, |s| {
                    s.ic0_call_on_cleanup(fun as u32, env as u32)
                })
                .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_cycles_add", {
            move |mut caller: Caller<'_, StoreData<S>>, amount: i64| {
                with_system_api(&mut caller, |s| s.ic0_call_cycles_add(amount as u64))
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_cycles_add128", {
            move |mut caller: Caller<'_, StoreData<S>>, amount_high: i64, amount_low: i64| {
                with_system_api(&mut caller, |s| {
                    s.ic0_call_cycles_add128(Cycles::from_parts(
                        amount_high as u64,
                        amount_low as u64,
                    ))
                })
                .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_perform", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::CALL_PERFORM,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_system_api(&mut caller, |s| s.ic0_call_perform())
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_stable_size())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_stable_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_grow", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, additional_pages: i32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE_GROW,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_system_api(&mut caller, |s| s.ic0_stable_grow(additional_pages as u32))
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_read", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::STABLE_READ,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE_READ,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable_read(dst as u32, offset as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_write", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, offset: i32, src: i32, size: i32| {
                let offset = offset as u32;
                let src = src as u32;
                let size = size as u32;
                let (stable_dirty_pages, dirty_page_cost) =
                    get_new_stable_dirty_pages(&mut caller, offset as u64, size as u64)?;
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::STABLE_WRITE,
                    size,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE_WRITE,
                        stable_dirty_pages,
                    },
                    dirty_page_cost,
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable_write(offset, src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_stable64_size())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_stable64_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_grow", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, additional_pages: i64| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE64_GROW,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_system_api(&mut caller, |s| {
                    s.ic0_stable64_grow(additional_pages as u64)
                })
                .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_read", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i64, offset: i64, size: i64| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::STABLE64_READ,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE64_READ,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable64_read(dst as u64, offset as u64, size as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_write", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, offset: i64, src: i64, size: i64| {
                let offset = offset as u64;
                let src = src as u64;
                let size = size as u64;
                let (stable_dirty_pages, dirty_page_cost) =
                    get_new_stable_dirty_pages(&mut caller, offset, size)?;
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::STABLE64_WRITE,
                    size as u32,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE64_WRITE,
                        stable_dirty_pages,
                    },
                    dirty_page_cost,
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable64_write(offset as u64, src as u64, size as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "time", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_time())
                    .map_err(|e| process_err(&mut caller, e))
                    .map(|s| s.as_nanos_since_unix_epoch())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "global_timer_set", {
            move |mut caller: Caller<'_, StoreData<S>>, time: i64| {
                with_system_api(&mut caller, |s| {
                    s.ic0_global_timer_set(Time::from_nanos_since_unix_epoch(time as u64))
                })
                .map_err(|e| process_err(&mut caller, e))
                .map(|s| s.as_nanos_since_unix_epoch())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "performance_counter", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, counter_type: u32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_complexity::overhead::PERFORMANCE_COUNTER,
                    0,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::PERFORMANCE_COUNTER,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )?;
                ic0_performance_counter_helper(&log, canister_id, &mut caller, counter_type)
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_version", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_canister_version())
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycle_balance", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_canister_cycle_balance())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_canister_cycle_balance failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycle_balance128", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: u32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::CANISTER_CYCLES_BALANCE128,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_canister_cycles_balance128(dst, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_available", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_available())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_msg_cycles_available failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_available128", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: u32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_CYCLES_AVAILABLE128,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_available128(dst, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_refunded", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_refunded())
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_msg_cycles_refunded failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_refunded128", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: u32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_CYCLES_REFUNDED128,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_refunded128(dst, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept", {
            move |mut caller: Caller<'_, StoreData<S>>, amount: i64| {
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_accept(amount as u64))
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept128", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>,
                  amount_high: i64,
                  amount_low: i64,
                  dst: u32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::MSG_CYCLES_ACCEPT128,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_accept128(
                        Cycles::from_parts(amount_high as u64, amount_low as u64),
                        dst,
                        memory,
                    )
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "out_of_instructions", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>| -> Result<(), _> {
                let global = get_num_instructions_global(&mut caller, &log, canister_id)?;
                let instruction_counter = load_value(&global, &mut caller, &log, canister_id)?;
                let instruction_counter =
                    with_system_api(&mut caller, |s| s.out_of_instructions(instruction_counter))
                        .map_err(|e| process_err(&mut caller, e))?;
                store_value(&global, instruction_counter, &mut caller, &log, canister_id)
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "update_available_memory", {
            move |mut caller: Caller<'_, StoreData<S>>,
                  native_memory_grow_res: i32,
                  additional_pages: i32| {
                with_system_api(&mut caller, |s| {
                    s.update_available_memory(native_memory_grow_res, additional_pages as u32)
                })
                .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_status", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_canister_status())
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "certified_data_set", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: u32, size: u32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::CERTIFIED_DATA_SET,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_certified_data_set(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_present", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_data_certificate_present())
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_data_certificate_size())
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_copy", {
            move |mut caller: Caller<'_, StoreData<S>>, dst: u32, offset: u32, size: u32| {
                observe_execution_complexity(
                    &log,
                    canister_id,
                    &mut caller,
                    &ExecutionComplexity {
                        cpu: system_api_complexity::cpu::DATA_CERTIFICATE_COPY,
                        ..Default::default()
                    },
                    stable_memory_dirty_page_limit,
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_data_certificate_copy(dst, offset, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "mint_cycles", {
            move |mut caller: Caller<'_, StoreData<S>>, amount: i64| {
                with_system_api(&mut caller, |s| s.ic0_mint_cycles(amount as u64))
                    .map_err(|e| process_err(&mut caller, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_mint_cycles failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
}
