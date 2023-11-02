use crate::wasmtime_embedder::{
    system_api_complexity, StoreData, WASM_HEAP_BYTEMAP_MEMORY_NAME, WASM_HEAP_MEMORY_NAME,
};

use ic_config::{
    embedders::{FeatureFlags, MeteringType},
    flag_status::FlagStatus,
};
use ic_interfaces::execution_environment::{
    ExecutionComplexity, HypervisorError, HypervisorResult, PerformanceCounterType,
    StableGrowOutcome, SystemApi, TrapCode,
};
use ic_logger::{error, ReplicaLogger};
use ic_registry_subnet_type::SubnetType;
use ic_sys::PAGE_SIZE;
use ic_types::{Cycles, NumBytes, NumInstructions, NumPages, Time};
use ic_wasm_types::WasmEngineError;

use wasmtime::{AsContextMut, Caller, Global, Linker, Val};

use crate::InternalErrorCode;
use std::convert::TryFrom;

use crate::wasmtime_embedder::system_api_complexity::system_api;
use ic_system_api::SystemApiImpl;

fn unexpected_err(s: String) -> HypervisorError {
    HypervisorError::WasmEngineError(WasmEngineError::Unexpected(s))
}

fn process_err(
    store: &mut impl AsContextMut<Data = StoreData>,
    e: HypervisorError,
) -> anyhow::Error {
    match store.as_context_mut().data_mut().system_api_mut() {
        Ok(api) => {
            let result = anyhow::Error::msg(format! {"{}", e});
            api.set_execution_error(e);
            result
        }
        Err(_) => anyhow::Error::msg(
            format! {"Failed to access system api while processing error: {}", e},
        ),
    }
}

/// Gets the global variable that stores the number of instructions from `caller`.
#[inline(always)]
fn get_num_instructions_global(caller: &Caller<'_, StoreData>) -> HypervisorResult<Global> {
    caller
        .data()
        .num_instructions_global
        .ok_or_else(|| unexpected_err("DataStore instructions counter is None".into()))
}

#[inline(always)]
fn load_value(global: &Global, caller: &mut Caller<'_, StoreData>) -> HypervisorResult<i64> {
    match global.get(caller) {
        Val::I64(instructions) => Ok(instructions),
        others => Err(unexpected_err(format!(
            "Failed to get global: Expected value of type I64 instead got {:?}",
            others,
        ))),
    }
}

#[inline(always)]
fn store_value(
    global: &Global,
    val: i64,
    caller: &mut Caller<'_, StoreData>,
) -> HypervisorResult<()> {
    global
        .set(caller, Val::I64(val))
        .map_err(|e| unexpected_err(format!("Failed to set global: {}", e)))
}

/// Updates heap bytemap marking which pages have been written to dst and size
/// need to have valid values (need to pass checks performed by the function
/// that actually writes to the heap)
#[inline(never)]
fn mark_writes_on_bytemap(
    caller: &mut Caller<'_, StoreData>,
    dst: usize,
    size: usize,
) -> Result<(), anyhow::Error> {
    if size < 1 {
        return Ok(());
    }
    let bitmap_mem = match caller.get_export(WASM_HEAP_BYTEMAP_MEMORY_NAME) {
        Some(wasmtime::Extern::Memory(mem)) => mem,
        _ => {
            return Err(process_err(
                caller,
                HypervisorError::ContractViolation("Failed to access heap bitmap".to_string()),
            ))
        }
    };

    let bitmap = bitmap_mem.data_mut(caller);
    let mut i = dst / PAGE_SIZE;
    let end = (dst + size - 1) / PAGE_SIZE + 1;
    while i < end {
        bitmap[i] = 1;
        i += 1;
    }
    Ok(())
}

struct Overhead {
    system_api_overhead: NumInstructions,
    cpu_complexity: ic_types::CpuComplexity,
    num_bytes: NumBytes,
}

macro_rules! overhead {
    ($name:ident, $metering_type:expr, $num_bytes:expr) => {
        match $metering_type {
            MeteringType::Old => Overhead {
                system_api_overhead: system_api_complexity::overhead::old::$name,
                cpu_complexity: system_api_complexity::cpu::$name,
                num_bytes: NumBytes::from($num_bytes as u64),
            },
            MeteringType::New => Overhead {
                system_api_overhead: system_api_complexity::overhead::new::$name,
                cpu_complexity: system_api_complexity::cpu::$name,
                num_bytes: NumBytes::from($num_bytes as u64),
            },
            MeteringType::None => Overhead {
                system_api_overhead: system_api_complexity::overhead::old::$name,
                cpu_complexity: system_api_complexity::cpu::$name,
                num_bytes: NumBytes::from($num_bytes as u64),
            },
        }
    };
}

fn charge_for_cpu(
    caller: &mut Caller<'_, StoreData>,
    overhead: Overhead,
) -> Result<(), anyhow::Error> {
    let complexity = ExecutionComplexity {
        cpu: overhead.cpu_complexity,
        ..Default::default()
    };
    charge_for_system_api_call(
        caller,
        overhead.system_api_overhead,
        overhead.num_bytes.get() as u32,
        complexity,
        NumInstructions::from(0),
        // since we are not adding any stable dirty pages, process this as if there was no limit
        NumPages::new(u64::MAX),
    )
    .map_err(|e| process_err(caller, e))
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
fn charge_for_system_api_call(
    caller: &mut Caller<'_, StoreData>,
    system_api_overhead: NumInstructions,
    num_bytes: u64,
    complexity: ExecutionComplexity,
    dirty_page_cost: NumInstructions,
    stable_memory_dirty_page_limit: NumPages,
) -> HypervisorResult<()> {
    let (system_api, log) = caller.data_mut().system_api_mut_log()?;
    observe_execution_complexity(log, system_api, complexity, stable_memory_dirty_page_limit)?;
    let num_instructions_from_bytes =
        system_api.get_num_instructions_from_bytes(NumBytes::from(num_bytes as u64));
    let (num_instructions1, overflow1) = num_instructions_from_bytes
        .get()
        .overflowing_add(dirty_page_cost.get());
    let (num_instructions, overflow2) =
        num_instructions1.overflowing_add(system_api_overhead.get());
    if overflow1 || overflow2 {
        return Err(unexpected_err(format!(
            "Overflow while calculating charge for System API Call: overhead: {}, num_bytes: {}, dirty_page_cost: {}",
            system_api_overhead,
            num_bytes,
            dirty_page_cost,
        )));
    }
    charge_direct_fee(caller, NumInstructions::from(num_instructions))
}

fn charge_direct_fee(
    caller: &mut Caller<'_, StoreData>,
    fee: NumInstructions,
) -> HypervisorResult<()> {
    if fee == NumInstructions::from(0) {
        return Ok(());
    }

    let num_instructions_global = get_num_instructions_global(caller)?;
    let mut instruction_counter = load_value(&num_instructions_global, caller)?;
    // Assert the current instruction counter is sane
    let (system_api, log) = caller.data_mut().system_api_mut_log()?;
    let instruction_limit = system_api.slice_instruction_limit().get() as i64;
    if instruction_counter > instruction_limit {
        error!(
            log,
            "[EXC-BUG] Canister {}: current instructions counter {} is greater than the limit {}",
            system_api.canister_id(),
            instruction_counter,
            instruction_limit
        );
        // Continue execution
    }

    // We are going to subtract a potentially large fee from the instruction
    // counter. To avoid underflows, we need to first ensure that the
    // instruction counter is not negative.
    if instruction_counter < 0 {
        instruction_counter = system_api.out_of_instructions(instruction_counter)?;
    }

    // Now we can subtract the fee and store the new instruction counter.
    instruction_counter -= fee.get() as i64;
    store_value(&num_instructions_global, instruction_counter, caller)?;

    // If the instruction counter became negative after subtracting the fee,
    // then we need to call the out-of-instructins handler again and store the
    // returned new counter value.
    if instruction_counter < 0 {
        let system_api = &mut caller.data_mut().system_api_mut()?;
        instruction_counter = system_api.out_of_instructions(instruction_counter)?;
        store_value(&num_instructions_global, instruction_counter, caller)?;
    }
    Ok(())
}

/// Returns the number of new stable dirty pages and their cost for a potential
/// write to stable memory.
fn get_new_stable_dirty_pages(
    caller: &mut Caller<'_, StoreData>,
    offset: u64,
    size: u64,
) -> HypervisorResult<(NumPages, NumInstructions)> {
    caller
        .data()
        .system_api()?
        .dirty_pages_from_stable_write(offset, size)
}

/// Observe execution complexity.
fn observe_execution_complexity(
    log: &ReplicaLogger,
    system_api: &mut SystemApiImpl,
    complexity: ExecutionComplexity,
    stable_memory_dirty_page_limit: NumPages,
) -> HypervisorResult<()> {
    #[allow(non_upper_case_globals)]
    const KiB: u64 = 1024;

    let canister_id = system_api.canister_id();

    let total_complexity = system_api.execution_complexity() + &complexity;
    match system_api.subnet_type() {
        // Do not observe the execution complexity on the system subnets.
        SubnetType::System => {}
        SubnetType::Application | SubnetType::VerifiedApplication => {
            let message_instruction_limit = system_api.message_instruction_limit();
            if total_complexity.cpu_reached(message_instruction_limit) {
                error!(
                    log,
                    "Canister {}: Error exceeding CPU complexity limit: (observed:{}, limit:{})",
                    canister_id,
                    total_complexity.cpu,
                    message_instruction_limit,
                );
                return Err(HypervisorError::ExecutionComplexityLimitExceeded);
            } else if total_complexity.stable_dirty_pages > stable_memory_dirty_page_limit {
                let error = HypervisorError::MemoryAccessLimitExceeded(
                    format!("Exceeded the limit for the number of modified pages in the stable memory in a single message execution: limit: {} KB.",
                        stable_memory_dirty_page_limit * (PAGE_SIZE as u64 / KiB),
                    ),
                );
                return Err(error);
            }
            system_api.set_execution_complexity(total_complexity);
        }
    }
    Ok(())
}

/// A helper to pass wasmtime counters to the System API
fn ic0_performance_counter_helper(
    caller: &mut Caller<'_, StoreData>,
    counter_type: u32,
) -> HypervisorResult<u64> {
    match counter_type {
        0 => {
            let num_instructions_global = get_num_instructions_global(caller)?;
            let instruction_counter = load_value(&num_instructions_global, caller)?;
            caller
                .data()
                .system_api()?
                .ic0_performance_counter(PerformanceCounterType::Instructions(instruction_counter))
        }
        _ => Err(HypervisorError::ContractViolation(format!(
            "Error getting performance counter type {}",
            counter_type
        ))),
    }
}

pub(crate) fn syscalls(
    linker: &mut Linker<StoreData>,
    feature_flags: FeatureFlags,
    stable_memory_dirty_page_limit: NumPages,
    stable_memory_access_page_limit: NumPages,
    metering_type: MeteringType,
) {
    fn with_system_api<T>(
        mut caller: &mut Caller<'_, StoreData>,
        f: impl Fn(&mut SystemApiImpl) -> HypervisorResult<T>,
    ) -> Result<T, anyhow::Error> {
        caller
            .data_mut()
            .system_api_mut()
            .and_then(|api| f(api))
            .map_err(|e| process_err(&mut caller, e))
    }

    fn with_error_handling<T>(
        caller: &mut Caller<'_, StoreData>,
        f: impl Fn(&mut Caller<'_, StoreData>) -> HypervisorResult<T>,
    ) -> Result<T, anyhow::Error> {
        f(caller).map_err(|e| process_err(caller, e))
    }

    fn with_memory_and_system_api<T>(
        mut caller: &mut Caller<'_, StoreData>,
        f: impl Fn(&mut SystemApiImpl, &mut [u8]) -> HypervisorResult<T>,
    ) -> Result<T, anyhow::Error> {
        caller
            .get_export(WASM_HEAP_MEMORY_NAME)
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
                f(store.system_api_mut()?, mem)
            })
            .map_err(|e| process_err(&mut caller, e))
    }

    linker
        .func_wrap("ic0", "msg_caller_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: i32, offset: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CALLER_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_caller_copy(dst as u32, offset as u32, size as u32, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u32 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_caller_copy_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i64, offset: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CALLER_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_caller_copy_64(
                        dst as u64,
                        offset as u64,
                        size as u64,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u64 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_caller_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(MSG_CALLER_SIZE, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_msg_caller_size()).and_then(|s| {
                    i32::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0::msg_caller_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_arg_data_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(MSG_ARG_DATA_SIZE, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_msg_arg_data_size()).and_then(|s| {
                    i32::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0::msg_arg_data_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_arg_data_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: i32, offset: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_ARG_DATA_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, mem| {
                    system_api.ic0_msg_arg_data_copy(dst as u32, offset as u32, size as u32, mem)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u32 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_arg_data_copy_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i64, offset: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_ARG_DATA_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, mem| {
                    system_api.ic0_msg_arg_data_copy_64(dst as u64, offset as u64, size as u64, mem)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u64 as usize, size as u64 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_method_name_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_METHOD_NAME_SIZE, metering_type, 0),
                )?;
                with_system_api(&mut caller, |s| s.ic0_msg_method_name_size()).and_then(|s| {
                    i32::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0::msg_metohd_name_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_method_name_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: i32, offset: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_METHOD_NAME_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_method_name_copy(
                        dst as u32,
                        offset as u32,
                        size as u32,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u32 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_method_name_copy_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i64, offset: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_METHOD_NAME_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_method_name_copy_64(
                        dst as u64,
                        offset as u64,
                        size as u64,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u64 as usize, size as u64 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "accept_message", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(ACCEPT_MESSAGE, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_accept_message())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reply_data_append", {
            move |mut caller: Caller<'_, StoreData>, src: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_REPLY_DATA_APPEND, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reply_data_append(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reply_data_append_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_REPLY_DATA_APPEND, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reply_data_append_64(src as u64, size as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reply", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(MSG_REPLY, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_msg_reply())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_code", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(MSG_REJECT_CODE, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_msg_reject_code())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject", {
            move |mut caller: Caller<'_, StoreData>, src: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_REJECT, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reject(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_REJECT, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reject_64(src as u64, size as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_msg_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_REJECT_MSG_SIZE, metering_type, 0),
                )?;
                with_system_api(&mut caller, |s| s.ic0_msg_reject_msg_size()).and_then(|s| {
                    i32::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0_msg_reject_msg_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_msg_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: i32, offset: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_REJECT_MSG_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reject_msg_copy(
                        dst as u32,
                        offset as u32,
                        size as u32,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u32 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_msg_copy_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i64, offset: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_REJECT_MSG_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reject_msg_copy_64(
                        dst as u64,
                        offset as u64,
                        size as u64,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u64 as usize, size as u64 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_self_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(CANISTER_SELF_SIZE, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_canister_self_size()).and_then(|s| {
                    i32::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0_canister_self_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_self_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: i32, offset: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CANISTER_SELF_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_canister_self_copy(
                        dst as u32,
                        offset as u32,
                        size as u32,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u32 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_self_copy_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: i64, offset: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CANISTER_SELF_COPY, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_canister_self_copy_64(
                        dst as u64,
                        offset as u64,
                        size as u64,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u64 as usize, size as u64 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "debug_print", {
            move |mut caller: Caller<'_, StoreData>, offset: i32, length: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(DEBUG_PRINT, metering_type, length as u64),
                )?;
                match (
                    caller.data().system_api.as_ref().unwrap().subnet_type(),
                    feature_flags.rate_limiting_of_debug_prints,
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
        .func_wrap("ic0", "debug_print_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, offset: i64, length: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(DEBUG_PRINT, metering_type, length as u64),
                )?;
                match (
                    caller.data().system_api.subnet_type(),
                    feature_flags.rate_limiting_of_debug_prints,
                ) {
                    // Debug print is a no-op on non-system subnets with rate limiting.
                    (SubnetType::Application, FlagStatus::Enabled) => Ok(()),
                    (SubnetType::VerifiedApplication, FlagStatus::Enabled) => Ok(()),
                    // If rate limiting is disabled or the subnet is a system subnet, then
                    // debug print produces output.
                    (_, FlagStatus::Disabled) | (SubnetType::System, FlagStatus::Enabled) => {
                        with_memory_and_system_api(&mut caller, |system_api, memory| {
                            system_api.ic0_debug_print_64(offset as u64, length as u64, memory)
                        })
                    }
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "trap", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData>, offset: i32, length: i32| -> Result<(), _> {
                charge_for_cpu(&mut caller, overhead!(TRAP, metering_type, length as u64))?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_trap(offset as u32, length as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "trap_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, offset: i64, length: i64| -> Result<(), _> {
                charge_for_cpu(&mut caller, overhead!(TRAP, metering_type, length as u64))?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_trap_64(offset as u64, length as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_new", {
            move |mut caller: Caller<'_, StoreData>,
                  callee_src: i32,
                  callee_size: i32,
                  name_src: i32,
                  name_len: i32,
                  reply_fun: i32,
                  reply_env: i32,
                  reject_fun: i32,
                  reject_env: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(
                        CALL_NEW,
                        metering_type,
                        (callee_size as u64).saturating_add(name_len as u64)
                    ),
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
        .func_wrap("ic0", "call_new_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>,
                  callee_src: i64,
                  callee_size: i64,
                  name_src: i64,
                  name_len: i64,
                  reply_fun: i32,
                  reply_env: i32,
                  reject_fun: i32,
                  reject_env: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(
                        CALL_NEW,
                        metering_type,
                        (callee_size as u64).saturating_add(name_len as u64)
                    ),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_call_new_64(
                        callee_src as u64,
                        callee_size as u64,
                        name_src as u64,
                        name_len as u64,
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
            move |mut caller: Caller<'_, StoreData>, src: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CALL_DATA_APPEND, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_call_data_append(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_data_append_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CALL_DATA_APPEND, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_call_data_append_64(src as u64, size as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_on_cleanup", {
            move |mut caller: Caller<'_, StoreData>, fun: i32, env: i32| {
                charge_for_cpu(&mut caller, overhead!(CALL_ON_CLEANUP, metering_type, 0))?;
                with_system_api(&mut caller, |s| {
                    s.ic0_call_on_cleanup(fun as u32, env as u32)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_cycles_add", {
            move |mut caller: Caller<'_, StoreData>, amount: i64| {
                charge_for_cpu(&mut caller, overhead!(CALL_CYCLES_ADD, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_call_cycles_add(amount as u64))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_cycles_add128", {
            move |mut caller: Caller<'_, StoreData>, amount_high: i64, amount_low: i64| {
                charge_for_cpu(&mut caller, overhead!(CALL_CYCLES_ADD128, metering_type, 0))?;
                with_system_api(&mut caller, |s| {
                    s.ic0_call_cycles_add128(Cycles::from_parts(
                        amount_high as u64,
                        amount_low as u64,
                    ))
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_perform", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(CALL_PERFORM, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_call_perform())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(STABLE_SIZE, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_stable_size()).and_then(|s| {
                    i32::try_from(s)
                        .map_err(|e| anyhow::Error::msg(format!("ic0_stable_size failed: {}", e)))
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_grow", {
            move |mut caller: Caller<'_, StoreData>, additional_pages: i32| {
                charge_for_cpu(&mut caller, overhead!(STABLE_GROW, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_stable_grow(additional_pages as u32))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_read", {
            move |mut caller: Caller<'_, StoreData>, dst: i32, offset: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(STABLE_READ, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable_read(dst as u32, offset as u32, size as u32, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u32 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_write", {
            move |mut caller: Caller<'_, StoreData>, offset: i32, src: i32, size: i32| {
                let offset = offset as u32;
                let src = src as u32;
                let size = size as u32;
                let (stable_dirty_pages, dirty_page_cost) =
                    get_new_stable_dirty_pages(&mut caller, offset as u64, size as u64)
                        .map_err(|e| process_err(&mut caller, e))?;

                charge_for_system_api_call(
                    &mut caller,
                    system_api::complexity_overhead!(STABLE_WRITE, metering_type),
                    size as u64,
                    ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE_WRITE,
                        stable_dirty_pages,
                    },
                    dirty_page_cost,
                    stable_memory_dirty_page_limit,
                )
                .map_err(|e| process_err(&mut caller, e))?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable_write(offset, src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(STABLE64_SIZE, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_stable64_size()).and_then(|s| {
                    i64::try_from(s)
                        .map_err(|e| anyhow::Error::msg(format!("ic0_stable64_size failed: {}", e)))
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_grow", {
            move |mut caller: Caller<'_, StoreData>, additional_pages: i64| {
                charge_for_cpu(&mut caller, overhead!(STABLE64_GROW, metering_type, 0))?;
                with_system_api(&mut caller, |s| {
                    s.ic0_stable64_grow(additional_pages as u64)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "stable_read_first_access", {
            move |mut caller: Caller<'_, StoreData>, dst: i64, offset: i64, size: i64| {
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.stable_read_without_bounds_checks(
                        dst as u64,
                        offset as u64,
                        size as u64,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u32 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_read", {
            move |mut caller: Caller<'_, StoreData>, dst: i64, offset: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(STABLE64_READ, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable64_read(dst as u64, offset as u64, size as u64, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as u32 as usize, size as u32 as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_write", {
            move |mut caller: Caller<'_, StoreData>, offset: i64, src: i64, size: i64| {
                let offset = offset as u64;
                let src = src as u64;
                let size = size as u64;
                let (stable_dirty_pages, dirty_page_cost) =
                    get_new_stable_dirty_pages(&mut caller, offset, size)
                        .map_err(|e| process_err(&mut caller, e))?;
                charge_for_system_api_call(
                    &mut caller,
                    system_api::complexity_overhead!(STABLE64_WRITE, metering_type),
                    size,
                    ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE64_WRITE,
                        stable_dirty_pages,
                    },
                    dirty_page_cost,
                    stable_memory_dirty_page_limit,
                )
                .map_err(|e| process_err(&mut caller, e))?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable64_write(offset, src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "time", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(TIME, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_time())
                    .map(|s| s.as_nanos_since_unix_epoch())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "global_timer_set", {
            move |mut caller: Caller<'_, StoreData>, time: i64| {
                charge_for_cpu(&mut caller, overhead!(GLOBAL_TIMER_SET, metering_type, 0))?;
                with_system_api(&mut caller, |s| {
                    s.ic0_global_timer_set(Time::from_nanos_since_unix_epoch(time as u64))
                })
                .map(|s| s.as_nanos_since_unix_epoch())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "performance_counter", {
            move |mut caller: Caller<'_, StoreData>, counter_type: u32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(PERFORMANCE_COUNTER, metering_type, 0),
                )?;
                ic0_performance_counter_helper(&mut caller, counter_type)
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_version", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(CANISTER_VERSION, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_canister_version())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycle_balance", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CANISTER_CYCLE_BALANCE, metering_type, 0),
                )?;
                with_system_api(&mut caller, |s| s.ic0_canister_cycle_balance()).and_then(|s| {
                    i64::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0_canister_cycle_balance failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycle_balance128", {
            move |mut caller: Caller<'_, StoreData>, dst: u32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CANISTER_CYCLE_BALANCE128, metering_type, 0),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_canister_cycle_balance128(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycle_balance128_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: u64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CANISTER_CYCLE_BALANCE128, metering_type, 0),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_canister_cycle_balance128_64(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_available", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CYCLES_AVAILABLE, metering_type, 0),
                )?;
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_available()).and_then(|s| {
                    i64::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0_msg_cycles_available failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_available128", {
            move |mut caller: Caller<'_, StoreData>, dst: u32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CYCLES_AVAILABLE128, metering_type, 0),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_available128(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_available128_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: u64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CYCLES_AVAILABLE128, metering_type, 0),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_available128_64(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_refunded", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CYCLES_REFUNDED, metering_type, 0),
                )?;
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_refunded()).and_then(|s| {
                    i64::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0_msg_cycles_refunded failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_refunded128", {
            move |mut caller: Caller<'_, StoreData>, dst: u32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CYCLES_REFUNDED128, metering_type, 0),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_refunded128(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_refunded128_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, dst: u64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CYCLES_REFUNDED128, metering_type, 0),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_refunded128_64(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept", {
            move |mut caller: Caller<'_, StoreData>, amount: i64| {
                charge_for_cpu(&mut caller, overhead!(MSG_CYCLES_ACCEPT, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_accept(amount as u64))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept128", {
            move |mut caller: Caller<'_, StoreData>, amount_high: i64, amount_low: i64, dst: u32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CYCLES_ACCEPT128, metering_type, 0),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_accept128(
                        Cycles::from_parts(amount_high as u64, amount_low as u64),
                        dst,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept128_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>,
                  amount_high: i64,
                  amount_low: i64,
                  dst: u64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(MSG_CYCLES_ACCEPT128, metering_type, 0),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_accept128_64(
                        Cycles::from_parts(amount_high as u64, amount_low as u64),
                        dst,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "out_of_instructions", {
            move |mut caller: Caller<'_, StoreData>| -> Result<(), _> {
                with_error_handling(&mut caller, |c| {
                    let global = get_num_instructions_global(c)?;
                    let instruction_counter = load_value(&global, c)?;
                    let instruction_counter = c
                        .data_mut()
                        .system_api_mut()?
                        .out_of_instructions(instruction_counter)?;
                    store_value(&global, instruction_counter, c)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "update_available_memory", {
            move |mut caller: Caller<'_, StoreData>,
                  native_memory_grow_res: i32,
                  additional_elements: i32,
                  element_size: i32| {
                with_system_api(&mut caller, |s| {
                    s.update_available_memory(
                        native_memory_grow_res as i64,
                        additional_elements as u32 as u64,
                        element_size as u32 as u64,
                    )
                })
                .map(|()| native_memory_grow_res)
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "update_available_memory_64", {
            move |mut caller: Caller<'_, StoreData<S>>,
                  native_memory_grow_res: i64,
                  additional_elements: i64,
                  element_size: i32| {
                with_system_api(&mut caller, |s| {
                    s.update_available_memory(
                        native_memory_grow_res,
                        additional_elements as u64,
                        element_size as u32 as u64,
                    )
                })
                .map(|()| native_memory_grow_res)
                .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "try_grow_stable_memory", {
            move |mut caller: Caller<'_, StoreData>,
                  current_size: i64,
                  additional_pages: i64,
                  stable_memory_api: i32| {
                charge_for_system_api_call(
                    &mut caller,
                    system_api::complexity_overhead_native!(STABLE_GROW, metering_type),
                    0,
                    ExecutionComplexity {
                        cpu: system_api_complexity::cpu::STABLE_GROW,
                        ..Default::default()
                    },
                    NumInstructions::from(0),
                    stable_memory_dirty_page_limit,
                )
                .map_err(|e| process_err(&mut caller, e))?;
                with_system_api(&mut caller, |s| {
                    match s.try_grow_stable_memory(
                        current_size as u64,
                        additional_pages as u64,
                        stable_memory_api
                            .try_into()
                            .map_err(|()| HypervisorError::Trapped(TrapCode::Other))?,
                    )? {
                        StableGrowOutcome::Success => Ok(current_size),
                        StableGrowOutcome::Failure => Ok(-1),
                    }
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_status", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead!(CANISTER_STATUS, metering_type, 0))?;
                with_system_api(&mut caller, |s| s.ic0_canister_status())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "certified_data_set", {
            move |mut caller: Caller<'_, StoreData>, src: u32, size: u32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CERTIFIED_DATA_SET, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_certified_data_set(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "certified_data_set_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: u64, size: u64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(CERTIFIED_DATA_SET, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_certified_data_set_64(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_present", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(DATA_CERTIFICATE_PRESENT, metering_type, 0),
                )?;
                with_system_api(&mut caller, |s| s.ic0_data_certificate_present())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(DATA_CERTIFICATE_SIZE, metering_type, 0),
                )?;
                with_system_api(&mut caller, |s| s.ic0_data_certificate_size())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "is_controller", {
            move |mut caller: Caller<'_, StoreData>, src: i32, size: i32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(IS_CONTROLLER, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_is_controller(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "is_controller_64", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, src: i64, size: i64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(IS_CONTROLLER, metering_type, size as u64),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_is_controller_64(src as u64, size as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_copy", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData>, dst: u32, offset: u32, size: u32| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(DATA_CERTIFICATE_COPY, metering_type, size),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_data_certificate_copy(dst, offset, size, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, size as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_copy_64", {
            move |mut caller: Caller<'_, StoreData<S>>, dst: u64, offset: u64, size: u64| {
                charge_for_cpu(
                    &mut caller,
                    overhead!(DATA_CERTIFICATE_COPY, metering_type, size),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_data_certificate_copy_64(dst, offset, size, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst as usize, size as usize)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "mint_cycles", {
            move |mut caller: Caller<'_, StoreData>, amount: i64| {
                with_system_api(&mut caller, |s| s.ic0_mint_cycles(amount as u64)).and_then(|s| {
                    i64::try_from(s)
                        .map_err(|e| anyhow::Error::msg(format!("ic0_mint_cycles failed: {}", e)))
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "internal_trap", {
            move |mut caller: Caller<'_, StoreData>, err_code: i32| -> Result<(), _> {
                let err = match InternalErrorCode::from_i32(err_code) {
                    InternalErrorCode::HeapOutOfBounds => {
                        HypervisorError::Trapped(TrapCode::HeapOutOfBounds)
                    }
                    InternalErrorCode::StableMemoryOutOfBounds => {
                        HypervisorError::Trapped(TrapCode::StableMemoryOutOfBounds)
                    }
                    InternalErrorCode::StableMemoryTooBigFor32Bit => {
                        HypervisorError::Trapped(TrapCode::StableMemoryTooBigFor32Bit)
                    }
                    InternalErrorCode::MemoryWriteLimitExceeded => {
                        HypervisorError::MemoryAccessLimitExceeded(
                            format!("Exceeded the limit for the number of modified pages in the stable memory in a single message execution: limit: {} KB.",
                                    stable_memory_dirty_page_limit * (PAGE_SIZE as u64 / 1024),
                            )
                        )
                    }
                    InternalErrorCode::MemoryAccessLimitExceeded => {
                        HypervisorError::MemoryAccessLimitExceeded(
                            format!("Exceeded the limit for the number of accessed pages in the stable memory in a single message execution: limit: {} KB.",
                                    stable_memory_access_page_limit * (PAGE_SIZE as u64 / 1024),
                            )
                        )
                    }
                    InternalErrorCode::StableGrowFailed => {
                        HypervisorError::CalledTrap("Internal error: `memory.grow` instruction failed to grow stable memory".to_string())
                    }
                    InternalErrorCode::Unknown => HypervisorError::CalledTrap(format!(
                        "Trapped with internal error code: {}",
                        err_code
                    )),
                };
                Err(process_err(&mut caller, err))
            }
        })
        .unwrap();
}
