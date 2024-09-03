use crate::wasmtime_embedder::{
    system_api_complexity::{overhead, overhead_native},
    StoreData, WASM_HEAP_BYTEMAP_MEMORY_NAME, WASM_HEAP_MEMORY_NAME,
};

use ic_config::{
    embedders::{FeatureFlags, StableMemoryPageLimit},
    flag_status::FlagStatus,
};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult, PerformanceCounterType, StableGrowOutcome, SystemApi,
    TrapCode,
};
use ic_logger::error;
use ic_registry_subnet_type::SubnetType;
use ic_sys::PAGE_SIZE;
use ic_types::{Cycles, NumBytes, NumInstructions, NumOsPages, Time};
use ic_wasm_types::WasmEngineError;

use wasmtime::{AsContextMut, Caller, Global, Linker, Val};

use crate::InternalErrorCode;
use std::convert::TryFrom;

use crate::wasm_utils::instrumentation::WasmMemoryType;
use ic_system_api::SystemApiImpl;

/// The amount of instructions required to process a single byte in a payload.
/// This includes the cost of memory as well as time passing the payload
/// from wasm sandbox to the replica execution environment.
const BYTE_TRANSMISSION_COST_FACTOR: usize = 50;

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
                HypervisorError::ToolchainContractViolation {
                    error: "Failed to access heap bitmap".to_string(),
                },
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

/// Charge for system api call that doesn't involve touching memory
fn charge_for_cpu(
    caller: &mut Caller<'_, StoreData>,
    overhead: NumInstructions,
) -> Result<(), anyhow::Error> {
    charge_for_system_api_call(caller, overhead, 0).map_err(|e| process_err(caller, e))
}

/// Charge for system api call that involves writing/reading heap
fn charge_for_cpu_and_mem(
    caller: &mut Caller<'_, StoreData>,
    overhead: NumInstructions,
    num_bytes: usize,
) -> Result<(), anyhow::Error> {
    charge_for_system_api_call(caller, overhead, num_bytes).map_err(|e| process_err(caller, e))
}

/// Charge for system api call that involves writing/reading stable memory
// TODO: RUN-841: Cover with tests
#[inline(never)]
fn charge_for_stable_write(
    caller: &mut Caller<'_, StoreData>,
    mut overhead: NumInstructions,
    offset: u64,
    size: u64,
    dirty_page_limit: StableMemoryPageLimit,
) -> HypervisorResult<()> {
    let system_api = caller.data().system_api()?;
    let (new_stable_dirty_pages, dirty_page_cost) =
        system_api.dirty_pages_from_stable_write(offset, size)?;

    let dirty_page_limit = system_api.get_page_limit(&dirty_page_limit);

    overhead = overhead
        .get()
        .checked_add(dirty_page_cost.get())
        .ok_or(unexpected_err(format!(
            "Overflow while calculating charge for stable write:\
             overhead: {}, dirty page cost: {}",
            overhead, dirty_page_cost
        )))?
        .into();

    #[allow(non_upper_case_globals)]
    const KiB: u64 = 1024;

    let stable_dirty_pages = &mut caller
        .data_mut()
        .num_stable_dirty_pages_from_non_native_writes;
    let total_pages = NumOsPages::from(
        stable_dirty_pages
            .get()
            .saturating_add(new_stable_dirty_pages.get()),
    );

    if total_pages > dirty_page_limit {
        let error = HypervisorError::MemoryAccessLimitExceeded(
                            format!("Exceeded the limit for the number of modified pages in the stable memory in a single message execution: limit: {} KB.",
                            dirty_page_limit * (PAGE_SIZE as u64 / KiB),
                            ),
                        );
        return Err(error);
    }
    *stable_dirty_pages = total_pages;

    charge_for_system_api_call(caller, overhead, size as usize)
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
// TODO: RUN-841: Cover with tests
#[inline(never)]
fn charge_for_system_api_call(
    caller: &mut Caller<'_, StoreData>,
    mut overhead: NumInstructions,
    num_bytes: usize,
) -> HypervisorResult<()> {
    let system_api = caller.data_mut().system_api()?;
    if num_bytes > 0 {
        let bytes_charge =
            system_api.get_num_instructions_from_bytes(NumBytes::from(num_bytes as u64));
        overhead = overhead
            .get()
            .checked_add(bytes_charge.get())
            .ok_or(unexpected_err(format!(
                "Overflow while calculating charge for System API call:\
             overhead: {}, bytes charge: {}",
                overhead, bytes_charge
            )))?
            .into();
    }

    charge_direct_fee(caller, overhead)
}

// TODO: RUN-841: Cover with tests
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

/// A helper to pass wasmtime counters to the System API
fn ic0_performance_counter_helper(
    caller: &mut Caller<'_, StoreData>,
    counter_type: u32,
) -> HypervisorResult<u64> {
    let num_instructions_global = get_num_instructions_global(caller)?;
    let instruction_counter = load_value(&num_instructions_global, caller)?;
    match counter_type {
        0 => caller
            .data()
            .system_api()?
            .ic0_performance_counter(PerformanceCounterType::Instructions(instruction_counter)),
        1 => caller.data().system_api()?.ic0_performance_counter(
            PerformanceCounterType::CallContextInstructions(instruction_counter),
        ),
        _ => Err(HypervisorError::UserContractViolation {
            error: format!("Error getting performance counter type {}", counter_type),
            suggestion: "".to_string(),
            doc_link: "".to_string(),
        }),
    }
}

pub(crate) fn syscalls<
    I: TryInto<usize>
        + TryInto<u64>
        + TryInto<u32>
        + TryFrom<usize>
        + wasmtime::WasmTy
        + std::fmt::Display
        + Copy,
>(
    linker: &mut Linker<StoreData>,
    feature_flags: FeatureFlags,
    stable_memory_dirty_page_limit: StableMemoryPageLimit,
    stable_memory_access_page_limit: StableMemoryPageLimit,
    main_memory_type: WasmMemoryType,
) where
    <I as TryInto<usize>>::Error: std::fmt::Display,
    <I as TryInto<usize>>::Error: std::fmt::Debug,
    <I as TryFrom<usize>>::Error: std::fmt::Display,
    <I as TryInto<u64>>::Error: std::fmt::Debug,
    <I as TryInto<u32>>::Error: std::fmt::Display,
{
    fn with_system_api<T>(
        mut caller: &mut Caller<'_, StoreData>,
        f: impl Fn(&mut SystemApiImpl) -> HypervisorResult<T>,
    ) -> Result<T, anyhow::Error> {
        caller
            .data_mut()
            .system_api_mut()
            .and_then(f)
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
            .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                error: "WebAssembly module must define memory".to_string(),
            })
            .and_then(|ext| {
                ext.into_memory()
                    .ok_or_else(|| HypervisorError::ToolchainContractViolation {
                        error: "export 'memory' is not a memory".to_string(),
                    })
            })
            .and_then(|mem| {
                // False positive clippy lint.
                // Issue: https://github.com/rust-lang/rust-clippy/issues/12856
                // Fixed in: https://github.com/rust-lang/rust-clippy/pull/12892
                #[allow(clippy::needless_borrows_for_generic_args)]
                let (mem, store) = mem.data_and_store_mut(&mut caller);
                f(store.system_api_mut()?, mem)
            })
            .map_err(|e| process_err(&mut caller, e))
    }

    /// Check if debug print is enabled.
    fn debug_print_is_enabled(
        caller: &mut Caller<'_, StoreData>,
        feature_flags: FeatureFlags,
    ) -> Result<bool, anyhow::Error> {
        match (
            feature_flags.rate_limiting_of_debug_prints,
            with_system_api(caller, |s| Ok(s.subnet_type()))?,
        ) {
            // Debug print is enabled if rate limiting is off or for system subnets.
            (FlagStatus::Disabled, _) | (_, SubnetType::System) => Ok(true),
            // Disabled otherwise.
            _ => Ok(false),
        }
    }

    /// Calculate logging charge bytes based on message size and remaining space in canister log.
    fn logging_charge_bytes(
        caller: &mut Caller<'_, StoreData>,
        message_num_bytes: u64,
    ) -> Result<u64, anyhow::Error> {
        let capacity = with_system_api(caller, |s| Ok(s.canister_log().capacity()))?;
        let remaining_space = with_system_api(caller, |s| Ok(s.canister_log().remaining_space()))?;
        let allocated_num_bytes = message_num_bytes.min(capacity as u64);
        let transmitted_num_bytes = message_num_bytes.min(remaining_space as u64);
        // LINT.IfChange
        // The cost of logging is proportional to the size of the message, but is limited
        // by the log capacity and the remaining space in the log.
        // The cost is calculated as follows:
        // - the allocated bytes (x2 to account for adding new message and removing the oldest one)
        //   - this must be in sync with `CanisterLog::add_record()` from `ic_management_canister_types`
        // - the transmitted bytes (multiplied by the cost factor) for sending the payload to the replica.
        Ok(2 * allocated_num_bytes + BYTE_TRANSMISSION_COST_FACTOR as u64 * transmitted_num_bytes)
        // LINT.ThenChange(logging_charge_bytes_rule)
    }

    linker
        .func_wrap("ic0", "msg_caller_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: I, offset: I, size: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                let offset: usize = offset.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::MSG_CALLER_COPY, size)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_caller_copy(dst, offset, size, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, size)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_caller_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_CALLER_SIZE)?;
                with_system_api(&mut caller, |s| s.ic0_msg_caller_size()).and_then(|s| {
                    I::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0::msg_caller_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_arg_data_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_ARG_DATA_SIZE)?;
                with_system_api(&mut caller, |s| s.ic0_msg_arg_data_size()).and_then(|s| {
                    I::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0::msg_arg_data_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_arg_data_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: I, offset: I, size: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                let offset: usize = offset.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::MSG_ARG_DATA_COPY, size)?;
                with_memory_and_system_api(&mut caller, |system_api, mem| {
                    system_api.ic0_msg_arg_data_copy(dst, offset, size, mem)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, size)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_method_name_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_METHOD_NAME_SIZE)?;
                with_system_api(&mut caller, |s| s.ic0_msg_method_name_size()).and_then(|s| {
                    I::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0::msg_metohd_name_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_method_name_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: I, offset: I, size: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                let offset: usize = offset.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::MSG_METHOD_NAME_COPY, size)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_method_name_copy(dst, offset, size, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, size)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "accept_message", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::ACCEPT_MESSAGE)?;
                with_system_api(&mut caller, |s| s.ic0_accept_message())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reply_data_append", {
            move |mut caller: Caller<'_, StoreData>, src: I, size: I| {
                let src: usize = src.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(
                    &mut caller,
                    overhead::MSG_REPLY_DATA_APPEND,
                    BYTE_TRANSMISSION_COST_FACTOR.saturating_mul(size),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reply_data_append(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reply", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_REPLY)?;
                with_system_api(&mut caller, |s| s.ic0_msg_reply())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_code", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_REJECT_CODE)?;
                with_system_api(&mut caller, |s| s.ic0_msg_reject_code())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject", {
            move |mut caller: Caller<'_, StoreData>, src: I, size: I| {
                let src: usize = src.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(
                    &mut caller,
                    overhead::MSG_REJECT,
                    BYTE_TRANSMISSION_COST_FACTOR.saturating_mul(size),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reject(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_msg_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_REJECT_MSG_SIZE)?;
                with_system_api(&mut caller, |s| s.ic0_msg_reject_msg_size()).and_then(|s| {
                    I::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0_msg_reject_msg_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_msg_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: I, offset: I, size: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                let offset: usize = offset.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::MSG_REJECT_MSG_COPY, size)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_reject_msg_copy(dst, offset, size, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, size)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_self_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::CANISTER_SELF_SIZE)?;
                with_system_api(&mut caller, |s| s.ic0_canister_self_size()).and_then(|s| {
                    I::try_from(s).map_err(|e| {
                        anyhow::Error::msg(format!("ic0_canister_self_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_self_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: I, offset: I, size: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                let offset: usize = offset.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::CANISTER_SELF_COPY, size)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_canister_self_copy(dst, offset, size, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, size)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "debug_print", {
            move |mut caller: Caller<'_, StoreData>, offset: I, length: I| {
                let length: u64 = length.try_into().expect("Failed to convert I to u64");
                let mut num_bytes = 0;
                num_bytes += logging_charge_bytes(&mut caller, length)?;
                let debug_print_is_enabled = debug_print_is_enabled(&mut caller, feature_flags)?;
                if debug_print_is_enabled {
                    num_bytes += length;
                }
                charge_for_cpu_and_mem(&mut caller, overhead::DEBUG_PRINT, num_bytes as usize)?;
                let offset: usize = offset.try_into().expect("Failed to convert I to usize");
                let length = length as usize;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.save_log_message(offset, length, memory);
                    if debug_print_is_enabled {
                        system_api.ic0_debug_print(offset, length, memory)
                    } else {
                        Ok(())
                    }
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "trap", {
            move |mut caller: Caller<'_, StoreData>, offset: I, length: I| -> Result<(), _> {
                let offset: usize = offset.try_into().expect("Failed to convert I to usize");
                let length: usize = length.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::TRAP, length)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_trap(offset, length, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_new", {
            move |mut caller: Caller<'_, StoreData>,
                  callee_src: I,
                  callee_size: I,
                  name_src: I,
                  name_len: I,
                  reply_fun: I,
                  reply_env: I,
                  reject_fun: I,
                  reject_env: I| {
                let callee_src: usize =
                    callee_src.try_into().expect("Failed to convert I to usize");
                let callee_size: usize = callee_size
                    .try_into()
                    .expect("Failed to convert I to usize");
                let name_src: usize = name_src.try_into().expect("Failed to convert I to usize");
                let name_len: usize = name_len.try_into().expect("Failed to convert I to usize");
                let reply_env: u64 = reply_env.try_into().expect("Failed to convert I to u64");
                let reject_env: u64 = reject_env.try_into().expect("Failed to convert I to u64");
                charge_for_cpu_and_mem(
                    &mut caller,
                    overhead::CALL_NEW,
                    callee_size.saturating_add(name_len),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    // A valid function index should be much smaller than u32::max
                    let reply_fun: u32 = reply_fun.try_into().unwrap_or(u32::MAX);
                    let reject_fun: u32 = reject_fun.try_into().unwrap_or(u32::MAX);
                    system_api.ic0_call_new(
                        callee_src,
                        callee_size,
                        name_src,
                        name_len,
                        reply_fun,
                        reply_env,
                        reject_fun,
                        reject_env,
                        memory,
                    )
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_data_append", {
            move |mut caller: Caller<'_, StoreData>, src: I, size: I| {
                let src: usize = src.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(
                    &mut caller,
                    overhead::CALL_DATA_APPEND,
                    BYTE_TRANSMISSION_COST_FACTOR.saturating_mul(size),
                )?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_call_data_append(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_on_cleanup", {
            move |mut caller: Caller<'_, StoreData>, fun: I, env: I| {
                let env: u64 = env.try_into().expect("Failed to convert I to usize");
                charge_for_cpu(&mut caller, overhead::CALL_ON_CLEANUP)?;
                with_system_api(&mut caller, |s| {
                    // A valid function index should be much smaller than u32::max
                    let fun: u32 = fun.try_into().unwrap_or(u32::MAX);
                    s.ic0_call_on_cleanup(fun, env)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_cycles_add", {
            move |mut caller: Caller<'_, StoreData>, amount: u64| {
                charge_for_cpu(&mut caller, overhead::CALL_CYCLES_ADD)?;
                with_system_api(&mut caller, |s| s.ic0_call_cycles_add(amount))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_cycles_add128", {
            move |mut caller: Caller<'_, StoreData>, amount_high: u64, amount_low: u64| {
                charge_for_cpu(&mut caller, overhead::CALL_CYCLES_ADD128)?;
                with_system_api(&mut caller, |s| {
                    s.ic0_call_cycles_add128(Cycles::from_parts(amount_high, amount_low))
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_cycles_add128_up_to", {
            move |mut caller: Caller<'_, StoreData>, amount_high: u64, amount_low: u64, dst: u32| {
                charge_for_cpu(&mut caller, overhead::CALL_CYCLES_ADD128_UP_TO)?;
                with_memory_and_system_api(&mut caller, |system, memory| {
                    system.ic0_call_cycles_add128_up_to(
                        Cycles::from_parts(amount_high, amount_low),
                        dst as usize,
                        memory,
                    )
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_perform", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::CALL_PERFORM)?;
                with_system_api(&mut caller, |s| s.ic0_call_perform())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::STABLE_SIZE)?;
                with_system_api(&mut caller, |s| s.ic0_stable_size())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_grow", {
            move |mut caller: Caller<'_, StoreData>, additional_pages: u32| {
                charge_for_cpu(&mut caller, overhead::STABLE_GROW)?;
                with_system_api(&mut caller, |s| s.ic0_stable_grow(additional_pages))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_read", {
            move |mut caller: Caller<'_, StoreData>, dst: u32, offset: u32, size: u32| {
                charge_for_cpu_and_mem(&mut caller, overhead::STABLE_READ, size as usize)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable_read(dst, offset, size, memory)
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
        .func_wrap("ic0", "stable_write", {
            move |mut caller: Caller<'_, StoreData>, offset: u32, src: u32, size: u32| {
                charge_for_stable_write(
                    &mut caller,
                    overhead::STABLE_WRITE,
                    offset as u64,
                    size as u64,
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
                charge_for_cpu(&mut caller, overhead::STABLE64_SIZE)?;
                with_system_api(&mut caller, |s| s.ic0_stable64_size())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_grow", {
            move |mut caller: Caller<'_, StoreData>, additional_pages: u64| {
                charge_for_cpu(&mut caller, overhead::STABLE64_GROW)?;
                with_system_api(&mut caller, |s| s.ic0_stable64_grow(additional_pages))
            }
        })
        .unwrap();

    linker
        .func_wrap("__", "stable_read_first_access", {
            move |mut caller: Caller<'_, StoreData>, dst: u64, offset: u64, size: u64| {
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.stable_read_without_bounds_checks(dst, offset, size, memory)
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
        .func_wrap("ic0", "stable64_read", {
            move |mut caller: Caller<'_, StoreData>, dst: u64, offset: u64, size: u64| {
                charge_for_cpu_and_mem(&mut caller, overhead::STABLE64_READ, size as usize)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_stable64_read(dst, offset, size, memory)
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
        .func_wrap("ic0", "stable64_write", {
            move |mut caller: Caller<'_, StoreData>, offset: u64, src: u64, size: u64| {
                charge_for_stable_write(
                    &mut caller,
                    overhead::STABLE64_WRITE,
                    offset,
                    size,
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
                charge_for_cpu(&mut caller, overhead::TIME)?;
                with_system_api(&mut caller, |s| s.ic0_time())
                    .map(|s| s.as_nanos_since_unix_epoch())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "global_timer_set", {
            move |mut caller: Caller<'_, StoreData>, time: u64| {
                charge_for_cpu(&mut caller, overhead::GLOBAL_TIMER_SET)?;
                with_system_api(&mut caller, |s| {
                    s.ic0_global_timer_set(Time::from_nanos_since_unix_epoch(time))
                })
                .map(|s| s.as_nanos_since_unix_epoch())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "performance_counter", {
            move |mut caller: Caller<'_, StoreData>, counter_type: u32| {
                charge_for_cpu(&mut caller, overhead::PERFORMANCE_COUNTER)?;
                ic0_performance_counter_helper(&mut caller, counter_type)
                    .map_err(|e| process_err(&mut caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_version", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::CANISTER_VERSION)?;
                with_system_api(&mut caller, |s| s.ic0_canister_version())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycle_balance", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::CANISTER_CYCLE_BALANCE)?;
                with_system_api(&mut caller, |s| s.ic0_canister_cycle_balance())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycle_balance128", {
            move |mut caller: Caller<'_, StoreData>, dst: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                charge_for_cpu(&mut caller, overhead::CANISTER_CYCLE_BALANCE128)?;
                with_memory_and_system_api(&mut caller, |s, memory| {
                    s.ic0_canister_cycle_balance128(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_available", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_CYCLES_AVAILABLE)?;
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_available())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_available128", {
            move |mut caller: Caller<'_, StoreData>, dst: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                charge_for_cpu(&mut caller, overhead::MSG_CYCLES_AVAILABLE128)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_available128(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_refunded", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_CYCLES_REFUNDED)?;
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_refunded())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_refunded128", {
            move |mut caller: Caller<'_, StoreData>, dst: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                charge_for_cpu(&mut caller, overhead::MSG_CYCLES_REFUNDED128)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_refunded128(dst, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, 16)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept", {
            move |mut caller: Caller<'_, StoreData>, amount: u64| {
                charge_for_cpu(&mut caller, overhead::MSG_CYCLES_ACCEPT)?;
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_accept(amount))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept128", {
            move |mut caller: Caller<'_, StoreData>, amount_high: u64, amount_low: u64, dst: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                charge_for_cpu(&mut caller, overhead::MSG_CYCLES_ACCEPT128)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_accept128(
                        Cycles::from_parts(amount_high, amount_low),
                        dst,
                        memory,
                    )
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, 16)
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

    match main_memory_type {
        WasmMemoryType::Wasm32 => {
            linker
                .func_wrap("__", "try_grow_wasm_memory", {
                    move |mut caller: Caller<'_, StoreData>,
                          native_memory_grow_res: i32,
                          additional_wasm_pages: u32| {
                        with_system_api(&mut caller, |s| {
                            s.try_grow_wasm_memory(
                                native_memory_grow_res as i64,
                                additional_wasm_pages as u64,
                            )
                        })
                        .map(|()| native_memory_grow_res)
                    }
                })
                .unwrap();
        }
        WasmMemoryType::Wasm64 => {
            linker
                .func_wrap("__", "try_grow_wasm_memory", {
                    move |mut caller: Caller<'_, StoreData>,
                          native_memory_grow_res: i64,
                          additional_wasm_pages: u64| {
                        with_system_api(&mut caller, |s| {
                            s.try_grow_wasm_memory(native_memory_grow_res, additional_wasm_pages)
                        })
                        .map(|()| native_memory_grow_res)
                    }
                })
                .unwrap();
        }
    }

    linker
        .func_wrap("__", "try_grow_stable_memory", {
            move |mut caller: Caller<'_, StoreData>,
                  current_size: i64,
                  additional_pages: i64,
                  stable_memory_api: i32| {
                charge_for_cpu(&mut caller, overhead_native::STABLE_GROW)?;
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
                charge_for_cpu(&mut caller, overhead::CANISTER_STATUS)?;
                with_system_api(&mut caller, |s| s.ic0_canister_status())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "certified_data_set", {
            move |mut caller: Caller<'_, StoreData>, src: I, size: I| {
                let src: usize = src.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::CERTIFIED_DATA_SET, size)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_certified_data_set(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_present", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::DATA_CERTIFICATE_PRESENT)?;
                with_system_api(&mut caller, |s| s.ic0_data_certificate_present())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_size", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::DATA_CERTIFICATE_SIZE)?;
                with_system_api(&mut caller, |s| s.ic0_data_certificate_size()).and_then(|x| {
                    I::try_from(x).map_err(|e| {
                        anyhow::Error::msg(format!("ic0::data_certificate_size failed: {}", e))
                    })
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "is_controller", {
            move |mut caller: Caller<'_, StoreData>, src: I, size: I| {
                let src: usize = src.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::IS_CONTROLLER, size)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_is_controller(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "in_replicated_execution", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::IN_REPLICATED_EXECUTION)?;
                with_system_api(&mut caller, |s| s.ic0_in_replicated_execution())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_copy", {
            move |mut caller: Caller<'_, StoreData>, dst: I, offset: I, size: I| {
                let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                let offset: usize = offset.try_into().expect("Failed to convert I to usize");
                let size: usize = size.try_into().expect("Failed to convert I to usize");
                charge_for_cpu_and_mem(&mut caller, overhead::DATA_CERTIFICATE_COPY, size)?;
                with_memory_and_system_api(&mut caller, |system_api, memory| {
                    system_api.ic0_data_certificate_copy(dst, offset, size, memory)
                })?;
                if feature_flags.write_barrier == FlagStatus::Enabled {
                    mark_writes_on_bytemap(&mut caller, dst, size)
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "mint_cycles", {
            move |mut caller: Caller<'_, StoreData>, amount: u64| {
                with_system_api(&mut caller, |s| s.ic0_mint_cycles(amount))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "cycles_burn128", {
            move |mut caller: Caller<'_, StoreData>, amount_high: u64, amount_low: u64, dst: I| {
                with_memory_and_system_api(&mut caller, |s, memory| {
                    let dst: usize = dst.try_into().expect("Failed to convert I to usize");
                    s.ic0_cycles_burn128(Cycles::from_parts(amount_high, amount_low), dst, memory)
                })
                .map_err(|e| anyhow::Error::msg(format!("ic0_cycles_burn128 failed: {}", e)))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_with_best_effort_response", {
            move |mut caller: Caller<'_, StoreData>, timeout_seconds: u32| {
                charge_for_cpu(&mut caller, overhead::CALL_WITH_BEST_EFFORT_RESPONSE)?;
                if feature_flags.best_effort_responses == FlagStatus::Enabled {
                    with_system_api(&mut caller, |system_api| {
                        system_api.ic0_call_with_best_effort_response(timeout_seconds)
                    })
                } else {
                    let err = HypervisorError::ToolchainContractViolation {
                        error: "ic0::call_with_best_effort_response is not enabled.".to_string(),
                    };
                    Err(process_err(&mut caller, err))
                }
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_deadline", {
            move |mut caller: Caller<'_, StoreData>| {
                charge_for_cpu(&mut caller, overhead::MSG_DEADLINE)?;
                if feature_flags.best_effort_responses == FlagStatus::Enabled {
                    with_system_api(&mut caller, |system_api| system_api.ic0_msg_deadline())
                } else {
                    let err = HypervisorError::ToolchainContractViolation {
                        error: "ic0::msg_deadline is not enabled.".to_string(),
                    };
                    Err(process_err(&mut caller, err))
                }
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
                            format!("Exceeded the limit for the number of modified pages in the stable memory in a single execution: limit {} KB for regular messages, {} KB for upgrade messages and {} KB for queries.",
                            stable_memory_dirty_page_limit.message.get() * (PAGE_SIZE as u64 / 1024),
                            stable_memory_dirty_page_limit.upgrade.get() * (PAGE_SIZE as u64 / 1024),
                            stable_memory_dirty_page_limit.query.get() * (PAGE_SIZE as u64 / 1024)
                            )
                        )
                    }
                    InternalErrorCode::MemoryAccessLimitExceeded => {
                        HypervisorError::MemoryAccessLimitExceeded(
                            format!("Exceeded the limit for the number of accessed pages in the stable memory in a single message execution: limit {} KB for regular messages and {} KB for queries.",
                                    stable_memory_access_page_limit.message.get() * (PAGE_SIZE as u64 / 1024), stable_memory_access_page_limit.query.get() * (PAGE_SIZE as u64 / 1024),
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
