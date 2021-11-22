use crate::wasmtime_embedder::{system_api_charges, StoreData};

use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult, SystemApi};
use ic_logger::{error, info, ReplicaLogger};
use ic_types::{CanisterId, Cycles, NumBytes, NumInstructions};

use wasmtime::{AsContextMut, Caller, Linker, Store, Trap, Val};

use std::convert::TryFrom;

fn process_err<S: SystemApi>(
    mut store: impl AsContextMut<Data = StoreData<S>>,
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
fn charge_for_system_api_call<S: SystemApi>(
    log: &ReplicaLogger,
    canister_id: CanisterId,
    mut caller: &mut Caller<'_, StoreData<S>>,
    system_api_charge: NumInstructions,
    num_bytes: u64,
) -> Result<(), Trap> {
    let num_instructions_global = match caller.data().num_instructions_global {
        None => {
            error!(
                log,
                "[EXC-BUG] Canister {}: instructions counter is set to None.", canister_id,
            );
            return Err(process_err(
                caller,
                HypervisorError::InstructionLimitExceeded,
            ));
        }
        Some(global) => global,
    };

    match num_instructions_global.get(&mut caller) {
        Val::I64(current_instructions) => {
            let fee = caller
                .as_context_mut()
                .data_mut()
                .system_api
                .get_num_instructions_from_bytes(NumBytes::from(num_bytes))
                .get() as i64
                + system_api_charge.get() as i64;
            if current_instructions < fee {
                info!(
                    log,
                    "Canister {}: ran out of instructions.  Current {}, fee {}",
                    canister_id,
                    current_instructions,
                    fee
                );
                return Err(process_err(
                    caller,
                    HypervisorError::InstructionLimitExceeded,
                ));
            }
            let updated_instructions = current_instructions - fee;
            if let Err(err) =
                num_instructions_global.set(&mut caller, Val::I64(updated_instructions))
            {
                error!(
                    log,
                    "[EXC-BUG] Canister {}: Setting instructions from {} to {} failed with {}",
                    canister_id,
                    current_instructions,
                    updated_instructions,
                    err
                );
                return Err(process_err(
                    caller,
                    HypervisorError::InstructionLimitExceeded,
                ));
            }
            Ok(())
        }
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

pub(crate) fn syscalls<S: SystemApi>(
    log: ReplicaLogger,
    canister_id: CanisterId,
    store: &Store<StoreData<S>>,
) -> Linker<StoreData<S>> {
    fn with_system_api<S, T>(caller: &mut Caller<'_, StoreData<S>>, f: impl Fn(&mut S) -> T) -> T {
        f(&mut caller.as_context_mut().data_mut().system_api)
    }

    fn with_memory_and_system_api<S: SystemApi, T>(
        mut caller: Caller<'_, StoreData<S>>,
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
                let mem = mem.data_mut(&mut caller);
                let ptr = mem.as_mut_ptr();
                let len = mem.len();
                // SAFETY: The memory array is valid for the duration of our borrow of the
                // `SystemApi` and the mutating the `SystemApi` cannot change the memory array
                // so it's safe to mutate both at once.  If the memory and system_api were two
                // fields of the `caller` struct then this would be allowed, but
                // since we access them through opaque functions the
                // compiler can't know that they are unrelated objects.
                f(&mut caller.as_context_mut().data_mut().system_api, unsafe {
                    std::slice::from_raw_parts_mut(ptr, len)
                })
            });
        match result {
            Err(e) => Err(process_err(caller, e)),
            Ok(r) => Ok(r),
        }
    }

    let mut linker = Linker::new(store.engine());

    linker
        .func_wrap("ic0", "msg_caller_copy", {
            move |caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_msg_caller_copy(dst as u32, offset as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_caller_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_caller_size())
                    .map_err(|e| process_err(caller, e))
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
                    .map_err(|e| process_err(caller, e))
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
                    system_api_charges::MSG_ARG_DATA_COPY,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, mem| {
                    system_api.ic0_msg_arg_data_copy(dst as u32, offset as u32, size as u32, mem)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_method_name_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_method_name_size())
                    .map_err(|e| process_err(caller, e))
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
                    system_api_charges::MSG_METHOD_NAME_COPY,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
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
                    .map_err(|e| process_err(caller, e))
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
                    system_api_charges::MSG_REPLY_DATA_APPEND,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_msg_reply_data_append(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reply", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_reply())
                    .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_code", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_reject_code())
                    .map_err(|e| process_err(caller, e))
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
                    system_api_charges::MSG_REJECT,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_msg_reject(src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_reject_msg_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_reject_msg_size())
                    .map_err(|e| process_err(caller, e))
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
                    system_api_charges::MSG_REJECT_MSG_COPY,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
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
                    .map_err(|e| process_err(caller, e))
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
            move |caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                with_memory_and_system_api(caller, |system_api, memory| {
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
                    .map_err(|e| process_err(caller, e))
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
            move |caller: Caller<'_, StoreData<S>>, dst: i32, offset: i32, size: i32| {
                with_memory_and_system_api(caller, |system_api, memory| {
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
                    system_api_charges::DEBUG_PRINT,
                    length as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_debug_print(offset as u32, length as u32, memory);
                    Ok(())
                })
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
                    system_api_charges::TRAP,
                    length as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
                    Err(system_api.ic0_trap(offset as u32, length as u32, memory))
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
                    system_api_charges::CALL_SIMPLE,
                    len as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
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
            move |caller: Caller<'_, StoreData<S>>,
                  callee_src: i32,
                  callee_size: i32,
                  name_src: i32,
                  name_len: i32,
                  reply_fun: i32,
                  reply_env: i32,
                  reject_fun: i32,
                  reject_env: i32| {
                with_memory_and_system_api(caller, |system_api, memory| {
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
                    system_api_charges::CALL_DATA_APPEND,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
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
                .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_cycles_add", {
            move |mut caller: Caller<'_, StoreData<S>>, amount: i64| {
                with_system_api(&mut caller, |s| s.ic0_call_cycles_add(amount as u64))
                    .map_err(|e| process_err(caller, e))
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
                .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "call_perform", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_call_perform())
                    .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_stable_size())
                    .map_err(|e| process_err(caller, e))
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
            move |mut caller: Caller<'_, StoreData<S>>, additional_pages: i32| {
                with_system_api(&mut caller, |s| s.ic0_stable_grow(additional_pages as u32))
                    .map_err(|e| process_err(caller, e))
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
                    system_api_charges::STABLE_READ,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_stable_read(dst as u32, offset as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable_write", {
            let log = log.clone();
            move |mut caller: Caller<'_, StoreData<S>>, offset: i32, src: i32, size: i32| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_charges::STABLE_WRITE,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_stable_write(offset as u32, src as u32, size as u32, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_stable64_size())
                    .map_err(|e| process_err(caller, e))
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
            move |mut caller: Caller<'_, StoreData<S>>, additional_pages: i64| {
                with_system_api(&mut caller, |s| {
                    s.ic0_stable64_grow(additional_pages as u64)
                })
                .map_err(|e| process_err(caller, e))
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
                    system_api_charges::STABLE64_READ,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_stable64_read(dst as u64, offset as u64, size as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "stable64_write", {
            move |mut caller: Caller<'_, StoreData<S>>, offset: i64, src: i64, size: i64| {
                charge_for_system_api_call(
                    &log,
                    canister_id,
                    &mut caller,
                    system_api_charges::STABLE64_WRITE,
                    size as u64,
                )?;
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_stable64_write(offset as u64, src as u64, size as u64, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "time", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_time())
                    .map_err(|e| process_err(caller, e))
                    .map(|s| s.as_nanos_since_unix_epoch())
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycle_balance", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_canister_cycle_balance())
                    .map_err(|e| process_err(caller, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_canister_cycle_balance failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_cycles_balance128", {
            move |caller: Caller<'_, StoreData<S>>, dst: u32| {
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_canister_cycles_balance128(dst, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_available", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_available())
                    .map_err(|e| process_err(caller, e))
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
            move |caller: Caller<'_, StoreData<S>>, dst: u32| {
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_available128(dst, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_refunded", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_refunded())
                    .map_err(|e| process_err(caller, e))
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
            move |caller: Caller<'_, StoreData<S>>, dst: u32| {
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_msg_cycles_refunded128(dst, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept", {
            move |mut caller: Caller<'_, StoreData<S>>, amount: i64| {
                with_system_api(&mut caller, |s| s.ic0_msg_cycles_accept(amount as u64))
                    .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "msg_cycles_accept128", {
            move |caller: Caller<'_, StoreData<S>>, amount_high: i64, amount_low: i64, dst: u32| {
                with_memory_and_system_api(caller, |system_api, memory| {
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
            move |mut caller: Caller<'_, StoreData<S>>| -> Result<(), _> {
                let err = with_system_api(&mut caller, |s| s.out_of_instructions());
                Err(process_err(caller, err))
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
                .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "canister_status", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_canister_status())
                    .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "certified_data_set", {
            move |caller: Caller<'_, StoreData<S>>, src: u32, size: u32| {
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_certified_data_set(src, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_present", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_data_certificate_present())
                    .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_size", {
            move |mut caller: Caller<'_, StoreData<S>>| {
                with_system_api(&mut caller, |s| s.ic0_data_certificate_size())
                    .map_err(|e| process_err(caller, e))
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "data_certificate_copy", {
            move |caller: Caller<'_, StoreData<S>>, dst: u32, offset: u32, size: u32| {
                with_memory_and_system_api(caller, |system_api, memory| {
                    system_api.ic0_data_certificate_copy(dst, offset, size, memory)
                })
            }
        })
        .unwrap();

    linker
        .func_wrap("ic0", "mint_cycles", {
            move |mut caller: Caller<'_, StoreData<S>>, amount: i64| {
                with_system_api(&mut caller, |s| s.ic0_mint_cycles(amount as u64))
                    .map_err(|e| process_err(caller, e))
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
