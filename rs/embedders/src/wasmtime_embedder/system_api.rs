use ic_interfaces::execution_environment::{HypervisorError, SystemApi};
use ic_types::NumBytes;
use std::borrow::Borrow;
use std::cell::{RefCell, RefMut};
use std::convert::TryFrom;
use std::ops::DerefMut;
use std::rc::Rc;
use wasmtime::{Caller, Linker, Store, Trap, Val};

#[derive(Clone)]
pub struct SystemApiHandle {
    inner: Rc<RefCell<Option<*mut dyn SystemApi>>>,
}

impl SystemApiHandle {
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(None)),
        }
    }

    pub fn replace(&self, system_api: &mut (dyn SystemApi + 'static)) {
        self.inner.replace(Some(system_api));
    }

    pub fn clear(&self) {
        self.inner.replace(None);
    }

    fn get_system_api(&self) -> RefMut<'_, dyn SystemApi> {
        unsafe {
            let r = self.inner.borrow_mut();
            RefMut::map(r, |x| &mut *x.expect("SystemApi pointer is not set"))
        }
    }
}

fn process_err(api: &mut dyn SystemApi, e: HypervisorError) -> wasmtime::Trap {
    let t = wasmtime::Trap::new(format! {"{}", e});
    api.set_execution_error(e);
    t
}

fn update_num_instructions_global(
    num_instructions_global_rc: &std::rc::Weak<RefCell<Option<wasmtime::Global>>>,
    api: &mut dyn SystemApi,
    num_bytes: u32,
) -> Result<(), Trap> {
    let num_instructions_global = num_instructions_global_rc.upgrade().unwrap();
    let num_instructions_global_ref = num_instructions_global.borrow_mut();
    let num_instructions_global = num_instructions_global_ref.as_ref().unwrap();

    match num_instructions_global.get() {
        Val::I64(current_instructions) => {
            let num_instructions = api
                .get_num_instructions_from_bytes(NumBytes::from(num_bytes as u64))
                .get() as i64;
            if current_instructions < num_instructions {
                return Err(process_err(api, HypervisorError::OutOfInstructions));
            }

            num_instructions_global
                .set(Val::I64(current_instructions - num_instructions))
                .unwrap_or_else(|_| {
                    panic!(
                        "Setting counter_instructions to {}  failed",
                        num_instructions
                    )
                });
            Ok(())
        }
        _ => unreachable!("invalid instructions counter type"),
    }
}

pub(crate) fn syscalls(
    store: &Store,
    api: SystemApiHandle,
    num_instructions_global: std::rc::Weak<RefCell<Option<wasmtime::Global>>>,
) -> Linker {
    fn get_memory(
        caller: Caller<'_>,
        api: &mut dyn SystemApi,
    ) -> Result<wasmtime::Memory, wasmtime::Trap> {
        caller
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
            .map_err(|e| process_err(&mut *api, e))
    }

    let mut linker = Linker::new(&store);

    linker
        .func("ic0", "msg_caller_copy", {
            let api = api.clone();
            move |caller: Caller<'_>, dst: i32, offset: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                api.ic0_msg_caller_copy(dst as u32, offset as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_caller_size", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_msg_caller_size()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0::msg_caller_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_arg_data_size", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_msg_arg_data_size()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0::msg_arg_data_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_arg_data_copy", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, dst: i32, offset: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    size as u32,
                )?;
                api.ic0_msg_arg_data_copy(dst as u32, offset as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_method_name_size", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_msg_method_name_size()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0::msg_metohd_name_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_method_name_copy", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, dst: i32, offset: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    size as u32,
                )?;
                api.ic0_msg_method_name_copy(dst as u32, offset as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "accept_message", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_accept_message()
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_reply_data_append", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, src: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    size as u32,
                )?;
                api.ic0_msg_reply_data_append(src as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_reply", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_msg_reply().map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_reject_code", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_msg_reject_code()
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_reject", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, src: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    size as u32,
                )?;
                api.ic0_msg_reject(src as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_reject_msg_size", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_msg_reject_msg_size()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_msg_reject_msg_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_reject_msg_copy", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, dst: i32, offset: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    size as u32,
                )?;
                api.ic0_msg_reject_msg_copy(dst as u32, offset as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "canister_self_size", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_canister_self_size()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_canister_self_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "canister_self_copy", {
            let api = api.clone();
            move |caller: Caller<'_>, dst: i32, offset: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                api.ic0_canister_self_copy(dst as u32, offset as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "controller_size", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_controller_size()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_controller_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "controller_copy", {
            let api = api.clone();
            move |caller: Caller<'_>, dst: i32, offset: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                api.ic0_controller_copy(dst as u32, offset as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "debug_print", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, offset: i32, length: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    length as u32,
                )?;
                api.ic0_debug_print(offset as u32, length as u32, memory);
                Ok(())
            }
        })
        .unwrap();

    linker
        .func("ic0", "trap", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, offset: i32, length: i32| -> Result<(), _> {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    length as u32,
                )?;
                let trap = api.ic0_trap(offset as u32, length as u32, memory);
                Err(process_err(&mut *api, trap))
            }
        })
        .unwrap();

    linker
        .func("ic0", "call_simple", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>,
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
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    len as u32,
                )?;
                api.ic0_call_simple(
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
                .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "call_new", {
            let api = api.clone();
            move |caller: Caller<'_>,
                  callee_src: i32,
                  callee_size: i32,
                  name_src: i32,
                  name_len: i32,
                  reply_fun: i32,
                  reply_env: i32,
                  reject_fun: i32,
                  reject_env: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                api.ic0_call_new(
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
                .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "call_data_append", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, src: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    size as u32,
                )?;
                api.ic0_call_data_append(src as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "call_on_cleanup", {
            let api = api.clone();
            move |fun: i32, env: i32| {
                let mut api = api.get_system_api();
                api.ic0_call_on_cleanup(fun as u32, env as u32)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "call_cycles_add", {
            let api = api.clone();
            move |amount: i64| {
                let mut api = api.get_system_api();
                api.ic0_call_cycles_add(amount as u64)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "call_perform", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_call_perform()
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "stable_size", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_stable_size()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i32::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_stable_size failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "stable_grow", {
            let api = api.clone();
            move |additional_pages: i32| {
                let mut api = api.get_system_api();
                api.ic0_stable_grow(additional_pages as u32)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "stable_read", {
            let api = api.clone();
            let num_instructions_global = num_instructions_global.clone();
            move |caller: Caller<'_>, dst: i32, offset: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    size as u32,
                )?;
                api.ic0_stable_read(dst as u32, offset as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "stable_write", {
            let api = api.clone();
            move |caller: Caller<'_>, offset: i32, src: i32, size: i32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                update_num_instructions_global(
                    num_instructions_global.borrow(),
                    api.deref_mut(),
                    size as u32,
                )?;
                api.ic0_stable_write(offset as u32, src as u32, size as u32, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "time", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_time()
                    .map_err(|e| process_err(&mut *api, e))
                    .map(|s| s.as_nanos_since_unix_epoch())
            }
        })
        .unwrap();

    linker
        .func("ic0", "canister_cycle_balance", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_canister_cycle_balance()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_canister_cycle_balance failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_cycles_available", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_msg_cycles_available()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_msg_cycles_available failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_cycles_refunded", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_msg_cycles_refunded()
                    .map_err(|e| process_err(&mut *api, e))
                    .and_then(|s| {
                        i64::try_from(s).map_err(|e| {
                            wasmtime::Trap::new(format!("ic0_msg_cycles_refunded failed: {}", e))
                        })
                    })
            }
        })
        .unwrap();

    linker
        .func("ic0", "msg_cycles_accept", {
            let api = api.clone();
            move |amount: i64| {
                let mut api = api.get_system_api();
                api.ic0_msg_cycles_accept(amount as u64)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("__", "out_of_instructions", {
            let api = api.clone();
            move || -> Result<(), _> {
                let mut api = api.get_system_api();
                let err = api.out_of_instructions();
                Err(process_err(&mut *api, err))
            }
        })
        .unwrap();

    linker
        .func("__", "update_available_memory", {
            let api = api.clone();
            move |native_memory_grow_res: i32, additional_pages: i32| {
                let mut api = api.get_system_api();
                api.update_available_memory(native_memory_grow_res, additional_pages as u32)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "canister_status", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_canister_status()
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "certified_data_set", {
            let api = api.clone();
            move |caller: Caller<'_>, src: u32, size: u32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                api.ic0_certified_data_set(src, size, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "data_certificate_present", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_data_certificate_present()
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "data_certificate_size", {
            let api = api.clone();
            move || {
                let mut api = api.get_system_api();
                api.ic0_data_certificate_size()
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "data_certificate_copy", {
            let api = api.clone();
            move |caller: Caller<'_>, dst: u32, offset: u32, size: u32| {
                let mut api = api.get_system_api();
                let mem = get_memory(caller, &mut *api)?;
                let memory = unsafe { mem.data_unchecked_mut() };
                api.ic0_data_certificate_copy(dst, offset, size, memory)
                    .map_err(|e| process_err(&mut *api, e))
            }
        })
        .unwrap();

    linker
        .func("ic0", "mint_cycles", {
            move |amount: i64| {
                let mut api = api.get_system_api();
                api.ic0_mint_cycles(amount as u64)
                    .map_err(|e| process_err(&mut *api, e))
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
