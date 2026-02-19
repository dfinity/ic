use std::{mem, time::Duration};

use slotmap::KeyData;

use crate::state::{SerialClosure, TASKS, Task, TaskId};

#[cfg_attr(
    target_family = "wasm",
    unsafe(export_name = "canister_update <ic-cdk internal> timer_executor")
)]
#[cfg_attr(
    not(target_family = "wasm"),
    unsafe(export_name = "canister_update_ic_cdk_internal.timer_executor")
)]
extern "C" fn timer_executor() {
    ic_cdk_executor::in_tracking_executor_context(|| {
        let mut caller = [0; 32];
        let caller = {
            let sz = ic0::msg_caller_size();
            ic0::msg_caller_copy(&mut caller[..sz], 0);
            &caller[..sz]
        };
        let mut canister_self = [0; 32];
        let canister_self = {
            let sz = ic0::canister_self_size();
            ic0::canister_self_copy(&mut canister_self[..sz], 0);
            &canister_self[..sz]
        };

        if caller != canister_self {
            ic0::trap(b"This function is internal to ic-cdk and should not be called externally.");
        }

        // timer_executor is only called by the canister itself (from global_timer),
        // so we can safely assume that the argument is a valid TimerId (u64).
        // And we don't need decode_one_with_config/DecoderConfig to defend against a malicious payload.
        assert!(ic0::msg_arg_data_size() == 8);
        let mut arg_bytes = [0; 8];
        ic0::msg_arg_data_copy(&mut arg_bytes, 0);
        let task_id = u64::from_be_bytes(arg_bytes);
        let task_id = TaskId::from(KeyData::from_ffi(task_id));

        // We can't be holding `TASKS` when we call the function, because it may want to schedule more tasks.
        // Instead, we swap the task out in order to call it, and then either swap it back in, or remove it.
        let task = TASKS.with_borrow_mut(|tasks| {
            if let Some(task) = tasks.get_mut(task_id) {
                // Replace with Invalid to take ownership.
                // The Invalid variant should not last past the end of this function.
                Some(mem::replace(task, Task::Invalid))
            } else {
                None
            }
        });
        if let Some(task) = task {
            // Each branch should:
            // - remove the Invalid task state OR panic, before any awaits
            // - call msg_reply OR panic when done
            match task {
                Task::Once(fut) => {
                    ic_cdk_executor::spawn_protected(async move {
                        fut.await;
                        ic0::msg_reply();
                    });
                    // Invalid cleared in the same round
                    TASKS.with_borrow_mut(|tasks| tasks.remove(task_id));
                }
                Task::Repeated {
                    mut func,
                    interval,
                    concurrent_calls,
                } => {
                    let invocation = func();
                    // Invalid cleared in the same round
                    TASKS.with_borrow_mut(|tasks| {
                        tasks[task_id] = Task::Repeated {
                            func,
                            interval,
                            concurrent_calls,
                        };
                    });
                    ic_cdk_executor::spawn_protected(async move {
                        invocation.await;
                        ic0::msg_reply();
                    });
                }
                Task::RepeatedSerial { func, interval } => {
                    // Invalid cleared in the same round
                    TASKS.with_borrow_mut(|tasks| {
                        tasks[task_id] = Task::RepeatedSerialBusy { interval };
                    });
                    ic_cdk_executor::spawn_protected(async move {
                        // Option for `take` in Drop; always Some
                        struct ReplaceGuard(Option<Box<dyn SerialClosure>>, Duration, TaskId);
                        impl Drop for ReplaceGuard {
                            fn drop(&mut self) {
                                let func = self.0.take().unwrap();
                                let interval = self.1;
                                let task_id = self.2;
                                TASKS.with_borrow_mut(|tasks| {
                                    tasks[task_id] = Task::RepeatedSerial { func, interval };
                                });
                            }
                        }
                        let mut guard = ReplaceGuard(Some(func), interval, task_id);
                        guard.0.as_mut().unwrap().call().await;
                        ic0::msg_reply();
                    });
                }
                Task::RepeatedSerialBusy { .. } => {
                    // Invalid cleared in the same round
                    TASKS.with_borrow_mut(|tasks| {
                        tasks[task_id] = task;
                    });
                    ic0::msg_reply();
                }
                Task::Invalid => {
                    // Invalid impossible
                    unreachable!(
                        "[ic-cdk-timers] internal error: invalid task state in executor method"
                    )
                }
            }
        } else {
            ic0::msg_reply();
        }
    });
}
