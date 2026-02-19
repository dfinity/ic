use std::{collections::BinaryHeap, ops::ControlFlow, time::Duration};

use ic_cdk_executor::MethodHandle;
use slotmap::Key;

use crate::state::{self, ALL_CALLS, TASKS, TIMERS, Task, TaskId, Timer};

fn reschedule_timer(timers: &mut BinaryHeap<Timer>, id: TaskId, base: u64, interval: Duration) {
    match base.checked_add(interval.as_nanos() as u64) {
        Some(time) => {
            timers.push(Timer {
                task: id,
                time,
                counter: state::next_counter(),
            });
        }
        None => ic0::debug_print(
            format!(
                "[ic-cdk-timers] Failed to reschedule task (needed {interval}, currently {base}, \
                    and this would exceed u64::MAX)",
                interval = interval.as_nanos()
            )
            .as_bytes(),
        ),
    }
}

// This function is called by the IC at or after the timestamp provided to `ic0.global_timer_set`.
#[unsafe(export_name = "canister_global_timer")]
extern "C" fn global_timer() {
    ic_cdk_executor::in_tracking_executor_context(|| {
        let mut canister_self = [0; 32];
        let canister_self = {
            let sz = ic0::canister_self_size();
            ic0::canister_self_copy(&mut canister_self[..sz], 0);
            &canister_self[..sz]
        };
        // All the calls are made concurrently, according only to the timestamp we *started* with.
        // This allows us to use the minimum number of execution rounds, as well as avoid any race conditions.
        // The only thing that can happen interleavedly is canceling a task, which is seamless by design.
        let now = ic0::time();
        TIMERS.with_borrow_mut(|timers| {
            let mut to_reschedule = Vec::new();
            let mut insn_count = 0;
            let mut first = true;
            // pop every timer that should have been completed by `now`, and get ready to run its task if it exists
            loop {
                if first {
                    first = false;
                } else if insn_count == 0 {
                    insn_count = ic0::performance_counter(0);
                } else if insn_count * 3 + ic0::performance_counter(0) > 40_000_000_000 {
                    ic0::debug_print(
                        b"[ic-cdk-timers] canister_global_timer: approaching instruction limit, \
                        deferring remaining timers to next round",
                    );
                    break;
                }
                if let Some(timer) = timers.peek() {
                    if timer.time <= now {
                        let timer: Timer = timers.pop().unwrap();
                        match do_timer(timer, canister_self, now, timers) {
                            ControlFlow::Continue(()) => continue,
                            ControlFlow::Break(reschedule) => {
                                if let Some(t) = reschedule {
                                    to_reschedule.push(t);
                                }
                                break;
                            }
                        }
                    }
                }
                break;
            }
            timers.extend(to_reschedule);
        });

        state::update_ic0_timer_clean();
    });
}

fn do_timer(
    timer: Timer,
    canister_self: &[u8],
    now: u64,
    timers: &mut BinaryHeap<Timer>,
) -> ControlFlow<Option<Timer>> {
    let timer_scheduled_time = timer.time;
    if TASKS.with_borrow(|tasks| tasks.contains_key(timer.task)) {
        let task_id = timer.task;
        // 1. Check global ratelimit
        if ALL_CALLS.get() >= 250 {
            ic0::debug_print(
                format!(
                    "[ic-cdk-timers] canister_global_timer: \
                    too many concurrent timer calls ({}), deferring timer to next round",
                    ALL_CALLS.get()
                )
                .as_bytes(),
            );
            return ControlFlow::Break(Some(timer));
        } else {
            let skip = TASKS.with_borrow(|tasks| {
                let task = &tasks[task_id];
                match &task {
                    // 2. Check per-timer ratelimit
                    Task::Repeated {
                        interval,
                        concurrent_calls,
                        ..
                    } => {
                        if *concurrent_calls >= 5 {
                            ic0::debug_print(
                                format!(
                                    "[ic-cdk-timers] canister_global_timer: \
                                    too many concurrent calls for single timer ({}), \
                                    rescheduling for next possible execution time",
                                    concurrent_calls
                                )
                                .as_bytes(),
                            );
                            // Reschedule based on `now`, not `timer_scheduled_time`,
                            // intentionally skipping intermediate executions.
                            reschedule_timer(timers, task_id, now, *interval);
                            return true; // skip
                        }
                    }
                    // 3. Check serial timer is available
                    Task::RepeatedSerialBusy { interval } => {
                        reschedule_timer(timers, task_id, timer_scheduled_time, *interval);
                        return true; // skip
                    }
                    _ => (),
                }
                false // do not skip
            });
            if skip {
                return ControlFlow::Continue(());
            }
        }
        // This is the biggest hack in this code. If a callback was called explicitly, and trapped,
        // the rescheduling step wouldn't happen. The closest thing to a catch_unwind that's available
        // here is performing an inter-canister call to ourselves; traps will be caught at the call
        // boundary. This invokes a meaningful cycles cost, and should an alternative for catching traps
        // become available, this code should be rewritten.
        let env = Box::new(CallEnv {
            timer,
            method_handle: ic_cdk_executor::extend_current_method_context(),
        });
        const METHOD_NAME: &str = "<ic-cdk internal> timer_executor";
        // 4. Check canister has enough cycles to pay for the call
        let liquid_cycles = ic0::canister_liquid_cycle_balance128();
        let cost = ic0::cost_call(METHOD_NAME.len() as u64, 8);
        // --- no allocations between the liquid cycles check and call_perform
        if liquid_cycles < cost {
            ic0::debug_print(b"[ic-cdk-timers] unable to schedule timer: not enough liquid cycles");
            return ControlFlow::Break(Some(env.timer));
        }
        let env = Box::<CallEnv>::into_raw(env) as usize;
        // 5. Make self-call with the timer ID as argument
        // SAFETY:
        // - `timer_scope_callback` is intended as an entrypoint and therefore can be called as both
        //      reply and reject fn for ic0.call_new.
        // - `timer_scope_cleanup` is intended as an entrypoint and therefore can be called as
        //      cleanup fn for ic0.call_on_cleanup.
        // - `state_ptr` is a pointer created via Box::<CallEnv>::into_raw, and can therefore
        //      be passed as the userdata for `callback` and `cleanup`.
        // - if-and-only-if ic0.call_perform returns 0, exactly one of `timer_scope_callback` or
        //      `timer_scope_cleanup` receive ownership of `state_ptr`
        // - both functions deallocate `state_ptr`, and this enclosing function deallocates
        //      `state_ptr` if ic0.call_perform returns !=0, and therefore `state_ptr`'s ownership
        //      can be passed to FFI without leaking memory.
        unsafe {
            ic0::call_new(
                canister_self,
                METHOD_NAME,
                timer_scope_callback,
                env,
                timer_scope_callback,
                env,
            );
            ic0::call_on_cleanup(timer_scope_cleanup, env);
        }
        ic0::call_with_best_effort_response(300);
        ic0::call_data_append(task_id.data().as_ffi().to_be_bytes().as_ref());
        let errcode = ic0::call_perform();
        // ---allocations resumed
        if errcode != 0 {
            // SAFETY:
            // - We just created this from a Box<CallEnv>
            // - A nonzero error code from call_perform releases ownership back to us
            let env = unsafe { Box::from_raw(env as *mut CallEnv) };
            ic0::debug_print(
                format!(
                    "[ic-cdk-timers] canister_global_timer: \
                    call_perform failed with error code {errcode}"
                )
                .as_bytes(),
            );
            // If the attempted call failed, we will try to execute the timer again later.
            // This error most likely will recur if any more timers are scheduled this round.
            return ControlFlow::Break(Some(env.timer));
        } else {
            // 6: Add this call to the semaphores
            state::increment_all_calls();
            // If a repeated timer is successfully dispatched (irrespective of the timer's own success), reschedule it.
            TASKS.with_borrow_mut(|tasks| {
                let task = &mut tasks[task_id];
                task.increment_concurrent();
                // 7: Reschedule repeated timers
                if let Task::Repeated { interval, .. } | Task::RepeatedSerial { interval, .. } =
                    task
                {
                    reschedule_timer(timers, task_id, timer_scheduled_time, *interval);
                }
            })
        }
    }
    ControlFlow::Continue(())
    // Execution diverts to timer_executor.rs, then resumes in timer_scope_callback.
}

struct CallEnv {
    timer: Timer,
    method_handle: MethodHandle,
}

/// # Safety
///
/// This function must only be passed to the IC with a pointer from Box::<CallEnv>::into_raw as userdata.
unsafe extern "C" fn timer_scope_callback(env: usize) {
    // 8. Remove this call from the semaphores
    state::decrement_all_calls();
    // SAFETY: This function is only ever called by the IC, and we only ever pass a Box<CallEnv> as userdata.
    let CallEnv {
        timer,
        method_handle,
    } = *unsafe { Box::<CallEnv>::from_raw(env as *mut CallEnv) };
    ic_cdk_executor::in_callback_executor_context_for(method_handle, || {
        let task_id = timer.task;
        TASKS.with_borrow_mut(|tasks| {
            tasks.get_mut(task_id).map(|t| {
                t.decrement_concurrent();
            })
        });
        let reject_code = ic0::msg_reject_code();
        // 9. Handle the result of the timer execution; reschedule on transient error
        match reject_code {
            0 => {} // success
            2 | 6 => {
                // Double check that it exists - in case of SYS_TRANSIENT it may have completed.
                if TASKS.with_borrow(|tasks| tasks.contains_key(task_id)) {
                    // Try to execute the timer again later.
                    TIMERS.with_borrow_mut(|timers| timers.push(timer));
                    state::update_ic0_timer();
                }
                return;
            }
            x => {
                log_failure(x);
            }
        }
        // 10. Delete one-shot tasks
        TASKS.with_borrow_mut(|tasks| {
            if let Some(task) = tasks.get(task_id) {
                match task {
                    // duplicated on purpose - it must be removed in the function call, to access self by value;
                    // and it must be removed here, because it may have trapped and not actually been removed.
                    // Luckily slotmap ops are equivalent to simple vector indexing.
                    Task::Once(_) => {
                        tasks.remove(task_id);
                    }
                    Task::Repeated { .. } | Task::RepeatedSerial { .. } | Task::RepeatedSerialBusy { .. } => {}
                    Task::Invalid => {
                        unreachable!(
                            "[ic-cdk-timers] internal error: invalid task state in global timer await callback"
                        )
                    }
                }
            }
        });
    });
}

fn log_failure(code: u32) {
    let reject_data_size = ic0::msg_reject_msg_size();
    let mut reject_data = Vec::with_capacity(reject_data_size);
    ic0::msg_reject_msg_copy_uninit(&mut reject_data.spare_capacity_mut()[..reject_data_size], 0);
    // SAFETY: ic0.msg_arg_data_copy fully initializes the vector up to reject_data_size.
    unsafe {
        reject_data.set_len(reject_data_size);
    }
    ic0::debug_print(
        format!(
            "[ic-cdk-timers] timer failed (code {code}): {}",
            String::from_utf8_lossy(&reject_data)
        )
        .as_bytes(),
    )
}

/// # Safety
///
/// This function must only be passed to the IC with a pointer from Box::<CallEnv>::into_raw as userdata.
unsafe extern "C" fn timer_scope_cleanup(env: usize) {
    // SAFETY: This function is only ever called by the IC, and we only ever pass a Box<CallEnv> as userdata.
    unsafe {
        drop(Box::from_raw(env as *mut CallEnv));
    }
    ic0::debug_print(b"[ic-cdk-timers] internal error: trap in scope callback");
}
