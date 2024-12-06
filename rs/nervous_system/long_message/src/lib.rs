#[cfg(target_arch = "wasm32")]
use ic_cdk::api::{call_context_instruction_counter, instruction_counter};
use ic_cdk::query;

#[cfg(not(target_arch = "wasm32"))]
use ic_nervous_system_temporary::Temporary;
#[cfg(not(target_arch = "wasm32"))]
use std::cell::{Cell, RefCell};

#[query(hidden = true)]
fn __long_message_noop() {
    // This function is used to break the message into smaller parts
}

#[cfg(not(target_arch = "wasm32"))]
thread_local! {
    static TEST_THRESHOLD_CALL_COUNTER: RefCell<u64> = const { RefCell::new(0) };
    static TEST_CALL_CONTEXT_OVER_LIMIT: Cell<bool> = const { Cell::new(false) };
}

#[allow(dead_code)]
#[cfg(not(target_arch = "wasm32"))]
pub fn in_test_temporarily_set_call_context_over_threshold() -> Temporary {
    Temporary::new(&TEST_CALL_CONTEXT_OVER_LIMIT, true)
}

/// Returns true if call context is over the threshold provided.
/// In non-wasm32 environments, this can be set to true with
/// `in_test_temporarily_set_call_context_over_threshold`.
#[cfg(not(target_arch = "wasm32"))]
fn is_call_context_over_threshold(_call_context_threshold: u64) -> bool {
    TEST_CALL_CONTEXT_OVER_LIMIT.with(|c| c.get())
}

/// Returns true if call context is over the threshold provided.
/// In wasm32 environments, we check the call_context_instruction_counter to see if we are over the threshold.
/// Note, this threshold is not for each individual message, but for all the messages executed
/// in this call context.  
#[cfg(target_arch = "wasm32")]
fn is_call_context_over_threshold(call_context_threshold: u64) -> bool {
    let total_instructions_used = call_context_instruction_counter();
    total_instructions_used > call_context_threshold
}

/// In non-wasm environments, no call can be made, so this function does nothing in test environments.
#[cfg(not(target_arch = "wasm32"))]
async fn make_noop_call() {}

/// Makes a call to a no-op function defined in this library.
#[cfg(target_arch = "wasm32")]
async fn make_noop_call() {
    () = ic_cdk::call(ic_cdk::id(), "__long_message_noop", ())
        .await
        .unwrap();
}

/// In non-wasm environments, this alternates returning true or false every other time it's called.
#[cfg(not(target_arch = "wasm32"))]
pub fn is_message_over_threshold(_message_threshold: u64) -> bool {
    TEST_THRESHOLD_CALL_COUNTER.with(|c| {
        *c.borrow_mut() += 1;
        *c.borrow() % 2 == 0
    })
}

/// Returns true if the message is over the specified instruction threshold
#[cfg(target_arch = "wasm32")]
pub fn is_message_over_threshold(instructions_threshold: u64) -> bool {
    let instructions_used = instruction_counter();
    // ic_cdk::println!("Instruction counter: {}", instructions_used);
    instructions_used >= instructions_threshold
}

/// Breaks the message into smaller parts if the number of instructions used
/// exceeds the given threshold.
/// The upper bound is used to determine the maximum number of instructions
/// that can be used in a single call context, split across any number of messages.
///
/// Note: Caller is responsible for validity of references across message bounds.  This could be
/// dangerous in places where global state is being referenced.
///
/// # Panics if the number of instructions used exceeds the given panic threshold.
pub async fn noop_self_call_if_over_instructions(
    message_threshold: u64,
    panic_threshold: Option<u64>,
) {
    // first we check the upper bound to see if we should panic.
    if let Some(upper_bound) = panic_threshold {
        if is_call_context_over_threshold(upper_bound) {
            panic!(
                "Canister call exceeded the limit of {} instructions in the call context.",
                upper_bound
            );
        }
    }

    if is_message_over_threshold(message_threshold) {
        make_noop_call().await;
    }
}
