use ic_cdk::{
    api::{call_context_instruction_counter, instruction_counter},
    query,
};

#[query(hidden = true)]
fn __long_message_noop() {
    // This function is used to break the message into smaller parts
}

const B: u64 = 1_000_000_000;

pub const LIMIT_FOR_APP_SUBNETS: u64 = 18 * B;
pub const LIMIT_FOR_SYSTEM_SUBNETS: u64 = 45 * B;

/// Breaks the message into smaller parts if the number of instructions used
/// exceeds the given threshold.
/// The upper bound is used to determine the maximum number of instructions
/// that can be used in a single call context, split across any number of messages.
///
/// # Panics if the number of instructions used exceeds the given upper bound.
pub async fn break_message_if_over_instructions(message_threshold: u64, upper_bound: Option<u64>) {
    // first we check the upper bound to see if we should panic.
    if let Some(upper_bound) = upper_bound {
        let total_instructions_used = call_context_instruction_counter();

        if total_instructions_used > upper_bound {
            panic!(
                "Canister call exceeded the limit of {} instructions in the call context.",
                upper_bound
            );
        }
    }

    let instructions_used = instruction_counter();
    if instructions_used < message_threshold {
        return;
    }

    () = ic_cdk::call(ic_cdk::id(), "__long_message_noop", ())
        .await
        .unwrap();
}
