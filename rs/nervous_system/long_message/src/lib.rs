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

async fn make_noop_call() {
    () = ic_cdk::call(ic_cdk::id(), "__long_message_noop", ())
        .await
        .unwrap();
}

fn is_message_over_threshold(message_threshold: u64) -> bool {
    let instructions_used = instruction_counter();
    // ic_cdk::println!("Instruction counter: {}", instructions_used);
    instructions_used >= message_threshold
}

fn is_call_context_over_threshold(call_context_threshold: u64) -> bool {
    let total_instructions_used = call_context_instruction_counter();
    total_instructions_used > call_context_threshold
}

/// Breaks the message into smaller parts if the number of instructions used
/// exceeds the given threshold.
/// The upper bound is used to determine the maximum number of instructions
/// that can be used in a single call context, split across any number of messages.
///
/// Note: Caller is responsible for validity of references across message bounds.  This could be
/// dangerous in places where global state is being referenced.
///
/// # Panics if the number of instructions used exceeds the given upper bound.
pub async fn break_message_if_over_instructions(message_threshold: u64, upper_bound: Option<u64>) {
    // first we check the upper bound to see if we should panic.
    if let Some(upper_bound) = upper_bound {
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

pub async fn run_chunked_task<R, C, T>(
    mut task: T,
    initial_value: C,
    message_threshold: u64,
    upper_bound: Option<u64>,
) -> R
where
    T: Task<C, R>,
{
    let mut continuation = Some(initial_value);

    while continuation.is_some() {
        continuation = task.next_chunk(continuation.unwrap(), || {
            is_message_over_threshold(message_threshold)
        });

        make_noop_call().await;

        if let Some(upper_bound) = upper_bound {
            let total_instructions_used = call_context_instruction_counter();

            if total_instructions_used > upper_bound {
                panic!(
                    "Canister call exceeded the limit of {} instructions in the call context.",
                    upper_bound
                );
            }
        }
    }

    task.result()
}

pub trait Task<C, R>: Sized {
    fn next_chunk(
        &mut self,
        continuation: C,
        is_message_over_soft_limit: impl Fn() -> bool,
    ) -> Option<C>;

    fn result(self) -> R;
}
