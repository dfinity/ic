use candid::CandidType;
use ic_cdk::{init, update};
use ic_nervous_system_long_message::{
    break_message_if_over_instructions, run_chunked_task, Continuation,
};
use serde::Deserialize;
use std::time::Duration;

struct Data {
    values: Vec<u64>,
}

static mut UNSAFE_DATA_FOR_JOB_RUNNER: Option<Data> = None;

#[init]
fn canister_init() {
    unsafe {
        UNSAFE_DATA_FOR_JOB_RUNNER = Some(Data {
            values: vec![17; 12],
        })
    };
    // println!("long_message_canister init!");
    ic_cdk_timers::set_timer(Duration::from_millis(1), || unsafe {
        // println!("Setting new values");
        let new_values = vec![18; 6];
        *UNSAFE_DATA_FOR_JOB_RUNNER
            .as_mut()
            .expect("data not initialized") = Data { values: new_values };
    });
}

#[derive(CandidType, Deserialize)]
struct BreakMessageParams {
    pub use_break: bool,
    pub message_threshold: u64,
    pub upper_bound: Option<u64>,
}

fn fib(n: u64) -> u64 {
    if n <= 1 {
        n
    } else {
        fib(n - 1) + fib(n - 2)
    }
}

#[update]
async fn test_next_message_if_over_instructions(params: BreakMessageParams) {
    // Just processing a message costs 30k instructions
    // each fib(17) costs about 80k instructions
    // so if we do that 10x, it's about 830k instructions.
    // The test setup for this canister allows for 500k instructions per message.

    let BreakMessageParams {
        use_break,
        message_threshold,
        upper_bound,
    } = params;

    // Doing anything costs about 30k instructions.
    for _x in 0..10 {
        // println!("Invocation number {}", x);
        // println!(
        //     "Instruction_counter: {}",
        //     ic_cdk::api::instruction_counter()
        // );
        // Fib(17) was benchmarked at about 80k instructions
        fib(17);
        if use_break {
            break_message_if_over_instructions(message_threshold, upper_bound).await;
        }
    }
}

#[derive(CandidType, Deserialize)]
struct ChunkedTaskParams {
    pub message_threshold: u64,
    pub upper_bound: Option<u64>,
}

#[update]
async fn test_run_chunked_task(params: ChunkedTaskParams) -> TaskResult {
    let initial_value = 0;

    let task = |continuation: Continuation<u64, u64, u64>,
                is_message_over_soft_limit: Box<dyn Fn() -> bool>|
     -> Continuation<u64, u64, u64> {
        let (mut index, mut sum) = match continuation {
            Continuation::Continue(index, sum) => (index, sum),
            Continuation::Done(_) => panic!("Continuation is done, we should not get this"),
        };
        // ic_cdk::println!("Continuing from index {}", index);
        while !is_message_over_soft_limit() {
            // println!("Processing index {}", index);
            let values = unsafe { &UNSAFE_DATA_FOR_JOB_RUNNER.as_ref().unwrap().values };
            if values.len() <= index as usize {
                return Continuation::Done(sum);
            }
            let n = values[index as usize];
            sum += fib(n);
            index += 1;
        }
        // println!("Breaking at index {}", index);
        Continuation::Continue(index, sum)
    };

    let result = run_chunked_task(
        task,
        Continuation::Continue(initial_value, 0),
        params.message_threshold,
        params.upper_bound,
    )
    .await;

    TaskResult { result }
}

/// This task demonstrates UNSAFE data handling, but in the task it
/// gets values in a way that is still safe.  
/// Generally you should get your data in another way.
// struct AddFibsTask<'a> {
//     data: &'a Data,
//     sum: u64,
// }
//
// impl<'a> Task<u64, u64> for AddFibsTask<'a> {
//     fn result(self) -> u64 {
//         self.sum
//     }
// }
//
#[derive(CandidType, Deserialize)]
struct TaskResult {
    pub result: u64,
}

fn main() {}
