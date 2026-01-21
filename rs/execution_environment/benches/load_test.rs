use ic_error_types::UserError;
use ic_management_canister_types::{self as ic00, CanisterIdRecord, Payload};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities_execution_environment::get_reply;
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::MessageId,
    PrincipalId,
};
use std::time::Instant;

const MAX_TICKS: usize = 100;

fn get_result(status: IngressStatus) -> Option<Result<WasmResult, UserError>> {
    match status {
        IngressStatus::Known {
            state: IngressState::Completed(result),
            ..
        } => Some(Ok(result)),
        IngressStatus::Known {
            state: IngressState::Failed(error),
            ..
        } => Some(Err(error)),
        _ => None,
    }
}

fn await_ingress_responses(
    env: &StateMachine,
    message_ids: &[MessageId],
) -> Vec<Result<WasmResult, UserError>> {
    let start_time = Instant::now();

    for _ in 0..MAX_TICKS {
        let results: Vec<_> = message_ids
            .iter()
            .filter_map(|msg_id| get_result(env.ingress_status(msg_id)))
            .collect();

        if results.len() == message_ids.len() {
            return results;
        }

        env.tick();
    }

    panic!(
        "Failed to receive ingress responses within {} ticks ({:?} elapsed)",
        MAX_TICKS,
        start_time.elapsed()
    );
}

fn main() {
    println!("Starting the canister creation process...");

    const CANISTERS_TO_CREATE: usize = 1_000;
    let env = StateMachineBuilder::default().build();

    let start = std::time::Instant::now();
    let message_ids: Vec<_> = (0..CANISTERS_TO_CREATE)
        .map(|_| {
            env.send_ingress(
                PrincipalId::new_anonymous(),
                ic00::IC_00,
                ic00::Method::ProvisionalCreateCanisterWithCycles,
                ic00::ProvisionalCreateCanisterWithCyclesArgs::new(Some(u128::MAX / 2), None)
                    .encode(),
            )
        })
        .collect();
    println!(
        "Sent {} canister creation messages in {:.3} s",
        CANISTERS_TO_CREATE,
        start.elapsed().as_secs_f64()
    );

    let start = std::time::Instant::now();
    let results = await_ingress_responses(&env, &message_ids);
    println!(
        "Received {} canister creation responses in {:.3} s",
        CANISTERS_TO_CREATE,
        start.elapsed().as_secs_f64()
    );

    let replies: Vec<_> = results.into_iter().map(get_reply).collect();
    let canister_ids: Vec<_> = replies
        .iter()
        .map(|bytes| {
            CanisterIdRecord::decode(&bytes[..])
                .expect("failed to decode canister ID record")
                .get_canister_id()
        })
        .collect();

    println!("Created {} canisters", canister_ids.len());
}
