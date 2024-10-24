pub use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types::{
    self as ic00, CanisterIdRecord, CanisterSettingsArgs, InstallCodeArgs, MasterPublicKeyId,
    Method, Payload,
};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
pub use ic_types::{
    canister_http::{
        CanisterHttpMethod, CanisterHttpRequestContext, CanisterHttpRequestId,
        CanisterHttpResponseMetadata,
    },
    crypto::{threshold_sig::ThresholdSigPublicKey, CryptoHash, CryptoHashOf},
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{CallbackId, HttpRequestError, MessageId},
    signature::BasicSignature,
    time::Time,
    CanisterId, CryptoHashOfState, Cycles, NumBytes, PrincipalId, SubnetId, UserId,
};
use std::time::Instant;

fn await_messages(
    env: &StateMachine,
    message_ids: &[MessageId],
) -> Vec<Result<WasmResult, UserError>> {
    let max_ticks = 100;
    let started_at = Instant::now();
    for _tick in 0..max_ticks {
        let statuses: Vec<_> = message_ids
            .iter()
            .map(|msg_id| env.ingress_status(msg_id))
            .collect();
        if statuses.iter().all(|status| match status {
            IngressStatus::Known {
                state: IngressState::Completed(_),
                ..
            } => true,
            IngressStatus::Known {
                state: IngressState::Failed(_),
                ..
            } => true,
            _ => false,
        }) {
            let results = statuses
                .into_iter()
                .map(|status| match status {
                    IngressStatus::Known {
                        state: IngressState::Completed(result),
                        ..
                    } => Ok(result),
                    IngressStatus::Known {
                        state: IngressState::Failed(error),
                        ..
                    } => Err(error),
                    _ => panic!("Unexpected ingress status"),
                })
                .collect();
            return results;
        }
        env.tick();
    }
    panic!(
        "Did not get answer to ingress after {} state machine ticks ({:?} elapsed)",
        max_ticks,
        started_at.elapsed()
    )
}

/*
$ bazel run //rs/execution_environment:load_test_bench
*/
fn main() {
    println!("hello, work!");

    let canisters_number = 2;

    let env = StateMachineBuilder::default().build();

    let settings: Option<CanisterSettingsArgs> = None;
    let ingress_ids: Vec<_> = (0..canisters_number)
        .map(|_| {
            env.send_ingress(
                PrincipalId::new_anonymous(),
                ic00::IC_00,
                ic00::Method::ProvisionalCreateCanisterWithCycles,
                ic00::ProvisionalCreateCanisterWithCyclesArgs {
                    amount: Some((u128::MAX / 2).into()),
                    settings: settings.clone(),
                    specified_id: None,
                    sender_canister_version: None,
                }
                .encode(),
            )
        })
        .collect();

    let results = await_messages(&env, &ingress_ids);

    println!("results: {:?}", results);
}
