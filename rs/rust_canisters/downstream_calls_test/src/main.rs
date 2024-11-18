use candid::{candid_method, Decode, Encode};
use downstream_calls_test::{CallOrResponse, State};
use ic_cdk::api::call::call_raw;
use ic_cdk_macros::update;

fn main() {}

/// Replies to or defers to another canister a list of actions (call or response commands),
/// along with counters keeping track of:
///  - The current call depth in the call tree.
///  - The total number of calls made.
///  - The sum of call tree depths at which these calls were made.
///
/// At each step, the first command in the actions list is extracted and executed. Therefore
/// the actions list becomes shorter at each step and traverses the call tree that it's elements
/// describe.
///
/// Once the list has exhausted all commands anywhere in the call tree, response commands are
/// executed until the tree is concluded and a response to the initiating ingress message is
/// formed.
///
/// The tree may also be concluded by sufficiently many response commands in a sequence in the
/// action list itself (even if the list is not empty at the time of conclusion).
///
/// Any action list will produce a finite call tree, provided the canister IDs it contains
/// correspond to running 'downstream-call-test-canisters'.
///
/// See `test_linear_sequence_call_tree_depth` and `test_multiple_branches_call_tree_depth` in
/// 'rs/messaging/tests/call_tree_tests.rs' for examples on how to use this canister.
#[candid_method(update)]
#[update]
async fn reply_or_defer(mut state: State) -> State {
    loop {
        match state.actions.pop_front() {
            Some(CallOrResponse::Call(canister_id)) => {
                let response = call_raw(
                    canister_id.into(),
                    "reply_or_defer",
                    Encode!(&State {
                        actions: state.actions,
                        call_count: state.call_count + 1,
                        current_depth: state.current_depth + 1,
                        depth_total: state.depth_total + state.current_depth,
                    })
                    .unwrap(),
                    0,
                )
                .await
                .expect("calling other canister failed");

                state = Decode!(&response, State).expect("decoding response failed");
            }
            Some(CallOrResponse::Response) | None => {
                return State {
                    actions: state.actions,
                    call_count: state.call_count,
                    current_depth: state.current_depth.saturating_sub(1),
                    depth_total: state.depth_total,
                }
            }
        }
    }
}
