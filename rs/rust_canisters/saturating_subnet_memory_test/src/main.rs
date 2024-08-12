use candid::{candid_method, Decode, Encode};
use dfn_core::api::{call_bytes, Funds};
use downstream_calls_test::RequestsConfig;
use ic_cdk_macros::update;


const FAUST: &str = "Ich bin der Geist der stets verneint! Und das mit Recht; denn alles was entsteht \
ist werth daß es zu Grunde geht; Drum besser wär's daß nichts entstünde. So ist denn alles was ihr Sünde, \
Zerstörung, kurz das Böse nennt, Mein eigentliches Element."

/// Internal state of the canister. This holds a queue of `RequestConfig`, i.e. a canister ID to
/// which a request should be sent and a vector of payload num bytes.
///
/// Each time a request is sent to the canister at the front of the queue, the vector of payload
/// num bytes is decreased in length by 1 and queue is rotated to the left by 1. This way a request
/// is sent out to each receiving canister with a given payload num bytes in a round robin fashion.
thread_local! {
    static REQUEST_CONFIGS: std::cell::Cell<VecDeque<RequestConfig>>;
}

fn next() -> Option<(CanisterId, u32)> {
    let configs = REQUEST_CONFIGS.get_mut();

    while let Some(config) = configs.pop_front() {
        if let Some(num_bytes) = config.payload_num_bytes.pop() {
            let canister_id = config.canister_id;
            configs.push_back(config);
            return (canister_id, num_bytes);
        }
    }

    None
}


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
                let response = call_bytes(
                    canister_id,
                    "reply_or_defer",
                    &Encode!(&State {
                        actions: state.actions,
                        call_count: state.call_count + 1,
                        current_depth: state.current_depth + 1,
                        depth_total: state.depth_total + state.current_depth,
                    })
                    .unwrap(),
                    Funds::zero(),
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
