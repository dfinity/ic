use ic_base_types::{NumBytes, NumSeconds};
use ic_replicated_state::SystemState;
use ic_test_utilities::types::{
    ids::{canister_test_id, user_test_id},
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{freeze_threshold_cycles, messages::RequestOrResponse, Cycles, QueueIndex};

#[test]
fn correct_charging_target_canister_for_a_response() {
    let freeze_threshold = NumSeconds::new(30 * 24 * 60 * 60);
    let initial_cycles = freeze_threshold_cycles(
        freeze_threshold,
        Cycles::from(2_000_000),
        NumBytes::from(4 << 30),
    ) + Cycles::new(5_000_000_000_000);
    let mut system_state = SystemState::new_running(
        canister_test_id(0),
        user_test_id(1).get(),
        initial_cycles,
        freeze_threshold,
    );
    let initial_cycles_balance = system_state.cycles_balance;

    let request = RequestOrResponse::Request(
        RequestBuilder::default()
            .sender(canister_test_id(1))
            .receiver(canister_test_id(0))
            .build(),
    );

    // Enqueue the Request.
    system_state
        .push_input(QueueIndex::from(0), request)
        .unwrap();

    // Assume it was processed and enqueue a Response.
    let response = ResponseBuilder::default()
        .respondent(canister_test_id(0))
        .originator(canister_test_id(1))
        .build();

    system_state.push_output_response(response);

    // Target canister should not be charged for receiving the request or sending
    // the response
    assert_eq!(initial_cycles_balance, system_state.cycles_balance);
}
