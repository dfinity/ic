use ic_base_types::{NumBytes, NumSeconds};
use ic_interfaces::messages::CanisterInputMessage;
use ic_replicated_state::{
    canister_state::{ENFORCE_MESSAGE_MEMORY_USAGE, QUEUE_INDEX_NONE},
    testing::SystemStateTesting,
    SystemState,
};
use ic_test_utilities::types::{
    ids::{canister_test_id, user_test_id},
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{freeze_threshold_cycles, messages::RequestOrResponse, Cycles, QueueIndex};

const CANISTER_AVAILABLE_MEMORY: i64 = 4 << 30;
const SUBNET_AVAILABLE_MEMORY: i64 = 300 << 30;

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
        .queues_mut()
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

#[test]
fn induct_messages_to_self_in_running_status_works() {
    let canister_id = canister_test_id(1);
    let mut system_state = SystemState::new_running(
        canister_id,
        user_test_id(1).get(),
        Cycles::new(5_000_000_000_000),
        NumSeconds::new(0),
    );
    let request = RequestBuilder::default()
        .sender(canister_id)
        .receiver(canister_id)
        .build();
    system_state
        .queues_mut()
        .push_output_request(request)
        .unwrap();
    system_state.induct_messages_to_self(
        CANISTER_AVAILABLE_MEMORY,
        &mut SUBNET_AVAILABLE_MEMORY.clone(),
    );
    assert!(system_state.has_input());
    assert!(!system_state.queues().has_output());
}

#[test]
fn induct_messages_to_self_in_stopped_status_does_not_work() {
    let canister_id = canister_test_id(1);
    let mut system_state = SystemState::new_stopped(
        canister_id,
        user_test_id(1).get(),
        Cycles::new(5_000_000_000_000),
        NumSeconds::new(0),
    );
    let request = RequestBuilder::default()
        .sender(canister_id)
        .receiver(canister_id)
        .build();
    system_state
        .queues_mut()
        .push_output_request(request)
        .unwrap();
    system_state.induct_messages_to_self(
        CANISTER_AVAILABLE_MEMORY,
        &mut SUBNET_AVAILABLE_MEMORY.clone(),
    );
    assert!(!system_state.has_input());
    assert!(system_state.queues().has_output());
}

#[test]
fn induct_messages_to_self_in_stopping_status_does_not_work() {
    let canister_id = canister_test_id(1);
    let mut system_state = SystemState::new_stopping(
        canister_id,
        user_test_id(1).get(),
        Cycles::new(5_000_000_000_000),
        NumSeconds::new(0),
    );
    let request = RequestBuilder::default()
        .sender(canister_id)
        .receiver(canister_id)
        .build();
    system_state
        .queues_mut()
        .push_output_request(request)
        .unwrap();
    system_state.induct_messages_to_self(
        CANISTER_AVAILABLE_MEMORY,
        &mut SUBNET_AVAILABLE_MEMORY.clone(),
    );
    assert!(!system_state.has_input());
    assert!(system_state.queues().has_output());
}

#[test]
fn induct_messages_to_self_respects_canister_memory_limit() {
    let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;
    induct_messages_to_self_respects_memory_limit_impl(0, &mut subnet_available_memory);
    assert_eq!(SUBNET_AVAILABLE_MEMORY, subnet_available_memory);
}

#[test]
fn induct_messages_to_self_respects_subnet_memory_limit() {
    let mut subnet_available_memory = 0;
    induct_messages_to_self_respects_memory_limit_impl(
        CANISTER_AVAILABLE_MEMORY,
        &mut subnet_available_memory,
    );
    assert_eq!(0, subnet_available_memory);
}

fn induct_messages_to_self_respects_memory_limit_impl(
    canister_available_memory: i64,
    subnet_available_memory: &mut i64,
) {
    let canister_id = canister_test_id(1);

    // Request and response to self.
    let request = RequestBuilder::default()
        .sender(canister_id)
        .receiver(canister_id)
        .build();
    let response = ResponseBuilder::default()
        .respondent(canister_id)
        .originator(canister_id)
        .build();

    // A system state with a reservation for an outgoing response.
    let mut system_state = SystemState::new_running(
        canister_id,
        user_test_id(1).get(),
        Cycles::new(5_000_000_000_000),
        NumSeconds::new(0),
    );
    system_state
        .queues_mut()
        .push_input(QUEUE_INDEX_NONE, request.clone().into())
        .unwrap();
    system_state.queues_mut().pop_input().unwrap();

    // Pushing an outgoing response will release `MAX_RESPONSE_COUNT_BYTES`.
    system_state
        .queues_mut()
        .push_output_response(response.clone());
    // So there should be memory for this request.
    system_state
        .queues_mut()
        .push_output_request(request.clone())
        .unwrap();
    // But not for this one.
    system_state
        .queues_mut()
        .push_output_request(request.clone())
        .unwrap();

    system_state.induct_messages_to_self(canister_available_memory, subnet_available_memory);

    // Expect the response and first request to have been inducted.
    assert_eq!(
        Some(CanisterInputMessage::Response(response)),
        system_state.pop_input()
    );
    assert_eq!(
        Some(CanisterInputMessage::Request(request.clone())),
        system_state.pop_input()
    );

    if ENFORCE_MESSAGE_MEMORY_USAGE {
        assert_eq!(None, system_state.pop_input());

        // Expect the second request to still be in the output queue.
        assert_eq!(
            vec![RequestOrResponse::Request(request)],
            system_state
                .output_into_iter(canister_id)
                .map(|(_, _, msg)| msg)
                .collect::<Vec<_>>()
        );
    } else {
        assert_eq!(
            Some(CanisterInputMessage::Request(request)),
            system_state.pop_input()
        );
        assert_eq!(None, system_state.pop_input());

        // Expect the output queue to be empty.
        assert!(!system_state.queues().has_output());
    }
}
