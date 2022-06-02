use ic_base_types::{NumBytes, NumSeconds};
use ic_interfaces::messages::CanisterInputMessage;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::{DEFAULT_QUEUE_CAPACITY, QUEUE_INDEX_NONE},
    testing::{CanisterQueuesTesting, SystemStateTesting},
    InputQueueType, SystemState,
};
use ic_test_utilities::types::{
    ids::{canister_test_id, user_test_id},
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{
    messages::{RequestOrResponse, MAX_RESPONSE_COUNT_BYTES},
    Cycles, QueueIndex,
};

const CANISTER_AVAILABLE_MEMORY: i64 = 4 << 30;
const SUBNET_AVAILABLE_MEMORY: i64 = 300 << 30;

/// Figure out how many cycles a canister should have so that it can support the
/// given amount of storage for the given amount of time, given the storage fee.
fn mock_freeze_threshold_cycles(
    freeze_threshold: NumSeconds,
    gib_storage_per_second_fee: Cycles,
    expected_canister_size: NumBytes,
) -> Cycles {
    let one_gib = 1024 * 1024 * 1024;
    Cycles::from(
        expected_canister_size.get() as u128
            * gib_storage_per_second_fee.get()
            * freeze_threshold.get() as u128
            / one_gib,
    )
}

#[test]
fn correct_charging_target_canister_for_a_response() {
    let freeze_threshold = NumSeconds::new(30 * 24 * 60 * 60);
    let initial_cycles = mock_freeze_threshold_cycles(
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
    let initial_cycles_balance = system_state.balance();

    let request = RequestOrResponse::Request(
        RequestBuilder::default()
            .sender(canister_test_id(1))
            .receiver(canister_test_id(0))
            .build(),
    );

    // Enqueue the Request.
    system_state
        .queues_mut()
        .push_input(QueueIndex::from(0), request, InputQueueType::RemoteSubnet)
        .unwrap();

    // Assume it was processed and enqueue a Response.
    let response = ResponseBuilder::default()
        .respondent(canister_test_id(0))
        .originator(canister_test_id(1))
        .build();

    system_state.push_output_response(response);

    // Target canister should not be charged for receiving the request or sending
    // the response
    assert_eq!(initial_cycles_balance, system_state.balance());
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
        SubnetType::Application,
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
        SubnetType::Application,
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
        SubnetType::Application,
    );
    assert!(!system_state.has_input());
    assert!(system_state.queues().has_output());
}

#[test]
fn induct_messages_to_self_respects_canister_memory_limit() {
    let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;
    induct_messages_to_self_memory_limit_test_impl(
        0,
        &mut subnet_available_memory,
        SubnetType::Application,
        true,
    );
    assert_eq!(SUBNET_AVAILABLE_MEMORY, subnet_available_memory);
}

#[test]
fn induct_messages_to_self_respects_subnet_memory_limit() {
    let mut subnet_available_memory = 0;
    induct_messages_to_self_memory_limit_test_impl(
        CANISTER_AVAILABLE_MEMORY,
        &mut subnet_available_memory,
        SubnetType::Application,
        true,
    );
    assert_eq!(0, subnet_available_memory);
}

#[test]
fn system_subnet_induct_messages_to_self_ignores_canister_memory_limit() {
    let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;
    let mut expected_subnet_available_memory = subnet_available_memory;
    induct_messages_to_self_memory_limit_test_impl(
        0,
        &mut subnet_available_memory,
        SubnetType::System,
        false,
    );
    expected_subnet_available_memory -= MAX_RESPONSE_COUNT_BYTES as i64;
    assert_eq!(expected_subnet_available_memory, subnet_available_memory);
}

#[test]
fn system_subnet_induct_messages_to_self_ignores_subnet_memory_limit() {
    let mut subnet_available_memory = 0;
    let mut expected_subnet_available_memory = subnet_available_memory;
    induct_messages_to_self_memory_limit_test_impl(
        CANISTER_AVAILABLE_MEMORY,
        &mut subnet_available_memory,
        SubnetType::System,
        false,
    );
    expected_subnet_available_memory -= MAX_RESPONSE_COUNT_BYTES as i64;
    assert_eq!(expected_subnet_available_memory, subnet_available_memory);
}

fn induct_messages_to_self_memory_limit_test_impl(
    canister_available_memory: i64,
    subnet_available_memory: &mut i64,
    own_subnet_type: SubnetType,
    should_enforce_limit: bool,
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
        .push_input(
            QUEUE_INDEX_NONE,
            request.clone().into(),
            InputQueueType::RemoteSubnet,
        )
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

    system_state.induct_messages_to_self(
        canister_available_memory,
        subnet_available_memory,
        own_subnet_type,
    );

    // Expect the response and first request to have been inducted.
    assert_eq!(
        Some(CanisterInputMessage::Response(response)),
        system_state.queues_mut().pop_input()
    );
    assert_eq!(
        Some(CanisterInputMessage::Request(request.clone())),
        system_state.queues_mut().pop_input()
    );

    if should_enforce_limit {
        assert_eq!(None, system_state.queues_mut().pop_input());

        // Expect the second request to still be in the output queue.
        assert_eq!(
            vec![RequestOrResponse::Request(request)],
            vec![system_state.output_into_iter(canister_id).next().unwrap().2]
        );
    } else {
        assert_eq!(
            Some(CanisterInputMessage::Request(request)),
            system_state.queues_mut().pop_input()
        );
        assert_eq!(None, system_state.queues_mut().pop_input());

        // Expect the output queue to be empty.
        assert!(!system_state.queues().has_output());
    }
}

#[test]
fn induct_messages_to_self_full_queue() {
    let canister_id = canister_test_id(1);
    let mut system_state = SystemState::new_running(
        canister_id,
        user_test_id(1).get(),
        Cycles::new(5_000_000_000_000),
        NumSeconds::new(0),
    );

    // Request to self.
    let request = RequestBuilder::default()
        .sender(canister_id)
        .receiver(canister_id)
        .build();

    // Push`DEFAULT_QUEUE_CAPACITY - 1` requests.
    for _ in 0..DEFAULT_QUEUE_CAPACITY - 1 {
        system_state
            .queues_mut()
            .push_output_request(request.clone())
            .unwrap();
    }

    system_state.induct_messages_to_self(
        CANISTER_AVAILABLE_MEMORY,
        &mut SUBNET_AVAILABLE_MEMORY.clone(),
        SubnetType::Application,
    );

    // Expect exactly one request to have been inducted before the queue filled up.
    assert_eq!(
        Some(CanisterInputMessage::Request(request)),
        system_state.pop_input()
    );
    assert_eq!(None, system_state.pop_input());

    // All other requests should still be in the output queue.
    assert_eq!(
        DEFAULT_QUEUE_CAPACITY - 2,
        system_state.queues().output_message_count()
    );
}
