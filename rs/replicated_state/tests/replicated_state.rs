use ic_base_types::{CanisterId, NumBytes, NumSeconds, PrincipalId, SubnetId};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::ENFORCE_MESSAGE_MEMORY_USAGE, replicated_state::ReplicatedStateMessageRouting,
    CanisterState, ReplicatedState, SchedulerState, StateError, SystemState,
};
use ic_test_utilities::types::{
    ids::user_test_id,
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{
    messages::{RequestOrResponse, MAX_RESPONSE_COUNT_BYTES},
    CountBytes, Cycles, QueueIndex,
};

const SUBNET_ID: SubnetId = SubnetId::new(PrincipalId::new(29, [0xfc; 29]));
const CANISTER_ID: CanisterId = CanisterId::from_u64(42);
const OTHER_CANISTER_ID: CanisterId = CanisterId::from_u64(13);

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

const MAX_CANISTER_MEMORY_SIZE: NumBytes = NumBytes::new(u64::MAX / 2);
const SUBNET_AVAILABLE_MEMORY: i64 = i64::MAX / 2;

fn replicated_state_test<F, R>(f: F) -> R
where
    F: FnOnce(ReplicatedState) -> R,
{
    let scheduler_state = SchedulerState::default();
    let system_state = SystemState::new_running(
        CANISTER_ID,
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let canister_state = CanisterState::new(system_state, None, scheduler_state);
    let mut state =
        ReplicatedState::new_rooted_at(SUBNET_ID, SubnetType::Application, "unused".into());
    state.put_canister_state(canister_state);

    f(state)
}

fn assert_total_memory_taken(queues_memory_usage: usize, state: &ReplicatedState) {
    if ENFORCE_MESSAGE_MEMORY_USAGE {
        assert_eq!(queues_memory_usage as u64, state.total_memory_taken().get());
    } else {
        // Expect zero memory used if we don't account for messages.
        assert_eq!(0, state.total_memory_taken().get());
    }
}

fn assert_subnet_available_memory(
    initial_available_memory: i64,
    queues_memory_usage: usize,
    actual: i64,
) {
    if ENFORCE_MESSAGE_MEMORY_USAGE {
        assert_eq!(
            initial_available_memory - queues_memory_usage as i64,
            actual
        );
    } else {
        // Expect all memory to be available if we don't account for messages.
        assert_eq!(initial_available_memory, actual);
    }
}

#[test]
fn total_memory_taken_by_canister_queues() {
    replicated_state_test(|mut state| {
        let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;

        // Zero memory used initially.
        assert_eq!(0, state.total_memory_taken().get());

        // Push a request into a canister input queue.
        state
            .push_input(
                QueueIndex::from(0),
                RequestBuilder::default()
                    .sender(OTHER_CANISTER_ID)
                    .receiver(CANISTER_ID)
                    .build()
                    .into(),
                MAX_CANISTER_MEMORY_SIZE,
                &mut subnet_available_memory,
            )
            .unwrap();

        // Reserved memory for one response.
        assert_total_memory_taken(MAX_RESPONSE_COUNT_BYTES, &state);
        assert_subnet_available_memory(
            SUBNET_AVAILABLE_MEMORY,
            MAX_RESPONSE_COUNT_BYTES,
            subnet_available_memory,
        );

        assert!(state
            .canister_state_mut(&CANISTER_ID)
            .unwrap()
            .pop_input()
            .is_some());

        // Unchanged memory usage.
        assert_total_memory_taken(MAX_RESPONSE_COUNT_BYTES, &state);

        // Push a response into the output queue.
        let response = ResponseBuilder::default()
            .respondent(CANISTER_ID)
            .originator(OTHER_CANISTER_ID)
            .build();
        state
            .canister_state_mut(&CANISTER_ID)
            .unwrap()
            .push_output_response(response.clone());

        // Memory used by response only.
        assert_total_memory_taken(response.count_bytes(), &state);
    })
}

#[test]
fn total_memory_taken_by_subnet_queues() {
    replicated_state_test(|mut state| {
        let mut subnet_available_memory = SUBNET_AVAILABLE_MEMORY;

        // Zero memory used initially.
        assert_eq!(0, state.total_memory_taken().get());

        // Push a request into the subnet input queues. Should ignore the
        // `max_canister_memory_size` argument.
        state
            .push_input(
                QueueIndex::from(0),
                RequestBuilder::default()
                    .sender(CANISTER_ID)
                    .receiver(SUBNET_ID.into())
                    .build()
                    .into(),
                0.into(),
                &mut subnet_available_memory,
            )
            .unwrap();

        // Reserved memory for one response.
        assert_total_memory_taken(MAX_RESPONSE_COUNT_BYTES, &state);
        assert_subnet_available_memory(
            SUBNET_AVAILABLE_MEMORY,
            MAX_RESPONSE_COUNT_BYTES,
            subnet_available_memory,
        );

        assert!(state.pop_subnet_input().is_some());

        // Unchanged memory usage.
        assert_total_memory_taken(MAX_RESPONSE_COUNT_BYTES, &state);

        // Push a response into the subnet output queues.
        let response = ResponseBuilder::default()
            .respondent(SUBNET_ID.into())
            .originator(CANISTER_ID)
            .build();
        state.push_subnet_output_response(response.clone());

        // Memory used by response only.
        assert_total_memory_taken(response.count_bytes(), &state);
    })
}

#[test]
fn total_memory_taken_by_stream_responses() {
    replicated_state_test(|mut state| {
        // Zero memory used initially.
        assert_eq!(0, state.total_memory_taken().get());

        // Push a request and a response into a stream.
        let mut streams = state.take_streams();
        streams.push(
            SUBNET_ID,
            RequestBuilder::default()
                .sender(CANISTER_ID)
                .receiver(OTHER_CANISTER_ID)
                .build()
                .into(),
        );
        let response: RequestOrResponse = ResponseBuilder::default()
            .respondent(CANISTER_ID)
            .originator(OTHER_CANISTER_ID)
            .build()
            .into();
        streams.push(SUBNET_ID, response.clone());
        state.put_streams(streams);

        // Memory only used by response, not request.
        assert_total_memory_taken(response.count_bytes(), &state);
    })
}

#[test]
fn push_subnet_queues_input_respects_subnet_available_memory() {
    replicated_state_test(|mut state| {
        let initial_available_memory = MAX_RESPONSE_COUNT_BYTES as i64;
        let mut subnet_available_memory = initial_available_memory;

        // Zero memory used initially.
        assert_eq!(0, state.total_memory_taken().get());

        // Push a request into the subnet input queues. Should ignore the
        // `max_canister_memory_size` argument.
        state
            .push_input(
                QueueIndex::from(0),
                RequestBuilder::default()
                    .sender(OTHER_CANISTER_ID)
                    .receiver(SUBNET_ID.into())
                    .build()
                    .into(),
                0.into(),
                &mut subnet_available_memory,
            )
            .unwrap();

        // Reserved memory for one response.
        assert_total_memory_taken(MAX_RESPONSE_COUNT_BYTES, &state);
        assert_subnet_available_memory(
            initial_available_memory,
            MAX_RESPONSE_COUNT_BYTES,
            subnet_available_memory,
        );

        // Push a second request into the subnet input queues.
        let request: RequestOrResponse = RequestBuilder::default()
            .sender(CANISTER_ID)
            .receiver(SUBNET_ID.into())
            .build()
            .into();
        let res = state.push_input(
            QueueIndex::from(0),
            request.clone(),
            0.into(),
            &mut subnet_available_memory,
        );

        if ENFORCE_MESSAGE_MEMORY_USAGE {
            // No more memory for a second request.
            assert_eq!(
                Err((
                    StateError::OutOfMemory {
                        requested: (MAX_RESPONSE_COUNT_BYTES as u64).into(),
                        available: 0.into()
                    },
                    request
                )),
                res
            );

            // Unchanged memory usage.
            assert_eq!(
                MAX_RESPONSE_COUNT_BYTES as u64,
                state.total_memory_taken().get()
            );
            assert_eq!(0, subnet_available_memory);
        } else {
            // Inserting a second request succeeds if we don't account for message memory
            // usage.
            assert!(res.is_ok());
            // No memory taken, subnet available memory unchanged.
            assert_eq!(0, state.total_memory_taken().get());
            assert_eq!(initial_available_memory, subnet_available_memory);
        }
    })
}
