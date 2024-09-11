use super::*;
use crate::canister_state::queues::{
    message_pool::MessagePool, tests::input_queue_type_from_local_canisters,
};
use assert_matches::assert_matches;
use ic_test_utilities_types::messages::RequestBuilder;
use InputQueueType::*;

#[test]
fn test_input_source() {
    let mut schedule = InputSchedule::default();

    assert_eq!(InputSource::default(), schedule.input_source());
    assert_eq!(InputSource::default(), schedule.next_input_source());

    assert_eq!(InputSource::Ingress, schedule.input_source());
    assert_eq!(InputSource::Ingress, schedule.next_input_source());

    assert_eq!(InputSource::RemoteSubnet, schedule.input_source());
    assert_eq!(InputSource::RemoteSubnet, schedule.next_input_source());

    assert_eq!(InputSchedule::default(), schedule);

    assert_eq!(InputSource::LocalSubnet, schedule.input_source());
    assert_eq!(InputSource::LocalSubnet, schedule.next_input_source());
}

#[test]
fn test_scheduling() {
    let local1 = CanisterId::from_u64(1);
    let local2 = CanisterId::from_u64(2);
    let remote1 = CanisterId::from_u64(1001);
    let remote2 = CanisterId::from_u64(1002);

    let mut schedule = InputSchedule::default();
    assert_schedule_eq((vec![], vec![]), &schedule);

    schedule.schedule(local1, LocalSubnet);
    assert_schedule_eq((vec![local1], vec![]), &schedule);

    schedule.schedule(remote1, RemoteSubnet);
    assert_schedule_eq((vec![local1], vec![remote1]), &schedule);

    schedule.schedule(local2, LocalSubnet);
    assert_schedule_eq((vec![local1, local2], vec![remote1]), &schedule);

    schedule.schedule(remote2, RemoteSubnet);
    assert_schedule_eq((vec![local1, local2], vec![remote1, remote2]), &schedule);

    schedule.reschedule(remote1, RemoteSubnet);
    assert_schedule_eq((vec![local1, local2], vec![remote2, remote1]), &schedule);

    assert_eq!(Some(&local1), schedule.peek(LocalSubnet));
    assert_eq!(Some(&remote2), schedule.peek(RemoteSubnet));

    assert_eq!(Some(local1), schedule.pop(LocalSubnet));
    assert_eq!(Some(&local2), schedule.peek(LocalSubnet));
    assert_schedule_eq((vec![local2], vec![remote2, remote1]), &schedule);

    assert_eq!(Some(local2), schedule.pop(LocalSubnet));
    assert_eq!(None, schedule.peek(LocalSubnet));
    assert_schedule_eq((vec![], vec![remote2, remote1]), &schedule);
    assert_eq!(None, schedule.pop(LocalSubnet));

    assert_eq!(Some(remote2), schedule.pop(RemoteSubnet));
    assert_eq!(Some(&remote1), schedule.peek(RemoteSubnet));
    assert_schedule_eq((vec![], vec![remote1]), &schedule);

    assert_eq!(Some(remote1), schedule.pop(RemoteSubnet));
    assert_eq!(None, schedule.peek(RemoteSubnet));
    assert_schedule_eq((vec![], vec![]), &schedule);
    assert_eq!(None, schedule.pop(RemoteSubnet));
}

fn test_schedule_again_impl(input_queue_type: InputQueueType) {
    let assert_schedule_for_type_eq = |expected: Vec<CanisterId>, schedule: &InputSchedule| {
        let expected = match input_queue_type {
            LocalSubnet => (expected, vec![]),
            RemoteSubnet => (vec![], expected),
        };
        assert_schedule_eq(expected, schedule);
    };

    let sender1 = CanisterId::from_u64(1);
    let sender2 = CanisterId::from_u64(2);

    let mut schedule = InputSchedule::default();
    assert_schedule_eq((vec![], vec![]), &schedule);

    schedule.schedule(sender1, input_queue_type);
    assert_schedule_for_type_eq(vec![sender1], &schedule);

    schedule.schedule(sender2, input_queue_type);
    assert_schedule_for_type_eq(vec![sender1, sender2], &schedule);

    // Scheduling the same sender again has no effect.
    schedule.schedule(sender2, input_queue_type);
    assert_schedule_for_type_eq(vec![sender1, sender2], &schedule);
    schedule.schedule(sender1, input_queue_type);
    assert_schedule_for_type_eq(vec![sender1, sender2], &schedule);

    // But popping the sender and scheduling it again does.
    assert_eq!(Some(sender1), schedule.pop(input_queue_type));
    assert_schedule_for_type_eq(vec![sender2], &schedule);
    schedule.schedule(sender1, input_queue_type);
    assert_schedule_for_type_eq(vec![sender2, sender1], &schedule);
}

#[test]
fn test_schedule_again() {
    test_schedule_again_impl(LocalSubnet);
    test_schedule_again_impl(RemoteSubnet);
}

/// Scheduling the same sender in the other queue has no effect.
#[test]
fn test_schedule_again_in_other_queue() {
    let sender = CanisterId::from_u64(1);

    let mut schedule = InputSchedule::default();
    assert_schedule_eq((vec![], vec![]), &schedule);

    schedule.schedule(sender, LocalSubnet);
    assert_schedule_eq((vec![sender], vec![]), &schedule);

    schedule.schedule(sender, RemoteSubnet);
    assert_schedule_eq((vec![sender], vec![]), &schedule);

    assert_eq!(Some(sender), schedule.pop(LocalSubnet));
    assert_schedule_eq((vec![], vec![]), &schedule);

    schedule.schedule(sender, RemoteSubnet);
    assert_schedule_eq((vec![], vec![sender]), &schedule);

    schedule.schedule(sender, LocalSubnet);
    assert_schedule_eq((vec![], vec![sender]), &schedule);

    assert_eq!(Some(sender), schedule.pop(RemoteSubnet));
    assert_schedule_eq((vec![], vec![]), &schedule);
}

fn test_reschedule_while_not_in_front_impl(input_queue_type: InputQueueType) {
    let sender1 = CanisterId::from_u64(1);
    let sender2 = CanisterId::from_u64(2);

    let mut schedule = InputSchedule::default();

    schedule.schedule(sender1, input_queue_type);
    schedule.schedule(sender2, input_queue_type);
    schedule.reschedule(sender2, input_queue_type);
}

#[test]
#[should_panic]
fn test_reschedule_while_not_in_front_local() {
    test_reschedule_while_not_in_front_impl(LocalSubnet);
}

#[test]
#[should_panic]
fn test_reschedule_while_not_in_front_remote() {
    test_reschedule_while_not_in_front_impl(RemoteSubnet);
}

fn test_reschedule_while_in_other_queue(input_queue_type: InputQueueType) {
    let sender = CanisterId::from_u64(1);

    let mut schedule = InputSchedule::default();

    schedule.schedule(sender, input_queue_type);
    // `sender` is enqueued in `input_queue_type`, so `reschedule()` will panic
    // because it expects `sender` to be in the other queue.
    let other_input_queue_type = match input_queue_type {
        LocalSubnet => RemoteSubnet,
        RemoteSubnet => LocalSubnet,
    };
    schedule.reschedule(sender, other_input_queue_type);
}

#[test]
#[should_panic]
fn test_reschedule_in_remote_while_in_local() {
    test_reschedule_while_in_other_queue(LocalSubnet);
}

#[test]
#[should_panic]
fn test_reschedule_in_local_while_in_remote() {
    test_reschedule_while_in_other_queue(RemoteSubnet);
}

#[test]
fn test_invariants() {
    // Generates input queues with the given sizes for the given canisters.
    fn input_queues_for_test(
        queue_sizes: Vec<(CanisterId, u8)>,
    ) -> Vec<(CanisterId, CanisterQueue)> {
        let mut pool = MessagePool::default();
        queue_sizes
            .into_iter()
            .map(|(canister_id, size)| {
                let mut queue = CanisterQueue::new(500);
                for _ in 0..size {
                    let id = pool.insert_inbound(RequestBuilder::default().build().into());
                    queue.push_request(id);
                }
                (canister_id, queue)
            })
            .collect()
    }

    // Calls `test_invariants{}` on the given schedule with the provided queues and
    // set of local canisters.
    fn test_invariants(
        schedule: &InputSchedule,
        queue_sizes: Vec<(CanisterId, u8)>,
        local_canisters: Vec<CanisterId>,
    ) -> Result<(), String> {
        schedule.test_invariants(
            input_queues_for_test(queue_sizes)
                .iter()
                .map(|(id, queue)| (id, queue)),
            &input_queue_type_from_local_canisters(local_canisters),
        )
    }

    let sender1 = CanisterId::from_u64(1);
    let sender2 = CanisterId::from_u64(2);
    let sender3 = CanisterId::from_u64(3);

    let mut schedule = InputSchedule::default();
    schedule.schedule(sender1, LocalSubnet);
    schedule.schedule(sender2, RemoteSubnet);
    assert_schedule_eq((vec![sender1], vec![sender2]), &schedule);

    // No queues.
    test_invariants(&schedule, vec![], vec![sender1]).unwrap();

    // Empty queues.
    test_invariants(&schedule, vec![(sender1, 0), (sender2, 0)], vec![sender1]).unwrap();

    // Non-empty queues.
    test_invariants(&schedule, vec![(sender1, 1), (sender2, 2)], vec![sender1]).unwrap();

    // All remote canisters.
    test_invariants(&schedule, vec![(sender1, 1), (sender2, 2)], vec![]).unwrap();

    // Local `sender2` enqueued in remote queue.
    assert_matches!(
        test_invariants(&schedule, vec![(sender1, 1), (sender2, 2)], vec![sender2]),
        Err(msg) if msg.contains("Local canister with non-empty input queue")
    );

    // Non-empty local `sender3` is not scheduled.
    assert_matches!(
        test_invariants(&schedule, vec![(sender3, 1)], vec![sender3]),
        Err(msg) if msg.contains("Local canister with non-empty input queue")
    );

    // Non-empty remote `sender3` is not scheduled.
    assert_matches!(
        test_invariants(&schedule, vec![(sender3, 1)], vec![]),
        Err(msg) if msg.contains("Remote canister with non-empty input queue")
    );

    // Duplicate canister in local schedule.
    let mut bad_schedule = schedule.clone();
    bad_schedule.local_sender_schedule.push_back(sender1);
    assert_matches!(
        test_invariants(&bad_schedule, vec![], vec![]),
        Err(msg) if msg.contains("Duplicate entries")
    );

    // Duplicate of local schedule canister in remote schedule.
    let mut bad_schedule = schedule.clone();
    bad_schedule.remote_sender_schedule.push_back(sender1);
    assert_matches!(
        test_invariants(&bad_schedule, vec![], vec![]),
        Err(msg) if msg.contains("Duplicate entries")
    );

    // Scheduled semder missing from `scheduled_senders`.
    let mut bad_schedule = schedule.clone();
    bad_schedule.local_sender_schedule.push_back(sender3);
    assert_matches!(
        test_invariants(&bad_schedule, vec![], vec![]),
        Err(msg) if msg.contains("Inconsistent input schedules")
    );

    // Extra sender in `scheduled_senders`.
    let mut bad_schedule = schedule.clone();
    bad_schedule.scheduled_senders.insert(sender3);
    assert_matches!(
        test_invariants(&bad_schedule, vec![], vec![]),
        Err(msg) if msg.contains("Inconsistent input schedules")
    );
}

fn assert_schedule_eq(
    (expected_local, expected_remote): (Vec<CanisterId>, Vec<CanisterId>),
    schedule: &InputSchedule,
) {
    assert_eq!(
        expected_local.iter().cloned().collect::<VecDeque<_>>(),
        schedule.local_sender_schedule
    );
    assert_eq!(
        expected_remote.iter().cloned().collect::<VecDeque<_>>(),
        schedule.remote_sender_schedule
    );
    assert_eq!(
        expected_local
            .iter()
            .chain(expected_remote.iter())
            .cloned()
            .collect::<BTreeSet<_>>(),
        schedule.scheduled_senders
    );
}
