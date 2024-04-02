use super::*;
use core::fmt::Debug;
use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
use ic_types::messages::Payload;
use maplit::btreeset;
use std::collections::{BTreeSet, VecDeque};
use std::time::Duration;

#[test]
fn test_insert() {
    let mut pool = MessagePool::default();

    // Insert one message of each kind / class / context.
    let id1 = pool.insert_inbound(request(NO_DEADLINE).into());
    assert!(!id1.is_outbound());
    assert!(!id1.is_response());
    let id2 = pool.insert_inbound(request(time(20)).into());
    assert!(!id2.is_outbound());
    assert!(!id2.is_response());
    let id3 = pool.insert_inbound(response(NO_DEADLINE).into());
    assert!(!id3.is_outbound());
    assert!(id3.is_response());
    let id4 = pool.insert_inbound(response(time(40)).into());
    assert!(!id4.is_outbound());
    assert!(id4.is_response());
    let id5 = pool.insert_outbound_request(request(NO_DEADLINE).into(), time(50).into());
    assert!(id5.is_outbound());
    assert!(!id5.is_response());
    let id6 = pool.insert_outbound_request(request(time(60)).into(), time(65).into());
    assert!(id6.is_outbound());
    assert!(!id6.is_response());
    let id7 = pool.insert_outbound_response(response(NO_DEADLINE).into());
    assert!(id7.is_outbound());
    assert!(id7.is_response());
    let id8 = pool.insert_outbound_response(response(time(80)).into());
    assert!(id8.is_outbound());
    assert!(id8.is_response());

    assert_eq!(8, pool.len());

    // Of the inbound messages, only the best-effort request should be in the
    // deadline queue. Of the outbound messages, only the guaranteed response should
    // not be in the deadline queue.
    assert_exact_queue_contents(
        vec![
            (Reverse(time(20)), id2),
            (Reverse(time(60)), id6),
            (Reverse(time(80)), id8),
            (Reverse(time(50 + REQUEST_LIFETIME.as_secs() as u32)), id5),
        ],
        &pool.deadline_queue,
    );

    // All best-effort messages should be in the load shedding queue.
    //
    // We don't want to predict message sizes, so we only test which messages are in
    // the deadline queue.
    assert_exact_messages_in_queue(btreeset! {id2, id4, id6, id8}, &pool.size_queue);
}

#[test]
fn test_insert_outbound_request_deadline_rounding() {
    let mut pool = MessagePool::default();

    // Sanity check: REQUEST_LIFETIME is a whole number of seconds.
    assert_eq!(
        REQUEST_LIFETIME,
        Duration::from_secs(REQUEST_LIFETIME.as_secs())
    );

    // Insert an outbound request for a guaranteed response call (i.e. no deadline)
    // at a timestamp that is not a round number of seconds.
    let current_time = Time::from_nanos_since_unix_epoch(13_500_000_000);
    // Sanity check that the above is actually 13+ seconds.
    assert_eq!(
        CoarseTime::from_secs_since_unix_epoch(13),
        CoarseTime::floor(current_time)
    );
    let expected_deadline =
        CoarseTime::from_secs_since_unix_epoch(13 + REQUEST_LIFETIME.as_secs() as u32);

    pool.insert_outbound_request(request(NO_DEADLINE).into(), current_time);

    assert_eq!(expected_deadline, pool.deadline_queue.peek().unwrap().0 .0);
}

#[test]
fn test_replace_inbound_timeout_response() {
    let mut pool = MessagePool::default();

    // Reserve a message ID for a timeout response.
    let placeholder = pool.insert_inbound_timeout_response();
    let id = placeholder.id();
    assert!(!id.is_outbound());
    assert!(id.is_response());
    assert_eq!(0, pool.len());
    assert_eq!(None, pool.get_response(id));

    // Replace the placeholder with a best-effort response.
    let msg: RequestOrResponse = response(time(5)).into();
    pool.replace_inbound_timeout_response(placeholder, msg.clone());
    assert_eq!(1, pool.len());
    assert_eq!(Some(&response(time(5)).into()), pool.get_response(id));

    // Response is in load shedding queue, but not in deadline queue.
    assert!(pool.expire_messages(time(u32::MAX).into()).is_empty());
    assert_eq!(Some((id, msg)), pool.shed_largest_message());
    assert_eq!(0, pool.len());
}

#[test]
#[should_panic(expected = "Message must be a best-effort response")]
fn test_replace_request() {
    let mut pool = MessagePool::default();

    // Reserve a placeholder for a timeout response.
    let placeholder = pool.insert_inbound_timeout_response();

    // Replace the placeholder with a request.
    pool.replace_inbound_timeout_response(placeholder, request(NO_DEADLINE).into());
}

#[test]
#[should_panic(expected = "Message must be a best-effort response")]
fn test_replace_guaranteed_response() {
    let mut pool = MessagePool::default();

    // Reserve a placeholder for a timeout response.
    let placeholder = pool.insert_inbound_timeout_response();

    // Replace the placeholder with a guaranteed response.
    pool.replace_inbound_timeout_response(placeholder, response(NO_DEADLINE).into());
}

#[test]
fn test_get() {
    let mut pool = MessagePool::default();

    // Insert into the pool a bunch of incoming messages with different deadlines.
    let messages: Vec<_> = (10..20)
        .map(|i| {
            let msg: RequestOrResponse = if i < 15 {
                request(time(i)).into()
            } else {
                response(time(i)).into()
            };
            let id = pool.insert_inbound(msg.clone());
            (id, msg)
        })
        .collect();

    // Check that all messages are in the pool.
    for (id, msg) in messages.iter() {
        assert_eq!(Some(msg), pool.get(*id));
    }

    // Same test, using the specific getters.
    for (id, msg) in messages.iter() {
        match msg {
            RequestOrResponse::Request(_) => {
                assert_eq!(Some(msg), pool.get_request(*id));
            }
            RequestOrResponse::Response(_) => {
                assert_eq!(Some(msg), pool.get_response(*id));
            }
        }
    }

    // Also do a negative test.
    let nonexistent_id = pool.next_message_id(Kind::Request, Context::Inbound);
    assert_eq!(None, pool.get(nonexistent_id));
}

#[test]
#[should_panic(expected = "!id.is_response()")]
fn test_get_request_on_response() {
    let mut pool = MessagePool::default();
    let id = pool.insert_inbound(response(NO_DEADLINE).into());

    pool.get_request(id);
}

#[test]
#[should_panic(expected = "id.is_response()")]
fn test_get_response_on_request() {
    let mut pool = MessagePool::default();
    let id = pool.insert_inbound(request(NO_DEADLINE).into());

    pool.get_response(id);
}

#[test]
fn test_take() {
    let mut pool = MessagePool::default();

    let request: RequestOrResponse = request(time(13)).into();
    let response: RequestOrResponse = response(time(14)).into();

    // Insert the two messages.
    let request_id = pool.insert_inbound(request.clone());
    let response_id = pool.insert_inbound(response.clone());

    // Ensure that the messages are now in the pool.
    assert_eq!(Some(&request), pool.get_request(request_id));
    assert_eq!(Some(&response), pool.get_response(response_id));

    // Messages are still in the pool.
    assert_eq!(Some(&request), pool.get_request(request_id));
    assert_eq!(Some(&response), pool.get_response(response_id));

    // Actually take the messages.
    assert_eq!(Some(request), pool.take(request_id));
    assert_eq!(Some(response), pool.take(response_id));

    // Messages are gone.
    assert_eq!(None, pool.get_request(request_id));
    assert_eq!(None, pool.get_response(response_id));

    // And cannot be taken out again.
    assert_eq!(None, pool.take(request_id));
    assert_eq!(None, pool.take(response_id));
}

#[test]
fn test_expiration() {
    let t10 = time(10).into();
    let t11 = time(11).into();
    let t20 = time(20).into();
    let t21 = time(21).into();
    let t30 = time(30).into();
    let t31 = time(31).into();
    let t41_plus_lifetime = Time::from(time(41)) + REQUEST_LIFETIME;
    let t_max = Time::from_nanos_since_unix_epoch(u64::MAX);
    let half_second = Duration::from_nanos(500_000_000);
    let empty_vec = Vec::<(MessageId, RequestOrResponse)>::new();

    let mut pool = MessagePool::default();

    // No messages are expiring.
    assert!(!pool.has_expired_deadlines(t_max));
    assert_eq!(empty_vec, pool.expire_messages(t_max));

    // Insert one of each kind / class of message that expires.
    let msg1 = request(time(10));
    let id1 = pool.insert_inbound(msg1.clone().into());
    let msg2 = request(time(20));
    let id2 = pool.insert_outbound_request(msg2.clone().into(), time(25).into());
    let msg3 = response(time(30));
    let id3 = pool.insert_outbound_response(msg3.clone().into());
    let msg4 = request(NO_DEADLINE);
    let id4 = pool.insert_outbound_request(msg4.clone().into(), time(40).into());

    // Sanity check.
    assert_eq!(4, pool.len());
    assert_exact_queue_contents(
        vec![
            (Reverse(time(10)), id1),
            (Reverse(time(20)), id2),
            (Reverse(time(30)), id3),
            (Reverse(time(40 + REQUEST_LIFETIME.as_secs() as u32)), id4),
        ],
        &pool.deadline_queue,
    );
    // There are expiring messages.
    assert!(pool.has_expired_deadlines(t_max));

    //
    // Expire the first message, with a deadline of 10 seconds.
    //

    // No messages expiring at 10 seconds or between 10 and 11 seconds.
    assert!(!pool.has_expired_deadlines(t10));
    assert!(!pool.has_expired_deadlines(t10 + half_second));
    // But expect message expiring at 11 seconds.
    assert!(pool.has_expired_deadlines(t11));

    // Nothing expires at 10 seconds or between 10 and 11 seconds.
    assert_eq!(empty_vec, pool.expire_messages(t10));
    assert_eq!(empty_vec, pool.expire_messages(t10 + half_second));
    // But (only) `msg1` expires at 11 seconds.
    assert_eq!(vec![(id1, msg1.into())], pool.expire_messages(t11));

    // Sanity check: `msg1` is now gone.
    assert_eq!(None, pool.get_request(id1));
    assert_eq!(3, pool.len());

    // And there is nothing expiring at 11 seconds anymore.
    assert!(!pool.has_expired_deadlines(t11));
    assert_eq!(empty_vec, pool.expire_messages(t11));

    //
    // Pop the second message, with a deadline of 20 seconds.
    //

    // No messages expiring at 20 seconds.
    assert!(!pool.has_expired_deadlines(t20));
    assert_eq!(empty_vec, pool.expire_messages(t10));
    // But expect message expiring at 21 seconds.
    assert!(pool.has_expired_deadlines(t21));

    // Now pop it.
    assert_eq!(Some(msg2.into()), pool.take(id2));
    assert_eq!(2, pool.len());

    // The pool still thinks it has a message expiring at 21 seconds.
    assert!(pool.has_expired_deadlines(t21));
    // But trying to expire it doesn't produce anything.
    assert_eq!(empty_vec, pool.expire_messages(t21));
    // It should have, however, consumed the deadline queue entry.
    assert!(!pool.has_expired_deadlines(t21));

    //
    // Pop the remaining messages.
    //

    // No messages expiring at 30 seconds.
    assert!(!pool.has_expired_deadlines(t30));
    // But expect message expiring at 31 seconds.
    assert!(pool.has_expired_deadlines(t31));

    // Nothing expires at 30 seconds.
    assert_eq!(empty_vec, pool.expire_messages(t30));
    // But both remaining messages expire at `t41_plus_lifetime`.
    assert_eq!(
        vec![(id3, msg3.into()), (id4, msg4.into())],
        pool.expire_messages(t41_plus_lifetime)
    );

    // Pool is now empty.
    assert_eq!(0, pool.len());
    // And no messages are expiring.
    assert!(!pool.has_expired_deadlines(t_max));
    assert_eq!(empty_vec, pool.expire_messages(t_max));
}

#[test]
fn test_expiration_of_non_expiring_messages() {
    let mut pool = MessagePool::default();

    // Insert one message of each kind / class / context.
    pool.insert_inbound(request(NO_DEADLINE).into());
    pool.insert_inbound(response(NO_DEADLINE).into());
    pool.insert_inbound(response(time(30)).into());
    pool.insert_outbound_response(response(NO_DEADLINE).into());

    // Sanity check.
    assert_eq!(4, pool.len());

    // No messages are expiring.
    assert!(!pool.has_expired_deadlines(Time::from_nanos_since_unix_epoch(u64::MAX)));
    assert!(pool
        .expire_messages(Time::from_nanos_since_unix_epoch(u64::MAX))
        .is_empty());

    // Sanity check.
    assert_eq!(4, pool.len());
}

#[test]
fn test_shed_message() {
    let mut pool = MessagePool::default();

    // Nothing to shed.
    assert_eq!(None, pool.shed_largest_message());

    // Insert one best-effort message of each kind / context.
    let msg1 = request_with_payload(1000, time(10));
    let id1 = pool.insert_inbound(msg1.clone().into());
    let msg2 = response_with_payload(4000, time(20));
    let id2 = pool.insert_inbound(msg2.clone().into());
    let msg3 = request_with_payload(3000, time(30));
    let id3 = pool.insert_outbound_request(msg3.clone().into(), time(35).into());
    let msg4 = response_with_payload(2000, time(40));
    let id4 = pool.insert_outbound_response(msg4.clone().into());

    // Sanity check.
    assert_eq!(4, pool.len());

    // Shed the largest message (`msg2`).
    assert_eq!(Some((id2, msg2.into())), pool.shed_largest_message());
    assert_eq!(3, pool.len());

    // Pop the next largest message ('msg3`).
    assert_eq!(Some(msg3.into()), pool.take(id3));

    // Shedding will now produce `msg4`.
    assert_eq!(Some((id4, msg4.into())), pool.shed_largest_message());
    assert_eq!(1, pool.len());

    // Pop the remaining message ('msg1`).
    assert_eq!(Some(msg1.into()), pool.take(id1));

    // Nothing left to shed.
    assert_eq!(None, pool.shed_largest_message());
    assert_eq!(0, pool.len());
    assert_eq!(0, pool.size_queue.len());
}

#[test]
fn test_shed_message_guaranteed_response() {
    let mut pool = MessagePool::default();

    // Insert one guaranteed response message of each kind / context.
    pool.insert_inbound(request(NO_DEADLINE).into());
    pool.insert_inbound(response(NO_DEADLINE).into());
    pool.insert_outbound_request(request(NO_DEADLINE).into(), time(30).into());
    pool.insert_outbound_response(response(NO_DEADLINE).into());

    assert_eq!(4, pool.len());

    // Nothing can be shed.
    assert_eq!(None, pool.shed_largest_message());
    assert_eq!(0, pool.size_queue.len());
}

#[test]
fn test_take_trims_queues() {
    let mut pool = MessagePool::default();

    // Insert a bunch of expiring best-effort messages.
    let request = request(time(10));
    let mut ids: Vec<_> = (0..100)
        .map(|_| pool.insert_inbound(request.clone().into()))
        .collect();

    // Sanity check.
    assert_eq!(ids.len(), pool.len());
    assert_eq!(ids.len(), pool.deadline_queue.len());
    assert_eq!(ids.len(), pool.size_queue.len());

    while let Some(id) = ids.pop() {
        assert!(pool.take(id).is_some());

        // Sanity check.
        assert_eq!(ids.len(), pool.len());

        // Ensure that the priority queues are always at most twice (+2) the pool size.
        assert_trimmed_priority_queues(&pool);
    }
}

#[test]
fn test_expire_messages_trims_queues() {
    let mut pool = MessagePool::default();

    // Insert a bunch of expiring messages.
    let mut expiration_times: VecDeque<_> = (0..100)
        .map(|i| {
            pool.insert_inbound(request(time(i + 1)).into());
            time(i + 2)
        })
        .collect();

    // Sanity check.
    assert_eq!(expiration_times.len(), pool.len());
    assert_eq!(expiration_times.len(), pool.deadline_queue.len());
    assert_eq!(expiration_times.len(), pool.size_queue.len());

    while !expiration_times.is_empty() {
        let expiration_time = expiration_times.pop_front().unwrap();
        assert_eq!(1, pool.expire_messages(expiration_time.into()).len());

        // Sanity check.
        assert_eq!(expiration_times.len(), pool.len());

        // Ensure that the priority queues are always at most twice (+2) the pool size.
        assert_trimmed_priority_queues(&pool);
    }
}

#[test]
fn test_shed_message_trims_queues() {
    let mut pool = MessagePool::default();

    // Insert a bunch of expiring best-effort messages.
    let request = request(time(10));
    let ids: Vec<_> = (0..100)
        .map(|_| pool.insert_inbound(request.clone().into()))
        .collect();

    // Sanity check.
    assert_eq!(ids.len(), pool.len());
    assert_eq!(ids.len(), pool.deadline_queue.len());
    assert_eq!(ids.len(), pool.size_queue.len());

    for i in (0..ids.len()).rev() {
        assert!(pool.shed_largest_message().is_some());

        // Sanity check.
        assert_eq!(i, pool.len());

        // Ensure that the priority queues are always at most twice (+2) the pool size.
        assert_trimmed_priority_queues(&pool);
    }
}

#[test]
fn test_equality() {
    let mut pool = MessagePool::default();

    // Insert one message of each kind / class / context.
    let id1 = pool.insert_inbound(request(NO_DEADLINE).into());
    let id2 = pool.insert_inbound(request_with_payload(2000, time(20)).into());
    let _id3 = pool.insert_inbound(response(NO_DEADLINE).into());
    let _id4 = pool.insert_inbound(response(time(40)).into());
    let _id5 = pool.insert_outbound_request(request(NO_DEADLINE).into(), time(50).into());
    let _id6 = pool.insert_outbound_request(request(time(60)).into(), time(65).into());
    let _id7 = pool.insert_outbound_response(response(NO_DEADLINE).into());
    let id8 = pool.insert_outbound_response(response(time(80)).into());

    // Make a clone.
    let mut other_pool = pool.clone();

    // The two pools should be equal.
    assert_eq!(pool, other_pool);

    // Pop the same message from either pool.
    assert!(pool.take(id1).is_some());
    assert!(other_pool.take(id1).is_some());
    // The two pools should still be equal.
    assert_eq!(pool, other_pool);

    // Shed a message from either pool.
    assert_eq!(id2, pool.shed_largest_message().unwrap().0);
    assert_eq!(id2, other_pool.shed_largest_message().unwrap().0);
    // The two pools should still be equal.
    assert_eq!(pool, other_pool);

    // Expire a message from either pool (id6).
    assert_eq!(1, pool.expire_messages(time(61).into()).len());
    assert_eq!(1, other_pool.expire_messages(time(61).into()).len());
    // The two pools should still be equal.
    assert_eq!(pool, other_pool);

    // Expire a message from one pool (id8), take it from the other.
    assert_eq!(1, pool.expire_messages(time(81).into()).len());
    assert!(other_pool.take(id8).is_some());
    // The two pools should no longer be equal.
    assert_ne!(pool, other_pool);

    // Restore the two pools to equality.
    let mut other_pool = pool.clone();
    assert_eq!(pool, other_pool);

    // Shed a message from one pool, take it from the other.
    let id = pool.shed_largest_message().unwrap().0;
    assert!(other_pool.take(id).is_some());
    // The two pools should no longer be equal.
    assert_ne!(pool, other_pool);
}

#[test]
fn test_message_id_sanity() {
    // Each bit is actually a single bit.
    assert_eq!(1, Kind::BIT.count_ones());
    assert_eq!(1, Context::BIT.count_ones());
    // And they are the trailing two bits.
    assert_eq!(
        MessageId::BITMASK_LEN,
        (Kind::BIT | Context::BIT).trailing_ones()
    );

    // `Kind::Request` and `Kind::Response` have different `u64` representations and
    // they are both confined to `KIND_BIT`.
    assert_ne!(Kind::Request as u64, Kind::Response as u64);
    assert_eq!(Kind::Request as u64, Kind::Request as u64 & Kind::BIT);
    assert_eq!(Kind::Response as u64, Kind::Response as u64 & Kind::BIT);

    // `Context::Inbound` and `Context::Outbound` have different `u64`
    // representations and they are both confined to `CONTEXT_BIT`.
    assert_ne!(Context::Inbound as u64, Context::Outbound as u64);
    assert_eq!(
        Context::Inbound as u64,
        Context::Inbound as u64 & Context::BIT
    );
    assert_eq!(
        Context::Outbound as u64,
        Context::Outbound as u64 & Context::BIT
    );
}

//
// Fixtures and helper functions.
//

fn request(deadline: CoarseTime) -> Request {
    RequestBuilder::new().deadline(deadline).build()
}

fn response(deadline: CoarseTime) -> Response {
    ResponseBuilder::new().deadline(deadline).build()
}

fn request_with_payload(payload_size: usize, deadline: CoarseTime) -> Request {
    RequestBuilder::new()
        .method_payload(vec![13; payload_size])
        .deadline(deadline)
        .build()
}

fn response_with_payload(payload_size: usize, deadline: CoarseTime) -> Response {
    ResponseBuilder::new()
        .response_payload(Payload::Data(vec![13; payload_size]))
        .deadline(deadline)
        .build()
}

fn time(seconds_since_unix_epoch: u32) -> CoarseTime {
    CoarseTime::from_secs_since_unix_epoch(seconds_since_unix_epoch)
}

fn assert_exact_messages_in_queue<T>(
    messages: BTreeSet<MessageId>,
    queue: &BinaryHeap<(T, MessageId)>,
) {
    assert_eq!(messages, queue.iter().map(|(_, id)| *id).collect())
}

fn assert_exact_queue_contents<T: Clone + Ord + PartialOrd + Eq + PartialEq + Debug>(
    expected: Vec<(T, MessageId)>,
    queue: &BinaryHeap<(T, MessageId)>,
) {
    let mut queue = (*queue).clone();
    let mut queue_contents = Vec::with_capacity(queue.len());
    while let Some(entry) = queue.pop() {
        queue_contents.push(entry)
    }
    assert_eq!(expected, queue_contents)
}

// Ensures that the priority queue sizes are at most `2 * pool.len() + 2`.
fn assert_trimmed_priority_queues(pool: &MessagePool) {
    assert!(
        pool.deadline_queue.len() <= 2 * pool.len() + 2,
        "Deadline queue length: {}, pool size: {}",
        pool.deadline_queue.len(),
        pool.len()
    );
    assert!(
        pool.size_queue.len() <= 2 * pool.len() + 2,
        "Load shedding queue length: {}, pool size: {}",
        pool.size_queue.len(),
        pool.len()
    );
}
