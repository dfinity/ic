use super::*;
use ic_test_utilities_types::messages::{RequestBuilder, ResponseBuilder};
use ic_types::messages::{Payload, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64};
use ic_types::time::UNIX_EPOCH;
use maplit::btreeset;
use std::collections::BTreeSet;
use std::time::Duration;

#[test]
fn test_insert() {
    use Class::*;
    use Context::*;
    use Kind::*;

    let mut pool = MessagePool::default();

    // Insert one message of each kind / class / context.
    let id1 = pool.insert_inbound(request(NO_DEADLINE).into());
    assert_eq!(Request, id1.kind());
    assert_eq!(Inbound, id1.context());
    assert_eq!(GuaranteedResponse, id1.class());
    let id2 = pool.insert_inbound(request(time(20)).into());
    assert_eq!(Request, id2.kind());
    assert_eq!(Inbound, id2.context());
    assert_eq!(BestEffort, id2.class());
    let id3 = pool.insert_inbound(response(NO_DEADLINE).into());
    assert_eq!(Response, id3.kind());
    assert_eq!(Inbound, id3.context());
    assert_eq!(GuaranteedResponse, id3.class());
    let id4 = pool.insert_inbound(response(time(40)).into());
    assert_eq!(Response, id4.kind());
    assert_eq!(Inbound, id4.context());
    assert_eq!(BestEffort, id4.class());
    let id5 = pool.insert_outbound_request(request(NO_DEADLINE).into(), time(50).into());
    assert_eq!(Request, id5.kind());
    assert_eq!(Outbound, id5.context());
    assert_eq!(GuaranteedResponse, id5.class());
    let id6 = pool.insert_outbound_request(request(time(60)).into(), time(65).into());
    assert_eq!(Request, id6.kind());
    assert_eq!(Outbound, id6.context());
    assert_eq!(BestEffort, id6.class());
    let id7 = pool.insert_outbound_response(response(NO_DEADLINE).into());
    assert_eq!(Response, id7.kind());
    assert_eq!(Outbound, id7.context());
    assert_eq!(GuaranteedResponse, id7.class());
    let id8 = pool.insert_outbound_response(response(time(80)).into());
    assert_eq!(Response, id8.kind());
    assert_eq!(Outbound, id8.context());
    assert_eq!(BestEffort, id8.class());

    assert_eq!(8, pool.len());

    // Of the inbound messages, only the best-effort request should be in the
    // deadline queue. Of the outbound messages, only the guaranteed response should
    // not be in the deadline queue.
    assert_eq!(
        maplit::btreeset! {
            (time(20), id2),
            (time(60), id6),
            (time(80), id8),
            (time(50 + REQUEST_LIFETIME.as_secs() as u32), id5)
        },
        pool.deadline_queue
    );

    // All best-effort messages should be in the load shedding queue.
    //
    // We don't want to predict message sizes, so we only test which messages are in
    // the load shedding queue.
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

    assert_eq!(expected_deadline, pool.deadline_queue.first().unwrap().0);
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

    // Also do a negative test.
    let nonexistent_id = pool.next_message_id(Kind::Request, Context::Inbound, Class::BestEffort);
    assert_eq!(None, pool.get(nonexistent_id));
}

#[test]
fn test_take() {
    let mut pool = MessagePool::default();

    for deadline in [NO_DEADLINE, time(13)] {
        for context in [Context::Inbound, Context::Outbound] {
            let request = request(deadline);
            let response = response(deadline);

            // Insert the two messages.
            let (request_id, response_id) = match context {
                Context::Inbound => (
                    pool.insert_inbound(request.clone().into()),
                    pool.insert_inbound(response.clone().into()),
                ),
                Context::Outbound => (
                    pool.insert_outbound_request(request.clone().into(), time(14).into()),
                    pool.insert_outbound_response(response.clone().into()),
                ),
            };

            let request: RequestOrResponse = request.into();
            let response: RequestOrResponse = response.into();

            // Ensure that the messages are now in the pool.
            assert_eq!(Some(&request), pool.get(request_id));
            assert_eq!(Some(&response), pool.get(response_id));

            // Actually take the messages.
            assert_eq!(Some(request), pool.take(request_id));
            assert_eq!(Some(response), pool.take(response_id));

            // Messages are gone.
            assert_eq!(None, pool.get(request_id));
            assert_eq!(None, pool.get(response_id));

            // And cannot be taken out again.
            assert_eq!(None, pool.take(request_id));
            assert_eq!(None, pool.take(response_id));
        }
    }

    // After resetting `message_id_generator`, pool is equal to default, i.e. empty.
    pool.message_id_generator = 0;
    assert_eq!(MessagePool::default(), pool);
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
    let empty_vec = Vec::<(Id, RequestOrResponse)>::new();

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
    assert_eq!(
        maplit::btreeset! {
            (time(10), id1),
            (time(20), id2),
            (time(30), id3),
            (time(40 + REQUEST_LIFETIME.as_secs() as u32), id4)
        },
        pool.deadline_queue
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
    assert_eq!(None, pool.get(id1));
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

    // There is now no longer a message expiring at 21 seconds.
    assert!(!pool.has_expired_deadlines(t21));
    assert_eq!(empty_vec, pool.expire_messages(t21));

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
    // The two pools should still be equal.
    assert_eq!(pool, other_pool);

    // Shed a message from one pool, take it from the other.
    let id = pool.shed_largest_message().unwrap().0;
    assert!(other_pool.take(id).is_some());
    // The two pools should still be equal.
    assert_eq!(pool, other_pool);
}

#[test]
fn test_message_id_sanity() {
    // Each bit is actually a single bit.
    assert_eq!(1, Kind::BIT.count_ones());
    assert_eq!(1, Context::BIT.count_ones());
    assert_eq!(1, Class::BIT.count_ones());
    // And they are the trailing three bits.
    assert_eq!(
        Id::BITMASK_LEN,
        (Kind::BIT | Context::BIT | Class::BIT).trailing_ones()
    );

    // `Kind::Request` and `Kind::Response` have different `u64` representations and
    // they are both confined to `Kind::BIT`.
    assert_ne!(Kind::Request as u64, Kind::Response as u64);
    assert_eq!(Kind::Request as u64, Kind::Request as u64 & Kind::BIT);
    assert_eq!(Kind::Response as u64, Kind::Response as u64 & Kind::BIT);

    // `Context::Inbound` and `Context::Outbound` have different `u64`
    // representations and they are both confined to `Context::BIT`.
    assert_ne!(Context::Inbound as u64, Context::Outbound as u64);
    assert_eq!(
        Context::Inbound as u64,
        Context::Inbound as u64 & Context::BIT
    );
    assert_eq!(
        Context::Outbound as u64,
        Context::Outbound as u64 & Context::BIT
    );

    // `Class::GuaranteedResponse` and `Class::BestEffort` have different `u64`
    // representations and they are both confined to `Class::BIT`.
    assert_ne!(Class::GuaranteedResponse as u64, Class::BestEffort as u64);
    assert_eq!(
        Class::GuaranteedResponse as u64,
        Class::GuaranteedResponse as u64 & Class::BIT
    );
    assert_eq!(
        Class::BestEffort as u64,
        Class::BestEffort as u64 & Class::BIT
    );
}

#[test]
fn test_message_id_flags() {
    // Guaranteed inbound request.
    let giq_id = Id::new(
        Kind::Request,
        Context::Inbound,
        Class::GuaranteedResponse,
        13,
    );
    assert_eq!(Kind::Request, giq_id.kind());
    assert_eq!(Context::Inbound, giq_id.context());
    assert_eq!(Class::GuaranteedResponse, giq_id.class());
    assert_eq!(13, giq_id.0 >> Id::BITMASK_LEN);

    // Best-effort outbound response, same generator.
    let bop_id = Id::new(Kind::Response, Context::Outbound, Class::BestEffort, 13);
    assert_eq!(Kind::Response, bop_id.kind());
    assert_eq!(Context::Outbound, bop_id.context());
    assert_eq!(Class::BestEffort, bop_id.class());
    assert_eq!(13, bop_id.0 >> Id::BITMASK_LEN);

    // IDs should be different.
    assert_ne!(giq_id, bop_id);
    // But equal to themselves.
    assert_eq!(giq_id, giq_id);
    assert_eq!(bop_id, bop_id);
}

#[test]
fn test_message_id_range() {
    const REQUEST: Kind = Kind::Request;
    const INBOUND: Context = Context::Inbound;
    const GUARANTEED: Class = Class::GuaranteedResponse;

    let id1 = Id::new(REQUEST, INBOUND, GUARANTEED, 0);
    assert_eq!(0, id1.0 >> Id::BITMASK_LEN);

    let id2 = Id::new(REQUEST, INBOUND, GUARANTEED, 13);
    assert_eq!(13, id2.0 >> Id::BITMASK_LEN);

    // Maximum generator value that will be preserved
    const GENERATOR_MAX: u64 = u64::MAX >> Id::BITMASK_LEN;
    let id3 = Id::new(REQUEST, INBOUND, GUARANTEED, GENERATOR_MAX);
    assert_eq!(GENERATOR_MAX, id3.0 >> Id::BITMASK_LEN);

    // Larger generator values still work, their high bits are just ignored.
    let id4 = Id::new(REQUEST, INBOUND, GUARANTEED, u64::MAX);
    assert_eq!(GENERATOR_MAX, id4.0 >> Id::BITMASK_LEN);
}

#[test]
fn test_message_stats_best_effort() {
    use Context::*;
    use QueueOp::*;

    let mut pool = MessagePool::default();

    //
    // All-zero stats iniially.
    //
    let mut stats = StatsFixture::default();
    assert_eq!(stats.inner, pool.message_stats);

    //
    // Insert a bunch of best-effort messages.
    //
    let request = request(time(10));
    let request_size_bytes = request.count_bytes();
    let response = response(time(20));
    let response_size_bytes = response.count_bytes();

    let _ = pool.insert_inbound(request.clone().into());
    stats.adjust_and_check(&pool, Push, Inbound, request.clone().into());
    let inbound_response_id = pool.insert_inbound(response.clone().into());
    stats.adjust_and_check(&pool, Push, Inbound, response.clone().into());
    let outbound_request_id = pool.insert_outbound_request(request.clone().into(), UNIX_EPOCH);
    stats.adjust_and_check(&pool, Push, Outbound, request.clone().into());
    let _ = pool.insert_outbound_response(response.clone().into());
    stats.adjust_and_check(&pool, Push, Outbound, response.clone().into());

    // Sanity check the absolute values.
    assert_eq!(
        MessageStats {
            size_bytes: 2 * (request_size_bytes + response_size_bytes),
            best_effort_message_bytes: 2 * (request_size_bytes + response_size_bytes),
            guaranteed_responses_size_bytes: 0,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: request_size_bytes + response_size_bytes,
            inbound_message_count: 2,
            inbound_response_count: 1,
            inbound_guaranteed_request_count: 0,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 2
        },
        pool.message_stats
    );
    // And the guaranteed memory usage is zero.
    assert_eq!(0, pool.message_stats.guaranteed_response_memory_usage());

    //
    // Take one request and one response.
    //
    assert!(pool.take(inbound_response_id).is_some());
    stats.adjust_and_check(&pool, Pop, Inbound, response.into());
    assert!(pool.take(outbound_request_id).is_some());
    stats.adjust_and_check(&pool, Pop, Outbound, request.into());

    // The guaranteed memory usage is still zero.
    assert_eq!(0, pool.message_stats.guaranteed_response_memory_usage());
    // Best-effort memory usage and total byte size are halved.
    assert_eq!(
        request_size_bytes + response_size_bytes,
        pool.message_stats.best_effort_message_bytes
    );
    assert_eq!(
        request_size_bytes + response_size_bytes,
        pool.message_stats.size_bytes
    );

    //
    // Shed one of the remaining messages and time out the other.
    //
    assert!(pool.shed_largest_message().is_some());
    assert_eq!(1, pool.expire_messages(time(u32::MAX).into()).len());

    // Back to all-zero stats.
    assert_eq!(MessageStats::default(), pool.message_stats);
}

#[test]
fn test_message_stats_guaranteed_response() {
    use Context::*;
    use QueueOp::*;

    let mut pool = MessagePool::default();

    //
    // All-zero stats iniially.
    //
    let mut stats = StatsFixture::default();
    assert_eq!(stats.inner, pool.message_stats);

    //
    // Insert a bunch of guaranteed response messages.
    //
    let request = request(NO_DEADLINE);
    let request_size_bytes = request.count_bytes();
    let response = response(NO_DEADLINE);
    let response_size_bytes = response.count_bytes();

    let inbound_request_id = pool.insert_inbound(request.clone().into());
    stats.adjust_and_check(&pool, Push, Inbound, request.clone().into());
    let inbound_response_id = pool.insert_inbound(response.clone().into());
    stats.adjust_and_check(&pool, Push, Inbound, response.clone().into());
    let _ = pool.insert_outbound_request(request.clone().into(), UNIX_EPOCH);
    stats.adjust_and_check(&pool, Push, Outbound, request.clone().into());
    let outbound_response_id = pool.insert_outbound_response(response.clone().into());
    stats.adjust_and_check(&pool, Push, Outbound, response.clone().into());

    // Sanity check the absolute values.
    assert_eq!(
        MessageStats {
            size_bytes: 2 * (request_size_bytes + response_size_bytes),
            best_effort_message_bytes: 0,
            guaranteed_responses_size_bytes: 2 * response_size_bytes,
            oversized_guaranteed_requests_extra_bytes: 0,
            inbound_size_bytes: request_size_bytes + response_size_bytes,
            inbound_message_count: 2,
            inbound_response_count: 1,
            inbound_guaranteed_request_count: 1,
            inbound_guaranteed_response_count: 1,
            outbound_message_count: 2
        },
        pool.message_stats
    );
    // And the guaranteed memory usage covers the two responses.
    assert_eq!(
        2 * response_size_bytes,
        pool.message_stats.guaranteed_response_memory_usage()
    );

    //
    // Take one request and one response.
    //
    assert!(pool.take(inbound_request_id).is_some());
    stats.adjust_and_check(&pool, Pop, Inbound, request.clone().into());
    assert!(pool.take(outbound_response_id).is_some());
    stats.adjust_and_check(&pool, Pop, Outbound, response.clone().into());

    // The guaranteed memory usage covers the remaining response.
    assert_eq!(
        response_size_bytes,
        pool.message_stats.guaranteed_response_memory_usage()
    );
    // Best-effort memory usage is still zero.
    assert_eq!(0, pool.message_stats.best_effort_message_bytes);
    // Total byte size accounts for the two remaining messages.
    assert_eq!(
        request_size_bytes + response_size_bytes,
        pool.message_stats.size_bytes
    );

    // Time out the one message that has an (implicit) deadline (the outgoing
    // request), take the other.
    assert_eq!(1, pool.expire_messages(time(u32::MAX).into()).len());
    stats.adjust_and_check(&pool, Pop, Outbound, request.into());
    assert!(pool.take(inbound_response_id).is_some());
    stats.adjust_and_check(&pool, Pop, Inbound, response.into());

    // Back to all-zero stats.
    assert_eq!(MessageStats::default(), pool.message_stats);
}

#[test]
fn test_message_stats_oversized_requests() {
    use Context::*;
    use QueueOp::*;

    let mut pool = MessagePool::default();

    //
    // All-zero stats iniially.
    //
    let mut stats = StatsFixture::default();
    assert_eq!(stats.inner, pool.message_stats);

    //
    // Insert a bunch of oversized requests.
    //
    let best_effort = request_with_payload(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize + 1000,
        time(10),
    );
    let best_effort_size_bytes = best_effort.count_bytes();
    let guaranteed = request_with_payload(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize + 2000,
        NO_DEADLINE,
    );
    let guaranteed_size_bytes = guaranteed.count_bytes();
    // The 2000 bytes we added above; plus the method name provided by
    // `RequestBuilder`; plus any difference in size between the `Request` and
    // `Response` structs, so better to compute it
    let guaranteed_extra_bytes = guaranteed_size_bytes - MAX_RESPONSE_COUNT_BYTES;

    let _ = pool.insert_inbound(best_effort.clone().into());
    stats.adjust_and_check(&pool, Push, Inbound, best_effort.clone().into());
    let inbound_guaranteed_id = pool.insert_inbound(guaranteed.clone().into());
    stats.adjust_and_check(&pool, Push, Inbound, guaranteed.clone().into());
    let outbound_best_effort_id =
        pool.insert_outbound_request(best_effort.clone().into(), UNIX_EPOCH);
    stats.adjust_and_check(&pool, Push, Outbound, best_effort.clone().into());
    let _ = pool.insert_outbound_request(guaranteed.clone().into(), UNIX_EPOCH);
    stats.adjust_and_check(&pool, Push, Outbound, guaranteed.clone().into());

    // Sanity check the absolute values.
    assert_eq!(
        MessageStats {
            size_bytes: 2 * (best_effort_size_bytes + guaranteed_size_bytes),
            best_effort_message_bytes: 2 * best_effort_size_bytes,
            guaranteed_responses_size_bytes: 0,
            oversized_guaranteed_requests_extra_bytes: 2 * guaranteed_extra_bytes,
            inbound_size_bytes: best_effort_size_bytes + guaranteed_size_bytes,
            inbound_message_count: 2,
            inbound_response_count: 0,
            inbound_guaranteed_request_count: 1,
            inbound_guaranteed_response_count: 0,
            outbound_message_count: 2
        },
        pool.message_stats
    );
    // And the guaranteed memory usage covers the extra bytes of the two guaranteed
    // requests.
    assert_eq!(
        2 * guaranteed_extra_bytes,
        pool.message_stats.guaranteed_response_memory_usage()
    );

    // Take one best-effort and one guaranteed request.
    assert!(pool.take(inbound_guaranteed_id).is_some());
    stats.adjust_and_check(&pool, Pop, Inbound, guaranteed.into());
    assert!(pool.take(outbound_best_effort_id).is_some());
    stats.adjust_and_check(&pool, Pop, Outbound, best_effort.into());

    // The guaranteed memory usage covers the extra bytes of the remaining
    // guaranteed request.
    assert_eq!(
        guaranteed_extra_bytes,
        pool.message_stats.guaranteed_response_memory_usage()
    );
    // Best-effort memory usage covers the remaining best-effort request.
    assert_eq!(
        best_effort_size_bytes,
        pool.message_stats.best_effort_message_bytes
    );
    // Total byte size accounts for both remaining requests.
    assert_eq!(
        best_effort_size_bytes + guaranteed_size_bytes,
        pool.message_stats.size_bytes
    );

    // Shed one the remaining best-effort request and time out guaranteed one.
    assert!(pool.shed_largest_message().is_some());
    assert_eq!(1, pool.expire_messages(time(u32::MAX).into()).len());

    // Back to all-zero stats.
    assert_eq!(MessageStats::default(), pool.message_stats);
}

/// Tests that an encode-decode roundtrip yields a result equal to the original
/// (and that the stats and priority queues of an organically constructed
/// `MessagePool` match those of a deserialized one).
#[test]
fn encode_roundtrip() {
    let mut pool = MessagePool::default();

    // Insert one message of each kind / class / context.
    pool.insert_inbound(request_with_payload(100, NO_DEADLINE).into());
    pool.insert_inbound(request_with_payload(200, time(20)).into());
    pool.insert_inbound(response_with_payload(300, NO_DEADLINE).into());
    pool.insert_inbound(response_with_payload(400, time(40)).into());
    pool.insert_outbound_request(
        request_with_payload(500, NO_DEADLINE).into(),
        time(50).into(),
    );
    pool.insert_outbound_request(request_with_payload(600, time(60)).into(), time(65).into());
    pool.insert_outbound_response(response_with_payload(700, NO_DEADLINE).into());
    pool.insert_outbound_response(response_with_payload(800, time(80)).into());

    let encoded: pb_queues::MessagePool = (&pool).into();
    let decoded = encoded.try_into().unwrap();

    assert_eq!(pool, decoded);
}

/// Tests an encode-decode roundtrip of an empty `MessagePool`.
#[test]
fn encode_roundtrip_empty() {
    let pool = MessagePool::default();

    let encoded: pb_queues::MessagePool = (&pool).into();
    let decoded = encoded.try_into().unwrap();

    assert_eq!(pool, decoded);
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

fn assert_exact_messages_in_queue<T>(messages: BTreeSet<Id>, queue: &BTreeSet<(T, Id)>) {
    assert_eq!(messages.len(), queue.len());
    assert_eq!(messages, queue.iter().map(|(_, id)| *id).collect())
}

/// Generates an `Id` for a best-effort inbound request.
pub(crate) fn new_request_message_id(generator: u64, class: Class) -> Id {
    Id::new(Kind::Request, Context::Inbound, class, generator)
}

/// Generates an `Id` for an inbound response.
pub(crate) fn new_response_message_id(generator: u64, class: Class) -> Id {
    Id::new(Kind::Response, Context::Inbound, class, generator)
}

#[derive(PartialEq, Eq)]
enum QueueOp {
    Push,
    Pop,
}

/// Fixture for validating updates to the message stats. Relies on a parallel
/// implementation of stats calculations.
#[derive(Default)]
struct StatsFixture {
    inner: MessageStats,
}

impl StatsFixture {
    /// Adjusts the wrapped stats according to the given message, operation and
    /// context, relying on an independent stats implementation; then validates the
    /// given pool's stats by comparing them against the just-updated stats.
    fn adjust_and_check(
        &mut self,
        pool: &MessagePool,
        op: QueueOp,
        context: Context,
        msg: RequestOrResponse,
    ) {
        match op {
            QueueOp::Push => self.inner += stats_delta2(&msg, context),
            QueueOp::Pop => self.inner -= stats_delta2(&msg, context),
        }
        assert_eq!(self.inner, pool.message_stats);
    }
}

/// Alternate calculation of the stats change caused by pushing (+) or popping
/// (-) the given message in the given context.
fn stats_delta2(msg: &RequestOrResponse, context: Context) -> MessageStats {
    match msg {
        RequestOrResponse::Request(req) => request_stats_delta2(req, context),
        RequestOrResponse::Response(rep) => response_stats_delta2(rep, context),
    }
}

/// Alternate calculation of the stats change caused by pushing (+) or popping
/// (-) the given request in the given context.
fn request_stats_delta2(req: &Request, context: Context) -> MessageStats {
    use Class::*;
    use Context::*;

    let class = if req.deadline == NO_DEADLINE {
        Class::GuaranteedResponse
    } else {
        Class::BestEffort
    };

    let size_bytes = req.count_bytes();
    let (best_effort_message_bytes, oversized_guaranteed_requests_extra_bytes) = match class {
        GuaranteedResponse => (0, size_bytes.saturating_sub(MAX_RESPONSE_COUNT_BYTES)),
        BestEffort => (size_bytes, 0),
    };
    let (inbound_size_bytes, inbound_message_count, outbound_message_count) = if context == Inbound
    {
        (size_bytes, 1, 0)
    } else {
        (0, 0, 1)
    };
    let inbound_guaranteed_request_count = if context == Inbound && class == GuaranteedResponse {
        1
    } else {
        0
    };
    // Response stats are unaffected.
    let guaranteed_responses_size_bytes = 0;
    let inbound_response_count = 0;
    let inbound_guaranteed_response_count = 0;

    MessageStats {
        size_bytes,
        best_effort_message_bytes,
        guaranteed_responses_size_bytes,
        oversized_guaranteed_requests_extra_bytes,
        inbound_size_bytes,
        inbound_message_count,
        inbound_response_count,
        inbound_guaranteed_request_count,
        inbound_guaranteed_response_count,
        outbound_message_count,
    }
}

/// Alternate calculation of the stats change caused by pushing (+) or popping
/// (-) the given response in the given context.
fn response_stats_delta2(rep: &Response, context: Context) -> MessageStats {
    use Class::*;
    use Context::*;

    let class = if rep.deadline == NO_DEADLINE {
        Class::GuaranteedResponse
    } else {
        Class::BestEffort
    };

    let size_bytes = rep.count_bytes();
    let (best_effort_message_bytes, guaranteed_responses_size_bytes) = match class {
        GuaranteedResponse => (0, size_bytes),
        BestEffort => (size_bytes, 0),
    };
    let (inbound_size_bytes, inbound_message_count, inbound_response_count, outbound_message_count) =
        if context == Inbound {
            (size_bytes, 1, 1, 0)
        } else {
            (0, 0, 0, 1)
        };
    let inbound_guaranteed_response_count = if context == Inbound && class == GuaranteedResponse {
        1
    } else {
        0
    };

    // Request stats are unaffected.
    let oversized_guaranteed_requests_extra_bytes = 0;
    let inbound_guaranteed_request_count = 0;

    MessageStats {
        size_bytes,
        best_effort_message_bytes,
        guaranteed_responses_size_bytes,
        oversized_guaranteed_requests_extra_bytes,
        inbound_size_bytes,
        inbound_message_count,
        inbound_response_count,
        inbound_guaranteed_request_count,
        inbound_guaranteed_response_count,
        outbound_message_count,
    }
}
