use candid::Principal;
use pocket_ic::{
    common::rest::{CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse},
    query_candid, PocketIc,
};
use std::time::Duration;

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

/// Advance the time by a given number of seconds followed by a tick.
fn advance_and_tick(pic: &PocketIc, seconds: u64) {
    pic.advance_time(Duration::from_secs(seconds));
    pic.tick();
}

#[test]
fn test_timers() {
    let wasm = cargo_build_canister("timers");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    update::<(), ()>(&pic, canister_id, "schedule", ()).expect("Failed to call schedule");
    // without time skip
    for _ in 0..5 {
        advance_and_tick(&pic, 1);
    }

    update::<(), ()>(&pic, canister_id, "schedule", ()).expect("Failed to call schedule");
    // with time skip: 3 and 4 are swapped because 3 is scheduled by another timer which must run first while 4 is available immediately
    advance_and_tick(&pic, 5);

    update::<_, ()>(&pic, canister_id, "schedule_long", ()).expect("Failed to call schedule_long");
    advance_and_tick(&pic, 5);
    update::<_, ()>(&pic, canister_id, "cancel_long", ()).expect("Failed to call cancel_long");
    advance_and_tick(&pic, 5);
    update::<_, ()>(&pic, canister_id, "start_repeating", ())
        .expect("Failed to call start_repeating");
    advance_and_tick(&pic, 3);
    update::<_, ()>(&pic, canister_id, "stop_repeating", ())
        .expect("Failed to call stop_repeating");
    advance_and_tick(&pic, 2);

    let (events,): (Vec<String>,) =
        query_candid(&pic, canister_id, "get_events", ()).expect("Failed to call get_events");
    assert_eq!(
        events[..],
        ["1", "2", "3", "4", "1", "2", "4", "3", "repeat", "repeat", "repeat"]
    );
}

#[test]
fn test_timers_can_cancel_themselves() {
    let pic = pic_base().build();
    let wasm = cargo_build_canister("timers");
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    update::<_, ()>(&pic, canister_id, "set_self_cancelling_timer", ())
        .expect("Failed to call set_self_cancelling_timer");
    update::<_, ()>(&pic, canister_id, "set_self_cancelling_periodic_timer", ())
        .expect("Failed to call set_self_cancelling_periodic_timer");

    advance_and_tick(&pic, 3);

    let (events,): (Vec<String>,) =
        query_candid(&pic, canister_id, "get_events", ()).expect("Failed to call get_events");
    assert_eq!(
        events,
        ["timer cancelled self", "periodic timer cancelled self"]
    );
}

#[test]
fn test_scheduling_many_timers() {
    let wasm = cargo_build_canister("timers");
    // Must be more than the self-imposed limit (250)
    let timers_to_schedule = 1_000_u32;
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100_000_000_000_000u128);
    pic.install_canister(canister_id, wasm, vec![], None);

    let () = update(
        &pic,
        canister_id,
        "schedule_n_timers",
        (timers_to_schedule,),
    )
    .expect("Error calling schedule_n_timers");

    // Up to 20 timers will be executed per round
    // Be conservative that advance 2 times the minimum number of rounds
    const TIMERS_PER_ROUND: u64 = 20;
    for _ in 0..2 * timers_to_schedule as u64 / TIMERS_PER_ROUND {
        advance_and_tick(&pic, 1);
    }

    let (executed_timers,): (u32,) = query_candid(&pic, canister_id, "executed_timers", ())
        .expect("Error querying executed_timers");
    assert_eq!(timers_to_schedule, executed_timers);

    let logs = pic
        .fetch_canister_logs(canister_id, Principal::anonymous())
        .unwrap();
    assert!(logs.iter().any(|line| str::from_utf8(&line.content)
        .is_ok_and(|s| s.contains("too many concurrent timer calls"))));
}

#[test]
fn test_set_global_timers() {
    let wasm = cargo_build_canister("timers");
    let pic = pic_base().build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    // Set a 9s timer at t0, it expires at t1 = t0 + 9s
    let t0 = pic.get_time().as_nanos_since_unix_epoch();
    let t1 = t0 + 9_000_000_000;
    update::<_, ()>(&pic, canister_id, "schedule_long", ()).expect("Failed to call schedule_long");

    // 5 seconds later, the 9s timer is still active
    advance_and_tick(&pic, 5);

    // Set the expiration time of the timer to t2 = t1 + 5s
    let t2 = t1 + 5_000_000_000;
    let (previous,) =
        update::<(u64,), (u64,)>(&pic, canister_id, "global_timer_set", (t2,)).unwrap();
    assert!(previous.abs_diff(t1) < 2); // time error no more than 1 nanosecond

    // Deactivate the timer
    let (previous,) =
        update::<(u64,), (u64,)>(&pic, canister_id, "global_timer_set", (0,)).unwrap();
    assert!(previous.abs_diff(t2) < 2); // time error no more than 1 nanosecond
}

#[test]
fn test_async_timers() {
    let wasm = cargo_build_canister("timers");
    let pic = pic_base().build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    update::<(), ()>(&pic, canister_id, "async_await", ()).unwrap();
    advance_and_tick(&pic, 5);

    let (events,): (Vec<String>,) =
        query_candid(&pic, canister_id, "get_events", ()).expect("Failed to call get_events");
    assert_eq!(events.len(), 8);
    assert_eq!(events[..4], ["0", "1", "method outer", "2",]);
    assert_eq!(
        events[4..]
            .iter()
            .filter(|e| *e == "method spawned")
            .count(),
        1
    );
    assert_eq!(
        events[4..]
            .iter()
            .filter(|e| *e == "method concurrent")
            .count(),
        3
    );
}

#[test]
fn test_periodic_timers_repeat_when_tasks_make_calls_despite_time_skipping() {
    let wasm = cargo_build_canister("timers");
    let pic = pic_base().build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    update::<(), ()>(&pic, canister_id, "start_repeating_async", ()).unwrap();
    // start_repeating_async sets a repeating timer with a 1s interval
    // advance time by 3 seconds should trigger 3 repeats
    advance_and_tick(&pic, 3);
    update::<(), ()>(&pic, canister_id, "stop_repeating", ()).unwrap();

    let (events,): (Vec<String>,) = query_candid(&pic, canister_id, "get_events", ()).unwrap();
    assert_eq!(
        events[..],
        ["method repeat", "method repeat", "method repeat"]
    );
}

#[test]
fn test_individual_timer_ratelimits_when_time_skips() {
    let wasm = cargo_build_canister("timers");
    let pic = pic_base().build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    update::<(), ()>(&pic, canister_id, "start_repeating", ()).unwrap();
    advance_and_tick(&pic, 20);
    update::<(), ()>(&pic, canister_id, "stop_repeating", ()).unwrap();

    let (events,): (Vec<String>,) = query_candid(&pic, canister_id, "get_events", ()).unwrap();
    assert_eq!(events.len(), 5);

    let logs = pic
        .fetch_canister_logs(canister_id, Principal::anonymous())
        .unwrap();
    assert!(logs.iter().any(|line| str::from_utf8(&line.content)
        .is_ok_and(|s| s.contains("too many concurrent calls for single timer"))));
}

#[test]
fn test_serial_timers_run_in_serial() {
    let wasm = cargo_build_canister("timers");
    let pic = pic_base().build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    update::<(), ()>(&pic, canister_id, "start_repeating_serial", ()).unwrap();
    for _ in 0..5 {
        advance_and_tick(&pic, 1);
    }
    // hack to enable the canister to 'sleep': advance time while an outcall is pending
    let reqs = pic.get_canister_http();
    for req in reqs {
        pic.mock_canister_http_response(MockCanisterHttpResponse {
            subnet_id: req.subnet_id,
            request_id: req.request_id,
            response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
                body: vec![],
                status: 200,
                headers: vec![],
            }),
            additional_responses: vec![],
        });
    }
    for _ in 0..5 {
        advance_and_tick(&pic, 1);
    }
    update::<(), ()>(&pic, canister_id, "stop_repeating", ()).unwrap();

    let (events,): (Vec<String>,) = query_candid(&pic, canister_id, "get_events", ()).unwrap();
    assert_eq!(
        events[..],
        ["method repeat serial", "method repeat serial",]
    );
}
