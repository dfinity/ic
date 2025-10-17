use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_proxied_canister_calls_tracker::ProxiedCanisterCallsTracker;
use maplit::btreemap;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
use tokio::task::JoinSet;

#[tokio::test]
async fn test_proxied_canister_calls_tracker_hand_crafted_blocks() {
    thread_local! {
        static TIME: RefCell<SystemTime> = RefCell::new(SystemTime::now());
    }
    let advance_time_seconds = |seconds| {
        TIME.with(|time| {
            let mut time = time.borrow_mut();
            *time += Duration::from_secs_f64(seconds);
        });
    };

    thread_local! {
        static TRACKER: RefCell<ProxiedCanisterCallsTracker> =
            RefCell::new(ProxiedCanisterCallsTracker::new(|| TIME.with(|t| *t.borrow())));
    }
    let debug_tracker = || TRACKER.with(|tracker| format!("{:#?}", tracker.borrow()));
    let len = || TRACKER.with(|tracker| tracker.borrow().len());
    let max_age = || {
        TRACKER.with(|tracker| {
            tracker
                .borrow()
                .get_method_name_caller_callee_to_in_flight_max_age()
        })
    };

    assert_eq!(len(), 0, "{}", debug_tracker());
    assert_eq!(max_age(), BTreeMap::new(), "{}", debug_tracker());

    async fn allow_overlap() {
        tokio::time::sleep(Duration::from_nanos(1)).await;
    }

    let canister_id = CanisterId::from(0xBEEF);
    let method_name = "hello_internet_computer";
    let payload = vec![];

    let mut ran_1 = false;
    let block_1 = async {
        let caller = PrincipalId::new_user_test_id(662_271);

        // Throw in an await so that there will be (a chance of) overlap
        // (but make it very short so that tests run fast).
        allow_overlap().await;

        let _tracker = ProxiedCanisterCallsTracker::start_tracking(
            &TRACKER,
            caller,
            canister_id,
            method_name,
            &payload,
        );
        advance_time_seconds(42.7);

        assert!(len() >= 1, "{}", debug_tracker());
        assert_eq!(
            *max_age()
                .get(&(method_name.to_string(), caller, canister_id))
                .unwrap(),
            Duration::from_secs_f64(42.7),
            "{}",
            debug_tracker(),
        );

        allow_overlap().await;

        ran_1 = true;
    };

    let mut ran_2 = false;
    let block_2 = async {
        let caller = PrincipalId::new_user_test_id(938_645);

        // Throw in an await so that there will be (a chance of) overlap
        // (but make it very short so that tests run fast).
        allow_overlap().await;

        let _tracker = ProxiedCanisterCallsTracker::start_tracking(
            &TRACKER,
            caller,
            canister_id,
            method_name,
            &payload,
        );
        advance_time_seconds(31.4);

        assert!(len() >= 1, "{}", debug_tracker());
        assert_eq!(
            *max_age()
                .get(&(method_name.to_string(), caller, canister_id))
                .unwrap(),
            Duration::from_secs_f64(31.4),
            "{}",
            debug_tracker(),
        );

        allow_overlap().await;

        ran_2 = true;
    };

    let mut ran_3 = false;
    let block_3 = async {
        let caller = PrincipalId::new_user_test_id(607_470);

        // Throw in an await so that there will be (a chance of) overlap
        // (but make it very short so that tests run fast).
        allow_overlap().await;

        let _tracker = ProxiedCanisterCallsTracker::start_tracking(
            &TRACKER,
            caller,
            canister_id,
            method_name,
            &payload,
        );
        advance_time_seconds(27.2);

        assert!(len() >= 1, "{}", debug_tracker());
        assert_eq!(
            *max_age()
                .get(&(method_name.to_string(), caller, canister_id))
                .unwrap(),
            Duration::from_secs_f64(27.2),
            "{}",
            debug_tracker(),
        );

        allow_overlap().await;

        ran_3 = true;
    };

    tokio::join!(block_1, block_2, block_3);

    // Double check that we reached the end of the two blocks.
    assert!(ran_1);
    assert!(ran_2);
    assert!(ran_3);

    assert_eq!(len(), 0, "{}", debug_tracker());
    assert_eq!(max_age(), BTreeMap::new(), "{}", debug_tracker());
}

#[tokio::test]
async fn test_proxied_canister_calls_tracker_many_blocks() {
    thread_local! {
        static TIME: RefCell<SystemTime> = RefCell::new(SystemTime::now());
    }
    let advance_time_seconds = |seconds| {
        TIME.with(|time| {
            let mut time = time.borrow_mut();
            *time += Duration::from_secs_f64(seconds);
        });
    };

    thread_local! {
        static TRACKER: RefCell<ProxiedCanisterCallsTracker> =
            RefCell::new(ProxiedCanisterCallsTracker::new(|| TIME.with(|t| *t.borrow())));
    }
    let debug_tracker = || TRACKER.with(|tracker| format!("{:#?}", tracker.borrow()));
    let len = || TRACKER.with(|tracker| tracker.borrow().len());
    let max_age = || {
        TRACKER.with(|tracker| {
            tracker
                .borrow()
                .get_method_name_caller_callee_to_in_flight_max_age()
        })
    };

    // Fresh TRACKER should have nothing in it.
    assert_eq!(len(), 0, "{}", debug_tracker());
    assert_eq!(max_age(), BTreeMap::new(), "{}", debug_tracker());

    async fn allow_overlap() {
        tokio::time::sleep(Duration::from_nanos(1)).await;
    }

    // Create a bunch of blocks, which we will later run concurrently via join.
    let mut join_set = JoinSet::new();
    for i in 0..25 {
        join_set.spawn(async move {
            let caller = PrincipalId::new_user_test_id(i + 100);
            // We make this vary with i, but it could be invariant wrt i without
            // having much effect on this test.
            let callee = CanisterId::from(i + 42);
            let method_name = format!("method_{i}");
            let args = vec![];

            allow_overlap().await;

            let _tracker = ProxiedCanisterCallsTracker::start_tracking(
                &TRACKER,
                caller,
                callee,
                &method_name,
                &args,
            );

            // Advance time by some crazy amount.
            let dt = 5.0 * ((i as f64 + 0.1).sin() + 1.0);
            advance_time_seconds(dt);

            // Unfortunately, we cannot await here, because that would throw off
            // our ability to assert the age of the request that's being tracked
            // in this async block.

            // Due to unpredictability of block execution overlap, we can't say
            // how exactly many live trackers there currently are. What we can
            // say for sure is that there is at least 1.
            assert!(len() >= 1, "{}", debug_tracker());

            assert_eq!(
                *max_age().get(&(method_name, caller, callee)).unwrap(),
                Duration::from_secs_f64(dt),
                "{}",
                debug_tracker(),
            );

            allow_overlap().await;
        });
    }

    // Set everything in motion.
    let mut done_count = 0;
    while let Some(result) = join_set.join_next().await {
        assert!(result.is_ok(), "{result:#?}");
        done_count += 1;
    }
    assert_eq!(done_count, 25);

    // TRACKER should now be drained.
    assert_eq!(len(), 0, "{}", debug_tracker());
    assert_eq!(max_age(), BTreeMap::new(), "{}", debug_tracker());
}

#[test]
fn test_proxied_canister_calls_tracker_concurrent() {
    thread_local! {
        static TIME: RefCell<SystemTime> = RefCell::new(SystemTime::now());
    }
    let advance_time_seconds = |seconds| {
        TIME.with(|time| {
            let mut time = time.borrow_mut();
            *time += Duration::from_secs_f64(seconds);
        });
    };

    thread_local! {
        static TRACKER: RefCell<ProxiedCanisterCallsTracker> =
            RefCell::new(ProxiedCanisterCallsTracker::new(|| TIME.with(|t| *t.borrow())));
    }
    let len = || TRACKER.with(|tracker| tracker.borrow().len());
    let max_age = || {
        TRACKER.with(|tracker| {
            tracker
                .borrow()
                .get_method_name_caller_callee_to_in_flight_max_age()
        })
    };

    assert_eq!(len(), 0, "{TRACKER:#?}");
    assert_eq!(max_age(), BTreeMap::new(), "{TRACKER:#?}");

    // Three calls are made.
    let args = vec![];

    let caller_1 = PrincipalId::new_user_test_id(662_271);
    let callee_1 = CanisterId::from(710_884);
    let method_name_1 = "hi".to_string();

    // The second call looks like the first.
    let caller_2 = caller_1;
    let callee_2 = callee_1;
    let method_name_2 = method_name_1.clone();

    let caller_3 = PrincipalId::new_user_test_id(507_602);
    let callee_3 = CanisterId::from(996_469);
    let method_name_3 = "bye".to_string();

    // Call 1 completes first, then 3, then 2.

    advance_time_seconds(1.0); // t = 1.0
    let tracker_1 = ProxiedCanisterCallsTracker::start_tracking(
        &TRACKER,
        caller_1,
        callee_1,
        &method_name_1,
        &args,
    );
    advance_time_seconds(20.0); // t = 21.0

    assert_eq!(len(), 1, "{TRACKER:#?}");
    assert_eq!(
        max_age(),
        btreemap! {
            (method_name_1.clone(), caller_1, callee_1) => Duration::from_secs_f64(20.0), // 21 - 1
        },
    );

    advance_time_seconds(300.0); // t = 321.0
    let tracker_2 = ProxiedCanisterCallsTracker::start_tracking(
        &TRACKER,
        caller_2,
        callee_2,
        &method_name_2,
        &args,
    );
    advance_time_seconds(4_000.0); // t = 4_321.0

    assert_eq!(len(), 2, "{TRACKER:#?}");
    assert_eq!(
        max_age(),
        btreemap! {
            (method_name_1.clone(), caller_1, callee_1) => Duration::from_secs_f64(4_320.0), // 4321 - 1
        },
    );

    advance_time_seconds(50_000.0); // t = 54_321
    let tracker_3 = ProxiedCanisterCallsTracker::start_tracking(
        &TRACKER,
        caller_3,
        callee_3,
        &method_name_3,
        &args,
    );
    advance_time_seconds(600_000.0); // t = 654_321

    assert_eq!(len(), 3, "{TRACKER:#?}");
    assert_eq!(
        max_age(),
        btreemap! {
            (method_name_1.clone(), caller_1, callee_1) => Duration::from_secs_f64(654_320.0), // 654_321 - 1
            (method_name_3.clone(), caller_3, callee_3) => Duration::from_secs_f64(600_000.0), // 654_321 - 54_321
        },
    );

    advance_time_seconds(7_000_000.0); // t = 7_654_321
    drop(tracker_1); // Unshadow the call that came in second.
    advance_time_seconds(80_000_000.0); // t = 87_654_321

    assert_eq!(len(), 2, "{TRACKER:#?}");
    assert_eq!(
        max_age(),
        btreemap! {
            (method_name_2.clone(), caller_2, callee_2) => Duration::from_secs_f64(87_654_000.0), // 87_654_321 - 321
            (method_name_3.clone(), caller_3, callee_3) => Duration::from_secs_f64(87_600_000.0), // 87_654_321 - 54_321
        },
    );

    advance_time_seconds(900_000_000.0); // t = 987_654_321
    drop(tracker_3); // Out of order!
    advance_time_seconds(8_000_000_000.0); // t = 8_987_654_321

    assert_eq!(len(), 1, "{TRACKER:#?}");
    assert_eq!(
        max_age(),
        btreemap! {
            (method_name_2.clone(), caller_2, callee_2) => Duration::from_secs_f64(8_987_654_000.0), // 8_987_654_321 - 321
        },
    );

    advance_time_seconds(70_000_000_000.0); // t = 78_987_654_321
    drop(tracker_2); // Out of order!
    advance_time_seconds(600_000_000_000.0); // t = 678_987_654_321

    assert_eq!(len(), 0, "{TRACKER:#?}");
    assert_eq!(max_age(), BTreeMap::new(), "{TRACKER:#?}");

    // This is to avoid clippy telling us to get rid of earlier clone
    // calls. Removing such calls causes code misalignment.
    drop(method_name_1);
    drop(method_name_2);
    drop(method_name_3);
}
