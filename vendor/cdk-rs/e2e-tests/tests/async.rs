use candid::Principal;
use pocket_ic::{query_candid, ErrorCode};

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn panic_after_await_frees_resources() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    for i in 1..3 {
        match update(&pic, canister_id, "panic_after_await", ()) {
            Ok(()) => panic!("expected a panic, but got success"),
            Err(rej) => {
                println!("Got a user error as expected: {rej}");

                assert_eq!(rej.error_code, ErrorCode::CanisterCalledTrap);
                let expected_message = "Goodbye, cruel world.";
                assert!(
                    rej.reject_message.contains(expected_message),
                    "Expected the user error to contain '{}', got: {}",
                    expected_message,
                    rej.reject_message
                );
            }
        }

        let (n,): (u64,) = update(&pic, canister_id, "get_locked_resource", ()).unwrap();

        assert_eq!(i, n, "expected the invocation count to be {i}, got {n}");
    }

    let (message,): (String,) =
        update(&pic, canister_id, "invalid_reply_payload_does_not_trap", ()).unwrap();
    assert!(message.contains("handled decoding error gracefully"));

    let rej = update::<_, ()>(&pic, canister_id, "panic_twice", ()).expect_err("failed to panic");
    assert!(rej.reject_message.contains("Call already trapped"));
    let _: (u64,) = update(&pic, canister_id, "notifications_received", ()).unwrap();
    let _: (u64,) = update(&pic, canister_id, "get_locked_resource", ()).unwrap();
}

#[test]
fn panic_after_await_frees_resources_in_spawn_migratory() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    update::<_, ()>(
        &pic,
        canister_id,
        "panic_after_await_in_spawn_migratory",
        (),
    )
    .unwrap();

    let res = update::<_, ()>(&pic, canister_id, "migratory_resume", ());
    let logs = pic
        .fetch_canister_logs(canister_id, Principal::anonymous())
        .unwrap();
    match res {
        Err(r) => assert!(r.reject_message.contains("Goodbye, cruel world.")),
        Ok(()) => assert!(logs.last().is_some_and(|log| str::from_utf8(&log.content)
            .unwrap()
            .contains("Goodbye, cruel world.",))),
    }

    update::<_, ()>(&pic, canister_id, "migratory_resume", ()).unwrap();
    assert!(
        pic.fetch_canister_logs(canister_id, Principal::anonymous())
            .unwrap()
            .len()
            == logs.len()
    );
    let _: (u64,) = update(&pic, canister_id, "notifications_received", ()).unwrap();
    let _: (u64,) = update(&pic, canister_id, "get_locked_resource", ()).unwrap();
}

#[test]
fn panic_after_await_destructors_cannot_schedule_tasks() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);
    let err = update::<_, ()>(&pic, canister_id, "schedule_on_panic", ()).unwrap_err();
    assert!(err
        .reject_message
        .contains("tasks cannot be spawned while recovering from a trap"));
    let (pre_bg_notifs,): (u64,) =
        query_candid(&pic, canister_id, "notifications_received", ()).unwrap();
    assert_eq!(pre_bg_notifs, 1);
    update::<_, ()>(&pic, canister_id, "on_notify", ()).unwrap();
    let (post_bg_notifs,): (u64,) =
        query_candid(&pic, canister_id, "notifications_received", ()).unwrap();
    assert_eq!(post_bg_notifs, 2);
}

#[test]
fn panic_after_await_destructors_can_schedule_timers() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);
    let err = update::<_, ()>(&pic, canister_id, "timer_on_panic", ()).unwrap_err();
    assert!(err.reject_message.contains("testing"));
    assert!(!err.reject_message.contains("recovery"));
    let (pre_bg_notifs,): (u64,) =
        query_candid(&pic, canister_id, "notifications_received", ()).unwrap();
    assert_eq!(pre_bg_notifs, 1);
    update::<_, ()>(&pic, canister_id, "on_notify", ()).unwrap();
    let (post_bg_notifs,): (u64,) =
        query_candid(&pic, canister_id, "notifications_received", ()).unwrap();
    assert_eq!(post_bg_notifs, 5);
}

#[test]
fn notify_calls() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let sender_id = pic.create_canister();
    pic.add_cycles(sender_id, 2_000_000_000_000);
    pic.install_canister(sender_id, wasm.clone(), vec![], None);
    let receiver_id = pic.create_canister();
    pic.add_cycles(receiver_id, 2_000_000_000_000);
    pic.install_canister(receiver_id, wasm, vec![], None);

    let (n,): (u64,) = query_candid(&pic, receiver_id, "notifications_received", ()).unwrap();
    assert_eq!(n, 0);

    let () = update(&pic, sender_id, "notify", (receiver_id, "on_notify")).unwrap();

    let (n,): (u64,) = query_candid(&pic, receiver_id, "notifications_received", ()).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn test_composite_query() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let sender_id = pic.create_canister();
    pic.add_cycles(sender_id, 2_000_000_000_000);
    pic.install_canister(sender_id, wasm.clone(), vec![], None);
    let receiver_id = pic.create_canister();
    pic.add_cycles(receiver_id, 2_000_000_000_000);
    pic.install_canister(receiver_id, wasm, vec![], None);

    let (greeting,): (String,) =
        query_candid(&pic, sender_id, "greet_self", (receiver_id,)).unwrap();
    assert_eq!(greeting, "Hello, myself");
}

#[test]
fn channels() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    let (greeting,): (String,) = update(&pic, canister_id, "await_channel_completion", ()).unwrap();
    assert_eq!(greeting, "Hello, myself");
}

#[test]
fn spawn_ordering() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    let () = update(&pic, canister_id, "spawn_ordering", ()).unwrap();
    let (n,): (u64,) = query_candid(&pic, canister_id, "notifications_received", ()).unwrap();
    assert_eq!(n, 2);
}

#[test]
fn early_panic_not_erased() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    let err = update::<_, ()>(&pic, canister_id, "panic_then_continue", ()).unwrap_err();
    assert!(err.reject_message.contains("already trapped"));

    let (n,): (u64,) = query_candid(&pic, canister_id, "notifications_received", ()).unwrap();
    assert_eq!(n, 2);
    let _: (u64,) = query_candid(&pic, canister_id, "get_locked_resource", ()).unwrap();
}

#[test]
fn protected_spawn_magnetism() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    update::<_, ()>(&pic, canister_id, "spawn_protected_with_distant_waker", ()).unwrap();
}

#[test]
fn protected_spawn_cannot_outlive() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    let err = update::<_, ()>(&pic, canister_id, "stalled_protected_task", ()).unwrap_err();
    assert!(err
        .reject_message
        .contains("protected task outlived its canister method"));
}

#[test]
fn protected_spawn_unavailable_in_migratory() {
    let wasm = cargo_build_canister("async");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    let err = update::<_, ()>(&pic, canister_id, "protected_from_migratory", ()).unwrap_err();
    assert!(err
        .reject_message
        .contains("cannot be called outside of a tracked method context"));
}
