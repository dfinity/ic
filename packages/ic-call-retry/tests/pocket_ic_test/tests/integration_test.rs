use candid::{decode_one, encode_args, encode_one, Principal};
use once_cell::sync::Lazy;
use pocket_ic::PocketIc;

static PIC: Lazy<PocketIc> = Lazy::new(|| PocketIc::new());

static WASM_BYTES: Lazy<Vec<u8>> = Lazy::new(|| {
    let wasm_path = std::env::var_os("TEST_CANISTER").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
});

fn install_canister(pic: &PocketIc) -> Principal {
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, WASM_BYTES.clone(), vec![], None);

    canister_id
}

fn set_policy(pic: &PocketIc, canister_id: Principal, policy: &str) {
    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "set_policy",
        encode_one(&policy).expect("Couldn't encode policy"),
    )
    .expect("Failed to set the policy");
}

fn call_idempotent(
    pic: &PocketIc,
    canister_id: Principal,
    id: u64,
    deadline: u64,
    use_unbounded_wait: bool,
) -> Result<u64, String> {
    let response = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "call_idempotent",
            encode_args((id, deadline, use_unbounded_wait)).expect("Couldn't encode args"),
        )
        .expect("Failed to call retry canister");

    decode_one(&response).expect("Failed to decode response: {}")
}

#[test]
fn test_with_no_failures() -> Result<(), String> {
    for use_unbounded_wait in [false, true] {
        let canister_id = install_canister(&PIC);

        let curr_time = PIC.get_time().as_nanos_since_unix_epoch();
        let deadline = curr_time + 300_000_000_000; // 300 seconds in the future

        let res = call_idempotent(&PIC, canister_id, 1, deadline, use_unbounded_wait);

        assert_eq!(
            res,
            Ok(1),
            "Failed with use_unbounded_wait = {}",
            use_unbounded_wait
        );
    }

    Ok(())
}

#[test]
fn deadline_respected() -> Result<(), String> {
    for use_unbounded_wait in [false, true] {
        let canister_id = install_canister(&PIC);

        set_policy(&PIC, canister_id, "DenyAll");

        let curr_time = PIC.get_time().as_nanos_since_unix_epoch();
        // Use a very short deadline of 20 nanoseconds in the future, since
        // PocketIC doesn't like when the canister takes a long time to respond
        let deadline = curr_time + 50;

        let res = call_idempotent(&PIC, canister_id, 1, deadline, use_unbounded_wait);

        assert!(
            res.is_err(),
            "Expected an error, but got a success with use_unbounded_wait = {}",
            use_unbounded_wait
        );
        assert!(
            PIC.get_time().as_nanos_since_unix_epoch() >= deadline,
            "Expected that the call failed because the deadline expired with use_unbounded_wait = {}",
            use_unbounded_wait
        );
    }

    Ok(())
}

#[test]
fn stopping_respected() -> Result<(), String> {
    for use_unbounded_wait in [false, true] {
        let canister_id = install_canister(&PIC);

        set_policy(&PIC, canister_id, "DenyAll");

        let curr_time = PIC.get_time().as_nanos_since_unix_epoch();
        let deadline = curr_time + 300_000_000_000; // 5 minutes in the future

        let request_id = PIC
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "call_idempotent",
                encode_args((1_u64, deadline, use_unbounded_wait)).expect("Couldn't encode args"),
            )
            .expect("Failed to call canister");
        PIC.tick();

        // Stop the canister
        PIC.stop_canister(canister_id, None)
            .expect("Couldn't stop the canister");

        // Wait for the call to finish
        let response: Result<u64, String> =
            decode_one(&PIC.await_call(request_id).expect("Failed to await call"))
                .expect("Failed to decode response");

        assert!(
            response.is_err(),
            "Expected an error, but got a success with use_unbounded_wait = {}",
            use_unbounded_wait
        );
        assert!(
            PIC.get_time().as_nanos_since_unix_epoch() < deadline,
            "Expected that the call failed because we tried stopping, not because the deadline expired with use_unbounded_wait = {}",
            use_unbounded_wait
        );
    }

    Ok(())
}

#[test]
fn intermittent_failures_overcome() -> Result<(), String> {
    for use_unbounded_wait in [false, true] {
        let canister_id = install_canister(&PIC);

        set_policy(&PIC, canister_id, "WithProbability");

        let curr_time = PIC.get_time().as_nanos_since_unix_epoch();
        let deadline = curr_time + 300_000_000_000; // 5 minutes in the future
        const NR_IDS: u64 = 10;

        for i in 0..NR_IDS {
            let res = call_idempotent(&PIC, canister_id, i, deadline, use_unbounded_wait);

            assert_eq!(
                res,
                Ok(i + 1),
                "Failed with use_unbounded_wait = {}",
                use_unbounded_wait
            );
        }
    }

    Ok(())
}

#[test]
fn fail_quickly_on_synchronous_errors() -> Result<(), String> {
    for use_unbounded_wait in [false, true] {
        // First set a policy to a "regular" denyall, then issue a "submit call"
        // with a longer timeout, then change the policy to a synchronous deny all,
        // and check that it returns immediately
        let canister_id = install_canister(&PIC);
        set_policy(&PIC, canister_id, "DenyAll");
        let curr_time = PIC.get_time().as_nanos_since_unix_epoch();
        let deadline = curr_time + 300_000_000_000; // 5 minutes in the future

        let request_id = PIC
            .submit_call(
                canister_id,
                Principal::anonymous(),
                "call_idempotent",
                encode_args((1_u64, deadline, use_unbounded_wait)).expect("Couldn't encode args"),
            )
            .expect("Failed to call canister");
        PIC.tick();
        // Change the policy to a synchronous deny all
        set_policy(&PIC, canister_id, "DenyAllSynchronously");
        // Wait for the call to finish
        let response: Result<u64, String> =
            decode_one(&PIC.await_call(request_id).expect("Failed to await call"))
                .expect("Failed to decode response");
        assert!(
            response.is_err(),
            "Expected an error, but got a success with use_unbounded_wait = {}",
            use_unbounded_wait
        );
        assert!(
            PIC.get_time().as_nanos_since_unix_epoch() < deadline,
            "Expected that the call failed because it hit a synchronous error, not because the deadline expired with use_unbounded_wait = {}",
            use_unbounded_wait
        );
    }
    Ok(())
}

fn call_non_idempotent(
    pic: &PocketIc,
    canister_id: Principal,
    use_unbounded_wait: bool,
) -> Result<u64, String> {
    let response = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "call_non_idempotent",
            encode_one(use_unbounded_wait).expect("Couldn't encode args"),
        )
        .expect("Failed to call canister");
    decode_one(&response).expect("Failed to decode response")
}

#[test]
fn nonidempotent_not_retried_on_canister_reject() -> Result<(), String> {
    for use_unbounded_wait in [false, true] {
        let canister_id = install_canister(&PIC);
        set_policy(&PIC, canister_id, "DenyWithCanisterReject");
        let curr_time = PIC.get_time().as_nanos_since_unix_epoch();
        let deadline = curr_time + 1_000_000_000; // 1 second in the future

        let res = call_non_idempotent(&PIC, canister_id, use_unbounded_wait);

        assert!(
            res.is_err(),
            "Expected an error, but got a success with use_unbounded_wait = {}",
            use_unbounded_wait
        );
        assert!(
            PIC.get_time().as_nanos_since_unix_epoch() < deadline,
            "Expected that the call failed because it hit a canister reject, not because the deadline expired with use_unbounded_wait = {}",
            use_unbounded_wait
        );
    }

    Ok(())
}

#[test]
fn nonidempotent_not_retried_on_sys_unknown() -> Result<(), String> {
    let canister_id = install_canister(&PIC);
    set_policy(&PIC, canister_id, "DenyWithSysUnknown");
    let curr_time = PIC.get_time().as_nanos_since_unix_epoch();
    let deadline = curr_time + 1_000_000; // 1 second in the future
    let res = call_non_idempotent(&PIC, canister_id, false);
    assert!(
        res.is_err(),
        "Expected an error, but got a success with use_unbounded_wait = {}",
        false
    );
    assert!(
        PIC.get_time().as_nanos_since_unix_epoch() < deadline,
        "Expected that the call failed because it hit a SYS_UNKNOWN, not because the deadline expired with use_unbounded_wait = {}",
        false
    );

    // Check that the call wasn't retried under the hood
    let response = PIC.query_call(canister_id, Principal::anonymous(), "get_counter", vec![])
        .expect("Failed to call get_counter");
    let counter: u64 = decode_one(&response).expect("Failed to decode the counter");

    assert_eq!(counter, 0, "The counter should not have been increased beyond once");

    Ok(())
}
