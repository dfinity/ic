use candid::{decode_one, encode_args, encode_one, Principal};
use once_cell::sync::Lazy;
use pocket_ic::PocketIc;

static TARGET_V1_BYTES: Lazy<Vec<u8>> = Lazy::new(|| {
    let wasm_path = std::env::var_os("TARGET_TEST_CANISTER_V1").expect("Missing test canister v1 wasm file");
    std::fs::read(wasm_path).unwrap()
});

const TARGET_V2_BYTES: Lazy<Vec<u8>> = Lazy::new(|| {
    let wasm_path = std::env::var_os("TARGET_TEST_CANISTER_V2").expect("Missing test canister v2 wasm file");
    std::fs::read(wasm_path).unwrap()
});

const UPGRADER_BYTES: Lazy<Vec<u8>> = Lazy::new(|| {
    let wasm_path = std::env::var_os("UPGRADER_TEST_CANISTER").expect("Missing upgrader canister wasm file");
    std::fs::read(wasm_path).unwrap()
});


fn install_canisters(pic: &PocketIc) -> (Principal, Principal) {
    let upgrader_canister_id = pic.create_canister();
    pic.add_cycles(upgrader_canister_id, 2_000_000_000_000);
    pic.install_canister(upgrader_canister_id, UPGRADER_BYTES.clone(), vec![], None);

    let target_canister_id = pic.create_canister();
    pic.add_cycles(target_canister_id, 2_000_000_000_000);
    pic.install_canister(target_canister_id, TARGET_V1_BYTES.clone(), vec![], None);
    pic.set_controllers(
        target_canister_id,
        None,
        vec![upgrader_canister_id, target_canister_id, Principal::anonymous()],
    ).expect("Couldn't set controllers");

    (upgrader_canister_id, target_canister_id)
}

fn set_policy(pic: &PocketIc, canister_id: Principal, policy: &str) {
    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "set_call_chaos_policy",
        encode_one(&policy).expect("Couldn't encode policy"),
    )
    .expect("Failed to set the policy");
}

fn try_upgrading_target(
    pic: &PocketIc,
    upgrader_canister_id: Principal,
    target_canister_id: Principal,
    deadline: u64,
    chunked: bool,
) -> Result<(), String> {
    let target_v2_wasm_bytes = TARGET_V2_BYTES.clone();

    let message_id = pic
        .submit_call(
            upgrader_canister_id,
            Principal::anonymous(),
            "try_upgrading_target",
            encode_args((target_canister_id, target_v2_wasm_bytes, deadline, chunked))
                .expect("Couldn't encode args"),
        )
        .expect("Failed to call try_upgrading_canister");

    while pic.get_time().as_nanos_since_unix_epoch() < deadline && pic.ingress_status(message_id.clone()).is_none() {
        pic.tick();
    }

    let response = pic.await_call(message_id).expect("Failed to await call");

    decode_one(&response).expect("Failed to decode response")
}

fn version_check(
    pic: &PocketIc,
    canister_id: Principal,
    expected_version: u32,
    expected_total_versions: usize,
) -> Result<(), String> {
    let response = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "version",
            encode_one(&()).expect("Couldn't encode args"),
        )
        .map_err(|e| format!("Failed to call version check: {}", e))?;

    let version: u32 = decode_one(&response).expect("Failed to decode response");
    assert_eq!(version, expected_version, "Version mismatch");

    let response = pic.update_call(
        canister_id,
        Principal::anonymous(),
        "self_history",
        encode_one(&()).expect("Couldn't encode args"),
    ).map_err(|e| format!("Failed to call self_history: {}", e))?;

    let history: Vec<Vec<u8>> = decode_one(&response).expect("Failed to decode response");

    assert_eq!(history.len(), expected_total_versions);

    Ok(())

}

fn upgrade_works_when_no_failures(chunked: bool) -> Result<(), String> {
    let pic = &PocketIc::new();
    let (upgrader_canister_id, target_canister_id) = install_canisters(pic);
    set_policy(pic, upgrader_canister_id, "AllowAll");

    let curr_time = pic.get_time().as_nanos_since_unix_epoch();
    let deadline = curr_time + 50; // 50 rounds to have some breathing room
    let res = try_upgrading_target(pic, upgrader_canister_id, target_canister_id, deadline, chunked);
    assert!(res.is_ok(), "Upgrade failed: {:?}", res);

    version_check(pic, target_canister_id, 2, 2)?;

    Ok(())
}

#[test]
fn upgrade_nonchunked_works_when_no_failures() -> Result<(), String> {
    upgrade_works_when_no_failures(false)
}

#[test]
fn upgrade_chunked_works_when_no_failures() -> Result<(), String>  {
    upgrade_works_when_no_failures(true)
}

fn upgrade_works_with_allow_every_other_policy(chunked: bool) -> Result<(), String> {
    let pic = &PocketIc::new();
    let (upgrader_canister_id, target_canister_id) = install_canisters(pic);
    set_policy(pic, upgrader_canister_id, "AllowEveryOther");

    let curr_time = pic.get_time().as_nanos_since_unix_epoch();
    let deadline = curr_time + 50; // 50 rounds, to allow for some failures
    let res = try_upgrading_target(pic, upgrader_canister_id, target_canister_id, deadline, chunked);
    assert!(res.is_ok(), "Upgrade failed: {:?}", res);

    version_check(pic, target_canister_id, 2, 2)?;

    Ok(())
}

#[test]
fn upgrade_nonchunked_works_with_allow_every_other_policy() -> Result<(), String> {
    upgrade_works_with_allow_every_other_policy(false)
}

#[test]
fn upgrade_chunked_works_with_allow_every_other_policy() -> Result<(), String> {
    upgrade_works_with_allow_every_other_policy(true)
}

fn upgrade_works_with_probability_policy(chunked: bool) -> Result<(), String> {
    let pic = &PocketIc::new();
    // We install the upgrader canister only once, as reinstalling it
    // times would reset the PRNG and we wouldn't end up testing different failure
    // scenarios. It's OK to reinstall the target canister multiple times, though.
    let (upgrader_canister_id, target_canister_id) = install_canisters(pic);
    set_policy(pic, upgrader_canister_id, "WithProbability");

    // Run multiple times to make WithProbability (hopefully) hit different failure points
    for i in 0..5 {
        let curr_time = pic.get_time().as_nanos_since_unix_epoch();
        let deadline = curr_time + 5_000; // 5000 rounds to make sure we get lucky enough to get the 5-6 messages through
        let res = try_upgrading_target(pic, upgrader_canister_id, target_canister_id, deadline, chunked);
        assert!(res.is_ok(), "Upgrade failed: {:?}", res);

        version_check(pic, target_canister_id, 2, 2*(i+1))?;
        pic.reinstall_canister(target_canister_id, TARGET_V1_BYTES.clone(), vec![], None).expect("Could not reinstall canister");
    }

    Ok(())
}

#[test]
fn upgrade_nonchunked_works_with_probability_policy() -> Result<(), String> {
    upgrade_works_with_probability_policy(false)
}

#[test]
fn upgrade_chunked_works_with_probability_policy() -> Result<(), String> {
    upgrade_works_with_probability_policy(true)
}

fn set_fail_at_stage_policy(pic: &PocketIc, canister_id: Principal, stage: u32) -> () {
    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "set_fail_at_stage_policy",
        encode_one(&stage).expect("Couldn't encode policy number"),
    )
    .expect("Failed to set the policy");
}

fn upgrade_respects_stopping(chunked: bool) -> Result<(), String> {
    let pic = &PocketIc::new();

    // Test each stage of the upgrade process
    for stage in 0..4 {
        let (upgrader_canister_id, target_canister_id) = install_canisters(pic);
        set_fail_at_stage_policy(pic, upgrader_canister_id, stage);

        let curr_time = pic.get_time().as_nanos_since_unix_epoch();
        let deadline = curr_time + 100; // 100 rounds in the future, should be enough not to trigger failures due to stopping

        // Start the upgrade
        let target_v2_wasm_bytes = TARGET_V2_BYTES.clone();
        let request_id = pic.submit_call(
            upgrader_canister_id,
            Principal::anonymous(),
            "try_upgrading_target",
            encode_args((target_canister_id, target_v2_wasm_bytes, deadline, chunked))
                .expect("Couldn't encode args"),
        ).expect("Failed to submit upgrade call");

        pic.tick();

        // Stop the canister
        pic.stop_canister(upgrader_canister_id, None).expect("Failed to stop canister");

        while pic.get_time().as_nanos_since_unix_epoch() < deadline {
            pic.tick();
        }

        // Wait for the call to finish
        let response: Result<(), String> = decode_one(&pic.await_call(request_id).expect("Failed to await call"))
            .expect("Failed to decode response");

        // The upgrade should fail due to stopping
        assert!(response.is_err(), "Upgrade should fail when canister is stopped");

        // Start the canister again if needed to check the version
        if stage > 0 {
            pic.start_canister(target_canister_id, None).expect("Failed to start target canister");
        }

        // Verify version hasn't changed
        version_check(pic, target_canister_id, 1, 1)?;
    }

    Ok(())
}

#[test]
fn upgrade_nonchunked_respects_stopping() -> Result<(), String> {
    upgrade_respects_stopping(false)
}

#[test]
fn upgrade_chunked_respects_stopping() -> Result<(), String> {
    upgrade_respects_stopping(true)
}

fn upgrade_respects_deadline(chunked: bool) -> Result<(), String> {
    let pic = &PocketIc::new();

    // Test each stage of the upgrade process
    for stage in 0..4 {
        let (upgrader_canister_id, target_canister_id) = install_canisters(pic);

        set_fail_at_stage_policy(pic, upgrader_canister_id, stage);

        let curr_time = pic.get_time().as_nanos_since_unix_epoch();
        let deadline = curr_time + 50;

        // Start the upgrade
        let target_v2_wasm_bytes = TARGET_V2_BYTES.clone();
        let request_id = pic.submit_call(
            upgrader_canister_id,
            Principal::anonymous(),
            "try_upgrading_target",
            encode_args((target_canister_id, target_v2_wasm_bytes, deadline, chunked))
                .expect("Couldn't encode args"),
        ).expect("Failed to submit upgrade call");

        while pic.get_time().as_nanos_since_unix_epoch() <= deadline {
            pic.tick();
        }

        pic.tick();

        // Wait for the call to finish
        let response: Result<(), String> = decode_one(&pic.await_call(request_id).expect("Failed to await call"))
            .expect("Failed to decode response");

        // The upgrade should fail due to deadline
        assert!(response.is_err(), "Upgrade should fail when deadline is reached");

        // If we're not failing calls at the first stage, we'll have to restart the canister
        // before checking the version
        if stage > 0 {
            pic.start_canister(target_canister_id, None).expect("Failed to start target canister");
        }
        let (expected_version, total_versions) = if stage < 3 {
            (1, 1)
        } else {
            (2, 2)
        };
        // Verify version hasn't changed
        println!("Failing in stage {}", stage);
        version_check(pic, target_canister_id, expected_version, total_versions)?;
    }

    Ok(())
}

#[test]
fn upgrade_nonchunked_respects_deadline() -> Result<(), String> {
    upgrade_respects_deadline(false)
}

#[test]
fn upgrade_chunked_respects_deadline() -> Result<(), String> {
    upgrade_respects_deadline(true)
}



