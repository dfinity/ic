use candid::{decode_args, encode_one, Principal};
use once_cell::sync::Lazy;
use pocket_ic::PocketIc;

static WASM_NO_FEATURE: Lazy<Vec<u8>> = Lazy::new(|| {
    let wasm_path = std::env::var_os("TEST_CANISTER_NO_CALL_CHAOS").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
});

static WASM_WITH_FEATURE: Lazy<Vec<u8>> = Lazy::new(|| {
    let wasm_path = std::env::var_os("TEST_CANISTER_WITH_CALL_CHAOS").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
});


fn call_ping(
    pic: &PocketIc,
    canister_id: Principal,
    times: u32,
) -> Result<(u32, u32, u32), String> {
    let response = pic
        .update_call(
            canister_id,
            Principal::anonymous(),
            "call_ping",
            encode_one(&times).expect("Couldn't encode times"),
        )
        .expect("Failed to call counter canister");

    decode_args(&response).map_err(|e| format!("Failed to decode response: {}", e))
}

#[test]
fn test_without_call_chaos() -> Result<(), String> {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, WASM_NO_FEATURE.clone(), vec![], None);

    let times = 10_u32;

    let (succeeded, failed, nr_pings) = call_ping(&pic, canister_id, times)?;

    assert_eq!(succeeded, times);
    assert_eq!(nr_pings, times);
    assert_eq!(failed, 0);

    Ok(())
}

#[test]
fn test_with_call_chaos() -> Result<(), String> {
    let pic = PocketIc::new();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, WASM_WITH_FEATURE.clone(), vec![], None);

    let times = 10_u32;

    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "set_policy",
        encode_one("AllowAll").expect("Couldn't encode policy"),
    )
    .expect("Failed to set policy");

    let (succeeded, failed, nr_pings): (u32, u32, u32) = call_ping(&pic, canister_id, times)?;

    assert_eq!(succeeded, times);
    assert_eq!(failed, 0);
    assert_eq!(nr_pings, times);

    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "set_policy",
        encode_one("AllowEveryOther").expect("Couldn't encode policy"),
    )
    .expect("Failed to set policy");

    let (succeeded, failed, nr_pings): (u32, u32, u32) = call_ping(&pic, canister_id, times)?;
    assert_eq!(succeeded + failed, times);
    assert_eq!(succeeded, times / 2);
    assert_eq!(failed, times / 2);
    assert_eq!(nr_pings, times / 2);

    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "set_policy",
        encode_one("DenyAll").expect("Couldn't encode policy"),
    )
    .expect("Failed to set policy");

    let (succeeded, failed, nr_pings): (u32, u32, u32) = call_ping(&pic, canister_id, times)?;
    assert_eq!(succeeded + failed, times);
    assert_eq!(succeeded, 0);
    assert_eq!(failed, times);
    assert_eq!(nr_pings, 0);

    pic.update_call(
        canister_id,
        Principal::anonymous(),
        "set_policy",
        encode_one("WithProbability").expect("Couldn't encode policy"),
    )
    .expect("Failed to set policy");

    let (succeeded, failed, nr_pings): (u32, u32, u32) = call_ping(&pic, canister_id, times)?;
    // Can't assert the exact number of succeeded and failed calls, but we can assert that
    // the sum of succeeded and failed is equal to times
    assert_eq!(succeeded + failed, times);
    assert!(succeeded <= nr_pings, "Calls that are known to have succeeded shouldn't be more than the calls that actually succeeded");
    assert!(nr_pings <= times);

    Ok(())
}
