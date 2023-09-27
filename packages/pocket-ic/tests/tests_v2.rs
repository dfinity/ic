use candid::Principal;
use ic_cdk::api::management_canister::main::CreateCanisterArgument;
use pocket_ic::PocketIcV2;
use std::time::SystemTime;

#[test]
fn test_get_and_set_time() {
    let pic = PocketIcV2::new();
    pic.set_time(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890));
    let time = pic.get_time();
    assert_eq!(
        time,
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1234567890)
    );
}

#[test]
fn test_update_call() {
    let pic = PocketIcV2::new();
    let canister_id = Principal::management_canister();
    let user = Principal::anonymous();

    let res = pic.update_call(
        canister_id,
        user,
        "provisional_create_canister_with_cycles",
        candid::encode_args((CreateCanisterArgument { settings: None },)).unwrap(),
    );
    assert!(res.is_ok());
    // TODO: check reply and see if it contains a canister id
}
