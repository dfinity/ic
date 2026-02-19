mod test_utilities;
use candid::Principal;
use ic_cdk::management_canister::{CanisterSettings, EnvironmentVariable, UpdateSettingsArgs};
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn bindgen() {
    let wasm = cargo_build_canister("bindgen");
    let callee_wasm = cargo_build_canister("bindgen_callee");

    let pic = pic_base().build();

    let callee_canister_id = pic.create_canister();
    pic.add_cycles(callee_canister_id, 100_000_000_000_000);
    pic.install_canister(callee_canister_id, callee_wasm, vec![], None);

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);
    // Make the callee canister a controller of the main canister.
    // We will impersonate a management canister call to set the env var later.
    pic.set_controllers(canister_id, None, vec![callee_canister_id])
        .expect("failed to set controllers");

    let _: () = update(&pic, canister_id, "call_management_canister", ()).unwrap();

    // The required env var is not set, so the call will fail.
    let required_env_var = "ICP_CANISTER_ID:bindgen_callee";
    let res: Result<(), _> = update(&pic, canister_id, "call_bindgen_callee", ());
    assert!(res.unwrap_err().reject_message.contains(&format!(
        "env var `{}` is not set. Canister controller can set it using tools like icp-cli.",
        required_env_var
    )));

    // Set a invalid value for the required env var.
    // Then the call will fail for a different reason.
    let effective_principal =
        pocket_ic::common::rest::RawEffectivePrincipal::CanisterId(canister_id.as_slice().to_vec());
    let invalid_value = "Not a Principal";
    let settings = CanisterSettings {
        environment_variables: Some(vec![EnvironmentVariable {
            name: required_env_var.into(),
            value: invalid_value.to_string(),
        }]),
        ..Default::default()
    };
    let args = UpdateSettingsArgs {
        canister_id,
        settings,
    };
    let _: () = pocket_ic::call_candid_as(
        &pic,
        Principal::management_canister(),
        effective_principal.clone(),
        callee_canister_id,
        "update_settings",
        (args,),
    )
    .expect("failed to call update_settings for setting env var");
    let res: Result<(), _> = update(&pic, canister_id, "call_bindgen_callee", ());
    assert!(res.unwrap_err().reject_message.contains(&format!(
        "failed to parse Principal from env var `{}`, value `{}`",
        required_env_var, invalid_value
    )));

    // Set the required env var.
    // This is expected to be set automatically by `icp-cli`.
    let settings = CanisterSettings {
        environment_variables: Some(vec![EnvironmentVariable {
            name: required_env_var.into(),
            value: callee_canister_id.to_string(),
        }]),
        ..Default::default()
    };
    let args = UpdateSettingsArgs {
        canister_id,
        settings,
    };

    let _: () = pocket_ic::call_candid_as(
        &pic,
        Principal::management_canister(),
        effective_principal,
        callee_canister_id,
        "update_settings",
        (args,),
    )
    .expect("failed to call update_settings for setting env var");
    let _: () = update(&pic, canister_id, "call_bindgen_callee", ()).unwrap();
}
