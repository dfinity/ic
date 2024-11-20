use candid::Principal;
use pocket_ic::{CanisterSettings, PocketIc};
use std::process::Command;

const POCKET_IC_CLI: &str = "POCKET_IC_CLI";

#[test]
fn change_controllers() {
    let pic = PocketIc::new();

    // A test user identity for which we don't have a private key.
    let user_id = Principal::from_slice(&[u8::MAX; 29]);

    // Create an empty canister and set the test user identity as the only controller.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100_000_000_000_000);
    let settings = CanisterSettings {
        controllers: Some(vec![user_id]),
        ..Default::default()
    };
    pic.update_canister_settings(canister_id, None, settings)
        .unwrap();
    let status = pic.canister_status(canister_id, Some(user_id)).unwrap();
    assert_eq!(status.settings.controllers, vec![user_id]);

    // Use `pocket-ic-cli` to add a pair of additional controllers.
    let add_controller_id = Principal::from_slice(&[42; 29]);
    let add_another_controller_id = Principal::from_slice(&[43; 29]);
    let pocketic_cli_path = std::env::var_os(POCKET_IC_CLI).unwrap();
    let out = Command::new(pocketic_cli_path.clone())
        .arg("--server-url")
        .arg(pic.get_server_url().as_str())
        .arg("canister")
        .arg(canister_id.to_string())
        .arg("--instance-id")
        .arg(pic.instance_id().to_string())
        .arg("--sender")
        .arg(user_id.to_string())
        .arg("update-settings")
        .arg("--add-controller")
        .arg(add_controller_id.to_string())
        .arg("--add-controller")
        .arg(add_another_controller_id.to_string())
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout, "Successfully executed.\n");
    assert!(out.status.success());
    let status = pic.canister_status(canister_id, Some(user_id)).unwrap();
    let new_controllers = status.settings.controllers;
    assert_eq!(new_controllers.len(), 3);
    assert!(new_controllers.contains(&user_id));
    assert!(new_controllers.contains(&add_controller_id));
    assert!(new_controllers.contains(&add_another_controller_id));

    // Failed attempt to add an additional controller if the sender does not control the canister.
    let add_yet_another_controller_id = Principal::from_slice(&[44; 29]);
    let out = Command::new(pocketic_cli_path)
        .arg("--server-url")
        .arg(pic.get_server_url().as_str())
        .arg("canister")
        .arg(canister_id.to_string())
        .arg("--instance-id")
        .arg(pic.instance_id().to_string())
        .arg("update-settings")
        .arg("--add-controller")
        .arg(add_yet_another_controller_id.to_string())
        .output()
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains(&format!(
        "Only controllers of canister {} can call ic00 method canister_status",
        canister_id
    )));
    assert!(!out.status.success());
    let status = pic.canister_status(canister_id, Some(user_id)).unwrap();
    let new_controllers = status.settings.controllers;
    assert_eq!(new_controllers.len(), 3);
}
