use candid::Principal;
use ic_cdk::management_canister::{
    CanisterInfoResult, CanisterInstallMode, Change, ChangeDetails, ChangeOrigin,
    CodeDeploymentMode::{Install, Reinstall, Upgrade},
    CodeDeploymentRecord, ControllersChangeRecord, CreationRecord, FromCanisterRecord,
    FromUserRecord, InstallCodeArgs, UninstallCodeArgs,
};
use pocket_ic::{call_candid_as, common::rest::RawEffectivePrincipal};

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn test_canister_info() {
    let wasm = cargo_build_canister("canister_info");
    let pic = pic_base().build();
    // As of PocketIC server v5.0.0 and client v4.0.0, the first canister creation happens at (time0+4).
    // Each operation advances the Pic by 2 nanos, except for the last operation which advances only by 1 nano.
    let time0: u64 = pic.get_time().as_nanos_since_unix_epoch();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 2_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);

    let new_canister: (Principal,) = update(&pic, canister_id, "canister_lifecycle", ())
        .expect("Error calling canister_lifecycle");

    let () = call_candid_as(
        &pic,
        Principal::management_canister(),
        RawEffectivePrincipal::None,
        Principal::anonymous(),
        "uninstall_code",
        (UninstallCodeArgs {
            canister_id: new_canister.0,
        },),
    )
    .expect("Error calling uninstall_code");
    let () = call_candid_as(
        &pic,
        Principal::management_canister(),
        RawEffectivePrincipal::None,
        Principal::anonymous(),
        "install_code",
        (InstallCodeArgs {
            mode: CanisterInstallMode::Install,
            arg: vec![],
            wasm_module: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
            canister_id: new_canister.0,
        },),
    )
    .expect("Error calling install_code");

    let info: (CanisterInfoResult,) =
        update(&pic, canister_id, "info", (new_canister.0,)).expect("Error calling canister_info");

    assert_eq!(
        info.0,
        CanisterInfoResult {
            total_num_changes: 9,
            recent_changes: vec![
                Change {
                    timestamp_nanos: time0 + 4,
                    canister_version: 0,
                    origin: ChangeOrigin::FromCanister(FromCanisterRecord {
                        canister_id,
                        canister_version: Some(1)
                    }),
                    details: Some(ChangeDetails::Creation(CreationRecord {
                        controllers: vec![canister_id],
                        environment_variables_hash: None
                    })),
                },
                Change {
                    timestamp_nanos: time0 + 6,
                    canister_version: 1,
                    origin: ChangeOrigin::FromCanister(FromCanisterRecord {
                        canister_id,
                        canister_version: Some(2)
                    }),
                    details: Some(ChangeDetails::CodeDeployment(CodeDeploymentRecord {
                        mode: Install,
                        module_hash: hex::decode(
                            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476"
                        )
                        .unwrap(),
                    })),
                },
                Change {
                    timestamp_nanos: time0 + 8,
                    canister_version: 2,
                    origin: ChangeOrigin::FromCanister(FromCanisterRecord {
                        canister_id,
                        canister_version: Some(3)
                    }),
                    details: Some(ChangeDetails::CodeUninstall),
                },
                Change {
                    timestamp_nanos: time0 + 10,
                    canister_version: 3,
                    origin: ChangeOrigin::FromCanister(FromCanisterRecord {
                        canister_id,
                        canister_version: Some(4)
                    }),
                    details: Some(ChangeDetails::CodeDeployment(CodeDeploymentRecord {
                        mode: Install,
                        module_hash: hex::decode(
                            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476"
                        )
                        .unwrap(),
                    })),
                },
                Change {
                    timestamp_nanos: time0 + 12,
                    canister_version: 4,
                    origin: ChangeOrigin::FromCanister(FromCanisterRecord {
                        canister_id,
                        canister_version: Some(5)
                    }),
                    details: Some(ChangeDetails::CodeDeployment(CodeDeploymentRecord {
                        mode: Reinstall,
                        module_hash: hex::decode(
                            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476"
                        )
                        .unwrap(),
                    })),
                },
                Change {
                    timestamp_nanos: time0 + 14,
                    canister_version: 5,
                    origin: ChangeOrigin::FromCanister(FromCanisterRecord {
                        canister_id,
                        canister_version: Some(6)
                    }),
                    details: Some(ChangeDetails::CodeDeployment(CodeDeploymentRecord {
                        mode: Upgrade,
                        module_hash: hex::decode(
                            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476"
                        )
                        .unwrap(),
                    })),
                },
                Change {
                    timestamp_nanos: time0 + 16,
                    canister_version: 6,
                    origin: ChangeOrigin::FromCanister(FromCanisterRecord {
                        canister_id,
                        canister_version: Some(7)
                    }),
                    details: Some(ChangeDetails::ControllersChange(ControllersChangeRecord {
                        controllers: vec![Principal::anonymous(), canister_id, new_canister.0]
                    })),
                },
                Change {
                    timestamp_nanos: time0 + 18,
                    canister_version: 7,
                    origin: ChangeOrigin::FromUser(FromUserRecord {
                        user_id: Principal::anonymous(),
                    }),
                    details: Some(ChangeDetails::CodeUninstall),
                },
                Change {
                    timestamp_nanos: time0 + 19,
                    canister_version: 8,
                    origin: ChangeOrigin::FromUser(FromUserRecord {
                        user_id: Principal::anonymous(),
                    }),
                    details: Some(ChangeDetails::CodeDeployment(CodeDeploymentRecord {
                        mode: Install,
                        module_hash: hex::decode(
                            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476"
                        )
                        .unwrap(),
                    })),
                },
            ],
            module_hash: Some(
                hex::decode("93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476")
                    .unwrap()
            ),
            controllers: vec![Principal::anonymous(), canister_id, new_canister.0],
        }
    );
}
