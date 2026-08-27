use super::*;
use crate::pb::v1::canister_settings::Controllers;
use ic_base_types::PrincipalId;

#[test]
fn test_root_canister_settings_try_from_forwards_every_field() {
    let canister_settings = crate::pb::v1::CanisterSettings {
        controllers: Some(Controllers {
            controllers: vec![PrincipalId::new_user_test_id(1)],
        }),
        compute_allocation: Some(10),
        memory_allocation: Some(1 << 30),
        freezing_threshold: Some(100),
        log_visibility: Some(LogVisibility::Public as i32),
        snapshot_visibility: Some(SnapshotVisibility::Public as i32),
        wasm_memory_limit: Some(1 << 31),
        wasm_memory_threshold: Some(1 << 32),
        reserved_cycles_limit: Some(1 << 29),
    };

    let root_settings = RootCanisterSettings::try_from(&canister_settings).unwrap();

    assert_eq!(
        root_settings,
        RootCanisterSettings {
            controllers: Some(vec![PrincipalId::new_user_test_id(1)]),
            compute_allocation: Some(Nat::from(10_u64)),
            memory_allocation: Some(Nat::from(1_u64 << 30)),
            freezing_threshold: Some(Nat::from(100_u64)),
            reserved_cycles_limit: Some(Nat::from(1_u64 << 29)),
            log_visibility: Some(RootLogVisibility::Public),
            snapshot_visibility: Some(RootSnapshotVisibility::Public),
            wasm_memory_limit: Some(Nat::from(1_u64 << 31)),
            wasm_memory_threshold: Some(Nat::from(1_u64 << 32)),
        },
    );
}

#[test]
fn test_root_canister_settings_try_from_all_none() {
    let canister_settings = crate::pb::v1::CanisterSettings::default();

    let root_settings = RootCanisterSettings::try_from(&canister_settings).unwrap();

    assert_eq!(root_settings, RootCanisterSettings::default());
}

#[test]
fn test_root_canister_settings_try_from_rejects_invalid_log_visibility() {
    let canister_settings = crate::pb::v1::CanisterSettings {
        log_visibility: Some(LogVisibility::Unspecified as i32),
        ..Default::default()
    };

    let result = RootCanisterSettings::try_from(&canister_settings);

    assert!(result.is_err());
}

#[test]
fn test_root_canister_settings_try_from_rejects_invalid_snapshot_visibility() {
    let canister_settings = crate::pb::v1::CanisterSettings {
        snapshot_visibility: Some(SnapshotVisibility::Unspecified as i32),
        ..Default::default()
    };

    let result = RootCanisterSettings::try_from(&canister_settings);

    assert!(result.is_err());
}
