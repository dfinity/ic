use super::*;
use crate::{
    governance::{Governance as GovernanceStruct, ValidGovernanceProto},
    pb::sns_root_types::Extensions,
    pb::v1::governance::Mode as ModePb,
    types::test_helpers::NativeEnvironment,
};
use futures::FutureExt;
use ic_nervous_system_canisters::{cmc::MockCMC, ledger::MockICRC1Ledger};
use ic_protobuf::types::v1::CanisterInstallMode as CanisterInstallModeProto;
use ic_test_utilities_types::ids::canister_test_id;
use lazy_static::lazy_static;
use maplit::btreemap;
use pretty_assertions::assert_eq;

lazy_static! {
    static ref ROOT_CANISTER_ID: CanisterId = canister_test_id(500);
    static ref GOVERNANCE_CANISTER_ID: CanisterId = canister_test_id(501);
    static ref LEDGER_CANISTER_ID: CanisterId = canister_test_id(502);
    static ref SWAP_CANISTER_ID: CanisterId = canister_test_id(503);
    static ref INDEX_CANISTER_ID: CanisterId = canister_test_id(504);
    static ref ARCHIVE_CANISTER_ID: CanisterId = canister_test_id(505);
    static ref DAPP_CANISTER_ID: CanisterId = canister_test_id(600);
    static ref OTHER_DAPP_CANISTER_ID: CanisterId = canister_test_id(601);
    static ref EXTENSION_CANISTER_ID: CanisterId = canister_test_id(700);
    static ref UNREGISTERED_CANISTER_ID: CanisterId = canister_test_id(800);
}

fn snapshot_id(canister_id: CanisterId, local_id: u64) -> Vec<u8> {
    SnapshotId::from((canister_id, local_id)).to_vec()
}

fn list_sns_canisters_response() -> ListSnsCanistersResponse {
    ListSnsCanistersResponse {
        root: Some(ROOT_CANISTER_ID.get()),
        governance: Some(GOVERNANCE_CANISTER_ID.get()),
        ledger: Some(LEDGER_CANISTER_ID.get()),
        swap: Some(SWAP_CANISTER_ID.get()),
        index: Some(INDEX_CANISTER_ID.get()),
        archives: vec![ARCHIVE_CANISTER_ID.get()],
        dapps: vec![DAPP_CANISTER_ID.get(), OTHER_DAPP_CANISTER_ID.get()],
        extensions: Some(Extensions {
            extension_canister_ids: vec![EXTENSION_CANISTER_ID.get()],
        }),
    }
}

/// An environment in which Root knows about the canisters above, and where no other calls are
/// expected.
fn new_env() -> NativeEnvironment {
    let mut env = NativeEnvironment::new(Some(*GOVERNANCE_CANISTER_ID));
    env.default_canister_call_response = Err((Some(1), "Unexpected call!".to_string()));
    env.set_call_canister_response(
        *ROOT_CANISTER_ID,
        "list_sns_canisters",
        Encode!(&ListSnsCanistersRequest {}).unwrap(),
        Ok(Encode!(&list_sns_canisters_response()).unwrap()),
    );
    env
}

/// An environment where no canister calls are expected at all.
fn new_env_that_expects_no_calls() -> NativeEnvironment {
    let mut env = NativeEnvironment::new(Some(*GOVERNANCE_CANISTER_ID));
    env.default_canister_call_response = Err((Some(1), "Unexpected call!".to_string()));
    env
}

fn new_governance(env: NativeEnvironment) -> GovernanceStruct {
    new_governance_with_proposals(env, BTreeMap::new())
}

fn new_governance_with_proposals(
    env: NativeEnvironment,
    proposals: BTreeMap<u64, ProposalData>,
) -> GovernanceStruct {
    let governance_proto = Governance {
        proposals,
        root_canister_id: Some(ROOT_CANISTER_ID.get()),
        ledger_canister_id: Some(LEDGER_CANISTER_ID.get()),
        swap_canister_id: Some(SWAP_CANISTER_ID.get()),
        sns_metadata: Some(SnsMetadata {
            logo: None,
            url: Some("https://example.com".to_string()),
            name: Some("Example".to_string()),
            description: Some("Very descriptive description".to_string()),
        }),
        parameters: Some(NervousSystemParameters::with_default_values()),
        mode: ModePb::Normal.into(),
        ..Default::default()
    };

    GovernanceStruct::new(
        ValidGovernanceProto::try_from(governance_proto).unwrap(),
        Box::new(env),
        Box::new(MockICRC1Ledger::default()),
        Box::new(MockICRC1Ledger::default()),
        Box::new(MockCMC::default()),
    )
}

fn validate_take(take_canister_snapshot: &TakeCanisterSnapshot) -> Result<String, String> {
    validate_and_render_take_canister_snapshot(
        take_canister_snapshot,
        &new_env(),
        *ROOT_CANISTER_ID,
        std::iter::empty(),
    )
    .now_or_never()
    .unwrap()
}

fn validate_load(load_canister_snapshot: &LoadCanisterSnapshot) -> Result<String, String> {
    validate_and_render_load_canister_snapshot(
        load_canister_snapshot,
        &new_env(),
        *ROOT_CANISTER_ID,
    )
    .now_or_never()
    .unwrap()
}

fn validate_action(action: Action, env: NativeEnvironment) -> Result<String, String> {
    let governance = new_governance(env);
    validate_and_render_action(&Some(action), &governance, vec![])
        .now_or_never()
        .unwrap()
        .map(|(rendering, _action_auxiliary)| rendering)
}

fn upgrade_with(
    take_canister_snapshot: Option<TakeSnapshotBeforeUpgrade>,
) -> UpgradeSnsControlledCanister {
    UpgradeSnsControlledCanister {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        canister_upgrade_arg: None,
        mode: Some(CanisterInstallModeProto::Upgrade.into()),
        chunked_canister_wasm: None,
        canister_upgrade_options: None,
        take_canister_snapshot,
    }
}

fn validate_upgrade(upgrade: &UpgradeSnsControlledCanister) -> Result<String, String> {
    validate_and_render_upgrade_sns_controlled_canister(
        upgrade,
        &new_env_that_expects_no_calls(),
        *ROOT_CANISTER_ID,
    )
    .now_or_never()
    .unwrap()
}

#[track_caller]
fn assert_err_contains(result: Result<String, String>, expected_substrings: &[&str]) {
    let err = match result {
        Ok(rendering) => panic!("Expected an error, but got Ok:\n{rendering}"),
        Err(err) => err,
    };
    for expected_substring in expected_substrings {
        assert!(
            err.contains(expected_substring),
            "Expected the error to contain {expected_substring:?}, but it was:\n{err}"
        );
    }
}

// ---------------------------------------------------------------------------
// validate_snapshot_id_of_canister
// ---------------------------------------------------------------------------

#[test]
fn test_validate_snapshot_id_of_canister() {
    // Ok.
    assert_eq!(
        validate_snapshot_id_of_canister(
            "snapshot_id",
            &snapshot_id(*DAPP_CANISTER_ID, 7),
            *DAPP_CANISTER_ID,
        ),
        Ok(SnapshotId::from((*DAPP_CANISTER_ID, 7))),
    );

    // A snapshot of a different canister.
    let err = validate_snapshot_id_of_canister(
        "snapshot_id",
        &snapshot_id(*OTHER_DAPP_CANISTER_ID, 7),
        *DAPP_CANISTER_ID,
    )
    .unwrap_err();
    assert!(
        err.contains(&format!(
            "is a snapshot of canister {}, not of the target canister {}",
            *OTHER_DAPP_CANISTER_ID, *DAPP_CANISTER_ID,
        )),
        "{err}"
    );

    // Malformed IDs.
    for malformed in [
        vec![],
        vec![1, 2, 3],
        // Too long.
        vec![0; SnapshotId::MAX_LENGTH_IN_BYTES + 1],
    ] {
        let err = validate_snapshot_id_of_canister("snapshot_id", &malformed, *DAPP_CANISTER_ID)
            .unwrap_err();
        assert!(
            err.contains("snapshot_id is not a valid snapshot ID"),
            "{err}"
        );
    }

    // Just the local ID (i.e. without the canister ID) is also not good enough.
    let err =
        validate_snapshot_id_of_canister("snapshot_id", &7_u64.to_be_bytes(), *DAPP_CANISTER_ID)
            .unwrap_err();
    assert!(err.contains("not of the target canister"), "{err}");
}

// ---------------------------------------------------------------------------
// TakeCanisterSnapshot
// ---------------------------------------------------------------------------

#[test]
fn test_take_canister_snapshot_renders() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    let rendering = validate_take(&TakeCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        replace_snapshot: None,
    })
    .unwrap();

    assert_eq!(
        rendering,
        format!(
            "# Proposal to Take a Snapshot of a Dapp Canister\n\
             \n\
             ## Target canister: {}\n\
             \n\
             ## Replaced snapshot\n\
             \n\
             None. (If the canister already has the maximum number of snapshots, this will fail.)\n\
             \n\
             ## About snapshots\n\
             \n\
             A snapshot holds a canister's Wasm module, (heap and stable) memory, and chunk \
             store, but not its settings, controllers, or cycles. The canister is stopped while \
             the snapshot is taken, and started again afterwards. The snapshot counts towards the \
             canister's memory usage (and is paid for by the canister) for as long as it exists.\n\
             \n\
             If this proposal is executed successfully, the ID of the new snapshot will be \
             recorded in this proposal's success_value.",
            *DAPP_CANISTER_ID,
        ),
    );
}

#[test]
fn test_take_canister_snapshot_with_replace_snapshot_renders() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();
    let replace_snapshot = snapshot_id(*DAPP_CANISTER_ID, 3);

    let rendering = validate_take(&TakeCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        replace_snapshot: Some(replace_snapshot.clone()),
    })
    .unwrap();

    let expected = format!(
        "## Replaced snapshot\n\n`{}` ({}-3) will be deleted, once the new snapshot has been \
         taken.",
        hex::encode(&replace_snapshot),
        *DAPP_CANISTER_ID,
    );
    assert!(rendering.contains(&expected), "{rendering}");
}

#[test]
fn test_take_canister_snapshot_rejects_replace_snapshot_of_other_canister() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    let result = validate_take(&TakeCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        replace_snapshot: Some(snapshot_id(*OTHER_DAPP_CANISTER_ID, 3)),
    });

    assert_err_contains(
        result,
        &[
            "TakeCanisterSnapshot was invalid",
            "replace_snapshot",
            &format!("is a snapshot of canister {}", *OTHER_DAPP_CANISTER_ID),
        ],
    );
}

#[test]
fn test_take_canister_snapshot_rejects_malformed_replace_snapshot() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    for malformed in [vec![], vec![42; 3]] {
        let result = validate_take(&TakeCanisterSnapshot {
            canister_id: Some(DAPP_CANISTER_ID.get()),
            replace_snapshot: Some(malformed),
        });

        assert_err_contains(result, &["replace_snapshot is not a valid snapshot ID"]);
    }
}

#[test]
fn test_take_canister_snapshot_requires_canister_id() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    let result = validate_take(&TakeCanisterSnapshot {
        canister_id: None,
        replace_snapshot: None,
    });

    assert_err_contains(result, &["canister_id field must be populated"]);
}

/// The canisters that must not be targeted by snapshot proposals, together with how they are
/// described in the resulting error.
fn non_dapp_canisters() -> Vec<(CanisterId, &'static str)> {
    vec![
        (*ROOT_CANISTER_ID, "is the SNS Root canister"),
        (*GOVERNANCE_CANISTER_ID, "is the SNS Governance canister"),
        (*LEDGER_CANISTER_ID, "is the SNS Ledger canister"),
        (*SWAP_CANISTER_ID, "is the SNS Swap canister"),
        (*INDEX_CANISTER_ID, "is the SNS Index canister"),
        (*ARCHIVE_CANISTER_ID, "is an SNS Ledger Archive canister"),
        (*EXTENSION_CANISTER_ID, "is an SNS extension"),
        (*UNREGISTERED_CANISTER_ID, "is not registered with this SNS"),
    ]
}

#[test]
fn test_take_canister_snapshot_rejects_non_dapp_canisters() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    for (canister_id, role) in non_dapp_canisters() {
        let result = validate_take(&TakeCanisterSnapshot {
            canister_id: Some(canister_id.get()),
            replace_snapshot: None,
        });

        assert_err_contains(
            result,
            &[
                &format!("Canister {canister_id} {role}"),
                "Only registered dapp canisters are allowed here",
            ],
        );
    }
}

#[test]
fn test_take_canister_snapshot_fails_when_root_cannot_list_canisters() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    // Root is not mocked, so the list_sns_canisters call fails.
    let result = validate_and_render_take_canister_snapshot(
        &TakeCanisterSnapshot {
            canister_id: Some(DAPP_CANISTER_ID.get()),
            replace_snapshot: None,
        },
        &new_env_that_expects_no_calls(),
        *ROOT_CANISTER_ID,
        std::iter::empty(),
    )
    .now_or_never()
    .unwrap();

    assert_err_contains(result, &["Root.list_sns_canisters failed"]);
}

// ---------------------------------------------------------------------------
// LoadCanisterSnapshot
// ---------------------------------------------------------------------------

#[test]
fn test_load_canister_snapshot_renders() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();
    let snapshot_id = snapshot_id(*DAPP_CANISTER_ID, 5);

    let rendering = validate_load(&LoadCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        snapshot_id: Some(snapshot_id.clone()),
    })
    .unwrap();

    assert_eq!(
        rendering,
        format!(
            "# Proposal to Load a Snapshot into a Dapp Canister\n\
             \n\
             ## Target canister: {dapp}\n\
             \n\
             ## Snapshot: `{hex}` ({dapp}-5)\n\
             \n\
             ## Warning: All state written after the snapshot was taken will be lost\n\
             \n\
             If adopted, the canister's Wasm module and (heap and stable) memory will be replaced \
             with the ones saved in the snapshot. This rolls the canister back to the state it \
             was in when the snapshot was taken: everything the canister stored or changed since \
             then will be lost. Effects outside of the canister (such as token transfers, or calls \
             that it made to other canisters) are not undone.\n\
             \n\
             A snapshot holds a canister's Wasm module, (heap and stable) memory, and chunk \
             store, but not its settings, controllers, or cycles. The canister is stopped while \
             the snapshot is loaded, and started again afterwards.",
            dapp = *DAPP_CANISTER_ID,
            hex = hex::encode(&snapshot_id),
        ),
    );
}

#[test]
fn test_load_canister_snapshot_rejects_snapshot_of_other_canister() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    // Both canisters are registered dapps (and both are controlled by Root), but a snapshot of
    // one must not be loaded into the other.
    let result = validate_load(&LoadCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        snapshot_id: Some(snapshot_id(*OTHER_DAPP_CANISTER_ID, 5)),
    });

    assert_err_contains(
        result,
        &[
            "LoadCanisterSnapshot was invalid",
            &format!(
                "is a snapshot of canister {}, not of the target canister {}",
                *OTHER_DAPP_CANISTER_ID, *DAPP_CANISTER_ID,
            ),
        ],
    );
}

#[test]
fn test_load_canister_snapshot_rejects_snapshot_of_core_canister() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    let result = validate_load(&LoadCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        snapshot_id: Some(snapshot_id(*GOVERNANCE_CANISTER_ID, 0)),
    });

    assert_err_contains(result, &["not of the target canister"]);
}

#[test]
fn test_load_canister_snapshot_rejects_malformed_snapshot_id() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    for malformed in [
        vec![],
        vec![42; 3],
        vec![0; SnapshotId::MAX_LENGTH_IN_BYTES + 1],
    ] {
        let result = validate_load(&LoadCanisterSnapshot {
            canister_id: Some(DAPP_CANISTER_ID.get()),
            snapshot_id: Some(malformed),
        });

        assert_err_contains(result, &["snapshot_id is not a valid snapshot ID"]);
    }
}

#[test]
fn test_load_canister_snapshot_requires_fields() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    assert_err_contains(
        validate_load(&LoadCanisterSnapshot {
            canister_id: Some(DAPP_CANISTER_ID.get()),
            snapshot_id: None,
        }),
        &["snapshot_id field must be populated"],
    );
    assert_err_contains(
        validate_load(&LoadCanisterSnapshot {
            canister_id: None,
            snapshot_id: Some(snapshot_id(*DAPP_CANISTER_ID, 5)),
        }),
        &["canister_id field must be populated"],
    );
}

#[test]
fn test_load_canister_snapshot_rejects_non_dapp_canisters() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    for (canister_id, role) in non_dapp_canisters() {
        // The snapshot ID is consistent with the target, so that only the target is wrong.
        let result = validate_load(&LoadCanisterSnapshot {
            canister_id: Some(canister_id.get()),
            snapshot_id: Some(snapshot_id(canister_id, 0)),
        });

        assert_err_contains(
            result,
            &[
                &format!("Canister {canister_id} {role}"),
                "Only registered dapp canisters are allowed here",
            ],
        );
    }
}

// ---------------------------------------------------------------------------
// UpgradeSnsControlledCanister.take_canister_snapshot
// ---------------------------------------------------------------------------

#[test]
fn test_upgrade_with_take_canister_snapshot_renders() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    let without_snapshot = validate_upgrade(&upgrade_with(None)).unwrap();
    let with_snapshot = validate_upgrade(&upgrade_with(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: None,
    })))
    .unwrap();

    assert_eq!(
        with_snapshot,
        format!(
            "{without_snapshot}\n\
             \n\
             ## Snapshot before upgrade\n\
             \n\
             A snapshot of the canister will be taken right before the new code is installed. \
             If taking the snapshot fails, the canister will not be upgraded. The ID of the new \
             snapshot will be recorded in this proposal's success_value; it can be used in a \
             LoadCanisterSnapshot proposal to restore the canister to its pre-upgrade state."
        ),
    );
}

#[test]
fn test_upgrade_with_take_canister_snapshot_and_replace_snapshot_renders() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();
    let replace_snapshot = snapshot_id(*DAPP_CANISTER_ID, 9);

    let rendering = validate_upgrade(&upgrade_with(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: Some(replace_snapshot.clone()),
    })))
    .unwrap();

    assert!(
        rendering.ends_with(&format!(
            "pre-upgrade state.\n\nThe new snapshot replaces the existing snapshot `{}` ({}-9).",
            hex::encode(&replace_snapshot),
            *DAPP_CANISTER_ID,
        )),
        "{rendering}"
    );
}

#[test]
fn test_upgrade_without_take_canister_snapshot_renders_as_before() {
    // The flag does not matter when take_canister_snapshot is not set.
    for enabled in [true, false] {
        let _flag = if enabled {
            crate::temporarily_enable_canister_snapshot_proposals()
        } else {
            crate::temporarily_disable_canister_snapshot_proposals()
        };

        let rendering = validate_upgrade(&upgrade_with(None)).unwrap();

        assert!(!rendering.contains("napshot"), "{rendering}");
        assert!(rendering.ends_with("No upgrade argument."), "{rendering}");
    }
}

#[test]
fn test_upgrade_rejects_replace_snapshot_of_other_canister() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    let result = validate_upgrade(&upgrade_with(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: Some(snapshot_id(*OTHER_DAPP_CANISTER_ID, 9)),
    })));

    assert_err_contains(
        result,
        &[
            "UpgradeSnsControlledCanister was invalid",
            "take_canister_snapshot.replace_snapshot",
            &format!("is a snapshot of canister {}", *OTHER_DAPP_CANISTER_ID),
        ],
    );
}

#[test]
fn test_upgrade_rejects_malformed_replace_snapshot() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    let result = validate_upgrade(&upgrade_with(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: Some(vec![1, 2, 3]),
    })));

    assert_err_contains(
        result,
        &["take_canister_snapshot.replace_snapshot is not a valid snapshot ID"],
    );
}

// ---------------------------------------------------------------------------
// Feature flag
// ---------------------------------------------------------------------------

#[test]
fn test_canister_snapshot_proposals_are_rejected_when_disabled() {
    let _disabled = crate::temporarily_disable_canister_snapshot_proposals();

    // No canister calls are expected: the flag is checked first.
    assert_err_contains(
        validate_action(
            Action::TakeCanisterSnapshot(TakeCanisterSnapshot {
                canister_id: Some(DAPP_CANISTER_ID.get()),
                replace_snapshot: None,
            }),
            new_env_that_expects_no_calls(),
        ),
        &["Canister snapshot proposals are not yet enabled"],
    );
    assert_err_contains(
        validate_action(
            Action::LoadCanisterSnapshot(LoadCanisterSnapshot {
                canister_id: Some(DAPP_CANISTER_ID.get()),
                snapshot_id: Some(snapshot_id(*DAPP_CANISTER_ID, 0)),
            }),
            new_env_that_expects_no_calls(),
        ),
        &["Canister snapshot proposals are not yet enabled"],
    );
    assert_err_contains(
        validate_upgrade(&upgrade_with(Some(TakeSnapshotBeforeUpgrade {
            replace_snapshot: None,
        }))),
        &["take_canister_snapshot cannot be used: Canister snapshot proposals are not yet enabled"],
    );
}

#[test]
fn test_canister_snapshot_proposals_are_disabled_by_default_in_production_builds() {
    assert_eq!(
        crate::are_canister_snapshot_proposals_enabled(),
        cfg!(feature = "test"),
    );
}

#[test]
fn test_validate_and_render_action_dispatches_canister_snapshot_actions() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();

    let take = validate_action(
        Action::TakeCanisterSnapshot(TakeCanisterSnapshot {
            canister_id: Some(DAPP_CANISTER_ID.get()),
            replace_snapshot: None,
        }),
        new_env(),
    )
    .unwrap();
    assert!(
        take.starts_with("# Proposal to Take a Snapshot of a Dapp Canister"),
        "{take}"
    );

    let load = validate_action(
        Action::LoadCanisterSnapshot(LoadCanisterSnapshot {
            canister_id: Some(DAPP_CANISTER_ID.get()),
            snapshot_id: Some(snapshot_id(*DAPP_CANISTER_ID, 0)),
        }),
        new_env(),
    )
    .unwrap();
    assert!(
        load.starts_with("# Proposal to Load a Snapshot into a Dapp Canister"),
        "{load}"
    );
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

fn take_action() -> Action {
    Action::TakeCanisterSnapshot(TakeCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        replace_snapshot: None,
    })
}

fn load_action() -> Action {
    Action::LoadCanisterSnapshot(LoadCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        snapshot_id: Some(snapshot_id(*DAPP_CANISTER_ID, 0)),
    })
}

#[test]
fn test_canister_snapshot_action_ids() {
    use crate::types::NativeAction;

    assert_eq!(NativeAction::TakeCanisterSnapshot as u64, 20);
    assert_eq!(NativeAction::LoadCanisterSnapshot as u64, 21);
    assert_eq!(u64::from(&take_action()), 20);
    assert_eq!(u64::from(&load_action()), 21);

    let take_function = NervousSystemFunction::from(take_action());
    assert_eq!(take_function.id, 20);
    assert_eq!(take_function.name, "Take canister snapshot");
    let load_function = NervousSystemFunction::from(load_action());
    assert_eq!(load_function.id, 21);
    assert_eq!(load_function.name, "Load canister snapshot");

    // They are native functions (e.g. for the purposes of following).
    let native_function_ids = Action::native_function_ids();
    assert!(native_function_ids.contains(&20), "{native_function_ids:?}");
    assert!(native_function_ids.contains(&21), "{native_function_ids:?}");
    let listed_ids = crate::types::native_action_ids::nervous_system_functions()
        .into_iter()
        .map(|function| function.id)
        .collect::<Vec<_>>();
    assert!(listed_ids.contains(&20), "{listed_ids:?}");
    assert!(listed_ids.contains(&21), "{listed_ids:?}");
}

#[test]
fn test_canister_snapshot_actions_are_upgrade_proposals() {
    for action in [take_action(), load_action()] {
        // When the action itself is set.
        let proposal_data = ProposalData {
            action: u64::from(&action),
            proposal: Some(Proposal {
                action: Some(action.clone()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(proposal_data.is_upgrade_proposal(), "{action:?}");

        // When only the action ID is set (as in some tests).
        let proposal_data = ProposalData {
            action: u64::from(&action),
            ..Default::default()
        };
        assert!(proposal_data.is_upgrade_proposal(), "{action:?}");
    }
}

#[test]
fn test_canister_snapshot_actions_allowed_when_resources_are_low() {
    // Load is the emergency rollback, so like UpgradeSnsControlledCanister, it is allowed even
    // when resources are low. Taking (yet another) snapshot is not urgent.
    assert!(load_action().allowed_when_resources_are_low());
    assert!(!take_action().allowed_when_resources_are_low());

    let proposal = Proposal {
        action: Some(load_action()),
        ..Default::default()
    };
    assert!(proposal.allowed_when_resources_are_low());
}

#[test]
fn test_canister_snapshot_actions_are_not_limited_in_proposal_listings() {
    // These actions have no large blob fields, so they are returned as is.
    for action in [take_action(), load_action()] {
        assert_eq!(action.limited_for_get_proposal(), action);
        assert_eq!(action.limited_for_list_proposals(), action);
    }

    // take_canister_snapshot survives the limiting of UpgradeSnsControlledCanister.
    let upgrade = upgrade_with(Some(TakeSnapshotBeforeUpgrade {
        replace_snapshot: Some(snapshot_id(*DAPP_CANISTER_ID, 9)),
    }));
    let action = Action::UpgradeSnsControlledCanister(upgrade.clone());
    for limited in [
        action.limited_for_get_proposal(),
        action.limited_for_list_proposals(),
    ] {
        let Action::UpgradeSnsControlledCanister(limited) = limited else {
            panic!("{limited:?}");
        };
        assert_eq!(
            limited.take_canister_snapshot,
            upgrade.take_canister_snapshot
        );
    }
}

#[test]
fn test_success_value_is_kept_in_proposal_listings() {
    let success_value = Some(crate::pb::v1::SuccessfulProposalExecutionValue {
        proposal_type: Some(
            crate::pb::v1::successful_proposal_execution_value::ProposalType::TakeCanisterSnapshot(
                crate::pb::v1::TakeCanisterSnapshotOk {
                    snapshot_id: snapshot_id(*DAPP_CANISTER_ID, 1),
                    taken_at_timestamp: 123,
                    total_size: 456,
                },
            ),
        ),
    });
    let proposal_data = ProposalData {
        success_value: success_value.clone(),
        ..Default::default()
    };

    assert_eq!(
        proposal_data
            .limited_for_list_proposals(&Default::default())
            .success_value,
        success_value
    );
    assert_eq!(
        proposal_data.limited_for_get_proposal().success_value,
        success_value
    );
}

// ---------------------------------------------------------------------------
// Snapshots that are about to be loaded must not be replaced
// ---------------------------------------------------------------------------

/// A proposal to load the given snapshot, in the given state.
fn load_proposal(id: u64, snapshot_id: Vec<u8>, status: ProposalDecisionStatus) -> ProposalData {
    let action = Action::LoadCanisterSnapshot(LoadCanisterSnapshot {
        canister_id: Some(DAPP_CANISTER_ID.get()),
        snapshot_id: Some(snapshot_id),
    });
    let yes = Tally {
        yes: 1,
        no: 0,
        total: 1,
        timestamp_seconds: 1,
    };
    let no = Tally {
        yes: 0,
        no: 1,
        total: 1,
        timestamp_seconds: 1,
    };
    let (
        latest_tally,
        decided_timestamp_seconds,
        executed_timestamp_seconds,
        failed_timestamp_seconds,
    ) = match status {
        ProposalDecisionStatus::Open => (None, 0, 0, 0),
        ProposalDecisionStatus::Adopted => (Some(yes), 1, 0, 0),
        ProposalDecisionStatus::Executed => (Some(yes), 1, 2, 0),
        ProposalDecisionStatus::Failed => (Some(yes), 1, 0, 2),
        ProposalDecisionStatus::Rejected => (Some(no), 1, 0, 0),
        ProposalDecisionStatus::Unspecified => panic!(),
    };
    let proposal_data = ProposalData {
        action: u64::from(&action),
        id: Some(ProposalId { id }),
        proposal: Some(Proposal {
            action: Some(action),
            ..Default::default()
        }),
        latest_tally,
        decided_timestamp_seconds,
        executed_timestamp_seconds,
        failed_timestamp_seconds,
        ..Default::default()
    };
    assert_eq!(proposal_data.status(), status);
    proposal_data
}

fn validate_action_with_proposals(
    action: Action,
    proposals: BTreeMap<u64, ProposalData>,
) -> Result<String, String> {
    let governance = new_governance_with_proposals(new_env(), proposals);
    validate_and_render_action(&Some(action), &governance, vec![])
        .now_or_never()
        .unwrap()
        .map(|(rendering, _action_auxiliary)| rendering)
}

/// The actions that would replace (i.e. delete) the given snapshot.
fn actions_that_replace(snapshot_id: Vec<u8>) -> Vec<Action> {
    vec![
        Action::TakeCanisterSnapshot(TakeCanisterSnapshot {
            canister_id: Some(DAPP_CANISTER_ID.get()),
            replace_snapshot: Some(snapshot_id.clone()),
        }),
        Action::UpgradeSnsControlledCanister(upgrade_with(Some(TakeSnapshotBeforeUpgrade {
            replace_snapshot: Some(snapshot_id),
        }))),
    ]
}

#[test]
fn test_replace_snapshot_is_refused_while_a_load_of_it_is_pending() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();
    let snapshot = snapshot_id(*DAPP_CANISTER_ID, 5);

    for action in actions_that_replace(snapshot.clone()) {
        for status in [
            ProposalDecisionStatus::Open,
            ProposalDecisionStatus::Adopted,
        ] {
            let result = validate_action_with_proposals(
                action.clone(),
                btreemap! { 7 => load_proposal(7, snapshot.clone(), status) },
            );

            assert_err_contains(
                result,
                &[
                    &format!(
                        "The snapshot `{}` ({}-5) cannot be replaced",
                        hex::encode(&snapshot),
                        *DAPP_CANISTER_ID,
                    ),
                    "because it would be loaded by proposal(s) 7, which have not been executed yet",
                ],
            );
        }
    }
}

#[test]
fn test_replace_snapshot_is_allowed_once_the_load_is_no_longer_pending() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();
    let snapshot = snapshot_id(*DAPP_CANISTER_ID, 5);
    let other_snapshot = snapshot_id(*DAPP_CANISTER_ID, 6);

    for action in actions_that_replace(snapshot.clone()) {
        for status in [
            ProposalDecisionStatus::Executed,
            ProposalDecisionStatus::Failed,
            ProposalDecisionStatus::Rejected,
        ] {
            let result = validate_action_with_proposals(
                action.clone(),
                btreemap! { 7 => load_proposal(7, snapshot.clone(), status) },
            );
            assert!(result.is_ok(), "{action:?} {status:?}: {result:?}");
        }

        // A pending load of a different snapshot does not matter either.
        let result = validate_action_with_proposals(
            action.clone(),
            btreemap! { 7 => load_proposal(7, other_snapshot.clone(), ProposalDecisionStatus::Open) },
        );
        assert!(result.is_ok(), "{action:?}: {result:?}");
    }
}

#[test]
fn test_pending_proposals_that_load_snapshot() {
    let snapshot = snapshot_id(*DAPP_CANISTER_ID, 5);
    let proposals = btreemap! {
        1 => load_proposal(1, snapshot.clone(), ProposalDecisionStatus::Open),
        2 => load_proposal(2, snapshot.clone(), ProposalDecisionStatus::Adopted),
        3 => load_proposal(3, snapshot.clone(), ProposalDecisionStatus::Executed),
        4 => load_proposal(4, snapshot.clone(), ProposalDecisionStatus::Failed),
        5 => load_proposal(5, snapshot.clone(), ProposalDecisionStatus::Rejected),
        6 => load_proposal(6, snapshot_id(*DAPP_CANISTER_ID, 6), ProposalDecisionStatus::Open),
        // Not a load at all.
        7 => ProposalData {
            id: Some(ProposalId { id: 7 }),
            proposal: Some(Proposal {
                action: Some(take_action()),
                ..Default::default()
            }),
            ..Default::default()
        },
    };

    assert_eq!(
        pending_proposals_that_load_snapshot(proposals.values(), &snapshot),
        vec![1, 2],
    );
    assert_eq!(
        check_snapshot_is_not_about_to_be_loaded(
            proposals.values(),
            &snapshot_id(*DAPP_CANISTER_ID, 99),
            "replaced"
        ),
        Ok(()),
    );
}
