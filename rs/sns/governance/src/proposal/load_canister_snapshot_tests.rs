use super::*;
use crate::types::{NativeAction, test_helpers::NativeEnvironment};
use futures::FutureExt;
use ic_test_utilities_types::ids::canister_test_id;
use pretty_assertions::assert_eq;

fn root_canister_id() -> CanisterId {
    canister_test_id(500)
}

fn dapp_canister_id() -> CanisterId {
    canister_test_id(600)
}

/// Root knows about one dapp canister (dapp_canister_id).
fn new_env() -> NativeEnvironment {
    let mut env = NativeEnvironment::new(Some(canister_test_id(501)));
    env.default_canister_call_response = Err((Some(1), "Unexpected call!".to_string()));
    env.set_call_canister_response(
        root_canister_id(),
        "list_sns_canisters",
        Encode!(&ListSnsCanistersRequest {}).unwrap(),
        Ok(Encode!(&ListSnsCanistersResponse {
            root: Some(root_canister_id().get()),
            governance: Some(canister_test_id(501).get()),
            dapps: vec![dapp_canister_id().get()],
            ..Default::default()
        })
        .unwrap()),
    );
    env
}

fn validate(canister_id: CanisterId, snapshot_id: Vec<u8>) -> Result<String, String> {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();
    let load_canister_snapshot = LoadCanisterSnapshot {
        canister_id: Some(canister_id.get()),
        snapshot_id: Some(snapshot_id),
    };
    validate_and_render_load_canister_snapshot(
        &load_canister_snapshot,
        &new_env(),
        root_canister_id(),
    )
    .now_or_never()
    .unwrap()
}

fn snapshot_id(canister_id: CanisterId, local_id: u64) -> Vec<u8> {
    SnapshotId::from((canister_id, local_id)).to_vec()
}

#[test]
fn test_valid_load_canister_snapshot_is_rendered() {
    let snapshot_id = snapshot_id(dapp_canister_id(), 5);

    let rendering = validate(dapp_canister_id(), snapshot_id.clone()).unwrap();

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
             that it made to other canisters) are not undone.",
            dapp = dapp_canister_id(),
            hex = hex::encode(&snapshot_id),
        ),
    );
}

#[test]
fn test_snapshot_of_another_canister_is_rejected() {
    // Root controls all dapp canisters, so without this check, it could be told to load a
    // snapshot of one dapp canister into another.
    let other_dapp_canister_id = canister_test_id(601);

    let err = validate(dapp_canister_id(), snapshot_id(other_dapp_canister_id, 5)).unwrap_err();

    assert!(
        err.contains(&format!(
            "is a snapshot of canister {other_dapp_canister_id}, not of the target canister {}",
            dapp_canister_id(),
        )),
        "{err}"
    );
}

#[test]
fn test_malformed_snapshot_id_is_rejected() {
    for malformed_snapshot_id in [vec![], vec![1, 2, 3], vec![0; 100]] {
        let err = validate(dapp_canister_id(), malformed_snapshot_id).unwrap_err();

        assert!(
            err.contains("snapshot_id is not a valid snapshot ID"),
            "{err}"
        );
    }
}

#[test]
fn test_non_dapp_target_is_rejected() {
    // E.g. SNS Governance (or any other canister that is not a registered dapp).
    let governance_canister_id = canister_test_id(501);

    let err = validate(
        governance_canister_id,
        snapshot_id(governance_canister_id, 0),
    )
    .unwrap_err();

    assert!(
        err.contains("is not a dapp canister registered with this SNS"),
        "{err}"
    );
}

#[test]
fn test_load_canister_snapshot_is_rejected_when_not_enabled() {
    let _disabled = crate::temporarily_disable_canister_snapshot_proposals();
    let load_canister_snapshot = LoadCanisterSnapshot {
        canister_id: Some(dapp_canister_id().get()),
        snapshot_id: Some(snapshot_id(dapp_canister_id(), 5)),
    };

    let err = validate_and_render_load_canister_snapshot(
        &load_canister_snapshot,
        &new_env(),
        root_canister_id(),
    )
    .now_or_never()
    .unwrap()
    .unwrap_err();

    assert!(err.contains("not yet enabled"), "{err}");
}

#[test]
fn test_load_canister_snapshot_classification() {
    let action = Action::LoadCanisterSnapshot(LoadCanisterSnapshot::default());

    assert_eq!(
        u64::from(&action),
        NativeAction::LoadCanisterSnapshot as u64
    );
    assert_eq!(
        crate::pb::v1::Topic::get_topic_for_native_action(&action),
        Some(crate::pb::v1::Topic::DappCanisterManagement),
    );

    // Serialized with other upgrades.
    let proposal_data = ProposalData {
        action: u64::from(&action),
        ..Default::default()
    };
    assert!(proposal_data.is_upgrade_proposal());

    // Like an upgrade, a rollback might be urgent.
    assert!(action.allowed_when_resources_are_low());
}
