use super::*;
use crate::types::test_helpers::NativeEnvironment;
use futures::FutureExt;
use ic_test_utilities_types::ids::canister_test_id;

fn root_canister_id() -> CanisterId {
    canister_test_id(500)
}

fn dapp_canister_id() -> CanisterId {
    canister_test_id(600)
}

/// Root knows about one dapp canister (dapp_canister_id).
fn new_env() -> NativeEnvironment {
    let mut env = NativeEnvironment::new(Some(canister_test_id(501)));
    // Validating an upgrade with an embedded Wasm makes no other canister calls.
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

fn snapshot_id(canister_id: CanisterId, local_id: u64) -> Vec<u8> {
    SnapshotId::from((canister_id, local_id)).to_vec()
}

#[test]
fn test_upgrade_with_take_canister_snapshot_validation_and_rendering() {
    let _enabled = crate::temporarily_enable_canister_snapshot_proposals();
    let upgrade = |replace_snapshot| UpgradeSnsControlledCanister {
        canister_id: Some(dapp_canister_id().get()),
        new_canister_wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
        take_canister_snapshot: Some(TakeSnapshotBeforeUpgrade { replace_snapshot }),
        ..Default::default()
    };
    let validate = |upgrade: UpgradeSnsControlledCanister| {
        validate_and_render_upgrade_sns_controlled_canister(
            &upgrade,
            &new_env(),
            root_canister_id(),
        )
        .now_or_never()
        .unwrap()
    };

    let rendering = validate(upgrade(Some(snapshot_id(dapp_canister_id(), 1)))).unwrap();
    assert!(
        rendering.ends_with(&format!(
            "## Snapshot before upgrade\n\n\
             A snapshot of the canister will be taken right before the new code is installed. \
             If that fails, the canister will not be upgraded. It replaces the existing \
             snapshot `{}`.",
            hex::encode(snapshot_id(dapp_canister_id(), 1)),
        )),
        "{rendering}"
    );

    // replace_snapshot must be a snapshot of the target canister.
    let err = validate(upgrade(Some(snapshot_id(canister_test_id(601), 1)))).unwrap_err();
    assert!(err.contains("not of the target canister"), "{err}");

    // The target must be a registered dapp canister (SNS Root refuses anything else), e.g. not
    // SNS Governance, nor SNS Root itself.
    for canister_id in [
        canister_test_id(501),
        root_canister_id(),
        canister_test_id(602),
    ] {
        let err = validate(UpgradeSnsControlledCanister {
            canister_id: Some(canister_id.get()),
            ..upgrade(None)
        })
        .unwrap_err();
        assert!(
            err.contains(&format!(
                "Canister {canister_id} is not a dapp canister registered with this SNS"
            )),
            "{err}"
        );
    }

    // Not available unless enabled.
    let _disabled = crate::temporarily_disable_canister_snapshot_proposals();
    let err = validate(upgrade(None)).unwrap_err();
    assert!(
        err.contains("take_canister_snapshot is not yet enabled"),
        "{err}"
    );
}
