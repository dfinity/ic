//! End-to-end tests of SNS canister snapshots, with a real NNS and SNS (built from this branch)
//! in PocketIC.

use candid::{Decode, Encode, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId, SnapshotId};
use ic_management_canister_types::CanisterStatusType;
use ic_nervous_system_agent::sns::Sns;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        NnsInstaller, add_wasms_to_sns_wasm, install_canister_on_subnet, load_registry_mutations,
        nns, sns,
    },
};
use ic_nervous_system_root::{
    load_canister_snapshot::{
        LoadCanisterSnapshotError, LoadCanisterSnapshotOk, LoadCanisterSnapshotRequest,
        LoadCanisterSnapshotResponse,
    },
    take_canister_snapshot::{
        TakeCanisterSnapshotError, TakeCanisterSnapshotRequest, TakeCanisterSnapshotResponse,
    },
};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_sns_swap::pb::v1::Lifecycle;
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use tempfile::TempDir;

/// A counter: `inc` increments it, and `get` replies with its value (as a little-endian u32).
const COUNTER_WAT: &str = r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
        (memory 1)

        (func $inc
            (i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.const 1)))
            (call $msg_reply))

        (func $get
            (call $msg_reply_data_append (i32.const 0) (i32.const 4))
            (call $msg_reply))

        (export "canister_update inc" (func $inc))
        (export "canister_query get" (func $get))
    )
"#;

async fn inc(pocket_ic: &PocketIc, canister_id: CanisterId) {
    pocket_ic
        .update_call(canister_id.into(), Principal::anonymous(), "inc", vec![])
        .await
        .unwrap();
}

async fn get(pocket_ic: &PocketIc, canister_id: CanisterId) -> u32 {
    let reply = pocket_ic
        .query_call(canister_id.into(), Principal::anonymous(), "get", vec![])
        .await
        .unwrap();
    u32::from_le_bytes(reply.try_into().unwrap())
}

/// Installs the NNS, publishes the SNS Wasms built from this branch, creates a dapp canister
/// running COUNTER_WAT, and creates an SNS that controls it.
async fn set_up_sns_with_dapp(state_dir: &TempDir) -> (PocketIc, Sns, CanisterId) {
    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir.path().to_path_buf())
        .with_nns_subnet()
        .with_sns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let mut nns_installer = NnsInstaller::default();
    nns_installer
        .with_current_nns_canister_versions()
        .with_cycles_minting_canister()
        .with_cycles_ledger()
        .with_custom_registry_mutations(vec![load_registry_mutations(
            state_dir.path().join("registry.proto"),
        )]);
    nns_installer.install(&pocket_ic).await;

    let with_mainnet_sns_canisters = false;
    add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
        .await
        .unwrap();

    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];
    let dapp_canister_id = install_canister_on_subnet(
        &pocket_ic,
        app_subnet,
        vec![],
        Some(Wasm::from_bytes(wat::parse_str(COUNTER_WAT).unwrap())),
        vec![ROOT_CANISTER_ID.into()],
    )
    .await;

    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .with_dapp_canisters(vec![dapp_canister_id])
        .build();
    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();
    let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
        &pocket_ic,
        create_service_nervous_system,
        "1",
    )
    .await;
    sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .unwrap();
    sns::swap::smoke_test_participate_and_finalize(
        &pocket_ic,
        sns.swap.canister_id,
        swap_parameters,
    )
    .await;

    (pocket_ic, sns, dapp_canister_id)
}

/// Calls SNS Root's take_canister_snapshot as SNS Governance (its only allowed caller).
async fn root_take_canister_snapshot(
    pocket_ic: &PocketIc,
    sns: &Sns,
    canister_id: CanisterId,
) -> TakeCanisterSnapshotResponse {
    let reply = pocket_ic
        .update_call(
            sns.root.canister_id.0,
            sns.governance.canister_id.0,
            "take_canister_snapshot",
            Encode!(&TakeCanisterSnapshotRequest {
                canister_id: canister_id.get(),
                replace_snapshot: None,
            })
            .unwrap(),
        )
        .await
        .unwrap();
    Decode!(&reply, TakeCanisterSnapshotResponse).unwrap()
}

/// Calls SNS Root's load_canister_snapshot as SNS Governance (its only allowed caller).
async fn root_load_canister_snapshot(
    pocket_ic: &PocketIc,
    sns: &Sns,
    canister_id: CanisterId,
    snapshot_id: Vec<u8>,
) -> LoadCanisterSnapshotResponse {
    let reply = pocket_ic
        .update_call(
            sns.root.canister_id.0,
            sns.governance.canister_id.0,
            "load_canister_snapshot",
            Encode!(&LoadCanisterSnapshotRequest {
                canister_id: canister_id.get(),
                snapshot_id,
            })
            .unwrap(),
        )
        .await
        .unwrap();
    Decode!(&reply, LoadCanisterSnapshotResponse).unwrap()
}

/// SNS Root's take_canister_snapshot and load_canister_snapshot work on registered dapp
/// canisters, and refuse every other target (SNS Governance, SNS Root itself, the SNS Ledger, and
/// a canister that Root controls but that is not registered as a dapp canister), without touching
/// it.
#[tokio::test]
async fn test_root_snapshot_methods_only_target_registered_dapp_canisters() {
    // Step 1: Prepare the world.
    let state_dir = TempDir::new().unwrap();
    let (pocket_ic, sns, dapp_canister_id) = set_up_sns_with_dapp(&state_dir).await;
    let root_canister_id = CanisterId::unchecked_from_principal(sns.root.canister_id);
    let governance_canister_id = CanisterId::unchecked_from_principal(sns.governance.canister_id);
    let ledger_canister_id = CanisterId::unchecked_from_principal(sns.ledger.canister_id);

    // Root controls this canister (just like the dapp canister), but it was never registered as a
    // dapp canister. Therefore, only Root's own check can stop Root from operating on it.
    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];
    let unregistered_canister_id = install_canister_on_subnet(
        &pocket_ic,
        app_subnet,
        vec![],
        Some(Wasm::from_bytes(wat::parse_str(COUNTER_WAT).unwrap())),
        vec![sns.root.canister_id],
    )
    .await;

    // Step 2: The registered dapp canister can be snapshotted and rolled back.
    for _ in 0..3 {
        inc(&pocket_ic, dapp_canister_id).await;
    }
    let snapshot_id = match root_take_canister_snapshot(&pocket_ic, &sns, dapp_canister_id).await {
        TakeCanisterSnapshotResponse::Ok(ok) => ok.id,
        err => panic!("{err:?}"),
    };
    let snapshots = pocket_ic
        .list_canister_snapshots(dapp_canister_id.into(), Some(sns.root.canister_id.0))
        .await
        .unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].id, snapshot_id);
    for _ in 0..2 {
        inc(&pocket_ic, dapp_canister_id).await;
    }
    assert_eq!(get(&pocket_ic, dapp_canister_id).await, 5);
    assert_eq!(
        root_load_canister_snapshot(&pocket_ic, &sns, dapp_canister_id, snapshot_id).await,
        LoadCanisterSnapshotResponse::Ok(LoadCanisterSnapshotOk {}),
    );
    assert_eq!(get(&pocket_ic, dapp_canister_id).await, 3);

    // Step 3: Every other target is refused, and left alone.

    // A real snapshot of the unregistered canister, to try to load (taken directly, as Root).
    for _ in 0..3 {
        inc(&pocket_ic, unregistered_canister_id).await;
    }
    let unregistered_snapshot_id = pocket_ic
        .take_canister_snapshot(
            unregistered_canister_id.into(),
            Some(sns.root.canister_id.0),
            None,
        )
        .await
        .unwrap()
        .id;
    for _ in 0..2 {
        inc(&pocket_ic, unregistered_canister_id).await;
    }

    for (target, controller, snapshot_id) in [
        (
            governance_canister_id,
            sns.root.canister_id,
            SnapshotId::from((governance_canister_id, 0)).to_vec(),
        ),
        (
            root_canister_id,
            sns.governance.canister_id,
            SnapshotId::from((root_canister_id, 0)).to_vec(),
        ),
        (
            ledger_canister_id,
            sns.root.canister_id,
            SnapshotId::from((ledger_canister_id, 0)).to_vec(),
        ),
        (
            unregistered_canister_id,
            sns.root.canister_id,
            unregistered_snapshot_id.clone(),
        ),
    ] {
        let description = format!("{target} is not a registered dapp canister of this SNS.");
        let snapshots_before = pocket_ic
            .list_canister_snapshots(target.into(), Some(controller.0))
            .await
            .unwrap();

        assert_eq!(
            root_take_canister_snapshot(&pocket_ic, &sns, target).await,
            TakeCanisterSnapshotResponse::Err(TakeCanisterSnapshotError {
                code: None,
                description: description.clone(),
            }),
        );
        assert_eq!(
            root_load_canister_snapshot(&pocket_ic, &sns, target, snapshot_id).await,
            LoadCanisterSnapshotResponse::Err(LoadCanisterSnapshotError {
                code: None,
                description,
            }),
        );

        // Nothing happened to the target: no new snapshot, and it was not stopped.
        let snapshots_after = pocket_ic
            .list_canister_snapshots(target.into(), Some(controller.0))
            .await
            .unwrap();
        assert_eq!(snapshots_after, snapshots_before, "{target}");
        let status = pocket_ic
            .canister_status(target.into(), Some(controller.0))
            .await
            .unwrap()
            .status;
        assert_eq!(status, CanisterStatusType::Running, "{target}");
    }

    // The snapshot was not loaded into the unregistered canister.
    assert_eq!(get(&pocket_ic, unregistered_canister_id).await, 5);
}
