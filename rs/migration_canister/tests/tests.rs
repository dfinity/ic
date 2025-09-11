//! TODO:
//! - source not controlled by user
//! - target not controlled by user
//! - source not controlled by MC
//! - target not controlled by MC
//! - not enough cycles for migration
//! - rate-limited
//! - disabled
//! - source not stopped
//! - target not stopped
//!

use candid::{CandidType, Decode, Encode, Principal};
use canister_test::Project;
use ic_base_types::CanisterId;
use ic_management_canister_types::CanisterSettings;
use pocket_ic::{
    PocketIcBuilder,
    common::rest::{IcpFeatures, IcpFeaturesConfig},
    nonblocking::PocketIc,
};
use registry_canister::init::RegistryCanisterInitPayload;
use serde::Deserialize;
use tempfile::TempDir;

pub const REGISTRY_CANISTER_ID: CanisterId = CanisterId::from_u64(0);
pub const MIGRATION_CANISTER_ID: CanisterId = CanisterId::from_u64(99);

#[derive(Clone, Debug, CandidType, Deserialize)]
struct MigrateCanisterArgs {
    pub source: Principal,
    pub target: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ValidationError {
    MigrationsDisabled,
    RateLimited,
    MigrationInProgress { canister: Principal },
    CanisterNotFound { canister: Principal },
    SameSubnet,
    CallerNotController { canister: Principal },
    NotController { canister: Principal },
    SourceNotStopped,
    SourceNotReady,
    TargetNotStopped,
    TargetHasSnapshots,
    TargetInsufficientCycles,
    CallFailed { reason: String },
}

pub struct Setup {
    pub pic: PocketIc,
    pub source: Principal,
    pub target: Principal,
    pub controllers: Vec<Principal>,
    pub source_subnet: Principal,
    pub target_subnet: Principal,
}

/// Sets up PocketIc with the registry canister, the migration canister and two canisters on different app subnets.
/// Returns: (PocketIc, source subnet, target subnet, source canister, target canister, controllers)
async fn setup() -> Setup {
    let state_dir = TempDir::new().unwrap();
    let state_dir = state_dir.path().to_path_buf();

    let pic = PocketIcBuilder::new()
        .with_icp_features(IcpFeatures {
            registry: Some(IcpFeaturesConfig::DefaultConfig),
            ..Default::default()
        })
        .with_state_dir(state_dir.clone())
        .with_application_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let system_controller = Principal::anonymous();
    let c1 = Principal::self_authenticating(vec![1]);
    let c2 = Principal::self_authenticating(vec![2]);
    let c3 = Principal::self_authenticating(vec![3]);
    let controllers = vec![c1, c2, c3];

    let migration_canister_wasm = Project::cargo_bin_maybe_from_env("migration-canister", &[]);

    pic.create_canister_with_id(
        Some(system_controller),
        Some(CanisterSettings {
            controllers: Some(vec![system_controller]),
            ..Default::default()
        }),
        MIGRATION_CANISTER_ID.into(),
    )
    .await
    .unwrap();
    pic.install_canister(
        MIGRATION_CANISTER_ID.into(),
        migration_canister_wasm.bytes(),
        Encode!(&RegistryCanisterInitPayload::default()).unwrap(),
        Some(system_controller),
    )
    .await;

    let subnets = pic.topology().await.get_app_subnets();
    let source_subnet = subnets[0];
    let target_subnet = subnets[1];

    let source = pic
        .create_canister_on_subnet(
            Some(c1),
            Some(CanisterSettings {
                controllers: Some(controllers.clone()),
                ..Default::default()
            }),
            source_subnet,
        )
        .await;
    pic.add_cycles(source, u128::MAX / 2).await;
    let target = pic
        .create_canister_on_subnet(
            Some(c1),
            Some(CanisterSettings {
                controllers: Some(controllers.clone()),
                ..Default::default()
            }),
            target_subnet,
        )
        .await;
    pic.add_cycles(target, u128::MAX / 2).await;

    Setup {
        pic,
        source,
        target,
        controllers,
        source_subnet,
        target_subnet,
    }
}

#[tokio::test]
async fn test_validation_succeeds() {
    let Setup {
        pic,
        source,
        target,
        controllers,
        ..
    } = setup().await;
    let sender = controllers[0];

    // make migration canister controller of source
    let mut new_controllers = controllers.clone();
    new_controllers.push(MIGRATION_CANISTER_ID.into());
    pic.update_canister_settings(
        source,
        Some(sender),
        CanisterSettings {
            controllers: Some(new_controllers.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // make migration canister controller of target
    pic.update_canister_settings(
        target,
        Some(sender),
        CanisterSettings {
            controllers: Some(new_controllers),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // stop source and target
    pic.stop_canister(source, Some(sender)).await.unwrap();
    pic.stop_canister(target, Some(sender)).await.unwrap();

    let res = pic
        .update_call(
            MIGRATION_CANISTER_ID.into(),
            sender,
            "migrate_canister",
            Encode!(&MigrateCanisterArgs { source, target }).unwrap(),
        )
        .await
        .unwrap();
    let res = Decode!(&res, Result<(), ValidationError>).unwrap();
    res.unwrap();
}
