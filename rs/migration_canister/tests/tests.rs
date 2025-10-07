use candid::{CandidType, Decode, Encode, Principal};
use canister_test::Project;
use ic_base_types::CanisterId;
use ic_management_canister_types::{CanisterLogRecord, CanisterSettings};
use itertools::Itertools;
use pocket_ic::{
    PocketIcBuilder,
    common::rest::{IcpFeatures, IcpFeaturesConfig},
    nonblocking::PocketIc,
};
use registry_canister::init::RegistryCanisterInitPayload;
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};
use strum::Display;

pub const REGISTRY_CANISTER_ID: CanisterId = CanisterId::from_u64(0);
pub const MIGRATION_CANISTER_ID: CanisterId = CanisterId::from_u64(17);

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
    SourceInsufficientCycles,
    CallFailed { reason: String },
}

#[derive(Clone, Display, PartialEq, Debug, CandidType, Deserialize)]
enum MigrationStatus {
    #[strum(to_string = "MigrationStatus::InProgress {{ status: {status} }}")]
    InProgress { status: String },
    #[strum(to_string = "MigrationStatus::Failed {{ reason: {reason}, time: {time} }}")]
    Failed { reason: String, time: u64 },
    #[strum(to_string = "MigrationStatus::Succeeded {{ time: {time} }}")]
    Succeeded { time: u64 },
}

pub struct Setup {
    pub pic: PocketIc,
    pub source: Principal,
    pub target: Principal,
    pub source_controllers: Vec<Principal>,
    pub target_controllers: Vec<Principal>,
    pub source_subnet: Principal,
    pub target_subnet: Principal,
    /// Controller of the NNS canisters including MC
    pub system_controller: Principal,
}

pub struct Settings {
    pub mc_controls_source: bool,
    pub mc_controls_target: bool,
    pub enough_cycles: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mc_controls_source: true,
            mc_controls_target: true,
            enough_cycles: true,
        }
    }
}

/// Sets up PocketIc with the registry canister, the migration canister and two canisters on different app subnets.
async fn setup(
    Settings {
        mc_controls_source,
        mc_controls_target,
        enough_cycles,
    }: Settings,
) -> Setup {
    let pic = PocketIcBuilder::new()
        .with_icp_features(IcpFeatures {
            registry: Some(IcpFeaturesConfig::DefaultConfig),
            ..Default::default()
        })
        .with_application_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let system_controller = Principal::anonymous();
    let c1 = Principal::self_authenticating(vec![1]);
    let c2 = Principal::self_authenticating(vec![2]);
    let c3 = Principal::self_authenticating(vec![3]);
    // Setup a unique controller each, and a shared one.
    let source_controllers = vec![c1, c2];
    let target_controllers = vec![c1, c3];

    // install fresh version of registry canister:
    let registry_wasm = Project::cargo_bin_maybe_from_env("registry-canister", &[]);
    pic.upgrade_canister(
        REGISTRY_CANISTER_ID.into(),
        registry_wasm.bytes(),
        vec![],
        Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap()), /* root canister */
    )
    .await
    .unwrap();

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

    // source canister
    let source = pic
        .create_canister_on_subnet(
            Some(c1),
            Some(CanisterSettings {
                controllers: Some(source_controllers.clone()),
                ..Default::default()
            }),
            source_subnet,
        )
        .await;
    if mc_controls_source {
        // make migration canister controller of source
        let mut new_controllers = source_controllers.clone();
        new_controllers.push(MIGRATION_CANISTER_ID.into());
        pic.update_canister_settings(
            source,
            Some(c1),
            CanisterSettings {
                controllers: Some(new_controllers.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    if enough_cycles {
        pic.add_cycles(source, u128::MAX / 2).await;
    } else {
        pic.add_cycles(source, 2_000_000).await;
    }
    pic.stop_canister(source, Some(c1)).await.unwrap();
    // target canister
    let target = pic
        .create_canister_on_subnet(
            Some(c1),
            Some(CanisterSettings {
                controllers: Some(target_controllers.clone()),
                ..Default::default()
            }),
            target_subnet,
        )
        .await;
    if mc_controls_target {
        // make migration canister controller of target
        let mut new_controllers = target_controllers.clone();
        new_controllers.push(MIGRATION_CANISTER_ID.into());
        pic.update_canister_settings(
            target,
            Some(c1),
            CanisterSettings {
                controllers: Some(new_controllers),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    if enough_cycles {
        pic.add_cycles(target, u128::MAX / 2).await;
    } else {
        pic.add_cycles(target, 2_000_000).await;
    }
    pic.stop_canister(target, Some(c1)).await.unwrap();
    println!("Source canister id: {}", source.to_text());
    println!("Target canister id: {}", target.to_text());
    Setup {
        pic,
        source,
        target,
        source_controllers,
        target_controllers,
        source_subnet,
        target_subnet,
        system_controller,
    }
}

async fn migrate_canister(
    pic: &PocketIc,
    sender: Principal,
    args: &MigrateCanisterArgs,
) -> Result<(), ValidationError> {
    let res = pic
        .update_call(
            MIGRATION_CANISTER_ID.into(),
            sender,
            "migrate_canister",
            Encode!(args).unwrap(),
        )
        .await
        .unwrap();
    Decode!(&res, Result<(), ValidationError>).unwrap()
}

async fn get_status(
    pic: &PocketIc,
    sender: Principal,
    args: &MigrateCanisterArgs,
) -> Vec<MigrationStatus> {
    let res = pic
        .update_call(
            MIGRATION_CANISTER_ID.into(),
            sender,
            "migration_status",
            Encode!(args).unwrap(),
        )
        .await
        .unwrap();
    Decode!(&res, Vec<MigrationStatus>).unwrap()
}

/// Advances time by a second and executes enough ticks that the state machine
/// can make progress.
async fn advance(pic: &PocketIc) {
    pic.advance_time(Duration::from_millis(1000)).await;
    for _ in 0..10 {
        pic.tick().await;
    }
}

#[derive(Default, Debug)]
struct Logs {
    map: HashMap<u64, String>,
}

impl Logs {
    pub fn add(&mut self, logs: Vec<CanisterLogRecord>) {
        for x in logs.into_iter() {
            self.map
                .insert(x.idx, String::from_utf8(x.content).unwrap());
        }
    }

    pub fn in_order(&self) -> Vec<(u64, String)> {
        self.map
            .iter()
            .sorted()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Takes a Vec of expected log substrings and checks that they occur
    /// in the given order. Other, unrelated logs may be interspersed and
    /// this will still return true.
    pub fn contains_in_order(&self, expected: Vec<&str>) -> bool {
        let mut logs = VecDeque::from(
            self.in_order()
                .into_iter()
                .map(|(_k, v)| v)
                .filter(|x| !x.is_empty())
                .collect::<Vec<String>>(),
        );
        if logs.is_empty() {
            println!("Empty Logs do not contain any expected substring.");
            return false;
        }
        let mut next = String::from("");
        for exp in expected.iter().filter(|x| !x.is_empty()) {
            while !next.contains(exp) {
                next = match logs.pop_front() {
                    Some(next) => next,
                    None => {
                        println!("Logs do not contain (in order): '{exp}'.");
                        return false;
                    }
                }
            }
        }
        true
    }
}

#[tokio::test]
async fn migration_succeeds() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        system_controller,
        target_subnet,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];

    migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target })
        .await
        .unwrap();

    let mut logs = Logs::default();

    for _ in 0..100 {
        // advance time by a lot such that the task which waits 5m can succeed quickly.
        pic.advance_time(Duration::from_secs(250)).await;
        pic.tick().await;

        let log = pic
            .fetch_canister_logs(MIGRATION_CANISTER_ID.into(), system_controller)
            .await
            .unwrap();
        logs.add(log);
    }

    // Test that the state machine transitions in expected order
    assert!(logs.contains_in_order(vec![
        "Entering `accepted` with 1 pending",
        "Exiting `accepted` with 1 successful",
        "Entering `controllers_changed` with 1 pending",
        "Exiting `controllers_changed` with 1 successful",
        "Entering `stopped` with 1 pending",
        "Exiting `stopped` with 1 successful",
        "Entering `renamed_target` with 1 pending",
        "Exiting `renamed_target` with 1 successful",
        "Entering `updated_routing_table` with 1 pending",
        "Exiting `updated_routing_table` with 1 successful",
        "Entering `routing_table_change_accepted` with 1 pending",
        "Exiting `routing_table_change_accepted` with 1 successful",
        "Entering `source_deleted` with 1 pending",
        "Exiting `source_deleted` with 1 successful",
    ]));

    let source_new_subnet = pic.get_subnet(source).await.unwrap();
    assert_eq!(source_new_subnet, target_subnet);
    pic.start_canister(source, Some(sender)).await.unwrap();
    let err = pic
        .update_call(source, sender, "yesn't", vec![])
        .await
        .unwrap_err();
    assert!(format!("{:?}", err).contains("no wasm module"));
}

#[tokio::test]
async fn validation_fails_not_found() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let nonexistent_canister = Principal::from_text("222ay-6aaaa-aaaah-alvrq-cai").unwrap();
    let Err(ValidationError::CanisterNotFound { canister }) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            source: nonexistent_canister,
            target,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, nonexistent_canister);

    // sender not controller of target
    let bad_sender = source_controllers[1];
    let Err(ValidationError::CanisterNotFound { canister }) = migrate_canister(
        &pic,
        bad_sender,
        &MigrateCanisterArgs {
            source,
            target: nonexistent_canister,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, nonexistent_canister);
}

#[tokio::test]
async fn validation_fails_same_subnet() {
    let Setup {
        pic,
        source,
        source_subnet,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let target = pic
        .create_canister_on_subnet(Some(sender), None, source_subnet)
        .await;
    let Err(ValidationError::SameSubnet) =
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await
    else {
        panic!()
    };
}

#[tokio::test]
async fn validation_fails_caller_not_controller() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        target_controllers,
        ..
    } = setup(Settings::default()).await;
    // sender not controller of source
    let bad_sender = target_controllers[1];
    let Err(ValidationError::CallerNotController { canister }) =
        migrate_canister(&pic, bad_sender, &MigrateCanisterArgs { source, target }).await
    else {
        panic!()
    };
    assert_eq!(canister, source);

    // sender not controller of target
    let bad_sender = source_controllers[1];
    let Err(ValidationError::CallerNotController { canister }) =
        migrate_canister(&pic, bad_sender, &MigrateCanisterArgs { source, target }).await
    else {
        panic!()
    };
    assert_eq!(canister, target);
}

#[tokio::test]
async fn validation_fails_mc_not_source_controller() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        ..
    } = setup(Settings {
        mc_controls_source: false,
        ..Default::default()
    })
    .await;
    // MC not controller of source
    let sender = source_controllers[0];
    let Err(ValidationError::NotController { canister }) =
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await
    else {
        panic!()
    };
    assert_eq!(canister, source);
}

#[tokio::test]
async fn validation_fails_mc_not_target_controller() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        ..
    } = setup(Settings {
        mc_controls_target: false,
        ..Default::default()
    })
    .await;
    // MC not controller of target
    let sender = source_controllers[0];
    let Err(ValidationError::NotController { canister }) =
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await
    else {
        panic!()
    };
    assert_eq!(canister, target);
}

#[tokio::test]
async fn validation_fails_not_stopped() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];

    // source
    pic.start_canister(source, Some(sender)).await.unwrap();
    assert!(matches!(
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await,
        Err(ValidationError::SourceNotStopped)
    ));

    pic.stop_canister(source, Some(sender)).await.unwrap();

    // target
    pic.start_canister(target, Some(sender)).await.unwrap();
    assert!(matches!(
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await,
        Err(ValidationError::TargetNotStopped)
    ));
}

#[tokio::test]
async fn validation_fails_rate_limited() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        system_controller,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    // rate limit canister
    #[derive(Clone, Debug, CandidType, Deserialize)]
    struct SetRateLimitArgs {
        pub max_active_requests: u64,
    }
    pic.update_call(
        MIGRATION_CANISTER_ID.into(),
        system_controller,
        "set_rate_limit",
        Encode!(&SetRateLimitArgs {
            max_active_requests: 0
        })
        .unwrap(),
    )
    .await
    .unwrap();

    assert!(matches!(
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await,
        Err(ValidationError::RateLimited)
    ));
}

#[tokio::test]
async fn validation_fails_disabled() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        system_controller,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    // disable canister API
    pic.update_call(
        MIGRATION_CANISTER_ID.into(),
        system_controller,
        "disable_api",
        Encode!().unwrap(),
    )
    .await
    .unwrap();

    assert!(matches!(
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await,
        Err(ValidationError::MigrationsDisabled)
    ));
}

#[tokio::test]
async fn validation_fails_snapshot() {
    let Setup {
        pic,
        source,
        target,
        target_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = target_controllers[0];
    // install a minimal Wasm module
    pic.install_canister(
        target,
        b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec(),
        vec![],
        Some(sender),
    )
    .await;
    let _ = pic
        .take_canister_snapshot(target, Some(sender), None)
        .await
        .unwrap();
    assert!(matches!(
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await,
        Err(ValidationError::TargetHasSnapshots)
    ));
}

#[tokio::test]
async fn validation_fails_insufficient_cycles() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        ..
    } = setup(Settings {
        enough_cycles: false,
        ..Default::default()
    })
    .await;
    let sender = source_controllers[0];

    assert!(matches!(
        migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target }).await,
        Err(ValidationError::SourceInsufficientCycles)
    ));
}

#[tokio::test]
async fn status_correct() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let args = MigrateCanisterArgs { source, target };
    migrate_canister(&pic, sender, &args).await.unwrap();

    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status[0],
        MigrationStatus::InProgress {
            status: "Accepted".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status[0],
        MigrationStatus::InProgress {
            status: "ControllersChanged".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status[0],
        MigrationStatus::InProgress {
            status: "StoppedAndReady".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status[0],
        MigrationStatus::InProgress {
            status: "RenamedTarget".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status[0],
        MigrationStatus::InProgress {
            status: "UpdatedRoutingTable".to_string()
        }
    );

    // TODO: Depends on a PocketIC change

    // advance(&pic).await;
    // let status = get_status(&pic, sender, &args).await;
    // assert_eq!(
    //     status[0],
    //     MigrationStatus::InProgress {
    //         status: "RoutingTableChangeAccepted".to_string()
    //     }
    // );

    // advance(&pic).await;
    // let status = get_status(&pic, sender, &args).await;
    // assert_eq!(
    //     status[0],
    //     MigrationStatus::InProgress {
    //         status: "SourceDeleted".to_string()
    //     }
    // );

    // advance(&pic).await;
    // let status = get_status(&pic, sender, &args).await;
    // assert_eq!(
    //     status[0],
    //     MigrationStatus::InProgress {
    //         status: "RestoredControllers".to_string()
    //     }
    // );
}

#[tokio::test]
async fn after_validation_source_not_stopped() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let args = MigrateCanisterArgs { source, target };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // validation succeeded. now we break migration by interfering.
    pic.start_canister(source, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status[0] else {
        panic!()
    };
    assert_eq!(reason, &"Source is not stopped.".to_string());
}

#[tokio::test]
async fn after_validation_target_not_stopped() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let args = MigrateCanisterArgs { source, target };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // validation succeeded. now we break migration by interfering.
    pic.start_canister(target, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status[0] else {
        panic!()
    };
    assert_eq!(reason, &"Target is not stopped.".to_string());
}

#[tokio::test]
async fn after_validation_target_has_snapshot() {
    let Setup {
        pic,
        source,
        target,
        target_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = target_controllers[0];
    let args = MigrateCanisterArgs { source, target };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // validation succeeded. now we break migration by interfering.
    // install a minimal Wasm module
    pic.install_canister(
        target,
        b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec(),
        vec![],
        Some(sender),
    )
    .await;
    let _ = pic
        .take_canister_snapshot(target, Some(sender), None)
        .await
        .unwrap();

    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status[0] else {
        panic!()
    };
    assert_eq!(reason, &"Target has snapshots.".to_string());
}

#[tokio::test]
async fn after_validation_insufficient_cycles() {
    let Setup {
        pic,
        source,
        target,
        target_controllers,
        ..
    } = setup(Settings {
        enough_cycles: false,
        ..Default::default()
    })
    .await;
    let sender = target_controllers[0];
    // Top up just enough to pass validation..
    pic.add_cycles(source, 10_000_000_000_000).await;
    let args = MigrateCanisterArgs { source, target };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // ..but then burn some cycles by reinstalling to get under the required amount.
    pic.reinstall_canister(
        source,
        b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec(),
        vec![],
        Some(sender),
    )
    .await
    .unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status[0] else {
        panic!()
    };
    assert!(reason.contains("Source does not have sufficient cycles"));
}

#[tokio::test]
async fn failure_controllers_restored() {
    let Setup {
        pic,
        source,
        target,
        mut source_controllers,
        mut target_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let args = MigrateCanisterArgs { source, target };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // Validation succeeded. Now we break migration by interfering.
    pic.start_canister(source, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { .. } = status[0] else {
        panic!()
    };
    let mut source_controllers_after = pic.get_controllers(source).await;
    let mut target_controllers_after = pic.get_controllers(target).await;
    source_controllers_after.sort();
    target_controllers_after.sort();
    source_controllers.sort();
    target_controllers.sort();
    // On failure, the MC should remain controller such that user can retry.
    assert_eq!(source_controllers, source_controllers_after);
    assert_eq!(target_controllers, target_controllers_after);
}

// TODO: Depends on a PocketIC change

// #[tokio::test]
// async fn success_controllers_restored() {
//     let Setup {
//         pic,
//         source,
//         target,
//         mut source_controllers,
//         ..
//     } = setup(Settings::default()).await;
//     let sender = source_controllers[0];
//     let args = MigrateCanisterArgs { source, target };
//     migrate_canister(&pic, sender, &args).await.unwrap();
//     for _ in 0..10 {
//         advance(&pic).await;
//     }
//     let status = get_status(&pic, sender, &args).await;
//     let MigrationStatus::Succeeded { .. } = status[0] else {
//         panic!()
//     };
//     let mut source_controllers_after = pic.get_controllers(source).await;
//     source_controllers_after.sort();
//     // On success, the MC should have removed itself from the controllers.
//     source_controllers.retain(|x| x != &MIGRATION_CANISTER_ID.get().0);
//     source_controllers.sort();
//     assert_eq!(source_controllers, source_controllers_after);
// }

// parallel processing

#[tokio::test]
async fn parallel_migrations() {
    const NUM_MIGRATIONS: usize = 20;
    let pic = PocketIcBuilder::new()
        .with_icp_features(IcpFeatures {
            registry: Some(IcpFeaturesConfig::DefaultConfig),
            ..Default::default()
        })
        .with_application_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    let system_controller = Principal::anonymous();
    let c1 = Principal::self_authenticating(vec![1]);
    let c2 = Principal::self_authenticating(vec![2]);
    let c3 = Principal::self_authenticating(vec![3]);
    // Setup a unique controller each, and a shared one.
    let source_controllers = vec![c1, c2];
    let target_controllers = vec![c1, c3];

    // install fresh version of registry canister:
    let registry_wasm = Project::cargo_bin_maybe_from_env("registry-canister", &[]);
    pic.upgrade_canister(
        REGISTRY_CANISTER_ID.into(),
        registry_wasm.bytes(),
        vec![],
        Some(Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap()), /* root canister */
    )
    .await
    .unwrap();

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

    // source canisters
    let mut sources = vec![];
    for _ in 0..NUM_MIGRATIONS {
        let source = pic
            .create_canister_on_subnet(
                Some(c1),
                Some(CanisterSettings {
                    controllers: Some(source_controllers.clone()),
                    ..Default::default()
                }),
                source_subnet,
            )
            .await;

        // make migration canister controller of source
        let mut new_controllers = source_controllers.clone();
        new_controllers.push(MIGRATION_CANISTER_ID.into());
        pic.update_canister_settings(
            source,
            Some(c1),
            CanisterSettings {
                controllers: Some(new_controllers.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        pic.add_cycles(source, u128::MAX / 2).await;
        pic.stop_canister(source, Some(c1)).await.unwrap();
        sources.push(source);
    }
    // target canisters
    let mut targets = vec![];
    for _ in 0..NUM_MIGRATIONS {
        let target = pic
            .create_canister_on_subnet(
                Some(c1),
                Some(CanisterSettings {
                    controllers: Some(target_controllers.clone()),
                    ..Default::default()
                }),
                target_subnet,
            )
            .await;
        // make migration canister controller of target
        let mut new_controllers = target_controllers.clone();
        new_controllers.push(MIGRATION_CANISTER_ID.into());
        pic.update_canister_settings(
            target,
            Some(c1),
            CanisterSettings {
                controllers: Some(new_controllers),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        pic.add_cycles(target, u128::MAX / 2).await;
        pic.stop_canister(target, Some(c1)).await.unwrap();
        targets.push(target);
    }
    // --------------------------------------------------------------------- //
    // setup done
    for i in 0..NUM_MIGRATIONS / 2 {
        migrate_canister(
            &pic,
            source_controllers[0],
            &MigrateCanisterArgs {
                source: sources[i],
                target: targets[i],
            },
        )
        .await
        .unwrap();
    }

    for i in (NUM_MIGRATIONS / 2)..NUM_MIGRATIONS {
        advance(&pic).await;
        migrate_canister(
            &pic,
            source_controllers[0],
            &MigrateCanisterArgs {
                source: sources[i],
                target: targets[i],
            },
        )
        .await
        .unwrap();
    }
    for _ in 0..10 {
        advance(&pic).await;
    }
    for i in 0..NUM_MIGRATIONS {
        let status = get_status(
            &pic,
            source_controllers[0],
            &MigrateCanisterArgs {
                source: sources[i],
                target: targets[i],
            },
        )
        .await;
        // TODO: should be Succeeded in the end.
        assert!(matches!(status[0], MigrationStatus::InProgress { .. }));
    }
}
