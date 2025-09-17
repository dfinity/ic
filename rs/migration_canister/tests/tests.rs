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
    // Setup a unique controller each, and a shared one.
    let source_controllers = vec![c1, c2];
    let target_controllers = vec![c1, c3];

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
async fn validation_succeeds() {
    let Setup {
        pic,
        source,
        target,
        source_controllers,
        system_controller,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];

    migrate_canister(&pic, sender, &MigrateCanisterArgs { source, target })
        .await
        .unwrap();

    let mut logs = Logs::default();

    for _ in 0..100 {
        pic.advance_time(Duration::from_millis(100)).await;
        pic.tick().await;

        let log = pic
            .fetch_canister_logs(MIGRATION_CANISTER_ID.into(), system_controller)
            .await
            .unwrap();
        logs.add(log);
    }

    // Low prio test that the state machine transitions in expected order
    assert!(logs.contains_in_order(vec![
        "Entering `accepted` with 1 pending",
        "Exiting `accepted` with 1 successful",
        "Entering `controllers_changed` with 1 pending",
        "Exiting `controllers_changed` with 1 successful",
        "Entering `stopped` with 1 pending",
        "Exiting `stopped` with 1 successful",
        "Entering `renamed_target` with 1 pending",
    ]));
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
