use candid::{CandidType, Decode, Encode, Principal, Reserved};
use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types::{CanisterLogRecord, CanisterSettings};
use ic_management_canister_types_private::{
    CanisterChangeDetails, CanisterInfoRequest, CanisterInfoResponse, Payload as _,
};
use ic_transport_types::Envelope;
use ic_transport_types::EnvelopeContent::Call;
use ic_universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};
use itertools::Itertools;
use pocket_ic::{
    PocketIcBuilder,
    common::rest::{IcpFeatures, IcpFeaturesConfig},
    nonblocking::PocketIc,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};
use strum::Display;

pub const REGISTRY_CANISTER_ID: CanisterId = CanisterId::from_u64(0);
pub const MIGRATION_CANISTER_ID: CanisterId = CanisterId::from_u64(17);

#[derive(Clone, Debug, CandidType, Deserialize)]
struct MigrateCanisterArgs {
    pub canister_id: Principal,
    pub replace_canister_id: Principal,
}

#[derive(CandidType, Deserialize, Default)]
struct MigrationCanisterInitArgs {
    allowlist: Option<Vec<Principal>>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum ValidationError {
    MigrationsDisabled(Reserved),
    RateLimited(Reserved),
    ValidationInProgress { canister: Principal },
    MigrationInProgress { canister: Principal },
    CanisterNotFound { canister: Principal },
    SameSubnet(Reserved),
    CallerNotController { canister: Principal },
    NotController { canister: Principal },
    SourceNotStopped(Reserved),
    SourceNotReady(Reserved),
    TargetNotStopped(Reserved),
    TargetHasSnapshots(Reserved),
    SourceInsufficientCycles(Reserved),
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
    pub sources: Vec<Principal>,
    pub targets: Vec<Principal>,
    pub source_controllers: Vec<Principal>,
    pub target_controllers: Vec<Principal>,
    pub source_subnet: Principal,
    pub target_subnet: Principal,
    /// Controller of the NNS canisters including MC
    pub system_controller: Principal,
}

pub struct Settings {
    pub num_migrations: u64,
    pub mc_controls_source: bool,
    pub mc_controls_target: bool,
    pub enough_cycles: bool,
    pub allowlist: Option<Vec<Principal>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            num_migrations: 1,
            mc_controls_source: true,
            mc_controls_target: true,
            enough_cycles: true,
            allowlist: None,
        }
    }
}

/// Sets up PocketIc with the registry canister, the migration canister and two canisters on different app subnets.
async fn setup(
    Settings {
        num_migrations,
        mc_controls_source,
        mc_controls_target,
        enough_cycles,
        allowlist,
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
        Encode!(&MigrationCanisterInitArgs {
            allowlist: allowlist.clone()
        })
        .unwrap(),
        Some(system_controller),
    )
    .await;

    let subnets = pic.topology().await.get_app_subnets();
    let source_subnet = subnets[0];
    let target_subnet = subnets[1];

    let mut sources = vec![];
    let mut targets = vec![];
    for _ in 0..num_migrations {
        // source canister
        let mut new_controllers = source_controllers.clone();
        if mc_controls_source {
            new_controllers.push(MIGRATION_CANISTER_ID.into());
        }
        if let Some(ref allowlist) = allowlist {
            new_controllers.extend(allowlist.clone());
        }
        let source = pic
            .create_canister_on_subnet(
                Some(c1),
                Some(CanisterSettings {
                    controllers: Some(new_controllers),
                    ..Default::default()
                }),
                source_subnet,
            )
            .await;
        if enough_cycles {
            pic.add_cycles(source, u128::MAX / 2).await;
        } else {
            pic.add_cycles(source, 2_000_000).await;
        }
        pic.stop_canister(source, Some(c1)).await.unwrap();
        sources.push(source);

        // target canister
        let mut new_controllers = target_controllers.clone();
        if mc_controls_target {
            new_controllers.push(MIGRATION_CANISTER_ID.into());
        }
        if let Some(ref allowlist) = allowlist {
            new_controllers.extend(allowlist.clone());
        }
        let target = pic
            .create_canister_on_subnet(
                Some(c1),
                Some(CanisterSettings {
                    controllers: Some(new_controllers),
                    ..Default::default()
                }),
                target_subnet,
            )
            .await;
        if enough_cycles {
            pic.add_cycles(target, u128::MAX / 2).await;
        } else {
            pic.add_cycles(target, 2_000_000).await;
        }
        pic.stop_canister(target, Some(c1)).await.unwrap();
        targets.push(target)
    }
    Setup {
        pic,
        sources,
        targets,
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
    Decode!(&res, Result<(), Option<ValidationError>>)
        .unwrap()
        .map_err(|err| err.unwrap())
}

async fn get_status(
    pic: &PocketIc,
    sender: Principal,
    args: &MigrateCanisterArgs,
) -> Option<MigrationStatus> {
    let res = pic
        .update_call(
            MIGRATION_CANISTER_ID.into(),
            sender,
            "migration_status",
            Encode!(args).unwrap(),
        )
        .await
        .unwrap();
    Decode!(&res, Option<MigrationStatus>).unwrap()
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

async fn canister_info(
    pic: &PocketIc,
    proxy_canister: Principal,
    canister_id: Principal,
) -> CanisterInfoResponse {
    let canister_id = CanisterId::unchecked_from_principal(PrincipalId(canister_id));
    let canister_info_request = CanisterInfoRequest::new(canister_id, Some(20)); // 20 entries is the maximum requested amount
    let call_args = CallArgs::default().other_side(canister_info_request.encode());
    let payload = wasm()
        .call_simple(CanisterId::ic_00(), "canister_info", call_args)
        .build();
    let res = pic
        .update_call(proxy_canister, Principal::anonymous(), "update", payload)
        .await
        .unwrap();
    CanisterInfoResponse::decode(&res).unwrap()
}

#[tokio::test]
async fn migration_succeeds() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        system_controller,
        target_subnet,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];

    // We deploy a universal canister acting as a proxy canister
    // for retrieving canister history.
    let proxy_canister = pic.create_canister().await;
    pic.add_cycles(proxy_canister, 1_000_000_000_000).await;
    pic.install_canister(
        proxy_canister,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        None,
    )
    .await;

    // We deploy the universal canister WASM to the "target" canister
    // so that we can call it via the "source" canister ID
    // after renaming.
    pic.add_cycles(target, 1_000_000_000_000).await;
    pic.install_canister(
        target,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        Some(sender),
    )
    .await;

    // There is 1 entry in the canister history of the "source" canister before migrating:
    // creation.
    let source_info = canister_info(&pic, proxy_canister, source).await;
    assert_eq!(source_info.total_num_changes(), 1);
    assert!(matches!(
        source_info.changes()[0].details(),
        CanisterChangeDetails::CanisterCreation(_)
    ));
    // There are 2 entries in the canister history of the "target" canister before migrating:
    // creation and installation.
    let target_info = canister_info(&pic, proxy_canister, target).await;
    assert_eq!(target_info.total_num_changes(), 2);
    assert!(matches!(
        target_info.changes()[0].details(),
        CanisterChangeDetails::CanisterCreation(_)
    ));
    assert!(matches!(
        target_info.changes()[1].details(),
        CanisterChangeDetails::CanisterCodeDeployment(_)
    ));

    migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: target,
        },
    )
    .await
    .unwrap();

    let mut logs = Logs::default();

    for _ in 0..100 {
        // advance time by a lot such that the task which waits 6m can succeed quickly.
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
    pic.update_call(source, sender, "update", wasm().reply().build())
        .await
        .unwrap();

    // We check the canister history of the "source" canister after renaming.
    let source_info = canister_info(&pic, proxy_canister, source).await;
    // There are 4 changes of the "source" canister after renaming:
    // creation, controllers change, renaming, and controllers change.
    assert_eq!(source_info.total_num_changes(), 4);
    // There are 5 entries in the canister history of the "source" canister after renaming:
    // creation, installation, controllers change of the "target" canister before renaming,
    // then renaming, and controllers change.
    let canister_history = source_info.changes();
    assert_eq!(canister_history.len(), 5);
    assert!(matches!(
        canister_history[0].details(),
        CanisterChangeDetails::CanisterCreation(_)
    ));
    assert!(matches!(
        canister_history[1].details(),
        CanisterChangeDetails::CanisterCodeDeployment(_)
    ));
    assert!(matches!(
        canister_history[2].details(),
        CanisterChangeDetails::CanisterControllersChange(_)
    ));
    assert!(matches!(
        canister_history[3].details(),
        CanisterChangeDetails::CanisterRename(_)
    ));
    assert!(matches!(
        canister_history[4].details(),
        CanisterChangeDetails::CanisterControllersChange(_)
    ));
    // The second-to-last entry in canister history is the renaming entry.
    let rename_details = canister_history[canister_history.len() - 2].details();
    match rename_details {
        CanisterChangeDetails::CanisterRename(rename_record) => {
            assert_eq!(rename_record.canister_id(), PrincipalId(target));
            // There were 3 entries in the canister history of the "target" canister before renaming:
            // creation, installation, and controllers change.
            assert_eq!(rename_record.total_num_changes(), 3);
            let rename_to = rename_record.rename_to();
            assert_eq!(rename_to.canister_id(), PrincipalId(source));
            // There were 2 entries in the canister history of the "source" canister before renaming:
            // creation and controllers change.
            assert_eq!(rename_to.total_num_changes(), 2);
            assert_eq!(rename_record.requested_by(), PrincipalId(sender));
        }
        _ => panic!("Unexpected canister history entry: {:?}", rename_details),
    };
}

async fn call_request(
    pic: &PocketIc,
    ingress_expiry: u64,
    canister_id: Principal,
) -> (reqwest::Response, [u8; 32]) {
    let content = Call {
        nonce: None,
        ingress_expiry,
        sender: Principal::anonymous(),
        canister_id,
        method_name: "update".to_string(),
        arg: wasm().reply().build(),
    };
    let envelope = Envelope {
        content: std::borrow::Cow::Borrowed(&content),
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    let mut serialized_bytes = Vec::new();
    let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
    serializer.self_describe().unwrap();
    envelope.serialize(&mut serializer).unwrap();

    let endpoint = format!(
        "instances/{}/api/v2/canister/{}/call",
        pic.instance_id,
        canister_id.to_text()
    );
    let client = reqwest::Client::new();
    let resp = client
        .post(pic.get_server_url().join(&endpoint).unwrap())
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .body(serialized_bytes)
        .send()
        .await
        .unwrap();
    (resp, *content.to_request_id())
}

#[tokio::test]
async fn replay_call_after_migration() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];

    // We deploy the universal canister WASM
    // to both the "source" and "target" canisters
    // so that we can call the "source" canister ID
    // both before and after renaming.
    for canister_id in [source, target] {
        pic.add_cycles(canister_id, 1_000_000_000_000).await;
        pic.install_canister(
            canister_id,
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            Some(sender),
        )
        .await;
    }

    // We restart the "source" canister for a moment so that
    // we can send an update call to it.
    pic.start_canister(source, Some(sender)).await.unwrap();

    // We manually submit an update call so that
    // we can replay the exact same HTTP request later.
    let ingress_expiry = pic.get_time().await.as_nanos_since_unix_epoch() + 330_000_000_000;
    let (resp, _) = call_request(&pic, ingress_expiry, source).await;
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);

    // We stop the "source" canister again so that
    // we can kick off canister migration.
    pic.stop_canister(source, Some(sender)).await.unwrap();

    let args = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();

    loop {
        let status = get_status(&pic, sender, &args).await;
        if let MigrationStatus::Succeeded { .. } = status.unwrap() {
            break;
        }
        // We proceed in small steps here so that
        // we reply the update call as soon as possible.
        pic.advance_time(Duration::from_secs(1)).await;
        pic.tick().await;
    }

    // We restart the "source" canister right away.
    pic.start_canister(source, Some(sender)).await.unwrap();

    // Replaying the update call from before should fail.
    let (resp, _) = call_request(&pic, ingress_expiry, source).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let message = String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap();
    assert!(message.contains("Invalid request expiry"));
}

async fn concurrent_migration(
    pic: &PocketIc,
    sender: Principal,
    args1: MigrateCanisterArgs,
    args2: MigrateCanisterArgs,
    duplicate_canister: Principal,
) {
    let msg_id1 = pic
        .submit_call(
            MIGRATION_CANISTER_ID.into(),
            sender,
            "migrate_canister",
            Encode!(&args1).unwrap(),
        )
        .await
        .unwrap();
    let msg_id2 = pic
        .submit_call(
            MIGRATION_CANISTER_ID.into(),
            sender,
            "migrate_canister",
            Encode!(&args2).unwrap(),
        )
        .await
        .unwrap();
    let raw_res1 = pic.await_call(msg_id1).await.unwrap();
    let raw_res2 = pic.await_call(msg_id2).await.unwrap();
    let res1 = Decode!(&raw_res1, Result<(), Option<ValidationError>>)
        .unwrap()
        .map_err(|err| err.unwrap());
    let res2 = Decode!(&raw_res2, Result<(), Option<ValidationError>>)
        .unwrap()
        .map_err(|err| err.unwrap());

    // One of the concurrent calls is a success and the other one is the expected validation error.
    assert!(res1.is_ok() || res2.is_ok());
    assert!(res1.is_err() || res2.is_err());
    if let Err(err) = res1 {
        assert!(
            matches!(err, ValidationError::ValidationInProgress { canister } if canister == duplicate_canister)
        );
    }
    if let Err(err) = res2 {
        assert!(
            matches!(err, ValidationError::ValidationInProgress { canister } if canister == duplicate_canister)
        );
    }
}

#[tokio::test]
async fn concurrent_migration_source() {
    const NUM_MIGRATIONS: usize = 2;
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings {
        num_migrations: NUM_MIGRATIONS as u64,
        ..Settings::default()
    })
    .await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target1 = targets[0];
    let target2 = targets[1];

    let args1 = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target1,
    };
    let args2 = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target2,
    };
    concurrent_migration(&pic, sender, args1, args2, source).await;
}

#[tokio::test]
async fn concurrent_migration_target() {
    const NUM_MIGRATIONS: usize = 2;
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings {
        num_migrations: NUM_MIGRATIONS as u64,
        ..Settings::default()
    })
    .await;
    let sender = source_controllers[0];
    let source1 = sources[0];
    let source2 = sources[1];
    let target = targets[0];

    let args1 = MigrateCanisterArgs {
        canister_id: source1,
        replace_canister_id: target,
    };
    let args2 = MigrateCanisterArgs {
        canister_id: source2,
        replace_canister_id: target,
    };
    concurrent_migration(&pic, sender, args1, args2, target).await;
}

#[tokio::test]
async fn validation_fails_not_allowlisted() {
    let special_caller = Principal::self_authenticating(vec![42]);
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings {
        allowlist: Some(vec![special_caller]),
        ..Settings::default()
    })
    .await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];

    let Err(ValidationError::MigrationsDisabled(Reserved)) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: target,
        },
    )
    .await
    else {
        panic!()
    };
    // but allowlisted principal succeeds
    migrate_canister(
        &pic,
        special_caller,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: target,
        },
    )
    .await
    .unwrap();

    pic.advance_time(Duration::from_secs(250)).await;
    advance(&pic).await;
}

#[tokio::test]
async fn validation_fails_not_found() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let nonexistent_canister = Principal::from_text("222ay-6aaaa-aaaah-alvrq-cai").unwrap();

    let err = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            canister_id: nonexistent_canister,
            replace_canister_id: target,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ValidationError::CallFailed { reason } if reason.contains(&format!("Call to management canister (`canister_status`) failed. Ensure that the canister {} is the expected source and try again later.", nonexistent_canister)))
    );

    let err = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: nonexistent_canister,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ValidationError::CallFailed { reason } if reason.contains(&format!("Call to management canister (`canister_status`) failed. Ensure that the canister {} is the expected target and try again later.", nonexistent_canister)))
    );
}

#[tokio::test]
async fn validation_fails_same_canister() {
    let Setup {
        pic,
        sources,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];

    let Err(ValidationError::SameSubnet(Reserved)) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: source,
        },
    )
    .await
    else {
        panic!()
    };
}

#[tokio::test]
async fn validation_fails_same_subnet() {
    let Setup {
        pic,
        sources,
        source_subnet,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];

    // Create a target canister on the same subnet.
    let mut new_controllers = source_controllers.clone();
    new_controllers.push(MIGRATION_CANISTER_ID.into());
    let target = pic
        .create_canister_on_subnet(
            Some(sender),
            Some(CanisterSettings {
                controllers: Some(new_controllers),
                ..Default::default()
            }),
            source_subnet,
        )
        .await;

    let Err(ValidationError::SameSubnet(Reserved)) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: target,
        },
    )
    .await
    else {
        panic!()
    };
}

#[tokio::test]
async fn validation_fails_caller_not_controller() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        target_controllers,
        ..
    } = setup(Settings::default()).await;
    // sender not controller of source
    let bad_sender = target_controllers[1];
    let source = sources[0];
    let target = targets[0];
    let Err(ValidationError::CallerNotController { canister }) = migrate_canister(
        &pic,
        bad_sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: target,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, source);

    // sender not controller of target
    let bad_sender = source_controllers[1];
    let Err(ValidationError::CallerNotController { canister }) = migrate_canister(
        &pic,
        bad_sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: target,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, target);
}

#[tokio::test]
async fn validation_fails_mc_not_source_controller() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings {
        mc_controls_source: false,
        ..Default::default()
    })
    .await;
    // MC not controller of source
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let Err(ValidationError::NotController { canister }) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: target,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, source);
}

#[tokio::test]
async fn validation_fails_mc_not_target_controller() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings {
        mc_controls_target: false,
        ..Default::default()
    })
    .await;
    // MC not controller of target
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let Err(ValidationError::NotController { canister }) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            canister_id: source,
            replace_canister_id: target,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, target);
}

#[tokio::test]
async fn validation_fails_not_stopped() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];

    // source
    pic.start_canister(source, Some(sender)).await.unwrap();
    assert!(matches!(
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                canister_id: source,
                replace_canister_id: target
            }
        )
        .await,
        Err(ValidationError::SourceNotStopped(Reserved))
    ));

    pic.stop_canister(source, Some(sender)).await.unwrap();

    // target
    pic.start_canister(target, Some(sender)).await.unwrap();
    assert!(matches!(
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                canister_id: source,
                replace_canister_id: target
            }
        )
        .await,
        Err(ValidationError::TargetNotStopped(Reserved))
    ));
}

#[tokio::test]
async fn validation_fails_disabled() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        system_controller,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
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
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                canister_id: source,
                replace_canister_id: target
            }
        )
        .await,
        Err(ValidationError::MigrationsDisabled(Reserved))
    ));
}

#[tokio::test]
async fn validation_fails_snapshot() {
    let Setup {
        pic,
        sources,
        targets,
        target_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = target_controllers[0];
    let source = sources[0];
    let target = targets[0];
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
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                canister_id: source,
                replace_canister_id: target
            }
        )
        .await,
        Err(ValidationError::TargetHasSnapshots(Reserved))
    ));
}

#[tokio::test]
async fn validation_fails_insufficient_cycles() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings {
        enough_cycles: false,
        ..Default::default()
    })
    .await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];

    assert!(matches!(
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                canister_id: source,
                replace_canister_id: target
            }
        )
        .await,
        Err(ValidationError::SourceInsufficientCycles(Reserved))
    ));
}

#[tokio::test]
async fn status_correct() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let args = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();

    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status.unwrap(),
        MigrationStatus::InProgress {
            status: "Accepted".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status.unwrap(),
        MigrationStatus::InProgress {
            status: "ControllersChanged".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status.unwrap(),
        MigrationStatus::InProgress {
            status: "StoppedAndReady".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status.unwrap(),
        MigrationStatus::InProgress {
            status: "RenamedTarget".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status.unwrap(),
        MigrationStatus::InProgress {
            status: "UpdatedRoutingTable".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status.unwrap(),
        MigrationStatus::InProgress {
            status: "RoutingTableChangeAccepted".to_string()
        }
    );

    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status.unwrap(),
        MigrationStatus::InProgress {
            status: "SourceDeleted".to_string()
        }
    );
    pic.advance_time(Duration::from_secs(360)).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    assert_eq!(
        status.unwrap(),
        MigrationStatus::InProgress {
            status: "RestoredControllers".to_string()
        }
    );
}

#[tokio::test]
async fn after_validation_source_not_stopped() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let args = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // validation succeeded. now we break migration by interfering.
    pic.start_canister(source, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status.unwrap() else {
        panic!()
    };
    assert_eq!(reason, &"Source is not stopped.".to_string());
}

#[tokio::test]
async fn after_validation_target_not_stopped() {
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let args = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // validation succeeded. now we break migration by interfering.
    pic.start_canister(target, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status.unwrap() else {
        panic!()
    };
    assert_eq!(reason, &"Target is not stopped.".to_string());
}

#[tokio::test]
async fn after_validation_target_has_snapshot() {
    let Setup {
        pic,
        sources,
        targets,
        target_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = target_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let args = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target,
    };
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
    let MigrationStatus::Failed { ref reason, .. } = status.unwrap() else {
        panic!()
    };
    assert_eq!(reason, &"Target has snapshots.".to_string());
}

#[tokio::test]
async fn after_validation_insufficient_cycles() {
    let Setup {
        pic,
        sources,
        targets,
        target_controllers,
        ..
    } = setup(Settings {
        enough_cycles: false,
        ..Default::default()
    })
    .await;
    let sender = target_controllers[0];
    let source = sources[0];
    let target = targets[0];
    // Top up just enough to pass validation..
    pic.add_cycles(source, 10_000_000_000_000).await;
    let args = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target,
    };
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
    let MigrationStatus::Failed { ref reason, .. } = status.unwrap() else {
        panic!()
    };
    assert!(reason.contains("Source does not have sufficient cycles"));
}

#[tokio::test]
async fn failure_controllers_restored() {
    let Setup {
        pic,
        sources,
        targets,
        mut source_controllers,
        mut target_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let args = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // Validation succeeded. Now we break migration by interfering.
    pic.start_canister(source, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { .. } = status.unwrap() else {
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

#[tokio::test]
async fn success_controllers_restored() {
    let Setup {
        pic,
        sources,
        targets,
        mut source_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = source_controllers[0];
    let source = sources[0];
    let target = targets[0];
    let args = MigrateCanisterArgs {
        canister_id: source,
        replace_canister_id: target,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    for _ in 0..10 {
        advance(&pic).await;
    }
    pic.advance_time(Duration::from_secs(360)).await;
    for _ in 0..10 {
        advance(&pic).await;
    }
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Succeeded { .. } = status.as_ref().unwrap() else {
        panic!("status: {:?}", status.unwrap());
    };
    let mut source_controllers_after = pic.get_controllers(source).await;
    source_controllers_after.sort();
    // On success, the MC should have removed itself from the controllers.
    source_controllers.retain(|x| x != &MIGRATION_CANISTER_ID.get().0);
    source_controllers.sort();
    assert_eq!(source_controllers, source_controllers_after);
}

// parallel processing
#[tokio::test]
async fn parallel_migrations() {
    const NUM_MIGRATIONS: usize = 51;
    let Setup {
        pic,
        sources,
        targets,
        source_controllers,
        ..
    } = setup(Settings {
        num_migrations: NUM_MIGRATIONS as u64,
        ..Settings::default()
    })
    .await;

    for i in 0..NUM_MIGRATIONS - 1 {
        migrate_canister(
            &pic,
            source_controllers[0],
            &MigrateCanisterArgs {
                canister_id: sources[i],
                replace_canister_id: targets[i],
            },
        )
        .await
        .unwrap();
    }
    // The last one should fail due to rate limit
    let err = migrate_canister(
        &pic,
        source_controllers[0],
        &MigrateCanisterArgs {
            canister_id: sources[NUM_MIGRATIONS - 1],
            replace_canister_id: targets[NUM_MIGRATIONS - 1],
        },
    )
    .await;
    assert!(matches!(err, Err(ValidationError::RateLimited(Reserved))));

    for _ in 0..10 {
        advance(&pic).await;
    }
    for i in 0..NUM_MIGRATIONS - 1 {
        let status = get_status(
            &pic,
            source_controllers[0],
            &MigrateCanisterArgs {
                canister_id: sources[i],
                replace_canister_id: targets[i],
            },
        )
        .await;
        let MigrationStatus::InProgress { ref status } = status.unwrap() else {
            panic!()
        };
        assert_eq!(status, "SourceDeleted");
    }
}

#[tokio::test]
async fn parallel_validations() {
    const NUM_MIGRATIONS: usize = 260;
    let Setup {
        pic,
        sources,
        targets,
        ..
    } = setup(Settings {
        num_migrations: NUM_MIGRATIONS as u64,
        ..Settings::default()
    })
    .await;

    let mut msg_ids = vec![];
    for i in 0..NUM_MIGRATIONS {
        let id = pic
            .submit_call(
                MIGRATION_CANISTER_ID.into(),
                Principal::anonymous(),
                "migrate_canister",
                Encode!(&MigrateCanisterArgs {
                    canister_id: sources[i],
                    replace_canister_id: targets[i],
                })
                .unwrap(),
            )
            .await
            .unwrap();

        msg_ids.push(id);
    }
    advance(&pic).await;

    let mut not_controller_counter = 0;
    let mut rate_limited_counter = 0;
    for msg_id in msg_ids.into_iter() {
        let res = pic.await_call(msg_id).await.unwrap();
        let res = Decode!(&res, Result<(), Option<ValidationError>>)
            .unwrap()
            .map_err(|err| err.unwrap());
        match res {
            Err(ValidationError::CallerNotController { .. }) => not_controller_counter += 1,
            Err(ValidationError::RateLimited(Reserved)) => rate_limited_counter += 1,
            _ => {
                panic!()
            }
        }
    }
    assert_eq!(not_controller_counter, 200);
    assert_eq!(rate_limited_counter, 60);
}
