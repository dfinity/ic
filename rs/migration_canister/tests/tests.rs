use candid::{CandidType, Decode, Encode, Principal, Reserved};
use canister_test::Project;
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types::{CanisterLogRecord, CanisterSettings};
use ic_management_canister_types_private::{
    CanisterChangeDetails, CanisterInfoRequest, CanisterInfoResponse, Payload as _,
};
use ic_nervous_system_common_test_utils::get_gauge;
use ic_transport_types::Envelope;
use ic_transport_types::EnvelopeContent::Call;
use ic_universal_canister::{CallArgs, UNIVERSAL_CANISTER_WASM, wasm};
use itertools::Itertools;
use pocket_ic::{
    PocketIcBuilder,
    common::rest::{IcpFeatures, IcpFeaturesConfig},
    nonblocking::PocketIc,
};
use prometheus_parse::Scrape;
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
    pub migrated_canister_id: Principal,
    pub replaced_canister_id: Principal,
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
    MigratedCanisterNotStopped(Reserved),
    MigratedCanisterNotReady(Reserved),
    ReplacedCanisterNotStopped(Reserved),
    ReplacedCanisterHasSnapshots(Reserved),
    MigratedCanisterInsufficientCycles(Reserved),
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
    pub migrateds: Vec<Principal>,
    pub replaceds: Vec<Principal>,
    pub migrated_canister_controllers: Vec<Principal>,
    pub replaced_canister_controllers: Vec<Principal>,
    pub migrated_canister_subnet: Principal,
    pub replaced_canister_subnet: Principal,
    /// Controller of the NNS canisters including MC
    pub system_controller: Principal,
}

pub struct Settings {
    pub num_migrations: u64,
    pub mc_controls_migrated: bool,
    pub mc_controls_replaced: bool,
    pub enough_cycles: bool,
    pub allowlist: Option<Vec<Principal>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            num_migrations: 1,
            mc_controls_migrated: true,
            mc_controls_replaced: true,
            enough_cycles: true,
            allowlist: None,
        }
    }
}

/// Sets up PocketIc with the registry canister, the migration canister and two canisters on different app subnets.
async fn setup(
    Settings {
        num_migrations,
        mc_controls_migrated,
        mc_controls_replaced,
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
    let migrated_canister_controllers = vec![c1, c2];
    let replaced_canister_controllers = vec![c1, c3];

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
    let migrated_canister_subnet = subnets[0];
    let replaced_canister_subnet = subnets[1];

    let mut migrateds = vec![];
    let mut replaceds = vec![];
    for _ in 0..num_migrations {
        // migrated canister
        let mut new_controllers = migrated_canister_controllers.clone();
        if mc_controls_migrated {
            new_controllers.push(MIGRATION_CANISTER_ID.into());
        }
        if let Some(ref allowlist) = allowlist {
            new_controllers.extend(allowlist.clone());
        }
        let migrated = pic
            .create_canister_on_subnet(
                Some(c1),
                Some(CanisterSettings {
                    controllers: Some(new_controllers),
                    ..Default::default()
                }),
                migrated_canister_subnet,
            )
            .await;
        if enough_cycles {
            pic.add_cycles(migrated, u128::MAX / 2).await;
        } else {
            pic.add_cycles(migrated, 2_000_000).await;
        }
        pic.stop_canister(migrated, Some(c1)).await.unwrap();
        migrateds.push(migrated);

        // replaced canister
        let mut new_controllers = replaced_canister_controllers.clone();
        if mc_controls_replaced {
            new_controllers.push(MIGRATION_CANISTER_ID.into());
        }
        if let Some(ref allowlist) = allowlist {
            new_controllers.extend(allowlist.clone());
        }
        let replaced = pic
            .create_canister_on_subnet(
                Some(c1),
                Some(CanisterSettings {
                    controllers: Some(new_controllers),
                    ..Default::default()
                }),
                replaced_canister_subnet,
            )
            .await;
        if enough_cycles {
            pic.add_cycles(replaced, u128::MAX / 2).await;
        } else {
            pic.add_cycles(replaced, 2_000_000).await;
        }
        pic.stop_canister(replaced, Some(c1)).await.unwrap();
        replaceds.push(replaced)
    }
    Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        replaced_canister_controllers,
        migrated_canister_subnet,
        replaced_canister_subnet,
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

async fn fetch_metrics(pic: &PocketIc) -> Scrape {
    let http_request = ic_http_types::HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: vec![],
        body: serde_bytes::ByteBuf::default(),
    };

    let res = pic
        .query_call(
            MIGRATION_CANISTER_ID.into(),
            Principal::anonymous(),
            "http_request",
            Encode!(&http_request).unwrap(),
        )
        .await
        .unwrap();

    let response = Decode!(&res, ic_http_types::HttpResponse).unwrap();

    let iterator = String::from_utf8(response.body.into_vec())
        .unwrap()
        .lines()
        .map(|s| Ok(s.to_owned()))
        .collect::<Vec<_>>()
        .into_iter();

    prometheus_parse::Scrape::parse(iterator).unwrap()
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
        migrateds,
        replaceds,
        migrated_canister_controllers,
        system_controller,
        replaced_canister_subnet,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];

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

    // We deploy the universal canister WASM to the "replaced" canister
    // so that we can call it via the "migrated" canister ID
    // after renaming.
    pic.add_cycles(replaced, 1_000_000_000_000).await;
    pic.install_canister(
        replaced,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
        Some(sender),
    )
    .await;

    // There is 1 entry in the canister history of the "migrated" canister before migrating:
    // creation.
    let migrated_canister_info = canister_info(&pic, proxy_canister, migrated).await;
    assert_eq!(migrated_canister_info.total_num_changes(), 1);
    assert!(matches!(
        migrated_canister_info.changes()[0].details(),
        CanisterChangeDetails::CanisterCreation(_)
    ));
    // There are 2 entries in the canister history of the "replaced" canister before migrating:
    // creation and installation.
    let replaced_canister_info = canister_info(&pic, proxy_canister, replaced).await;
    assert_eq!(replaced_canister_info.total_num_changes(), 2);
    assert!(matches!(
        replaced_canister_info.changes()[0].details(),
        CanisterChangeDetails::CanisterCreation(_)
    ));
    assert!(matches!(
        replaced_canister_info.changes()[1].details(),
        CanisterChangeDetails::CanisterCodeDeployment(_)
    ));

    migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: replaced,
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
        "Entering `renamed_replaced` with 1 pending",
        "Exiting `renamed_replaced` with 1 successful",
        "Entering `updated_routing_table` with 1 pending",
        "Exiting `updated_routing_table` with 1 successful",
        "Entering `routing_table_change_accepted` with 1 pending",
        "Exiting `routing_table_change_accepted` with 1 successful",
        "Entering `migrated_canister_deleted` with 1 pending",
        "Exiting `migrated_canister_deleted` with 1 successful",
    ]));

    let migrated_canister_new_subnet = pic.get_subnet(migrated).await.unwrap();
    assert_eq!(migrated_canister_new_subnet, replaced_canister_subnet);
    pic.start_canister(migrated, Some(sender)).await.unwrap();
    pic.update_call(migrated, sender, "update", wasm().reply().build())
        .await
        .unwrap();

    // We check the canister history of the "migrated" canister after renaming.
    let migrated_canister_info = canister_info(&pic, proxy_canister, migrated).await;
    // There are 4 changes of the "migrated" canister after renaming:
    // creation, controllers change, renaming, and controllers change.
    assert_eq!(migrated_canister_info.total_num_changes(), 4);
    // There are 5 entries in the canister history of the "migrated" canister after renaming:
    // creation, installation, controllers change of the "replaced" canister before renaming,
    // then renaming, and controllers change.
    let canister_history = migrated_canister_info.changes();
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
            assert_eq!(rename_record.canister_id(), PrincipalId(replaced));
            // There were 3 entries in the canister history of the "replaced" canister before renaming:
            // creation, installation, and controllers change.
            assert_eq!(rename_record.total_num_changes(), 3);
            let rename_to = rename_record.rename_to();
            assert_eq!(rename_to.canister_id(), PrincipalId(migrated));
            // There were 2 entries in the canister history of the "migrated" canister before renaming:
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
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];

    assert_eq!(
        get_gauge(
            &fetch_metrics(&pic).await,
            "migration_canister_num_successes_in_past_24_h"
        ),
        0.0
    );

    // We deploy the universal canister WASM
    // to both the "migrated" and "replaced" canisters
    // so that we can call the "migrated" canister ID
    // both before and after renaming.
    for canister_id in [migrated, replaced] {
        pic.add_cycles(canister_id, 1_000_000_000_000).await;
        pic.install_canister(
            canister_id,
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            Some(sender),
        )
        .await;
    }

    // We restart the "migrated" canister for a moment so that
    // we can send an update call to it.
    pic.start_canister(migrated, Some(sender)).await.unwrap();

    // We manually submit an update call so that
    // we can replay the exact same HTTP request later.
    let ingress_expiry = pic.get_time().await.as_nanos_since_unix_epoch() + 330_000_000_000;
    let (resp, _) = call_request(&pic, ingress_expiry, migrated).await;
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);

    // We stop the "migrated" canister again so that
    // we can kick off canister migration.
    pic.stop_canister(migrated, Some(sender)).await.unwrap();

    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
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

    assert_eq!(
        get_gauge(
            &fetch_metrics(&pic).await,
            "migration_canister_num_successes_in_past_24_h"
        ),
        1.0
    );

    // We restart the "migrated" canister right away.
    pic.start_canister(migrated, Some(sender)).await.unwrap();

    // Replaying the update call from before should fail.
    let (resp, _) = call_request(&pic, ingress_expiry, migrated).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let message = String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap();
    assert!(message.contains("Invalid request expiry"));
    assert_eq!(
        get_gauge(
            &fetch_metrics(&pic).await,
            "migration_canister_num_successes_in_past_24_h"
        ),
        1.0
    );
}

#[tokio::test]
async fn metrics() {
    let Setup { pic, .. } = setup(Settings::default()).await;

    let metrics = fetch_metrics(&pic).await;

    assert_eq!(
        get_gauge(&metrics, "migration_canister_num_successes_in_past_24_h"),
        0.0
    );

    assert_eq!(
        get_gauge(&metrics, "migration_canister_migrations_enabled"),
        1.0
    );
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
async fn concurrent_migration_migrated() {
    const NUM_MIGRATIONS: usize = 2;
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings {
        num_migrations: NUM_MIGRATIONS as u64,
        ..Settings::default()
    })
    .await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced1 = replaceds[0];
    let replaced2 = replaceds[1];

    let args1 = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced1,
    };
    let args2 = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced2,
    };
    concurrent_migration(&pic, sender, args1, args2, migrated).await;
}

#[tokio::test]
async fn concurrent_migration_replaced() {
    const NUM_MIGRATIONS: usize = 2;
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings {
        num_migrations: NUM_MIGRATIONS as u64,
        ..Settings::default()
    })
    .await;
    let sender = migrated_canister_controllers[0];
    let migrated1 = migrateds[0];
    let migrated2 = migrateds[1];
    let replaced = replaceds[0];

    let args1 = MigrateCanisterArgs {
        migrated_canister_id: migrated1,
        replaced_canister_id: replaced,
    };
    let args2 = MigrateCanisterArgs {
        migrated_canister_id: migrated2,
        replaced_canister_id: replaced,
    };
    concurrent_migration(&pic, sender, args1, args2, replaced).await;
}

async fn canister_changed_before_migration<F, Fut>(setup: &Setup, race: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = Principal>,
{
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];

    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
    };
    migrate_canister(pic, sender, &args).await.unwrap();

    // Change the canister (migrated or replaced) right away after requesting its migration;
    // in particular, before the (accepted) request is processed in a timer.
    let canister = race().await;
    assert!(canister == migrated || canister == replaced);

    for _ in 0..10 {
        // Advance time so that timers are triggered.
        pic.advance_time(Duration::from_secs(1)).await;
        pic.tick().await;
    }

    let status = get_status(pic, sender, &args).await;
    assert!(matches!(
        status.unwrap(),
        MigrationStatus::Failed {reason, ..} if reason.contains(&format!("Failed to set the migration canister as the exclusive controller of canister {}", canister))
    ));
}

#[tokio::test]
async fn migrated_canister_controllers_changed_before_migration() {
    let setup = setup(Settings::default()).await;

    let pic = &setup.pic;
    let sender = setup.migrated_canister_controllers[0];
    let migrated = setup.migrateds[0];
    let race = || async {
        pic.set_controllers(migrated, Some(sender), vec![sender])
            .await
            .unwrap();
        migrated
    };
    canister_changed_before_migration(&setup, race).await;
}

#[tokio::test]
async fn migrated_canister_deleted_before_migration() {
    let setup = setup(Settings::default()).await;

    let pic = &setup.pic;
    let sender = setup.migrated_canister_controllers[0];
    let migrated = setup.migrateds[0];
    let race = || async {
        pic.delete_canister(migrated, Some(sender)).await.unwrap();
        migrated
    };
    canister_changed_before_migration(&setup, race).await;
}

#[tokio::test]
async fn replaced_canister_controllers_changed_before_migration() {
    let setup = setup(Settings::default()).await;

    let pic = &setup.pic;
    let sender = setup.migrated_canister_controllers[0];
    let replaced = setup.replaceds[0];
    let race = || async {
        pic.set_controllers(replaced, Some(sender), vec![sender])
            .await
            .unwrap();
        replaced
    };
    canister_changed_before_migration(&setup, race).await;
}

#[tokio::test]
async fn replaced_canister_deleted_before_migration() {
    let setup = setup(Settings::default()).await;

    let pic = &setup.pic;
    let sender = setup.migrated_canister_controllers[0];
    let replaced = setup.replaceds[0];
    let race = || async {
        pic.delete_canister(replaced, Some(sender)).await.unwrap();
        replaced
    };
    canister_changed_before_migration(&setup, race).await;
}

#[tokio::test]
async fn validation_fails_not_allowlisted() {
    let special_caller = Principal::self_authenticating(vec![42]);
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings {
        allowlist: Some(vec![special_caller]),
        ..Settings::default()
    })
    .await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];

    let Err(ValidationError::MigrationsDisabled(Reserved)) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: replaced,
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
            migrated_canister_id: migrated,
            replaced_canister_id: replaced,
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
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let nonexistent_canister = Principal::from_text("222ay-6aaaa-aaaah-alvrq-cai").unwrap();

    let err = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            migrated_canister_id: nonexistent_canister,
            replaced_canister_id: replaced,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ValidationError::CanisterNotFound {canister} if canister == nonexistent_canister)
    );

    let err = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: nonexistent_canister,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ValidationError::CanisterNotFound {canister} if canister == nonexistent_canister)
    );
}

#[tokio::test]
async fn validation_fails_same_canister() {
    let Setup {
        pic,
        migrateds,
        migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];

    let Err(ValidationError::SameSubnet(Reserved)) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: migrated,
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
        migrateds,
        migrated_canister_subnet,
        migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];

    // Create a replaced canister on the same subnet.
    let mut new_controllers = migrated_canister_controllers.clone();
    new_controllers.push(MIGRATION_CANISTER_ID.into());
    let replaced = pic
        .create_canister_on_subnet(
            Some(sender),
            Some(CanisterSettings {
                controllers: Some(new_controllers),
                ..Default::default()
            }),
            migrated_canister_subnet,
        )
        .await;

    let Err(ValidationError::SameSubnet(Reserved)) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: replaced,
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
        migrateds,
        replaceds,
        migrated_canister_controllers,
        replaced_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    // sender not controller of migrated canister
    let bad_sender = replaced_canister_controllers[1];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let Err(ValidationError::CallerNotController { canister }) = migrate_canister(
        &pic,
        bad_sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: replaced,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, migrated);

    // sender not controller of replaced canister
    let bad_sender = migrated_canister_controllers[1];
    let Err(ValidationError::CallerNotController { canister }) = migrate_canister(
        &pic,
        bad_sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: replaced,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, replaced);
}

#[tokio::test]
async fn validation_fails_mc_not_migrated_canister_controller() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings {
        mc_controls_migrated: false,
        ..Default::default()
    })
    .await;
    // MC not controller of migrated canister
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let Err(ValidationError::NotController { canister }) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: replaced,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, migrated);
}

#[tokio::test]
async fn validation_fails_mc_not_replaced_canister_controller() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings {
        mc_controls_replaced: false,
        ..Default::default()
    })
    .await;
    // MC not controller of replaced canister
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let Err(ValidationError::NotController { canister }) = migrate_canister(
        &pic,
        sender,
        &MigrateCanisterArgs {
            migrated_canister_id: migrated,
            replaced_canister_id: replaced,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(canister, replaced);
}

#[tokio::test]
async fn validation_fails_not_stopped() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];

    pic.start_canister(migrated, Some(sender)).await.unwrap();
    assert!(matches!(
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                migrated_canister_id: migrated,
                replaced_canister_id: replaced
            }
        )
        .await,
        Err(ValidationError::MigratedCanisterNotStopped(Reserved))
    ));

    pic.stop_canister(migrated, Some(sender)).await.unwrap();

    pic.start_canister(replaced, Some(sender)).await.unwrap();
    assert!(matches!(
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                migrated_canister_id: migrated,
                replaced_canister_id: replaced
            }
        )
        .await,
        Err(ValidationError::ReplacedCanisterNotStopped(Reserved))
    ));
}

#[tokio::test]
async fn validation_fails_disabled() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        system_controller,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
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
                migrated_canister_id: migrated,
                replaced_canister_id: replaced
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
        migrateds,
        replaceds,
        replaced_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = replaced_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    // install a minimal Wasm module
    pic.install_canister(
        replaced,
        b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec(),
        vec![],
        Some(sender),
    )
    .await;
    let _ = pic
        .take_canister_snapshot(replaced, Some(sender), None)
        .await
        .unwrap();
    assert!(matches!(
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                migrated_canister_id: migrated,
                replaced_canister_id: replaced
            }
        )
        .await,
        Err(ValidationError::ReplacedCanisterHasSnapshots(Reserved))
    ));
}

#[tokio::test]
async fn validation_fails_insufficient_cycles() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings {
        enough_cycles: false,
        ..Default::default()
    })
    .await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];

    assert!(matches!(
        migrate_canister(
            &pic,
            sender,
            &MigrateCanisterArgs {
                migrated_canister_id: migrated,
                replaced_canister_id: replaced
            }
        )
        .await,
        Err(ValidationError::MigratedCanisterInsufficientCycles(
            Reserved
        ))
    ));
}

#[tokio::test]
async fn status_correct() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
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
            status: "RenamedReplacedCanister".to_string()
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
            status: "MigratedCanisterDeleted".to_string()
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
async fn after_validation_migrated_canister_not_stopped() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // validation succeeded. now we break migration by interfering.
    pic.start_canister(migrated, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status.unwrap() else {
        panic!()
    };
    assert_eq!(reason, &"Migrated canister is not stopped.".to_string());
}

#[tokio::test]
async fn after_validation_replaced_canister_not_stopped() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // validation succeeded. now we break migration by interfering.
    pic.start_canister(replaced, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status.unwrap() else {
        panic!()
    };
    assert_eq!(reason, &"Replaced canister is not stopped.".to_string());
}

#[tokio::test]
async fn after_validation_replaced_canister_has_snapshot() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        replaced_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = replaced_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // validation succeeded. now we break migration by interfering.
    // install a minimal Wasm module
    pic.install_canister(
        replaced,
        b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec(),
        vec![],
        Some(sender),
    )
    .await;
    let _ = pic
        .take_canister_snapshot(replaced, Some(sender), None)
        .await
        .unwrap();

    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status.unwrap() else {
        panic!()
    };
    assert_eq!(reason, &"Replaced canister has snapshots.".to_string());
}

#[tokio::test]
async fn after_validation_insufficient_cycles() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        replaced_canister_controllers,
        ..
    } = setup(Settings {
        enough_cycles: false,
        ..Default::default()
    })
    .await;
    let sender = replaced_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    // Top up just enough to pass validation..
    pic.add_cycles(migrated, 10_000_000_000_000).await;
    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // ..but then burn some cycles by reinstalling to get under the required amount.
    pic.reinstall_canister(
        migrated,
        b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec(),
        vec![],
        Some(sender),
    )
    .await
    .unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { ref reason, .. } = status.unwrap() else {
        panic!()
    };
    assert!(reason.contains("Migrated canister does not have sufficient cycles"));
}

#[tokio::test]
async fn failure_controllers_restored() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        mut migrated_canister_controllers,
        mut replaced_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
    };
    migrate_canister(&pic, sender, &args).await.unwrap();
    // Validation succeeded. Now we break migration by interfering.
    pic.start_canister(migrated, Some(sender)).await.unwrap();
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    advance(&pic).await;
    let status = get_status(&pic, sender, &args).await;
    let MigrationStatus::Failed { .. } = status.unwrap() else {
        panic!()
    };
    let mut migrated_canister_controllers_after = pic.get_controllers(migrated).await;
    let mut replaced_canister_controllers_after = pic.get_controllers(replaced).await;
    migrated_canister_controllers_after.sort();
    replaced_canister_controllers_after.sort();
    migrated_canister_controllers.sort();
    replaced_canister_controllers.sort();
    // On failure, the MC should remain controller such that user can retry.
    assert_eq!(
        migrated_canister_controllers,
        migrated_canister_controllers_after
    );
    assert_eq!(
        replaced_canister_controllers,
        replaced_canister_controllers_after
    );
}

#[tokio::test]
async fn success_controllers_restored() {
    let Setup {
        pic,
        migrateds,
        replaceds,
        mut migrated_canister_controllers,
        ..
    } = setup(Settings::default()).await;
    let sender = migrated_canister_controllers[0];
    let migrated = migrateds[0];
    let replaced = replaceds[0];
    let args = MigrateCanisterArgs {
        migrated_canister_id: migrated,
        replaced_canister_id: replaced,
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
    let mut migrated_canister_controllers_after = pic.get_controllers(migrated).await;
    migrated_canister_controllers_after.sort();
    // On success, the MC should have removed itself from the controllers.
    migrated_canister_controllers.retain(|x| x != &MIGRATION_CANISTER_ID.get().0);
    migrated_canister_controllers.sort();
    assert_eq!(
        migrated_canister_controllers,
        migrated_canister_controllers_after
    );
}

// parallel processing
#[tokio::test]
async fn parallel_migrations() {
    const NUM_MIGRATIONS: usize = 51;
    let Setup {
        pic,
        migrateds,
        replaceds,
        migrated_canister_controllers,
        ..
    } = setup(Settings {
        num_migrations: NUM_MIGRATIONS as u64,
        ..Settings::default()
    })
    .await;

    for i in 0..NUM_MIGRATIONS - 1 {
        migrate_canister(
            &pic,
            migrated_canister_controllers[0],
            &MigrateCanisterArgs {
                migrated_canister_id: migrateds[i],
                replaced_canister_id: replaceds[i],
            },
        )
        .await
        .unwrap();
    }
    // The last one should fail due to rate limit
    let err = migrate_canister(
        &pic,
        migrated_canister_controllers[0],
        &MigrateCanisterArgs {
            migrated_canister_id: migrateds[NUM_MIGRATIONS - 1],
            replaced_canister_id: replaceds[NUM_MIGRATIONS - 1],
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
            migrated_canister_controllers[0],
            &MigrateCanisterArgs {
                migrated_canister_id: migrateds[i],
                replaced_canister_id: replaceds[i],
            },
        )
        .await;
        let MigrationStatus::InProgress { ref status } = status.unwrap() else {
            panic!()
        };
        assert_eq!(status, "MigratedCanisterDeleted");
    }
}

#[tokio::test]
async fn parallel_validations() {
    const NUM_MIGRATIONS: usize = 260;
    let Setup {
        pic,
        migrateds,
        replaceds,
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
                    migrated_canister_id: migrateds[i],
                    replaced_canister_id: replaceds[i],
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
