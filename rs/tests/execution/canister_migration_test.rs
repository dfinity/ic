use std::collections::BTreeMap;
use std::iter::zip;
use std::time::Duration;

use anyhow::{Result, bail};
use candid::{CandidType, Decode, Deserialize, Encode, Principal, Reserved};
use canister_test::Canister;
use futures::future::join_all;
use ic_agent::Agent;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, MIGRATION_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::governance::{pause_canister_migrations, unpause_canister_migrations};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    IcNodeSnapshot,
};
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::util::*;
use ic_system_test_driver::{retry_with_msg_async, systest};
use ic_universal_canister::{call_args, wasm};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;
use slog::{Logger, info};
use tokio_util::sync::CancellationToken;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(Duration::from_secs(1100))
        .with_overall_timeout(Duration::from_secs(1100))
        .execute_from_args()?;

    Ok(())
}

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet.nodes().for_each(|node| {
            node.await_status_is_healthy()
                .unwrap_or_else(|_| panic!("Node {} did not become healty.", node.ic_name))
        })
    });
    install_nns_and_check_progress(env.topology_snapshot());
}

fn test(env: TestEnv) {
    block_on(test_async(env));
}

#[derive(Clone, Debug, CandidType)]
struct MigrateCanisterArgs {
    pub canister_id: Principal,
    pub replace_canister_id: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum ValidationError {
    MigrationsDisabled(Reserved),
    RateLimited(Reserved),
    ValidationInProgress { canister: Principal },
    MigrationInProgress { canister: Principal },
    CanisterNotFound { canister: Principal },
    SameSubnet(Reserved),
    CallerNotController { canister: Principal },
    NotController { canister: Principal },
    MigratedNotStopped(Reserved),
    MigratedNotReady(Reserved),
    ReplacedNotStopped(Reserved),
    ReplacedHasSnapshots(Reserved),
    MigratedInsufficientCycles(Reserved),
    CallFailed { reason: String },
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
enum MigrationStatus {
    InProgress { status: String },
    Failed { reason: String, time: u64 },
    Succeeded { time: u64 },
}

/// Install a stopped canister with the migration canister as one of the controllers.
async fn install_canister<'a>(
    node: &IcNodeSnapshot,
    agent: &'a Agent,
    migration_canister_id: Principal,
    logger: &Logger,
) -> UniversalCanister<'a> {
    info!(
        logger,
        "Installing canister on subnet {}",
        node.subnet_id().unwrap()
    );

    let management_canister = ManagementCanister::create(agent);
    let canister =
        UniversalCanister::new_with_retries(agent, node.effective_canister_id(), logger).await;
    add_controller(&management_canister, &canister, migration_canister_id).await;
    management_canister
        .stop_canister(&canister.canister_id())
        .call_and_wait()
        .await
        .expect("Failed to stop canister.");
    canister
}

async fn add_controller(
    management_canister: &ManagementCanister<'_>,
    canister: &UniversalCanister<'_>,
    controller: Principal,
) {
    let (status_result,) = management_canister
        .canister_status(&canister.canister_id())
        .call_and_wait()
        .await
        .expect("Failed to query canister controllers.");

    let current_controllers: Vec<Principal> = status_result.settings.controllers;

    let mut call = management_canister
        .update_settings(&canister.canister_id())
        .with_controller(controller);

    for current_controller in current_controllers {
        call = call.with_controller(current_controller);
    }
    call.call_and_wait()
        .await
        .expect("Failed to update canister controllers.");
}

async fn test_async(env: TestEnv) {
    let logger = env.logger();
    let migration_canister_id: Principal = MIGRATION_CANISTER_ID.into();
    let nns = env.get_first_healthy_node_snapshot_from_nth_subnet_where(|_| true, 0);
    let nns_agent = nns.build_default_agent_async().await;

    let app_subnet_1 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(|_| true, 1);
    let app_subnet_1_agent = app_subnet_1.build_default_agent_async().await;
    let migrated_canister = install_canister(
        &app_subnet_1,
        &app_subnet_1_agent,
        migration_canister_id,
        &logger,
    )
    .await;
    let migrated_canister2 = install_canister(
        &app_subnet_1,
        &app_subnet_1_agent,
        migration_canister_id,
        &logger,
    )
    .await;
    let other_canister1 = UniversalCanister::new_with_retries(
        &app_subnet_1_agent,
        app_subnet_1.effective_canister_id(),
        &logger,
    )
    .await;
    let app_subnet_2 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(|_| true, 2);
    let app_subnet_2_agent = app_subnet_2.build_default_agent_async().await;
    let replaced_canister = install_canister(
        &app_subnet_2,
        &app_subnet_2_agent,
        migration_canister_id,
        &logger,
    )
    .await;
    let replaced_canister2 = install_canister(
        &app_subnet_2,
        &app_subnet_2_agent,
        migration_canister_id,
        &logger,
    )
    .await;
    let other_canister2 = UniversalCanister::new_with_retries(
        &app_subnet_2_agent,
        app_subnet_2.effective_canister_id(),
        &logger,
    )
    .await;
    let app_subnet_3 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(|_| true, 3);
    let app_subnet_3_agent = app_subnet_3.build_default_agent_async().await;
    let other_canister3 = UniversalCanister::new_with_retries(
        &app_subnet_3_agent,
        app_subnet_3.effective_canister_id(),
        &logger,
    )
    .await;

    let token = CancellationToken::new();
    let handle = {
        let token = token.clone();
        let app_subnet_1_agent = app_subnet_1_agent.clone();
        let app_subnet_2_agent = app_subnet_2_agent.clone();
        let migrated_canister_id = migrated_canister.canister_id();
        let replaced_canister_id = replaced_canister.canister_id();
        let api_bn = env
            .topology_snapshot()
            .api_boundary_nodes()
            .next()
            .expect("There should be at least one API boundary node");
        let bn_agent = api_bn.build_default_agent_async().await;
        let other_canister_id1 = other_canister1.canister_id();
        let other_canister_id2 = other_canister2.canister_id();
        let other_canister_id3 = other_canister3.canister_id();
        let logger = logger.clone();

        tokio::spawn(async move {
            let data = [4, 2];
            let original_canister =
                UniversalCanister::from_canister_id(&app_subnet_1_agent, migrated_canister_id);
            let migrated_canister =
                UniversalCanister::from_canister_id(&app_subnet_2_agent, migrated_canister_id);
            let replaced_canister =
                UniversalCanister::from_canister_id(&app_subnet_2_agent, replaced_canister_id);
            let bn_canister = UniversalCanister::from_canister_id(&bn_agent, migrated_canister_id);
            let other_canister1 =
                UniversalCanister::from_canister_id(&bn_agent, other_canister_id1);
            let other_canister2 =
                UniversalCanister::from_canister_id(&bn_agent, other_canister_id2);
            let other_canister3 =
                UniversalCanister::from_canister_id(&bn_agent, other_canister_id3);

            let mut counts: BTreeMap<(String, String), usize> = Default::default();

            let call_from_everywhere = async |counts: &mut BTreeMap<(String, String), usize>| {
                let mut requests = BTreeMap::new();
                // Ingress message to the migrated canister, sent to the migrated canister subnet directly.
                requests.insert(
                    "migrated_canister_subnet".to_string(),
                    original_canister.update(wasm().reply_data(&data)),
                );
                // Ingress message to the migrated canister, sent to the replaced canister subnet directly.
                requests.insert(
                    "replaced_canister_subnet".to_string(),
                    migrated_canister.update(wasm().reply_data(&data)),
                );
                // Ingress message to the migrated canister, sent to the boundary node.
                requests.insert(
                    "boundary node".to_string(),
                    bn_canister.update(wasm().reply_data(&data)),
                );
                // Ingress message to the replaced canister.
                requests.insert(
                    "replaced canister".to_string(),
                    replaced_canister.update(wasm().reply_data(&data)),
                );
                // XNet message to the migrated canister, sent from the migrated canister subnet.
                requests.insert(
                    "xnet from migrated_canister_subnet".to_string(),
                    other_canister1.update(
                        wasm().inter_update(
                            migrated_canister_id,
                            call_args()
                                .other_side(wasm().reply_data(&data))
                                .on_reject(wasm().reject_message().reject()),
                        ),
                    ),
                );
                // XNet message to the migrated canister, sent from the replaced canister subnet.
                requests.insert(
                    "xnet from replaced_canister_subnet".to_string(),
                    other_canister2.update(
                        wasm().inter_update(
                            migrated_canister_id,
                            call_args()
                                .other_side(wasm().reply_data(&data))
                                .on_reject(wasm().reject_message().reject()),
                        ),
                    ),
                );
                // XNet message to the migrated canister, sent from a subnet not involved in the migration.
                requests.insert(
                    "xnet from third".to_string(),
                    other_canister3.update(
                        wasm().inter_update(
                            migrated_canister_id,
                            call_args()
                                .other_side(wasm().reply_data(&data))
                                .on_reject(wasm().reject_message().reject()),
                        ),
                    ),
                );
                // XNet message to the replaced canister, sent from the migrated canister subnet.
                requests.insert(
                    "xnet from migrated_canister_subnet to replaced_canister".to_string(),
                    other_canister1.update(
                        wasm().inter_update(
                            replaced_canister_id,
                            call_args()
                                .other_side(wasm().reply_data(&data))
                                .on_reject(wasm().reject_message().reject()),
                        ),
                    ),
                );
                // XNet message to the replaced canister, sent from the replaced canister subnet.
                requests.insert(
                    "xnet from replaced_canister_subnet to replaced_canister".to_string(),
                    other_canister2.update(
                        wasm().inter_update(
                            replaced_canister_id,
                            call_args()
                                .other_side(wasm().reply_data(&data))
                                .on_reject(wasm().reject_message().reject()),
                        ),
                    ),
                );
                // XNet message to the replaced canister, sent from a subnet not involved in the migration.
                requests.insert(
                    "xnet from third to replaced_canister".to_string(),
                    other_canister3.update(
                        wasm().inter_update(
                            replaced_canister_id,
                            call_args()
                                .other_side(wasm().reply_data(&data))
                                .on_reject(wasm().reject_message().reject()),
                        ),
                    ),
                );

                let (keys, tasks): (Vec<_>, Vec<_>) = requests.into_iter().unzip();
                let responses = join_all(tasks).await;
                for (key, res) in zip(keys, responses) {
                    if format!("{:?}", res).contains("is stopped") {
                        // Message was correctly routed to the stopped canister.
                        *counts.entry((key, "stopped".to_string())).or_default() += 1;
                    } else if format!("{:?}", res).contains("not found") {
                        // Canister was either not on the subnet that received the message, or has been deleted.
                        *counts.entry((key, "not found".to_string())).or_default() += 1;
                    } else if format!("{:?}", res).contains("migration in progress") {
                        // XNet message arriving at a subnet that did not own the canister according to the routing table.
                        *counts
                            .entry((key, "migration in progress".to_string()))
                            .or_default() += 1;
                    } else {
                        // Something else happened.
                        info!(logger, "Response ({}): {:?}", key, res);
                        *counts.entry((key, "other".to_string())).or_default() += 1;
                    }
                }
            };

            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        break;
                    }
                    () = call_from_everywhere(&mut counts) => {}
                }
            }

            info!(logger, "Messages breakdown:");
            for ((key, category), count) in counts {
                info!(logger, "({}, {}): {}", key, category, count);
            }
        })
    };

    let nns_runtime = runtime_from_url(nns.get_public_url(), nns.effective_canister_id());
    let governance_canister = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    info!(logger, "Pausing migrations");

    pause_canister_migrations(&governance_canister).await;

    let args = Encode!(&MigrateCanisterArgs {
        canister_id: migrated_canister.canister_id(),
        replace_canister_id: replaced_canister.canister_id(),
    })
    .unwrap();
    let args2 = Encode!(&MigrateCanisterArgs {
        canister_id: migrated_canister2.canister_id(),
        replace_canister_id: replaced_canister2.canister_id(),
    })
    .unwrap();

    info!(logger, "Calling migrate_canister on paused canister");

    let result = nns_agent
        .update(&migration_canister_id, "migrate_canister")
        .with_arg(args.clone())
        .call_and_wait()
        .await
        .expect("Failed to call migrate_canister.");

    let decoded_result = Decode!(&result, Result<(), Option<ValidationError>>)
        .expect("Failed to decode reponse from migrate_canister.");

    assert_eq!(
        decoded_result,
        Err(Some(ValidationError::MigrationsDisabled(Reserved)))
    );

    info!(logger, "Unpausing migrations");

    unpause_canister_migrations(&governance_canister).await;

    info!(logger, "Calling migrate_canister on unpaused canister");

    let result = nns_agent
        .update(&migration_canister_id, "migrate_canister")
        .with_arg(args.clone())
        .call_and_wait()
        .await
        .expect("Failed to call migrate_canister.");

    let _result = nns_agent
        .update(&migration_canister_id, "migrate_canister")
        .with_arg(args2.clone())
        .call_and_wait()
        .await
        .expect("Failed to call migrate_canister.");

    let decoded_result = Decode!(&result, Result<(), Option<ValidationError>>)
        .expect("Failed to decode reponse from migrate_canister.");

    assert_eq!(decoded_result, Ok(()));

    // The migration canister has a step where it waits for 6 minutes, so we give it a minute more than that.
    println!("Wait 7 minutes for processing.");

    retry_with_msg_async!(
        "Wait 7m for migration canister to process",
        &logger,
        Duration::from_secs(420),
        Duration::from_secs(10),
        || async {
            let status = nns_agent
                .update(&migration_canister_id, "migration_status")
                .with_arg(args.clone())
                .call_and_wait()
                .await
                .expect("Failed to call migration_status.");
            let decoded_status = Decode!(&status, Option<MigrationStatus>)
                .expect("Failed to decode response from migration_status.")
                .expect("There should be a migration status available.");

            if matches!(decoded_status, MigrationStatus::Succeeded { .. }) {
                Ok(())
            } else {
                bail!("Not ready. Status: {:?}", decoded_status)
            }
        }
    )
    .await
    .unwrap();

    // assert that the migrated canister is on the replaced canister subnet.
    #[derive(CandidType, Deserialize)]
    struct GetSubnetForCanisterArgs {
        principal: Option<Principal>,
    }
    #[derive(CandidType, Deserialize)]
    struct Response {
        subnet_id: Option<Principal>,
    }
    let res = nns_agent
        .update(&REGISTRY_CANISTER_ID.into(), "get_subnet_for_canister")
        .with_arg(
            Encode!(&GetSubnetForCanisterArgs {
                principal: Some(migrated_canister.canister_id())
            })
            .unwrap(),
        )
        .call_and_wait()
        .await
        .unwrap();
    let Ok(Response { subnet_id }) = Decode!(&res, Result<Response, String>).unwrap() else {
        panic!()
    };
    assert_eq!(
        subnet_id.unwrap(),
        app_subnet_2.subnet_id().unwrap().get().0
    );

    let migrated_canister =
        UniversalCanister::from_canister_id(&app_subnet_2_agent, migrated_canister.canister_id());
    let mgr = ManagementCanister::create(&app_subnet_2_agent);

    // wait until delegation updates
    retry_with_msg_async!(
        "Wait 10m for delegation to change",
        &logger,
        Duration::from_secs(660),
        Duration::from_secs(10),
        || async {
            // assert that "migrated" canister responds
            match mgr.start_canister(&migrated_canister.canister_id()).await {
                Ok(_) => Ok(()),
                Err(_) => bail!("Not ready"),
            }
        }
    )
    .await
    .unwrap();

    let data = [4, 2];
    let res = migrated_canister
        .update(wasm().reply_data(&data))
        .await
        .unwrap();
    assert_eq!(data, &res[0..2]);

    token.cancel();
    handle.await.expect("Worker task panicked!");

    assert_no_critical_errors(&env, &logger).await;
}

async fn assert_no_critical_errors(env: &TestEnv, log: &slog::Logger) {
    let nodes = env.topology_snapshot().subnets().flat_map(|s| s.nodes());
    const NUM_RETRIES: u32 = 10;
    const BACKOFF_TIME_MILLIS: u64 = 500;

    let metrics = MetricsFetcher::new(nodes, vec!["critical_errors".to_string()]);
    for i in 0..NUM_RETRIES {
        match metrics.fetch::<u64>().await {
            Ok(result) => {
                assert!(!result.is_empty());
                let filtered_results = result
                    .iter()
                    .filter(|(_, v)| v.iter().any(|x| *x > 0))
                    .collect::<BTreeMap<_, _>>();
                assert!(
                    filtered_results.is_empty(),
                    "Critical error detected: {filtered_results:?}"
                );
                return;
            }
            Err(e) => {
                info!(log, "Could not scrape metrics: {e}, attempt {i}.");
            }
        }
        tokio::time::sleep(Duration::from_millis(BACKOFF_TIME_MILLIS)).await;
    }
    panic!("Couldn't obtain metrics after {NUM_RETRIES} attempts.");
}
