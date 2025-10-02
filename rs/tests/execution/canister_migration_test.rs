use std::time::Duration;

use anyhow::Result;
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_agent::Agent;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_nns_constants::{MIGRATION_CANISTER_ID, REGISTRY_CANISTER_ID};
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
use ic_system_test_driver::systest;
use ic_system_test_driver::util::*;
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;
use slog::{Logger, info};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
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
    pub source: Principal,
    pub target: Principal,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
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
    let nns_agent = env
        .get_first_healthy_node_snapshot_from_nth_subnet_where(|_| true, 0)
        .build_default_agent_async()
        .await;

    let app_subnet_1 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(|_| true, 1);
    let app_subnet_1_agent = app_subnet_1.build_default_agent_async().await;
    let source_canister = install_canister(
        &app_subnet_1,
        &app_subnet_1_agent,
        migration_canister_id,
        &logger,
    )
    .await;
    let source_canister2 = install_canister(
        &app_subnet_1,
        &app_subnet_1_agent,
        migration_canister_id,
        &logger,
    )
    .await;
    let app_subnet_2 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(|_| true, 2);
    let app_subnet_2_agent = app_subnet_2.build_default_agent_async().await;
    let target_canister = install_canister(
        &app_subnet_2,
        &app_subnet_2_agent,
        migration_canister_id,
        &logger,
    )
    .await;
    let target_canister2 = install_canister(
        &app_subnet_2,
        &app_subnet_2_agent,
        migration_canister_id,
        &logger,
    )
    .await;

    let args = Encode!(&MigrateCanisterArgs {
        source: source_canister.canister_id(),
        target: target_canister.canister_id(),
    })
    .unwrap();
    let args2 = Encode!(&MigrateCanisterArgs {
        source: source_canister2.canister_id(),
        target: target_canister2.canister_id(),
    })
    .unwrap();

    info!(logger, "Calling migrate_canister");

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

    let decoded_result = Decode!(&result, Result<(), ValidationError>)
        .expect("Failed to decode reponse from migrate_canister.");

    assert_eq!(decoded_result, Ok(()));

    // The migration canister has a step where it waits for 5 minutes, so we give it a minute more than that.
    println!("Wait over 5 minutes for processing.");
    tokio::time::sleep(Duration::from_secs(360)).await;

    let status = nns_agent
        .update(&migration_canister_id, "migration_status")
        .with_arg(args.clone())
        .call_and_wait()
        .await
        .expect("Failed to call migration_status.");
    let decoded_status = Decode!(&status, Vec<MigrationStatus>)
        .expect("Failed to decode response from migration_status.");

    assert!(matches!(
        decoded_status[0],
        MigrationStatus::Succeeded { .. }
    ));

    // assert that the source canister is on the target subnet.
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
                principal: Some(source_canister.canister_id())
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
}
