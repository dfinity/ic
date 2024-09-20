/* tag::catalog[]

Title:: Subnet Splitting Test

Goal::
Ensure that Subnet Splitting works

Runbook::
. Deploy an IC with two application subnets.
. Add canister migration entry to the registry.
. Halt the source subnet at CUP height.
. Reroute the canisters.
. Download the state from the source subnet.
. Split the state.
. Propose a CUP with the new state for the source subnet.
. Upload the new state to one of the nodes in the source subnet.
. Propose a CUP with the new state for the destination subnet.
. Upload the new state to one of the nodes in the destination subnet.
. Wait until the CUPs have been observed by the nodes in both subnets.
. Unhalt both subnets.
. Remove canister migration entries from the registry.

Success::
. Both subnets are functional after the split and the canisters are migrated.

end::catalog[] */

use ic_base_types::SubnetId;
use ic_consensus_system_test_utils::subnet::assert_subnet_is_healthy;
use ic_consensus_system_test_utils::{
    rw_message::{
        can_read_msg, cert_state_makes_progress_with_retries, install_nns_and_check_progress,
        store_message,
    },
    set_sandbox_env_vars,
};
use ic_recovery::{file_sync_helper, get_node_metrics, RecoveryArgs};
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_subnet_splitting::subnet_splitting::{StepType, SubnetSplitting, SubnetSplittingArgs};
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use ic_system_test_driver::{
    driver::{
        constants::SSH_USERNAME,
        driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR},
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{IcNodeSnapshot, SubnetSnapshot, *},
    },
    util::*,
};
use ic_types::{CanisterId, Height, PrincipalId, ReplicaVersion};

use anyhow::Result;
use candid::Principal;
use slog::{info, Logger};
use std::{thread, time::Duration};

const DKG_INTERVAL: u64 = 9;
const APP_NODES: usize = 1;

const MESSAGE_IN_THE_CANISTER_TO_BE_MIGRATED: &str =
    "Message in the canister to be migrated from source subnet to the destination subnet";
const MESSAGE_IN_THE_CANISTER_TO_STAY_IN_SOURCE_SUBNET: &str =
    "Message in the canister to stay in the source subnet";

/// Setup an IC with
/// 1. One NNS subnet
/// 2. Two application subnets with one node each.
fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        // Source Subnet
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(APP_NODES),
        )
        // Destination Subnet
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .halted()
                .add_nodes(APP_NODES),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn subnet_splitting_test(env: TestEnv) {
    //
    // 1. Prepare for subnet splitting
    //
    let logger = env.logger();

    let initial_replica_version = env
        .get_initial_replica_version()
        .expect("Failed to get master version");

    let (source_subnet, destination_subnet) = get_subnets(&env);

    assert!(
        destination_subnet.raw_subnet_record().is_halted,
        "The destination subnet should be halted from the beginning!"
    );

    let (
        download_node_source,
        upload_node_source,
        canister_id_to_be_migrated,
        canister_id_to_stay_in_source_subnet,
    ) = prepare_source_subnet(&source_subnet, &logger);

    let upload_node_destination = prepare_destination_subnet(&destination_subnet, &logger);

    let recovery_dir = get_dependency_path("rs/tests");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    //
    // 2. Do subnet splitting
    //
    info!(
        logger,
        "Starting splitting of subnet {}", source_subnet.subnet_id,
    );

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: get_nns_node(&env.topology_snapshot()).get_public_url(),
        replica_version: Some(initial_replica_version.clone()),
        key_file: Some(
            env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
                .join(SSH_USERNAME),
        ),
        test_mode: true,
        skip_prompts: true,
    };

    let subnet_splitting_args = SubnetSplittingArgs {
        source_subnet_id: source_subnet.subnet_id,
        destination_subnet_id: destination_subnet.subnet_id,
        pub_key: Some(
            file_sync_helper::read_file(
                &env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR).join(SSH_USERNAME),
            )
            .expect("Couldn't read public key"),
        ),
        keep_downloaded_state: Some(true),
        download_node_source: Some(download_node_source.get_ip_addr()),
        upload_node_source: Some(upload_node_source.get_ip_addr()),
        upload_node_destination: Some(upload_node_destination.get_ip_addr()),
        next_step: None,
        /* we migrate only one canister */
        canister_id_ranges_to_move: vec![CanisterIdRange {
            start: canister_id_from_principal(canister_id_to_be_migrated),
            end: canister_id_from_principal(canister_id_to_be_migrated),
        }],
    };

    let subnet_splitting = SubnetSplitting::new(
        env.logger(),
        recovery_args,
        /*neuron_args=*/ None,
        subnet_splitting_args,
    );

    for (step_type, step) in subnet_splitting {
        info!(logger, "Next step: {:?}", step_type);

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {:?} failed: {}", step_type, e));

        if step_type == StepType::HaltSourceSubnetAtCupHeight {
            wait_until_halted_at_cup_height(&source_subnet, &logger);
            info!(
                logger,
                "Wait 15 seconds to make sure that \
                the Orchestrator on the `download_node_source` creates a new CUP"
            );
            std::thread::sleep(Duration::from_secs(15));
        }
    }

    //
    // 3. Verify that subnet splitting went well
    //
    info!(logger, "Blocking for newer registry version");
    let topology_snapshot = block_on(env.topology_snapshot().block_for_newer_registry_version())
        .expect("Could not block for newer registry version");

    verify_source_subnet(
        &topology_snapshot,
        source_subnet.subnet_id,
        &initial_replica_version,
        canister_id_to_stay_in_source_subnet,
        &logger,
    );
    verify_destination_subnet(
        &topology_snapshot,
        destination_subnet.subnet_id,
        &initial_replica_version,
        canister_id_to_be_migrated,
        &logger,
    );
}

fn prepare_source_subnet(
    subnet: &SubnetSnapshot,
    logger: &Logger,
) -> (
    /*download_node*/ IcNodeSnapshot,
    /*upload_node*/ IcNodeSnapshot,
    /*canister_id_to_migrate*/ Principal,
    /*canister_id_to_stay*/ Principal,
) {
    info!(logger, "Preparing the source subnet");
    let mut nodes = subnet.nodes().collect::<Vec<_>>().into_iter().cycle();
    let download_node = nodes.next().expect("Failed to find download node");
    let upload_node = nodes.next().expect("Failed to find upload node");

    cert_state_makes_progress_with_retries(
        &download_node.get_public_url(),
        download_node.effective_canister_id(),
        logger,
        secs(600),
        secs(10),
    );

    let canister_id_to_stay = store_message(
        &download_node.get_public_url(),
        download_node.effective_canister_id(),
        MESSAGE_IN_THE_CANISTER_TO_STAY_IN_SOURCE_SUBNET,
        logger,
    );
    assert!(can_read_msg(
        logger,
        &download_node.get_public_url(),
        canister_id_to_stay,
        MESSAGE_IN_THE_CANISTER_TO_STAY_IN_SOURCE_SUBNET,
    ));

    let canister_id_to_be_migrated = store_message(
        &download_node.get_public_url(),
        download_node.get_last_canister_id_in_allocation_ranges(),
        MESSAGE_IN_THE_CANISTER_TO_BE_MIGRATED,
        logger,
    );
    assert!(can_read_msg(
        logger,
        &download_node.get_public_url(),
        canister_id_to_be_migrated,
        MESSAGE_IN_THE_CANISTER_TO_BE_MIGRATED,
    ));

    (
        download_node,
        upload_node,
        canister_id_to_be_migrated,
        canister_id_to_stay,
    )
}

fn prepare_destination_subnet(subnet: &SubnetSnapshot, logger: &Logger) -> IcNodeSnapshot {
    info!(logger, "Preparing the destination subnet");
    subnet.nodes().next().expect("Failed to find upload node")
}

fn verify_destination_subnet(
    topology_snapshot: &TopologySnapshot,
    subnet_id: SubnetId,
    replica_version: &ReplicaVersion,
    migrated_canister_id: Principal,
    logger: &Logger,
) {
    info!(logger, "Verifying the destination subnet");
    verify_common(
        topology_snapshot,
        subnet_id,
        replica_version,
        migrated_canister_id,
        MESSAGE_IN_THE_CANISTER_TO_BE_MIGRATED,
        logger,
    );
}

fn verify_source_subnet(
    topology_snapshot: &TopologySnapshot,
    subnet_id: SubnetId,
    replica_version: &ReplicaVersion,
    canister_id: Principal,
    logger: &Logger,
) {
    info!(logger, "Verifying the source subnet");
    verify_common(
        topology_snapshot,
        subnet_id,
        replica_version,
        canister_id,
        MESSAGE_IN_THE_CANISTER_TO_STAY_IN_SOURCE_SUBNET,
        logger,
    );
}

fn verify_common(
    topology_snapshot: &TopologySnapshot,
    subnet_id: SubnetId,
    replica_version: &ReplicaVersion,
    canister_id: Principal,
    canister_message: &str,
    logger: &Logger,
) {
    let subnet = topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_id == subnet_id)
        .expect("Couldn't find the subnet");
    let nodes = subnet.nodes().collect::<Vec<_>>();

    info!(logger, "Verifying the subnet record in the registry");
    assert!(!subnet.raw_subnet_record().halt_at_cup_height);
    assert!(!subnet.raw_subnet_record().is_halted);
    assert!(subnet
        .subnet_canister_ranges()
        .iter()
        .any(|canister_id_range| canister_id_range
            .contains(&canister_id_from_principal(canister_id))));

    info!(logger, "Verifying that the subnet is healthy");
    assert_subnet_is_healthy(
        &nodes,
        replica_version.into(),
        canister_id,
        canister_message,
        logger,
    );
    info!(logger, "Success!");

    info!(
        logger,
        "Verifying that at least one node has advanced to the height from the CUP"
    );
    assert!(nodes.iter().any(|node| {
        let height = block_on(get_node_metrics(logger, &node.get_ip_addr()))
            .unwrap()
            .finalization_height;
        info!(
            logger,
            "Node {} finalization height: {:?}", node.node_id, height
        );

        height > Height::from(1000)
    }));
    info!(logger, "Success!");
}

fn wait_until_halted_at_cup_height(subnet: &SubnetSnapshot, logger: &Logger) {
    let mut heights = vec![];

    for node in subnet.nodes() {
        info!(
            logger,
            "Waiting for the node {} to halt at CUP height.",
            node.get_ip_addr()
        );
        let mut height = block_on(get_node_metrics(logger, &node.get_ip_addr()))
            .unwrap()
            .certification_height;

        loop {
            info!(
                logger,
                "Current certified height: {}. Sleeping for 5 seconds...", height
            );
            thread::sleep(Duration::from_secs(5));

            let tmp = block_on(get_node_metrics(logger, &node.get_ip_addr()))
                .unwrap()
                .certification_height;

            if tmp == height {
                break;
            }

            height = tmp;
        }

        heights.push(height);
    }

    // verify that the nodes have halted at a CUP height (an integer multiple of DKG_INTERVAL + 1).
    assert!(heights.iter().all(|x| x.get() % (DKG_INTERVAL + 1) == 0));
    // verify that all the heights are equal.
    assert_eq!(heights.iter().min(), heights.iter().max());
}

fn get_subnets(env: &TestEnv) -> (SubnetSnapshot, SubnetSnapshot) {
    let app_subnets = env
        .topology_snapshot()
        .subnets()
        .filter(|subnet| subnet.subnet_type() == SubnetType::Application)
        .collect::<Vec<_>>();

    let source_subnet = app_subnets.first().expect("there is no application subnet");
    let destination_subnet = app_subnets.get(1).expect("there is no application subnet");

    (source_subnet.clone(), destination_subnet.clone())
}

fn canister_id_from_principal(principal: Principal) -> CanisterId {
    CanisterId::try_from(PrincipalId::from(principal)).unwrap()
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(subnet_splitting_test))
        .execute_from_args()
}
