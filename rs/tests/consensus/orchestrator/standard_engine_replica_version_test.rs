/* tag::catalog[]
Title:: Cloud Engines use StandardEngineReplicaVersionRecord.

Goal::
Verify the following

1. A Cloud Engine subnet created with a blank `replica_version_id`
   determines what replica version to run based on
   `StandardEngineReplicaVersionRecord`. (Cloud Engines are created
   via `engine_controller.create_engine`, not via proposal)

2. Passing a `UpdateStandardEngineReplicaVersion` NNS proposal that
   decreases `deployment_progress` causes some Cloud Engines to
   roll back.

3. Increasing `deployment_progress` causes Cloud Engines to roll
   forward.

Background::
Cloud Engines are a special kind of subnet. One thing special about them
is that `replica_version_id` in their `SubnetRecord` is allowed to be
blank (and blank is typical in practice). When blank, the replica version
is determined by `StandardEngineReplicaVersionRecord`, which gets updated
via `UpdateStandardEngineReplicaVersion` NNS proposals.

A non-blank `replica_version_id` behaves like other subnets, overriding
`StandardEngineReplicaVersionRecord`.

Each Cloud Engine has an upgrade priority (a pseudo-random number in
[0.0, 1.0], derived from the engine's subnet ID and the candidate new
replica version). An engine takes the new replica version once its
priority is <= `deployment_progress`; otherwise, it keeps the old one.

Runbook::
0. Set up an IC with an NNS subnet, plus a pool of unassigned nodes to
   form 2 Cloud Engines.

1. Install NNS. Blank replica_version_id is enabled in Registry.
   This requires using registry-canister-test, not the regular/release
   build, registry-canister. Once this feature has survived its
   probation period, this test can switch to registry-canister.

2. Elect a second GuestOS/replica version.

3. Submit (and vote through) a `UpdateStandardEngineReplicaVersion`
   proposal that tells all Cloud Engines to run the newly elected
   replica version. To achieve this, the following parameters are
   used:
    - new: The newly elected replica version.
    - deployment_progress: 1.0 aka 100%.
    - old: The original replica version (the one that the NNS subnet
      is running at this point).

4. Create 2 Cloud Engines by calling `engine_controller.create_engine`
   with `replica_version_id: ""`.

5. Wait for the new Cloud Engines to run the replica version elected
   in step 2. This is a strong signal that
   `StandardEngineReplicaVersionRecord` is controlling Cloud Engines
   (at least when they are first created), because that replica
   version has never been deployed before, because it was only made
   available for deployment just now.

6. Roll back only ONE of the Cloud Engines to the original replica
   version, by submitting a second `UpdateStandardEngineReplicaVersion`
   proposal that decreases `deployment_progress` so that it falls
   (strictly) between the upgrade priorities of the two Cloud Engines.

7. Wait for the higher-priority engine to roll back to the original
   replica version. Furthermore, assert that the lower-priority engine
   stays on the newly elected replica version, does NOT roll back.

8. Increase `deployment_progress` back to 1.0 using a third
   `UpdateStandardEngineReplicaVersion` proposal (same version pair as
   steps 3 and 6).

9. Wait for the higher-priority engine (rolled back in step 7) to roll
   FORWARD again, back to the replica version elected in step 2. The
   lower-priority engine, which never left that version, is unaffected.

Success::
Both Cloud Engines start out on the replica version elected in step 2.
Exactly one rolls back to the original replica version at partial
deployment progress (the one with the higher upgrade priority), and it
rolls forward again, back to the replica version elected in step 2, once
deployment progress returns to 1.0.

end::catalog[] */

use anyhow::Result;
use candid::Principal;
use canister_test::Canister;
use dfn_candid::candid_one;
use futures::future;
use ic_base_types::SubnetId;
use ic_canister_client::Sender;
use ic_consensus_system_test_upgrade_common::elect_target_version;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_version_with_time, get_assigned_replica_version,
};
use ic_engine_controller::{CreateEngineArgs, NewSubnet};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_nns_constants::ENGINE_CONTROLLER_CANISTER_ID;
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_registry_client_helpers::subnet::engine_upgrade_priority;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Node},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
            NnsCustomizations, TopologySnapshot,
        },
    },
    nns::{
        get_governance_canister, submit_update_standard_engine_replica_version_proposal,
        vote_execute_proposal_assert_executed,
    },
    systest,
    util::{block_on, runtime_from_url},
};
use ic_types::ReplicaVersion;
use registry_canister::init::RegistryCanisterInitPayload;
use slog::{Logger, info};
use std::time::Duration;

// 4 is the smallest value allowed by the Engine Controller.
const ENGINE_NODE_COUNT: usize = 4;

// More than 1 so that a `deployment_progress` between the two engines'
// upgrade priorities can upgrade one, but not the other.
const NUM_ENGINES: usize = 2;

// How long to wait for one Cloud Engine node to come up on another replica
// version, and how often to poll it in the meantime.
//
// Every such wait is a full GuestOS upgrade cycle: the orchestrator downloads
// the ~580 MiB update image, `tar`-unpacks it into ~11 GiB of boot.img +
// root.img, `dd`s those onto the inactive slot, reboots, and only then starts
// the replica. There is no shortcut for a version that already sits on the
// inactive slot (see `ImageUpgrader::execute_upgrade`), so the roll back in
// [Step 7] and the roll forward in [Step 9] each pay for the cycle again.
//
// On Farm one cycle fits in the 600 s that `assert_assigned_replica_version`
// defaults to. On the `local` backend it does not: all 8 engine nodes run the
// cycle simultaneously on a single host that the 10 VMs of this test
// oversubscribe (60 vCPUs and 40 GiB of guest RAM), and a measured cycle took
// ~9 min there -- ~90 s to download, ~240 s to unpack, ~35 s to `dd`, ~150 s to
// reboot -- leaving no room for the replica to start before the deadline.
const REPLICA_VERSION_TIMEOUT_SECS: u64 = 20 * 60;
const REPLICA_VERSION_BACKOFF_SECS: u64 = 10;

/// Waits until `node` is healthy and running `expected_version`, panicking if
/// that does not happen within [`REPLICA_VERSION_TIMEOUT_SECS`].
fn assert_assigned_replica_version(
    node: &IcNodeSnapshot,
    expected_version: &ReplicaVersion,
    logger: Logger,
) {
    assert_assigned_replica_version_with_time(
        node,
        expected_version,
        logger,
        REPLICA_VERSION_TIMEOUT_SECS,
        REPLICA_VERSION_BACKOFF_SECS,
    )
}

fn setup(env: TestEnv) {
    let logger = env.logger();

    info!(logger, "[Step 0] Create an IC.");
    let mut ic = InternetComputer::new()
        .with_api_boundary_nodes_playnet(1)
        .add_fast_single_node_subnet(SubnetType::System);

    // Nodes that will be used to form Cloud Engines.
    for _ in 0..(NUM_ENGINES * ENGINE_NODE_COUNT) {
        ic = ic.with_unassigned_node(
            Node::new()
                // This is required for Cloud Engines.
                .with_node_reward_type(NodeRewardType::Type4),
        );
    }

    ic.setup_and_start(&env)
        .expect("failed to setup IC under test");

    info!(logger, "[Step 1] Install NNS.");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations {
            registry_canister_init_payload: RegistryCanisterInitPayload {
                is_blank_replica_version_id_for_cloud_engines_enabled: Some(true),
                ..Default::default()
            },
            ..Default::default()
        },
    );
}

/// Creates a Cloud Engine with a blank `replica_version_id` out of
/// `node_ids`, and returns its (new) subnet ID.
async fn create_engine(
    engine_controller: &Canister<'_>,
    sender: &Sender,
    node_ids: Vec<Principal>,
) -> SubnetId {
    let create_engine_result: Result<NewSubnet, String> = engine_controller
        .update_from_sender(
            "create_engine",
            candid_one,
            CreateEngineArgs {
                node_ids,
                subnet_admins: vec![],
                replica_version_id: "".to_string(),
            },
            sender,
        )
        .await
        .expect("create_engine call failed");
    create_engine_result
        .expect("create_engine returned an error")
        .new_subnet_id
        .expect("create_engine did not return a new_subnet_id")
}

/// Finds the nodes of the (already-created) Cloud Engine `subnet_id`.
fn get_engine_nodes(
    topology_snapshot: &TopologySnapshot,
    subnet_id: SubnetId,
) -> Vec<IcNodeSnapshot> {
    let engine_subnet = topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_id == subnet_id)
        .expect("Cloud Engine subnet not found in topology");
    let nodes: Vec<IcNodeSnapshot> = engine_subnet.nodes().collect();
    assert_eq!(nodes.len(), ENGINE_NODE_COUNT);
    nodes
}

fn test(env: TestEnv) {
    let logger = env.logger();

    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");

    // Prepare to make various NNS proposals.
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = get_governance_canister(&nns_runtime);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);

    let original_replica_version = get_assigned_replica_version(&nns_node)
        .expect("failed to read the NNS node's own replica version");
    info!(
        logger,
        "original replica version: {original_replica_version}"
    );

    info!(logger, "[Step 2] Elect another replica version.");
    let new_replica_version = elect_target_version(&env, &nns_node);

    info!(
        logger,
        "[Step 3] Upsert StandardEngineReplicaVersionRecord to {{old: \
         original_replica_version, new: new_replica_version, deployment_progress: 1.0}}."
    );
    update_standard_engine_replica_version(
        &governance,
        proposal_sender.clone(),
        test_neuron_id,
        &new_replica_version,
        &original_replica_version,
        1.0, // deployment_progress. 100%
        &logger,
    );

    info!(
        logger,
        "[Step 4] Create 2 Cloud Engines, both with a blank replica_version_id."
    );
    let topology_snapshot = env.topology_snapshot();
    let unassigned_node_ids: Vec<Principal> = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id.get().0)
        .collect();
    assert_eq!(unassigned_node_ids.len(), NUM_ENGINES * ENGINE_NODE_COUNT);

    let engine_controller = Canister::new(&nns_runtime, ENGINE_CONTROLLER_CANISTER_ID);
    info!(
        logger,
        "Creating 2 Cloud Engines with blank `replica_version_id`..."
    );
    let (node_ids_a, node_ids_b) = unassigned_node_ids.split_at(ENGINE_NODE_COUNT);
    // Create both Cloud Engines concurrently, to save time.
    let (engine_a_id, engine_b_id) = block_on(future::join(
        create_engine(&engine_controller, &proposal_sender, node_ids_a.to_vec()),
        create_engine(&engine_controller, &proposal_sender, node_ids_b.to_vec()),
    ));
    info!(
        logger,
        "Created Cloud Engines: subnets {engine_a_id} and {engine_b_id}"
    );

    info!(
        logger,
        "[Step 5] Verify that both Cloud Engines are running new_replica_version."
    );
    let topology_snapshot = block_on(topology_snapshot.block_for_newer_registry_version())
        .expect("failed to observe the newly-created Cloud Engine subnets in the topology");
    let engine_a_nodes = get_engine_nodes(&topology_snapshot, engine_a_id);
    let engine_b_nodes = get_engine_nodes(&topology_snapshot, engine_b_id);
    for node in engine_a_nodes.iter().chain(engine_b_nodes.iter()) {
        assert_assigned_replica_version(node, &new_replica_version, logger.clone());
    }
    info!(
        logger,
        "Both Cloud Engines have been created and are running the new \
         replica version ({new_replica_version})."
    );

    info!(
        logger,
        "[Step 6] Compute each Cloud Engines upgrade priority. Then, choose \
         `deployment_progress` between them. That way, only one of them will be rolled back."
    );

    // Calculate upgrade priorities.
    let upgrade_priority_a = engine_upgrade_priority(engine_a_id, new_replica_version.as_ref());
    let upgrade_priority_b = engine_upgrade_priority(engine_b_id, new_replica_version.as_ref());
    assert_ne!(
        upgrade_priority_a, upgrade_priority_b,
        "The two Cloud Engines have the same upgrade priority!?!? Either we found a \
        SHA-256 collision, or we have a bug! In any case, this test needs them to \
        differ.",
    );

    // Decrease deployment_progress to intermediate value.
    let deployment_progress = (upgrade_priority_a + upgrade_priority_b) / 2.0;
    info!(
        logger,
        "Decreased deployment_progress to {deployment_progress} so that one \
         Cloud Engine rolls back. Upgrade priorities: {engine_a_id}: {upgrade_priority_a}, \
         {engine_b_id}: {upgrade_priority_b}"
    );
    update_standard_engine_replica_version(
        &governance,
        proposal_sender.clone(),
        test_neuron_id,
        &new_replica_version,
        &original_replica_version,
        deployment_progress,
        &logger,
    );

    // Identify which Cloud Engine has the (lower|higher) upgrade priority.
    let (
        (low_priority_engine_id, low_priority_nodes), // Low priority
        (high_priority_engine_id, high_priority_nodes), // High priority
    ) = if upgrade_priority_a < upgrade_priority_b {
        (
            (engine_a_id, engine_a_nodes), // Low priority
            (engine_b_id, engine_b_nodes), // High priority
        )
    } else {
        (
            (engine_b_id, engine_b_nodes), // Low priority
            (engine_a_id, engine_a_nodes), // High priority
        )
    };

    info!(
        logger,
        "[Step 7] Verify that ONLY the higher-priority engine rolled back."
    );
    for node in &high_priority_nodes {
        assert_assigned_replica_version(node, &original_replica_version, logger.clone());
    }
    for node in &low_priority_nodes {
        assert_assigned_replica_version(node, &new_replica_version, logger.clone());
    }
    info!(
        logger,
        "Cloud Engine {high_priority_engine_id} rolled back to {original_replica_version}, while \
         {low_priority_engine_id} stayed on {new_replica_version}."
    );

    info!(
        logger,
        "[Step 8] Increase deployment_progress back to 1.0, so that we can verify that \
         rolling forward also works (not just rolling back)."
    );
    update_standard_engine_replica_version(
        &governance,
        proposal_sender,
        test_neuron_id,
        &new_replica_version,
        &original_replica_version,
        1.0, // deployment_progress. 100%
        &logger,
    );

    info!(
        logger,
        "[Step 9] Verify that the high priority Cloud Engine rolled FORWARD, back to \
         new_replica_version. Similarly, verify that the low priority Cloud Engine has \
         continued on new_replica_version."
    );
    for node in &high_priority_nodes {
        assert_assigned_replica_version(node, &new_replica_version, logger.clone());
    }
    for node in &low_priority_nodes {
        assert_assigned_replica_version(node, &new_replica_version, logger.clone());
    }
    info!(
        logger,
        "Cloud Engine {high_priority_engine_id} rolled FORWARD again (back to \
         {new_replica_version}) after deployment_progress was increased back \
         to 1.0."
    );
}

/// Submits and votes through an `UpdateStandardEngineReplicaVersion` proposal.
fn update_standard_engine_replica_version(
    governance: &Canister<'_>,
    proposal_sender: Sender,
    test_neuron_id: NeuronId,
    new_replica_version: &ReplicaVersion,
    old_replica_version: &ReplicaVersion,
    deployment_progress: f64,
    logger: &Logger,
) {
    info!(
        logger,
        "Updating StandardEngineReplicaVersionRecord: old: {old_replica_version}, new: \
         {new_replica_version}, deployment_progress: {deployment_progress}"
    );
    let proposal_id = block_on(submit_update_standard_engine_replica_version_proposal(
        governance,
        proposal_sender,
        test_neuron_id,
        new_replica_version.to_string(),
        old_replica_version.to_string(),
        deployment_progress,
    ));
    block_on(vote_execute_proposal_assert_executed(
        governance,
        proposal_id,
    ));
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        // Give this test more time. One successful Farm run was observed to
        // take about 20 minutes; on the `local` backend each of the three
        // upgrade waves costs ~10 minutes on its own (see
        // `REPLICA_VERSION_TIMEOUT_SECS`), so budget enough for that while
        // staying under the `test_timeout = "eternal"` (1 hour) that the BUILD
        // file gives the whole action.
        .with_timeout_per_test(Duration::from_secs(50 * 60))
        .execute_from_args()?;
    Ok(())
}
