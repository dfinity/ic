/* tag::catalog[]
Title:: Cloud Engines use StandardEngineReplicaVersionRecord.

Goal::
Verify the following

1. A Cloud Engine subnet created with a blank `replica_version_id`
   determines what replica version to run based on
   `StandardEngineReplicaVersionRecord`. (This is done via
   `engine_controller.create_engine`, with no NNS proposal.)

2. Passing a `UpdateStandardEngineReplicaVersion` NNS proposal
   causes the Cloud Engine to upgrade.

Background::
Cloud Engines are a special kind of subnet. One thing special about them
is that `replica_version_id` in their `SubnetRecord` is allowed to be
blank (and blank is typical in practice). When blank, the replica version
is determined by `StandardEngineReplicaVersionRecord`, which gets updated
via `UpdateStandardEngineReplicaVersion` NNS proposals.

A non-blank `replica_version_id` behaves like other subnets, overriding
`StandardEngineReplicaVersionRecord`.

Runbook::
0. Set up an IC with an NNS subnet, plus a pool of unassigned nodes to
   form a Cloud Engine.

1. Install NNS. Blank replica_version_id is enabled in Registry.
   This requires using registry-canister-test, not the regular/release
   build, registry-canister. Once this feature has survived its
   probation period, this test can switch to registry-canister.

2. Elect a second GuestOS/replica version.

3. Submit (and vote through) a `UpdateStandardEngineReplicaVersion`
   proposal where deployment progress is 100% to control that the Cloud
   Engine will initially have the replica version that was elected in
   the previous step.

4. Create the Cloud Engine by calling `engine_controller.create_engine`
   with `replica_version_id: ""`.

5. Wait for the new Cloud Engine subnet to appear, and for its nodes to
   become healthy, then assert that they're running the replica version
   elected in step 2, demonstrating that
   `StandardEngineReplicaVersionRecord` is being used.

Success::
Every Cloud Engine node is running the elected replica version.

end::catalog[] */

use anyhow::Result;
use candid::Principal;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_canister_client::Sender;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_version, elect_replica_version_with_urls, get_assigned_replica_version,
};
use ic_engine_controller::{CreateEngineArgs, NewSubnet};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_nns_constants::ENGINE_CONTROLLER_CANISTER_ID;
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Node},
        resource::BootImage,
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
            NnsCustomizations, NnsInstallationBuilder, SubnetSnapshot,
            get_guestos_update_img_sha256, get_guestos_update_img_url,
            get_guestos_update_img_version, get_guestos_update_launch_measurements,
        },
    },
    nns::{
        get_governance_canister, submit_update_standard_engine_replica_version_proposal,
        vote_execute_proposal_assert_executed,
    },
    systest,
    util::{block_on, runtime_from_url},
};
use registry_canister::init::RegistryCanisterInitPayload;
use slog::info;

// 4 is the smallest value allowed by the Engine Controller.
const ENGINE_NODE_COUNT: usize = 4;

fn setup(env: TestEnv) {
    let mut ic = InternetComputer::new().add_fast_single_node_subnet(SubnetType::System);

    // Add nodes that can be used to form a Cloud Engine.
    for _ in 0..ENGINE_NODE_COUNT {
        ic = ic.with_unassigned_node(
            Node::new()
                .with_boot_image(BootImage::GroupDefault)
                // This is required for Cloud Engines.
                .with_node_reward_type(NodeRewardType::Type4),
        );
    }

    ic.setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn test(env: TestEnv) {
    let logger = env.logger();

    // [Step 1] Install NNS. Blank `replica_version_id` for Cloud Engines
    // is enabled (in Registry).
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    NnsInstallationBuilder::new()
        .with_customizations(NnsCustomizations {
            registry_canister_init_payload: RegistryCanisterInitPayload {
                is_blank_replica_version_id_for_cloud_engines_enabled: Some(true),
                ..Default::default()
            },
            ..Default::default()
        })
        .install(&nns_node, &env)
        .expect("NNS canisters not installed");
    info!(logger, "NNS canisters installed");

    // Prepare to make various NNS proposals.
    let topology_snapshot = env.topology_snapshot();
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

    // [Step 2] Elect another replica version.
    let new_replica_version = get_guestos_update_img_version();
    info!(
        logger,
        "Electing another replica version: {new_replica_version}"
    );
    block_on(elect_replica_version_with_urls(
        &nns_node,
        &topology_snapshot,
        &new_replica_version,
        vec![get_guestos_update_img_url(&env).to_string()],
        get_guestos_update_img_sha256(),
        Some(get_guestos_update_launch_measurements()),
        &logger,
    ));

    // [Step 3] Upsert StandardEngineReplicaVersionRecord to
    // {old: original_replica_version, new: new_replica_version,
    // deployment_progress: 1.0}.
    info!(
        logger,
        "Updating StandardEngineReplicaVersionRecord: {original_replica_version} \
         -> {new_replica_version}"
    );
    let proposal_id = block_on(submit_update_standard_engine_replica_version_proposal(
        &governance,
        proposal_sender.clone(),
        test_neuron_id,
        new_replica_version.to_string(),
        original_replica_version.to_string(),
        1.0,
    ));
    block_on(vote_execute_proposal_assert_executed(
        &governance,
        proposal_id,
    ));

    // [Step 4] Create the Cloud Engine with a blank replica_version_id
    // via the Engine Controller.
    let node_ids: Vec<Principal> = topology_snapshot
        .unassigned_nodes()
        .map(|node| node.node_id.get().0)
        .collect();
    assert_eq!(node_ids.len(), ENGINE_NODE_COUNT);

    info!(
        logger,
        "Creating a Cloud Engine with blank `replica_version_id`..."
    );
    let engine_controller = Canister::new(&nns_runtime, ENGINE_CONTROLLER_CANISTER_ID);
    let create_engine_result: Result<NewSubnet, String> =
        block_on(engine_controller.update_from_sender(
            "create_engine",
            candid_one,
            CreateEngineArgs {
                node_ids,
                subnet_admins: vec![],
                replica_version_id: "".to_string(),
            },
            &proposal_sender,
        ))
        .expect("create_engine call failed");
    let new_subnet = create_engine_result.expect("create_engine returned an error");
    let engine_subnet_id = new_subnet
        .new_subnet_id
        .expect("create_engine did not return a new_subnet_id");
    info!(logger, "Created Cloud Engine: subnet {engine_subnet_id}");

    // [Step 5] Verify that the Cloud Engine is running new_replica_version,
    // per StandardEngineReplicaVersionRecord.
    let topology_snapshot = block_on(topology_snapshot.block_for_newer_registry_version())
        .expect("failed to observe the newly-created Cloud Engine subnet in the topology");
    let engine_subnet: SubnetSnapshot = topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_id == engine_subnet_id)
        .expect("newly-created Cloud Engine subnet not found in topology");
    let engine_nodes: Vec<IcNodeSnapshot> = engine_subnet.nodes().collect();
    assert_eq!(engine_nodes.len(), ENGINE_NODE_COUNT);
    for node in &engine_nodes {
        assert_assigned_replica_version(node, &new_replica_version, logger.clone());
    }
    info!(
        logger,
        "All Cloud Engine nodes are healthy, running {new_replica_version}, \
         confirming that they are taking orders from \
         StandardEngineReplicaVersionRecord."
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
