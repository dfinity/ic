/* tag::catalog[]

Title:: Adding new nodes to a subnet test

Goal::
Ensure the subnet is making progress after adding new nodes to it

Runbook::
. Deploy an IC with one application subnet, initially with a single node.
. Add several nodes to the subnet, one at the time, and after each node is added, check whether the
  subnet is making progress.

Success::
. The subnet is making progress when adding new members to it

end::catalog[] */

use anyhow::Result;
use candid::Principal;
use canister_test::Canister;
use ic_base_types::{NodeId, SubnetId};
use ic_consensus_system_test_utils::{
    node::await_subnet_earliest_topology_version,
    rw_message::{
        can_read_msg, can_read_msg_with_retries, cert_state_makes_progress_with_retries,
        install_nns_and_check_progress, store_message,
    },
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{SubnetSnapshot, *},
    },
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    systest,
    util::{block_on, runtime_from_url},
};
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use slog::{Logger, info};

const DKG_INTERVAL: u64 = 9;
const INITIAL_APP_NODES_COUNT: usize = 1;
const TERMINAL_APP_NODES_COUNT: usize = 7;

const MESSAGE_IN_THE_CANISTER: &str = "Message in the canister";

/// Setup an IC with
/// 1. One NNS subnet
/// 2. One application subnet with a single node.
fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(INITIAL_APP_NODES_COUNT),
        )
        .with_unassigned_nodes(TERMINAL_APP_NODES_COUNT - INITIAL_APP_NODES_COUNT)
        .setup_and_start(&env)
        .expect("Should be able to set up IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn adding_new_nodes_to_subnet_test(env: TestEnv) {
    let logger = env.logger();

    let (nns_subnet, app_subnet) = get_subnets(&env);
    let unassigned_nodes = env
        .topology_snapshot()
        .unassigned_nodes()
        .collect::<Vec<_>>();
    let canister_id = prepare_subnet(&app_subnet, &logger);

    for unassigned_node in unassigned_nodes {
        let current_topology_snapshot = env.topology_snapshot();

        add_node_to_subnet(
            unassigned_node.node_id,
            app_subnet.subnet_id,
            &nns_subnet.nodes().next().unwrap(),
            &logger,
        );

        wait_until_node_in_subnet(
            unassigned_node.node_id,
            app_subnet.subnet_id,
            &current_topology_snapshot,
            &logger,
        );

        assert!(can_read_msg_with_retries(
            &logger,
            &unassigned_node.get_public_url(),
            canister_id,
            MESSAGE_IN_THE_CANISTER,
            10,
        ));
    }

    let (_, app_subnet) = get_subnets(&env);
    for node in app_subnet.nodes() {
        cert_state_makes_progress_with_retries(
            &node.get_public_url(),
            node.effective_canister_id(),
            &logger,
            secs(600),
            secs(10),
        );
    }
}

fn add_node_to_subnet(
    node_id: NodeId,
    subnet_id: SubnetId,
    nns_node: &IcNodeSnapshot,
    logger: &Logger,
) {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    info!(
        logger,
        "Sending a proposal for node {} to join subnet {} via the governance canister",
        node_id,
        subnet_id,
    );
    let proposal_payload = AddNodesToSubnetPayload {
        subnet_id: subnet_id.get(),
        node_ids: vec![node_id],
    };
    let proposal_id = block_on(submit_external_proposal_with_test_id(
        &governance,
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
    ));

    info!(
        logger,
        "Executing the proposal to add node {} to subnet {}", node_id, subnet_id
    );
    block_on(vote_execute_proposal_assert_executed(
        &governance,
        proposal_id,
    ));
}

fn wait_until_node_in_subnet(
    node_id: NodeId,
    subnet_id: SubnetId,
    current_topology_snapshot: &TopologySnapshot,
    logger: &Logger,
) {
    info!(
        logger,
        "Waiting until node {} is assigned to subnet {}", node_id, subnet_id
    );

    let new_topology_snapshot =
        block_on(current_topology_snapshot.block_for_newer_registry_version())
            .expect("Should get newer registry version");

    // The node is not unassigned anymore
    assert!(
        !new_topology_snapshot
            .unassigned_nodes()
            .any(|node| node.node_id == node_id)
    );

    let subnet = new_topology_snapshot
        .subnets()
        .find(|s| s.subnet_id == subnet_id)
        .unwrap();
    let target_version = new_topology_snapshot.get_registry_version();
    await_subnet_earliest_topology_version(&subnet, target_version, logger);
}

fn prepare_subnet(subnet: &SubnetSnapshot, logger: &Logger) -> Principal {
    info!(logger, "Preparing the subnet");
    let mut nodes = subnet.nodes().collect::<Vec<_>>().into_iter().cycle();
    let node = nodes.next().expect("Should have at least one node");

    cert_state_makes_progress_with_retries(
        &node.get_public_url(),
        node.effective_canister_id(),
        logger,
        secs(600),
        secs(10),
    );

    let canister_id = store_message(
        &node.get_public_url(),
        node.effective_canister_id(),
        MESSAGE_IN_THE_CANISTER,
        logger,
    );
    assert!(can_read_msg(
        logger,
        &node.get_public_url(),
        canister_id,
        MESSAGE_IN_THE_CANISTER,
    ));

    canister_id
}

fn get_subnets(
    env: &TestEnv,
) -> (
    /*nns_subnet=*/ SubnetSnapshot,
    /*app_subnet=*/ SubnetSnapshot,
) {
    let nns_subnet = env.topology_snapshot().root_subnet();

    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("There should be at least one Application subnet")
        .clone();

    (nns_subnet, app_subnet)
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(adding_new_nodes_to_subnet_test))
        .execute_from_args()
}
