use anyhow::Result;
use ic_base_types::NodeId;
use ic_consensus_system_test_utils::{
    rw_message::install_nns_and_check_progress, ssh_access::execute_bash_command,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::SshSession,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot},
    },
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    systest,
    util::{block_on, get_app_subnet_and_node, get_nns_node, runtime_from_url},
};
use ic_types::Height;
use registry_canister::mutations::do_add_nodes_to_subnet::AddNodesToSubnetPayload;
use slog::info;

const DKG_INTERVAL_LENGTH: u64 = 14;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH))
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH))
                .add_nodes(1),
        )
        .with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn test(env: TestEnv) {
    let topo_snapshot = env.topology_snapshot();
    let logger = env.logger();
    let nns_node = get_nns_node(&topo_snapshot);

    let unassigned_node_ids: Vec<NodeId> = topo_snapshot
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect();
    let unassigned_nodes = topo_snapshot.unassigned_nodes();

    // get application node
    info!(logger, "Getting application node");
    let (app_subnet, app_node) = get_app_subnet_and_node(&topo_snapshot);
    info!(
        logger,
        "Continuing with app node: {}",
        app_node.get_ip_addr()
    );

    // Create NNS runtime.
    info!(logger, "Creating NNS runtime");
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());

    // Send a proposal for the nodes to join a subnet via the governance canister.
    let governance_canister = canister_test::Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let proposal_payload = AddNodesToSubnetPayload {
        subnet_id: app_subnet.subnet_id.get(),
        node_ids: unassigned_node_ids,
    };

    info!(
        logger,
        "Submitting AddNodeToSubnet proposal: {:#?}", proposal_payload
    );
    let proposal_id = block_on(submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::AddNodeToSubnet,
        proposal_payload,
    ));

    // Explicitly vote for the proposal to add nodes to subnet.
    info!(logger, "Voting on proposal");
    block_on(vote_execute_proposal_assert_executed(
        &governance_canister,
        proposal_id,
    ));

    // Set unassigned nodes to the Application subnet.
    let newly_assigned_nodes: Vec<_> = unassigned_nodes.collect();

    // Wait for registry update
    info!(logger, "Waiting for registry update");
    block_on(topo_snapshot.block_for_newer_registry_version())
        .expect("Could not block for newer registry version");

    // Assert that new nodes are reachable (via http call).
    info!(logger, "Assert that new nodes are reachable");
    for n in newly_assigned_nodes.iter() {
        n.await_status_is_healthy().unwrap();
    }

    // Store some extra data, and trigger a redeployment
    let s = newly_assigned_nodes
        .first()
        .unwrap()
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");
    let script = r#"set -e
        echo 'Hello world!' | sudo tee /var/lib/ic/data/content
        sudo touch /boot/config/REDEPLOY
        sudo reboot
        "#
    .to_string();

    info!(logger, "Trigger node redeployment",);
    if let Err(e) = execute_bash_command(&s, script) {
        panic!("Script execution failed: {:?}", e);
    }

    block_on(async { tokio::time::sleep(std::time::Duration::from_secs(10)).await });

    // Check that the node goes down
    info!(logger, "Check that node picks up subnet again",);
    for n in newly_assigned_nodes.iter() {
        n.await_status_is_unavailable().unwrap();
    }

    // And back up
    info!(logger, "Check that node picks up subnet again",);
    for n in newly_assigned_nodes.iter() {
        n.await_status_is_healthy().unwrap();
    }

    // Check that the stored data is gone
    let s = newly_assigned_nodes
        .first()
        .unwrap()
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");
    let script = r#"set -e
        sudo cat /var/lib/ic/data/content
        "#
    .to_string();

    info!(logger, "Check for previous data",);
    match execute_bash_command(&s, script) {
        Err(e) => {
            info!(logger, "Error found is: {e}");
            assert!(e.contains("No such file or directory"))
        }
        _ => panic!("Expected previous data to be gone."),
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
