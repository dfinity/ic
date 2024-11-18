/* tag::catalog[]
Title:: Node reassignment test

Goal:: Verify that nodes can be removed from a subnet and later assigned to a different subnet

Runbook::
. Set up two subnets
. Install a message canister in both
. Verify that the canisters can be updated and the modifications queried
. Reassign 2 nodes from nns to app subnet
. Verify that these two nodes have the state of the app subnet
. Verify that both subnets are functional by storing new messages.
. Remove 2 nodes from the app subnet, making them unassigned
. Replace 2 nns nodes with the two unassigned nodes, using change_subnet_membership
. Add 2 unassigned nodes (former nns nodes) to the app subnet, using change_subnet_membership
. Verify that both subnets are functional.

Success:: All mutations to the subnets and installed canisters on them occur
in the expected way before and after the node reassignment.

Coverage::
. Node unassignment works even when removing more nodes than f.
. Nodes successfully join a new subnet after the reassignment and sync the state from it.


end::catalog[] */

use anyhow::Result;
use ic_consensus_system_test_utils::rw_message::{
    can_read_msg, can_read_msg_with_retries, install_nns_and_check_progress, store_message,
};
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    nns::{add_nodes_to_subnet, change_subnet_membership, remove_nodes_via_endpoint},
    util::{block_on, get_app_subnet_and_node},
};
use ic_types::Height;
use slog::info;

const DKG_INTERVAL: u64 = 14;
const NNS_SUBNET_SIZE: usize = 4;
const APP_SUBNET_SIZE: usize = 1;

fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_features(SubnetFeatures::default())
                .add_nodes(NNS_SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures::default())
                .add_nodes(APP_SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn test(env: TestEnv) {
    let log = &env.logger();
    let topo_snapshot = env.topology_snapshot();

    // Take all NNS nodes
    let mut nodes = topo_snapshot.root_subnet().nodes();

    // These nodes will be reassigned from the NNS to the APP subnet
    let node1 = nodes.next().unwrap();
    let node2 = nodes.next().unwrap();
    // These nodes will stay in the NNS subnet
    let node3 = nodes.next().unwrap();
    let node4 = nodes.next().unwrap();

    // Before we move the nodes, we store a message and make sure the message is shared across
    // NNS nodes.
    let nns_msg = "hello world from nns!";

    let nns_can_id = store_message(
        &node1.get_public_url(),
        node1.effective_canister_id(),
        nns_msg,
        log,
    );
    assert!(can_read_msg(
        log,
        &node1.get_public_url(),
        nns_can_id,
        nns_msg
    ));
    assert!(can_read_msg_with_retries(
        log,
        &node2.get_public_url(),
        nns_can_id,
        nns_msg,
        5
    ));

    info!(log, "Message on both NNS nodes verified!");

    // Now we store another message on the app subnet.
    let (app_subnet, app_node) = get_app_subnet_and_node(&topo_snapshot);
    let app_msg = "hello world from app subnet!";
    let app_can_id = store_message(
        &app_node.get_public_url(),
        app_node.effective_canister_id(),
        app_msg,
        log,
    );
    assert!(can_read_msg(
        log,
        &app_node.get_public_url(),
        app_can_id,
        app_msg
    ));
    info!(log, "Message on app node verified!");

    // Unassign 2 NNS nodes using remove_nodes_from_subnet operation
    node3.await_status_is_healthy().unwrap();
    node4.await_status_is_healthy().unwrap();
    let node_ids: Vec<_> = vec![node1.node_id, node2.node_id];
    block_on(remove_nodes_via_endpoint(node3.get_public_url(), &node_ids)).unwrap();
    info!(log, "Removed node ids {:?} from the NNS subnet", node_ids);

    // Wait until the nodes become unassigned.
    node1.await_status_is_unavailable().unwrap();
    node2.await_status_is_unavailable().unwrap();

    block_on(add_nodes_to_subnet(
        node3.get_public_url(),
        app_subnet.subnet_id,
        &node_ids,
    ))
    .unwrap();
    info!(
        log,
        "Added node ids {:?} to subnet {}", node_ids, app_subnet.subnet_id
    );
    info!(
        log,
        "Waiting for moved nodes to return the app subnet message..."
    );
    node1.await_status_is_healthy().unwrap();
    node2.await_status_is_healthy().unwrap();
    assert!(can_read_msg_with_retries(
        log,
        &node1.get_public_url(),
        app_can_id,
        app_msg,
        100
    ));
    assert!(can_read_msg_with_retries(
        log,
        &node2.get_public_url(),
        app_can_id,
        app_msg,
        5
    ));
    info!(log, "App message on former NNS nodes could be retrieved!");

    assert!(can_read_msg(
        log,
        &node3.get_public_url(),
        nns_can_id,
        nns_msg
    ));
    assert!(can_read_msg(
        log,
        &node4.get_public_url(),
        nns_can_id,
        nns_msg
    ));
    info!(
        log,
        "NNS message on remaining NNS nodes could be retrieved!"
    );

    // Now make sure the subnets are able to store new messages
    info!(log, "Try to store new messages on NNS...");
    let nns_msg_2 = "hello again on NNS!";
    let nns_can_id_2 = store_message(
        &node3.get_public_url(),
        node3.effective_canister_id(),
        nns_msg_2,
        log,
    );
    assert!(can_read_msg_with_retries(
        log,
        &node4.get_public_url(),
        nns_can_id_2,
        nns_msg_2,
        5
    ));

    info!(log, "Try to store new messages on app subnet...");
    let app_msg_2 = "hello again on app subnet!";
    let app_can_id_2 = store_message(
        &app_node.get_public_url(),
        app_node.effective_canister_id(),
        app_msg_2,
        log,
    );
    assert!(can_read_msg_with_retries(
        log,
        &node1.get_public_url(),
        app_can_id_2,
        app_msg_2,
        5
    ));
    info!(
        log,
        "New messages could be written and retrieved on both subnets!"
    );

    // From here on, test the change_subnet_membership command
    // After the previous test, the subnets are:
    // NNS: [node3, node4]
    // APP: [node1, node2, <original-app-subnet-nodes>]
    //
    // Let's move node1 and node2 back into the NNS subnet, and node3, node4 into the APP subnet
    // So that we get:
    // NNS: [node1, node2]
    // APP: [node3, node4, <original-app-subnet-nodes>]
    node1.await_status_is_healthy().unwrap();
    node2.await_status_is_healthy().unwrap();
    let nns_subnet_id = topo_snapshot.root_subnet().subnet_id;
    let app_subnet_id = app_subnet.subnet_id;
    let node_ids_remove: Vec<_> = vec![node1.node_id, node2.node_id];
    block_on(change_subnet_membership(
        node3.get_public_url(),
        app_subnet_id,
        &[],
        &node_ids_remove,
    ))
    .unwrap();
    info!(
        log,
        "Changed subnet {} membership: added nodes [] removed nodes {:?}",
        app_subnet_id,
        node_ids_remove
    );

    // Wait until the nodes become unassigned.
    node1.await_status_is_unavailable().unwrap();
    node2.await_status_is_unavailable().unwrap();

    // Next, add node1 and node2 to the NNS subnet, and remove node3 and node4 at the same time
    let node_ids_add: Vec<_> = vec![node1.node_id, node2.node_id];
    let node_ids_remove: Vec<_> = vec![node3.node_id, node4.node_id];
    block_on(change_subnet_membership(
        node3.get_public_url(),
        nns_subnet_id,
        &node_ids_add,
        &node_ids_remove,
    ))
    .unwrap();
    info!(
        log,
        "Changed subnet {} membership: added nodes {:?} removed nodes {:?}",
        nns_subnet_id,
        node_ids_add,
        node_ids_remove
    );
    info!(log, "Waiting for the new nodes to become healthy...");

    node1.await_status_is_healthy().unwrap();
    node2.await_status_is_healthy().unwrap();
    node3.await_status_is_unavailable().unwrap();
    node4.await_status_is_unavailable().unwrap();
    assert!(can_read_msg_with_retries(
        log,
        &node1.get_public_url(),
        nns_can_id_2,
        nns_msg_2,
        100
    ));
    assert!(can_read_msg_with_retries(
        log,
        &node2.get_public_url(),
        nns_can_id_2,
        nns_msg_2,
        5
    ));
    info!(
        log,
        "NNS message on the former APP nodes could be retrieved!"
    );

    let node_ids_add: Vec<_> = vec![node3.node_id, node4.node_id];
    block_on(change_subnet_membership(
        node1.get_public_url(),
        app_subnet_id,
        &node_ids_add,
        &[],
    ))
    .unwrap();
    info!(log, "Added node ids {:?} to the APP subnet", node_ids_add);
    info!(
        log,
        "Changed subnet {} membership: added nodes {:?} removed nodes []",
        app_subnet_id,
        node_ids_add
    );
    node3.await_status_is_healthy().unwrap();
    node4.await_status_is_healthy().unwrap();

    assert!(can_read_msg_with_retries(
        log,
        &node3.get_public_url(),
        app_can_id_2,
        app_msg_2,
        100
    ));
    assert!(can_read_msg_with_retries(
        log,
        &node4.get_public_url(),
        app_can_id_2,
        app_msg_2,
        5
    ));
    info!(
        log,
        "APP message on the former NNS nodes could be retrieved!"
    );

    info!(log, "Test finished successfully");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
