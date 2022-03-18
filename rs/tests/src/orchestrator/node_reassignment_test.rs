/* tag::catalog[]
Title:: Node reassignment test

Goal:: Verify that nodes can be removed from a subnet and later assigned to a different subnet

Runbook::
. Set up two subnets with four nodes each
. Install a universal canister in both
. Verify that the canisters can be updated and the modifications queried
. Reassign 2 nodes from nns to app subnet
. Verify that these two nodes have the state of the app subnet
. Verify that both subnets are functional by storing new messages.

Success:: All mutations to the subnets and installed canisters on them occur
in the expected way before and after the node reassignment.

Coverage::
. Node unassignment works even when removing more nodes than f.
. Nodes successfully join a new subnet after the reassignment and sync the state from it.


end::catalog[] */

use crate::nns::{add_nodes_to_subnet, remove_nodes_via_endpoint, NnsExt};
use crate::util::*;
use ic_agent::export::Principal;
use ic_fondue::{
    ic_manager::IcHandle,
    prod_tests::ic::{InternetComputer, Subnet},
};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use slog::{debug, info};
use url::Url;

const DKG_INTERVAL: u64 = 14;
const SUBNET_SIZE: usize = 4;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let log = &ctx.logger;
    ctx.install_nns_canisters(&handle, true);
    info!(ctx.logger, "NNS canisters installed");

    let mut rng = ctx.rng.clone();
    // // Take all nns nodes
    let nodes = &handle
        .as_permutation(&mut rng)
        .filter(|ep| ep.is_root_subnet)
        .collect::<Vec<_>>();

    // these nodes will be reassigned
    let node1 = nodes[0];
    let node2 = nodes[1];
    // These nodes will stay
    let node3 = nodes[2];
    let node4 = nodes[3];

    // Before we move the nodes, we store a message and make sure the message is shared across
    // NNS nodes.
    block_on(node1.assert_ready(ctx));
    block_on(node2.assert_ready(ctx));

    let nns_msg = "hello world from nns!";

    let nns_can_id = block_on(store_message(&node1.url, nns_msg));
    assert!(block_on(can_read_msg(log, &node1.url, nns_can_id, nns_msg)));
    assert!(block_on(can_read_msg_with_retries(
        log, &node2.url, nns_can_id, nns_msg, 5
    )));

    info!(ctx.logger, "Message on both nns nodes verified!");

    // Now we store another message on the app subnet.
    let app_node = get_random_application_node_endpoint(&handle, &mut rng);
    block_on(app_node.assert_ready(ctx));
    let app_msg = "hello world from app subnet!";
    let app_can_id = block_on(store_message(&app_node.url, app_msg));
    assert!(block_on(can_read_msg(
        log,
        &app_node.url,
        app_can_id,
        app_msg
    )));
    info!(ctx.logger, "Message on app node verified!");

    // Unassign 2 nns nodes
    let node_ids: Vec<_> = vec![node1.node_id, node2.node_id];
    block_on(remove_nodes_via_endpoint(node3.url.clone(), &node_ids)).unwrap();
    info!(
        ctx.logger,
        "Removed node ids {:?} from the NNS subnet", node_ids
    );

    let subnet_id = app_node.subnet_id().unwrap();
    block_on(add_nodes_to_subnet(node3.url.clone(), subnet_id, &node_ids)).unwrap();
    info!(
        ctx.logger,
        "Added node ids {:?} to subnet {}", node_ids, subnet_id
    );
    info!(
        ctx.logger,
        "Waiting for moved nodes to return the app subnet message..."
    );
    block_on(node1.assert_ready(ctx));
    block_on(node2.assert_ready(ctx));
    assert!(block_on(can_read_msg_with_retries(
        log, &node1.url, app_can_id, app_msg, 50
    )));
    assert!(block_on(can_read_msg_with_retries(
        log, &node2.url, app_can_id, app_msg, 5
    )));
    info!(
        ctx.logger,
        "App message on former NNS nodes could be retrieved!"
    );

    block_on(node3.assert_ready(ctx));
    block_on(node4.assert_ready(ctx));
    assert!(block_on(can_read_msg(log, &node3.url, nns_can_id, nns_msg)));
    assert!(block_on(can_read_msg(log, &node4.url, nns_can_id, nns_msg)));
    info!(
        ctx.logger,
        "NNS message on remaining NNS nodes could be retrieved!"
    );

    // Now make sure the subnets are able to store new messages
    info!(ctx.logger, "Try to store new messages on NNS...");
    let nns_msg_2 = "hello again on nns!";
    let nns_can_id_2 = block_on(store_message(&node3.url, nns_msg_2));
    assert!(block_on(can_read_msg_with_retries(
        log,
        &node4.url,
        nns_can_id_2,
        nns_msg_2,
        5
    )));

    info!(ctx.logger, "Try to store new messages on app subnet...");
    let app_msg_2 = "hello again on app subnet!";
    let app_can_id_2 = block_on(store_message(&app_node.url, app_msg_2));
    assert!(block_on(can_read_msg_with_retries(
        log,
        &node1.url,
        app_can_id_2,
        app_msg_2,
        5
    )));
    info!(
        ctx.logger,
        "New messages could be written and retrieved on both subnets!"
    );

    info!(ctx.logger, "Test finished successfully");
}

pub async fn store_message(url: &Url, msg: &str) -> Principal {
    let bytes = msg.as_bytes();
    let agent = assert_create_agent(url.as_str()).await;
    let ucan = UniversalCanister::new(&agent).await;
    // send an update call to it
    ucan.store_to_stable(0, bytes).await;
    ucan.canister_id()
}

pub async fn can_read_msg(
    log: &slog::Logger,
    url: &Url,
    canister_id: Principal,
    msg: &str,
) -> bool {
    can_read_msg_with_retries(log, url, canister_id, msg, 0).await
}

pub async fn can_read_msg_with_retries(
    log: &slog::Logger,
    url: &Url,
    canister_id: Principal,
    msg: &str,
    retries: usize,
) -> bool {
    let bytes = msg.as_bytes();
    for i in 0..retries + 1 {
        debug!(log, "Try to create agent for node {:?}...", url.as_str());
        match create_agent(url.as_str()).await {
            Ok(agent) => {
                debug!(log, "Try to get canister reference");
                let ucan = UniversalCanister::from_canister_id(&agent, canister_id);
                debug!(log, "Success, will try to read next");
                if ucan.read_stable(0, msg.len() as u32).await == Ok(bytes.to_vec()) {
                    return true;
                } else {
                    info!(
                        log,
                        "Could not read expected message, will retry {:?} times",
                        retries - i
                    );
                }
            }
            Err(e) => {
                debug!(
                    log,
                    "Could not create agent: {:?}, will retry {:?} times",
                    e,
                    retries - i
                );
            }
        };
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    false
}
