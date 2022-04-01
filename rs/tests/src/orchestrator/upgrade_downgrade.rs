/* tag::catalog[]
Title:: Upgradability to/from oldest prod replica version.

Goal:: Ensure the upgradability of the branch version against the oldest used replica version

Runbook::
. Setup an IC with 4-nodes NNS and 4-nodes app subnet using the code from the branch.
. Downgrade each type of subnet to the mainnet version and back.
. During both upgrades simulate a disconnected node and make sure it catches up.

Success:: Upgrades work into both directions for all subnet types.

end::catalog[] */

use crate::nns::NnsExt;
use crate::orchestrator::node_reassignment_test::{can_read_msg, store_message};
use crate::orchestrator::utils::upgrade::{
    assert_assigned_replica_version, bless_replica_version, get_assigned_replica_version,
    update_subnet_replica_version, UpdateImageType,
};
use crate::util::{
    assert_endpoints_reachability, block_on, get_random_nns_node_endpoint, EndpointsStatus,
};
use crate::{
    driver::ic::{InternetComputer, Subnet},
    driver::vm_control::IcControl,
};
use ic_fondue::{
    ic_manager::IcEndpoint,
    ic_manager::IcHandle, // we run the test on the IC
    pot::Context,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use slog::{info, Logger};
use std::env;

const DKG_INTERVAL: u64 = 9;
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

// Tests a downgrade of the nns subnet to the mainnet version and an upgrade back to the branch version
pub fn upgrade_downgrade_nns_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    upgrade_downgrade(handle, ctx, SubnetType::System);
}

// Tests a downgrade of the app subnet to the mainnet version and an upgrade back to the branch version
pub fn upgrade_downgrade_app_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    upgrade_downgrade(handle, ctx, SubnetType::Application);
}

// Downgrades a subnet to $TARGET_VERSION and back to branch version
fn upgrade_downgrade(handle: IcHandle, ctx: &ic_fondue::pot::Context, subnet_type: SubnetType) {
    let mainnet_version =
        env::var("TARGET_VERSION").expect("Environment variable $TARGET_VERSION is not set!");

    ctx.install_nns_canisters(&handle, true);

    let nns_node = get_random_nns_node_endpoint(&handle, &mut ctx.rng.clone());
    block_on(nns_node.assert_ready(ctx));

    let original_branch_version = get_assigned_replica_version(nns_node).unwrap();
    // We have to upgrade to `<VERSION>-test` because the original version is stored without the
    // download URL in the registry.
    let branch_version = format!("{}-test", original_branch_version);

    // Bless both replica versions
    block_on(bless_replica_version(
        nns_node,
        &mainnet_version,
        UpdateImageType::Image,
        &ctx.logger,
    ));
    block_on(bless_replica_version(
        nns_node,
        &original_branch_version,
        UpdateImageType::ImageTest,
        &ctx.logger,
    ));
    info!(&ctx.logger, "Blessed all versions");

    downgrade_upgrade_roundtrip(
        &handle,
        ctx,
        nns_node,
        &mainnet_version,
        &branch_version,
        subnet_type,
    );
}

// Downgrades and upgrades a subnet with one faulty node.
fn downgrade_upgrade_roundtrip(
    handle: &IcHandle,
    ctx: &Context,
    nns_node: &IcEndpoint,
    target_version: &str,
    branch_version: &str,
    subnet_type: SubnetType,
) {
    let (subnet_node, faulty_node) = {
        let mut iter = handle.as_random_iter(&mut ctx.rng.clone()).filter(|ep| {
            if subnet_type == SubnetType::System {
                // We don't want to hit the node we're using for sending the proposals
                ep.is_root_subnet && ep.node_id != nns_node.node_id
            } else {
                !ep.is_root_subnet
            }
        });
        (iter.next().unwrap(), iter.next().unwrap())
    };
    block_on(subnet_node.assert_ready(ctx));
    block_on(faulty_node.assert_ready(ctx));

    let msg = "hello world!";
    let can_id = block_on(store_message(&subnet_node.url, msg));
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &subnet_node.url,
        can_id,
        msg
    )));
    info!(ctx.logger, "Could store and read message '{:?}'", msg);

    stop_node(ctx, faulty_node);

    upgrade_to(nns_node, subnet_node, target_version, &ctx.logger);

    start_node(ctx, faulty_node);
    assert_assigned_replica_version(faulty_node, target_version, &ctx.logger);

    assert!(block_on(can_read_msg(
        &ctx.logger,
        &faulty_node.url,
        can_id,
        msg
    )));
    info!(ctx.logger, "After upgrade could read message '{:?}'", msg);

    let msg_2 = "hello world after downgrade!";
    let can_id_2 = block_on(store_message(&faulty_node.url, msg_2));
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &faulty_node.url,
        can_id_2,
        msg_2
    )));
    info!(ctx.logger, "Could store and read message '{:?}'", msg_2);

    stop_node(ctx, faulty_node);
    upgrade_to(nns_node, subnet_node, branch_version, &ctx.logger);

    let msg_3 = "hello world after upgrade!";
    let can_id_3 = block_on(store_message(&subnet_node.url, msg_3));

    start_node(ctx, faulty_node);
    assert_assigned_replica_version(faulty_node, branch_version, &ctx.logger);

    for (c, m) in &[(can_id, msg), (can_id_2, msg_2), (can_id_3, msg_3)] {
        assert!(block_on(can_read_msg(&ctx.logger, &faulty_node.url, *c, m)));
    }

    info!(ctx.logger, "Could read all previously stored messages!");
}

fn upgrade_to(
    nns_node: &IcEndpoint,
    subnet_node: &IcEndpoint,
    target_version: &str,
    logger: &Logger,
) {
    let subnet_id = subnet_node.subnet_id().unwrap();
    info!(
        logger,
        "Upgrading subnet {} to {}", subnet_id, target_version
    );
    use std::convert::TryFrom;
    block_on(update_subnet_replica_version(
        nns_node,
        &ic_types::ReplicaVersion::try_from(target_version).unwrap(),
        subnet_id,
    ));
    assert_assigned_replica_version(subnet_node, target_version, logger);
    info!(
        logger,
        "Successfully upgraded subnet {} to {}", subnet_id, target_version
    );
}

// Stops the node and makes sure it becomes unreachable
pub fn stop_node(ctx: &Context, app_node: &IcEndpoint) {
    let app_node_ip = app_node.ip_address().unwrap();
    info!(ctx.logger, "Kill node: {}", app_node_ip);
    block_on(async {
        assert_endpoints_reachability(&[app_node], EndpointsStatus::AllReachable).await
    });
    app_node.kill_node(ctx.logger.clone());
    block_on(async {
        assert_endpoints_reachability(&[app_node], EndpointsStatus::AllUnreachable).await
    });
    info!(
        ctx.logger,
        "Node killed: {}",
        app_node.ip_address().unwrap()
    );
}

// Starts a node and makes sure it becomes reachable
pub fn start_node(ctx: &Context, app_node: &IcEndpoint) -> IcEndpoint {
    block_on(async {
        assert_endpoints_reachability(&[app_node], EndpointsStatus::AllUnreachable).await
    });
    info!(
        ctx.logger,
        "Starting node: {}",
        app_node.ip_address().unwrap()
    );
    let app_node2 = app_node.start_node(ctx.logger.clone());
    block_on(async {
        assert_endpoints_reachability(&[&app_node2], EndpointsStatus::AllReachable).await
    });
    info!(
        ctx.logger,
        "Node started: {}",
        app_node.ip_address().unwrap()
    );
    app_node2
}
