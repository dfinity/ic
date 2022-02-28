/* tag::catalog[]

Title:: Checking the CUP fetching across upgrades

Goal::
Ensure that we can upgrade nodes and that obtaining CUPs via http didn't
become incompatible between versions.

Description::
We deploy an IC with a subnet running replicas of the current branch version.
We update the subnet to the master branch version against which we want to
check the compatibility. Later on we also update back to the original version.
Before the upgrade process one node is killed in order to make sure it won't
receive the CUP via gossip protocol but only via http later on when is
restarted. That way we can check that the http mechanism of requesting CUPs is
compatible between the two versions.

Runbook::
. Deploy an IC with a subnet.
. Bless a master branch version.
. Kill a random node from the subnet.
. Send a proposal to upgrade to the master version.
. Wait for some node of the subnet to update to the master version.
. Start again the node that was killed.
. Check that it also got updated eventually.
. Do the same process from the master to the original version.

Success::
. Restarted node runs the expected version.

end::catalog[] */

use crate::nns::{
    get_governance_canister, submit_bless_replica_version_proposal,
    submit_update_subnet_replica_version_proposal, vote_execute_proposal_assert_executed, NnsExt,
};
use crate::orchestrator::node_reassignment_test::{can_read_msg, store_message};
use crate::orchestrator::utils::upgrade::{fetch_update_file_sha256, get_blessed_replica_versions};
use crate::util::{
    assert_endpoints_reachability, block_on, get_other_subnet_nodes,
    get_random_application_node_endpoint, get_random_nns_node_endpoint, get_update_image_url,
    runtime_from_url, EndpointsStatus, UpdateImageType,
};
use core::time;
use ic_canister_client::Sender;
use ic_fondue::pot::Context;
use ic_fondue::{
    ic_instance::{InternetComputer, Subnet},
    ic_manager::{IcControl, IcEndpoint, IcHandle},
};
use ic_nns_common::types::NeuronId;
use ic_nns_constants::ids::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_registry_common::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_types::{messages::ReplicaHealthStatus, Height, ReplicaVersion, SubnetId};
use slog::{info, warn};
use std::convert::TryFrom;
use std::{env, thread};

const DKG_INTERVAL: u64 = 14;
const SUBNET_SIZE: usize = 4;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
}

pub fn test(handle: IcHandle, ctx: &Context) {
    let mut rng = ctx.rng.clone();

    info!(ctx.logger, "Starting the replica upgrade http test...");

    let master_version = match env::var("MASTER_GIT_REVISION") {
        Ok(ver) => ver,
        Err(_) => panic!("Environment variable $MASTER_GIT_REVISION is not set!"),
    };
    info!(ctx.logger, "MASTER_GIT_REVISION: {}", master_version);

    ctx.install_nns_canisters(&handle, true);

    let nns_node = get_random_nns_node_endpoint(&handle, &mut rng);
    block_on(nns_node.assert_ready(ctx));

    let app_node = get_random_application_node_endpoint(&handle, &mut rng);
    block_on(app_node.assert_ready(ctx));

    let msg = "first message for app subnet!";
    info!(ctx.logger, "Store message '{}'", msg);
    let app_can_id = block_on(store_message(&app_node.url, msg));
    info!(ctx.logger, "Read message '{}'", msg);
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &app_node.url,
        app_can_id,
        msg
    )));

    let subnet_id = app_node.subnet_id().unwrap();
    let other_nodes = get_other_subnet_nodes(&handle, app_node);

    let original_version = get_replica_version(app_node).unwrap();
    info!(ctx.logger, "Original version: {}", original_version);
    if original_version == master_version {
        warn!(
            ctx.logger,
            "Update to a same version is useless: original_version == master_version!"
        );
        return;
    }

    let app_node2 = upgrade_replica_after_subnet_upgraded(
        &original_version,
        &master_version,
        &master_version,
        nns_node,
        app_node,
        &other_nodes,
        subnet_id,
        ctx,
    );
    // 2. update needs to update to the "-test" version. going back to the
    // initial one is not possible because its not fully blessed. on the other
    // hand additinall blessing the initial version is also not possible as it
    // is already in the registry - hence half blessed.
    upgrade_replica_after_subnet_upgraded(
        &master_version,
        &original_version,
        &format!("{}-test", original_version),
        nns_node,
        &app_node2,
        &other_nodes,
        subnet_id,
        ctx,
    );
}

/// This function will do upgrade of a subnet while one of the nodes is down.
/// Once the subnet is updated the node will be started again and it will have
/// to download the CUP via http since it is not able to communicate via gossip
/// anymore.
#[allow(clippy::too_many_arguments)]
fn upgrade_replica_after_subnet_upgraded(
    original_version: &str,
    target_version: &str,
    replica_version: &str,
    nns_node: &IcEndpoint,
    app_node: &IcEndpoint,
    other_nodes: &[&IcEndpoint],
    subnet_id: SubnetId,
    ctx: &Context,
) -> IcEndpoint {
    info!(
        ctx.logger,
        "Upgrade from {} to: {}", original_version, replica_version
    );
    let new_replica_version = ReplicaVersion::try_from(replica_version).unwrap();

    // bless the target version
    propose_blessed_version(
        nns_node,
        target_version,
        replica_version,
        &new_replica_version,
        ctx,
    );

    // kill a node
    stop_node(app_node, ctx);

    // check that the subnet is still running
    // use replica version as a message that will be stored in the state
    info!(ctx.logger, "Store message '{}'", original_version);
    let app_can_id = block_on(store_message(&other_nodes[0].url, original_version));
    info!(ctx.logger, "Read message '{}'", original_version);
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &other_nodes[0].url,
        app_can_id,
        original_version
    )));

    // proposal to upgrade the subnet nodes
    proposal_upgrade_nodes(nns_node, &new_replica_version, subnet_id);

    // make sure the whole subnet is of the target version now
    for node in other_nodes.iter() {
        assert_replica_version(node, replica_version, ctx);
    }

    // read again the message to make sure the state is kept after the upgrade
    info!(ctx.logger, "Read again message '{}'", original_version);
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &other_nodes[0].url,
        app_can_id,
        original_version
    )));

    // start node again
    let app_node2 = start_stoped_node(ctx, app_node);

    // make sure it has the target version now
    assert_replica_version(&app_node2, replica_version, ctx);

    // check that the subnet is still running
    info!(ctx.logger, "Store message '{}'", replica_version);
    let app_can_id2 = block_on(store_message(&app_node2.url, replica_version));
    info!(ctx.logger, "Read message '{}'", replica_version);
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &app_node2.url,
        app_can_id2,
        replica_version
    )));

    app_node2
}

fn propose_blessed_version(
    nns_node: &IcEndpoint,
    target_version: &str,
    replica_version: &str,
    new_replica_version: &ReplicaVersion,
    ctx: &Context,
) {
    let upgrade_url = if target_version == replica_version {
        get_update_image_url(UpdateImageType::Image, target_version)
    } else {
        get_update_image_url(UpdateImageType::ImageTest, target_version)
    };
    info!(ctx.logger, "Upgrade URL: {}", upgrade_url);
    let sha_url = get_update_image_url(UpdateImageType::Sha256, target_version);

    let nns = runtime_from_url(nns_node.url.clone());
    let governance_canister = get_governance_canister(&nns);
    let registry_canister = RegistryCanister::new(vec![nns_node.url.clone()]);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    block_on(async {
        let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
        info!(ctx.logger, "Initial: {:?}", blessed_versions);
        let sha256 = fetch_update_file_sha256(&sha_url, target_version != replica_version).await;

        let proposal_id = submit_bless_replica_version_proposal(
            &governance_canister,
            proposal_sender.clone(),
            test_neuron_id,
            new_replica_version.clone(),
            sha256,
            upgrade_url,
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
        let blessed_versions = get_blessed_replica_versions(&registry_canister).await;
        info!(ctx.logger, "Updated: {:?}", blessed_versions);
    });
}

fn proposal_upgrade_nodes(
    nns_node: &IcEndpoint,
    new_replica_version: &ReplicaVersion,
    subnet_id: SubnetId,
) {
    let nns = runtime_from_url(nns_node.url.clone());
    let governance_canister = get_governance_canister(&nns);
    let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
    let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
    block_on(async {
        let proposal2_id = submit_update_subnet_replica_version_proposal(
            &governance_canister,
            proposal_sender.clone(),
            test_neuron_id,
            new_replica_version.clone(),
            subnet_id,
        )
        .await;
        vote_execute_proposal_assert_executed(&governance_canister, proposal2_id).await;
    });
}

fn stop_node(app_node: &IcEndpoint, ctx: &Context) {
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

fn start_stoped_node(ctx: &Context, app_node: &IcEndpoint) -> IcEndpoint {
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

fn assert_replica_version(endpoint: &IcEndpoint, expected_version: &str, ctx: &Context) {
    for i in 1..=50 {
        let fetched_version = get_replica_version(endpoint).ok();
        info!(
            ctx.logger,
            "Try: {}. replica version: {:?}", i, fetched_version
        );
        if Some(expected_version.to_string()) == fetched_version {
            return;
        };
        thread::sleep(time::Duration::from_secs(10));
    }

    panic!("Couldn't detect the replica version {}", expected_version)
}

fn get_replica_version(endpoint: &IcEndpoint) -> Result<String, String> {
    let version = match block_on(async { endpoint.status().await }) {
        Ok(status) => {
            if Some(ReplicaHealthStatus::Healthy) == status.replica_health_status {
                status
            } else {
                return Err("Replica is not healty".to_string());
            }
        }
        Err(err) => return Err(err.to_string()),
    }
    .impl_version;
    match version {
        Some(ver) => Ok(ver),
        None => Err("No version found in status".to_string()),
    }
}
