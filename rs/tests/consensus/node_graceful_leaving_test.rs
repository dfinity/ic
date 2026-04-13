/* tag::catalog[]
Title:: Graceful node removal from the subnet

Goal:: Test whether graceful nodes removal (making nodes unassigned) from a subnet results in the consensus membership update.

Runbook::
. Setup:
    . System subnet comprising N nodes and all necessary NNS canisters.
. Gracefully remove X=floor(N/3)+1 nodes from the subnet via proposal (committee rearrangement check requires that we remove X > f nodes, where N=3*f+1).
. Assert all nodes have been removed from the subnet (assert that endpoints [IPv6]/api/v2/status are unreachable).
. Kill X removed node.
. Assert that `update` messages can be executed in the subnet (this additionally confirms that the nodes had been removed from the consensus membership).

Success::
. Status endpoints of gracefully removed nodes are unreachable.
.`Update` message call executes successfully after killing the removed nodes.

end::catalog[] */

use ic_base_types::NodeId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::ic::{InternetComputer, Subnet},
    driver::{
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    nns::remove_nodes_via_endpoint,
    util::{
        EndpointsStatus, assert_nodes_health_statuses, assert_subnet_can_make_progress, block_on,
    },
};
use ic_types::Height;

use anyhow::Result;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;
use slog::info;

const DKG_INTERVAL: u64 = 14;
const NODES_COUNT: usize = 4;
const REMOVE_NODES_COUNT: usize = (NODES_COUNT / 3) + 1;
// Seed for a random generator
const RND_SEED: u64 = 42;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();

    topology.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    let mut nns_nodes: Vec<_> = topology.root_subnet().nodes().collect();
    let (nns_node, nns_nodes_to_remove) = {
        let mut rng: ChaCha8Rng = rand::SeedableRng::seed_from_u64(RND_SEED);
        nns_nodes.shuffle(&mut rng);
        (&nns_nodes[0], &nns_nodes[1..REMOVE_NODES_COUNT + 1])
    };

    info!(log, "Installing NNS canisters ...");
    NnsInstallationBuilder::new()
        .install(nns_node, &env)
        .expect("Could not install NNS canisters");
    info!(
        log,
        "Assert nodes are healthy before their removal from subnet"
    );

    assert_nodes_health_statuses(
        log.clone(),
        nns_nodes_to_remove,
        EndpointsStatus::AllHealthy,
    );
    info!(
        log,
        "Remove X=floor(N/3)+1=floor({NODES_COUNT}/3+1)={REMOVE_NODES_COUNT} nodes via proposal",
    );

    block_on(async {
        let node_ids: Vec<NodeId> = nns_nodes_to_remove.iter().map(|n| n.node_id).collect();
        remove_nodes_via_endpoint(nns_node.get_public_url(), node_ids.as_slice())
            .await
            .unwrap();
    });

    info!(
        log,
        "Assert nodes are unhealthy after their removal from subnet"
    );
    assert_nodes_health_statuses(
        log.clone(),
        nns_nodes_to_remove,
        EndpointsStatus::AllUnhealthy,
    );

    info!(log, "Kill nodes after removal (last shot to the victims)");
    nns_nodes_to_remove.iter().for_each(|node| node.vm().kill());
    // Assert that `update` call can still be executed, this ensures that removed+killed nodes are not part of the consensus committee.
    let update_message = b"This beautiful prose should be persisted for future generations";
    block_on(async { assert_subnet_can_make_progress(update_message, nns_node).await });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
