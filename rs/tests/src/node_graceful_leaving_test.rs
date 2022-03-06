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

use crate::{
    nns::NnsExt,
    util::{
        assert_endpoints_reachability, assert_subnet_can_make_progress, block_on, EndpointsStatus,
    },
};
use ic_fondue::{
    ic_manager::{IcControl, IcEndpoint, IcHandle},
    prod_tests::ic::{InternetComputer, Subnet},
};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;

const DKG_INTERVAL: u64 = 14;
const NODES_COUNT: usize = 4;
const REMOVE_NODES_COUNT: usize = (NODES_COUNT / 3) + 1;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .with_dkg_interval_length(Height::from(DKG_INTERVAL))
            .add_nodes(NODES_COUNT),
    )
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Setup: install all necessary NNS canisters.
    ctx.install_nns_canisters(&handle, true);
    let mut rng = ctx.rng.clone();
    let mut endpoints: Vec<_> = handle.as_permutation(&mut rng).collect();
    // Assert all nodes are reachable via http:://[IPv6]:8080/api/v2/status
    block_on(async {
        assert_endpoints_reachability(endpoints.as_slice(), EndpointsStatus::AllReachable).await
    });
    // Randomly select X=floor(N/3)+1 nodes for removal.
    let endpoint_to_remain = endpoints.pop().unwrap();
    let mut endpoints_to_remove: Vec<&IcEndpoint> = Vec::new();
    for _ in 0..REMOVE_NODES_COUNT {
        endpoints_to_remove.push(endpoints.pop().unwrap());
    }
    // Remove the nodes via proposal.
    let node_ids = endpoints_to_remove
        .iter()
        .map(|ep| ep.node_id)
        .collect::<Vec<_>>();
    ctx.remove_nodes(&handle, node_ids.as_slice());
    // Assert all nodes are now unreachable via http:://[IPv6]:8080/api/v2/status
    block_on(async {
        assert_endpoints_reachability(
            endpoints_to_remove.as_slice(),
            EndpointsStatus::AllUnreachable,
        )
        .await
    });
    // Kill nodes after removal (last shot to the victims).
    for ep in endpoints_to_remove {
        ep.kill_node(ctx.logger.clone());
    }
    // Assert that `update` call can still be executed, this ensures that removed+killed nodes are not part of the consensus committee.
    let update_message = b"This beautiful prose should be persisted for future generations";
    block_on(async { assert_subnet_can_make_progress(update_message, endpoint_to_remain).await });
}
