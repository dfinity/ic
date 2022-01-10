/* tag::catalog[]
Title:: Node Restart Meta-Test

Goal:: Ensure that our node restart functionality is actually working.

Runbook::
. Set up one subnet
. Restarts one node
. Wait until we see that the newly started node is ready again.

Success:: The restarted node reports block finalizations.

Coverage::
. IcControl::restart_node();


end::catalog[] */

use ic_fondue::{self};
use ic_fondue::{
    ic_instance::{InternetComputer, Subnet},
    ic_manager::{IcControl, IcHandle},
};
use ic_registry_subnet_type::SubnetType;

use crate::util;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .with_unassigned_nodes(1)
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Choose the only available NNS node.
    let mut rng = ctx.rng.clone();
    let node = util::get_random_nns_node_endpoint(&handle, &mut rng);
    // Wait until the node becomes ready.
    util::block_on(node.assert_ready(ctx));
    // Triggers a restart.
    let node = node.restart_node(ctx.logger.clone());
    // Verify that the re-started node eventually becomes ready again.
    util::block_on(node.assert_ready(ctx));
}
