/* tag::catalog[]

Title:: Nodes can rejoin a subnet under load

Runbook::
. setup the testnet of 3f + 1 nodes
. pick a random node and install the universal canister through it
. pick another random node rejoin_node and kill it
. make a number of updates to the universal canister
. kill f random nodes
. start the rejoin_node
. wait a few seconds before checking the success condition

Success::
.. if an update can be made to the universal canister and queried back

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::vm_control::IcControl;
use crate::util::{assert_all_ready, assert_create_agent, block_on, UniversalCanister};
use ic_fondue::{
    ic_manager::{IcEndpoint, IcHandle},
    iterator::PermOf,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use slog::info;
use std::time::Duration;

const ALLOWED_FAILURES: usize = 1;
const NODES_COUNT: usize = 3 * ALLOWED_FAILURES + 1;
const DKG_INTERVAL: u64 = 14;
const NOTARY_DELAY: Duration = Duration::from_millis(100);

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .add_nodes(NODES_COUNT)
            .with_dkg_interval_length(Height::from(DKG_INTERVAL))
            .with_initial_notary_delay(NOTARY_DELAY),
    )
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    info!(&ctx.logger, "Checking readiness of all nodes...");
    block_on(assert_all_ready(
        handle
            .public_api_endpoints
            .iter()
            .collect::<Vec<&IcEndpoint>>()
            .as_slice(),
        ctx,
    ));

    let mut rng = ctx.rng.clone();
    let mut perm = PermOf::new(&handle.public_api_endpoints, &mut rng);
    let node = perm.next().unwrap();
    info!(
        &ctx.logger,
        "All nodes are ready. Installing universal canister on random node: {}...", node.url
    );
    let agent = block_on(assert_create_agent(node.url.as_str()));
    let universal_canister = block_on(UniversalCanister::new(&agent));

    let rejoin_node = perm.next().unwrap();
    info!(&ctx.logger, "Killing random node: {}...", rejoin_node.url);
    rejoin_node.kill_node(ctx.logger.clone());

    info!(&ctx.logger, "Making some canister update calls...");
    for i in 0..3 * DKG_INTERVAL {
        store_and_read_stable(i.to_string().as_bytes(), &universal_canister);
    }

    info!(&ctx.logger, "Killing {} nodes...", ALLOWED_FAILURES);
    for node_to_kill in perm.take(ALLOWED_FAILURES) {
        info!(&ctx.logger, "Killing node {}...", node_to_kill.url);
        node_to_kill.kill_node(ctx.logger.clone());
    }

    info!(&ctx.logger, "Starting the first killed node again...");
    let _rejoin_node = &rejoin_node.start_node(ctx.logger.clone());

    let delay: Duration = NOTARY_DELAY.mul_f64(5.0 * DKG_INTERVAL as f64);
    info!(&ctx.logger, "Sleeping for {:?}...", delay);
    std::thread::sleep(delay);

    info!(&ctx.logger, "Checking for subnet progress...");
    let message = b"This beautiful prose should be persisted for future generations";
    store_and_read_stable(message, &universal_canister);
}

pub fn store_and_read_stable(message: &[u8], universal_canister: &UniversalCanister) {
    block_on(universal_canister.store_to_stable(0, message));
    assert_eq!(
        block_on(universal_canister.try_read_stable(0, message.len() as u32)),
        message.to_vec()
    );
}
