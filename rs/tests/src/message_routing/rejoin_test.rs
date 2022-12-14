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
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasGroupSetup, HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer,
};
use crate::util::{block_on, UniversalCanister};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use slog::info;
use std::time::Duration;

const ALLOWED_FAILURES: usize = 1;
const NODES_COUNT: usize = 3 * ALLOWED_FAILURES + 1;
const DKG_INTERVAL: u64 = 14;
const NOTARY_DELAY: Duration = Duration::from_millis(100);

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(NODES_COUNT)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_initial_notary_delay(NOTARY_DELAY),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let mut nodes = env.topology_snapshot().root_subnet().nodes();
    let node = nodes.next().unwrap();
    let rejoin_node = nodes.next().unwrap();
    info!(
        logger,
        "Installing universal canister on a node {} ...",
        node.get_public_url()
    );
    let agent = node.with_default_agent(|agent| async move { agent });
    let universal_canister = block_on(UniversalCanister::new_with_retries(
        &agent,
        node.effective_canister_id(),
        &logger,
    ));

    info!(
        logger,
        "Killing a node: {} ...",
        rejoin_node.get_public_url()
    );
    rejoin_node.vm().kill();

    info!(logger, "Making some canister update calls ...");
    for i in 0..3 * DKG_INTERVAL {
        store_and_read_stable(i.to_string().as_bytes(), &universal_canister);
    }

    info!(logger, "Killing {} nodes ...", ALLOWED_FAILURES);
    for _ in 0..ALLOWED_FAILURES {
        let node = nodes.next().unwrap();
        info!(logger, "Killing node {} ...", node.get_public_url());
        node.vm().kill();
    }

    info!(logger, "Starting the first killed node again...");
    rejoin_node.vm().start();

    let delay: Duration = NOTARY_DELAY.mul_f64(5.0 * DKG_INTERVAL as f64);
    info!(logger, "Sleeping for {:?} ...", delay);
    std::thread::sleep(delay);

    info!(logger, "Checking for subnet progress...");
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
