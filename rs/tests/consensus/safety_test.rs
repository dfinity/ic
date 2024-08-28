/* tag::catalog[]
Title:: Consensus Safety Test

Goal:: Demonstrate that there are no conflicting states for different
replicas in the presence of malicious behavior.

Runbook::
. Set up one subnets with 3f+1 nodes, f of which malicious.
. Install a universal canister in an honest node.
. Continuously push messages to the canister's stable memory
. Pull the last sent message and compare with the expectation.

Success:: Check the messages have really been written to memory
by pulling the last one from a different node.
The `ekg::finalized_hashes_agree` does not detect different
hashes for the same height. This is part of `ekg::basic_monitoring`, and
hence, checked by default.

Coverage::
. Consensus doesn't break in the presence of simple malicious behavior

Caveats and Future Work::
. Add a check that certified state hashes also agree
. Work on a `certified_state_safety_test` where we flip bits of certified state and observe the replica restart.


end::catalog[] */

use ic_consensus_system_test_liveness_test_common::test;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::systest;
use ic_types::malicious_behaviour::MaliciousBehaviour;

use anyhow::Result;

fn setup(env: TestEnv) {
    let malicious_behavior = MaliciousBehaviour::new(true)
        .set_maliciously_propose_empty_blocks()
        .set_maliciously_notarize_all()
        .set_maliciously_finalize_all();

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(3)
                .add_malicious_nodes(1, malicious_behavior),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
