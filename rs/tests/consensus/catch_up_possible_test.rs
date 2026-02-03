/* tag::catalog[]
Title:: Catch Up Test
/// Common test function for a couple of catch up tests.

Goal:: Demonstrate catch up behavior of nodes when both execution and state sync are slow.

Runbook::
. Set up a malicious (defect) node that uses delays to simulate slow execution and state sync
. The defect node is now shut down and after a couple minutes restarted
. Check whether the node is able to catch up
. Additionally, we check that the artifacts are always purged below the latest CUP height (with some
  cushion), even when we are severely lagging behind the other nodes.

Success::
. Depending on the parameters we set in this test, we either expect the node to be able to catch up or not

Coverage::
In the test, the delays are artificially introduced. However, they simulate real node behavior
in certain situations. The speed of state sync depends on the size of the state, while the execution speed
depends on the number of messages in the blocks to replay.

end::catalog[] */

use ic_consensus_system_test_catch_up_test_common::test_catch_up_possible;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;

use anyhow::Result;
use ic_types::Height;
use ic_types::malicious_behavior::MaliciousBehavior;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30 * 60);

const EXECUTION_DELAY_FACTOR: f64 = 0.8;
const STATE_SYNC_DELAY_FACTOR: f64 = 0.5;
const TARGET_FR_MS: u64 = 320;
const DKG_INTERVAL_TIME_MS: u64 = TARGET_FR_MS * DKG_INTERVAL;
const DKG_INTERVAL: u64 = 150;

fn setup(env: TestEnv) {
    let execution_delay_ms = (EXECUTION_DELAY_FACTOR * TARGET_FR_MS as f64) as u64;
    let state_sync_delay_ms = (STATE_SYNC_DELAY_FACTOR * DKG_INTERVAL_TIME_MS as f64) as u64;

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_unit_delay(Duration::from_millis(TARGET_FR_MS))
                .with_initial_notary_delay(Duration::from_millis(TARGET_FR_MS))
                .with_dkg_interval_length(Height::from(DKG_INTERVAL - 1))
                .add_nodes(3)
                .add_malicious_nodes(
                    1,
                    MaliciousBehavior::new(true)
                        .set_maliciously_delay_execution(Duration::from_millis(execution_delay_ms))
                        .set_maliciously_delay_state_sync(Duration::from_millis(
                            state_sync_delay_ms,
                        )),
                ),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_catch_up_possible))
        .with_timeout_per_test(TIMEOUT)
        .with_overall_timeout(TIMEOUT)
        .execute_from_args()?;

    Ok(())
}
