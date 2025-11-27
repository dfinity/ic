/* tag::catalog[]

Goal:: Test the node registration process by mocking the HSM signing.

Runbook::
. Setup an IC with 1-node NNS and 1 unassigned node with a node provider and a node operator principals (we use the same one).
. Remove the node from the registry.
. Wait for the registry update and make sure we have no unassigned nodes.
. Delete crypto key on the unassigned node and restart the replica and the csp process again.
. Restart the replica process.
. Wait for the registry update and make sure we have 1 unassigned nodes.

Success:: We end the test again with 1 registered unassigned nodes.

end::catalog[] */

use anyhow::Result;

use ic_consensus_system_test_node_registration_test_common::{setup, test_with_node_allowance};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_with_node_allowance))
        .execute_from_args()?;

    Ok(())
}
