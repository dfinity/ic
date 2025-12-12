/* tag::catalog[]
Title:: End-to-end NNS Recovery Test

Goal:: Ensure that the subnet recovery of an NNS subnet without changing the node membership and without requiring admin access on all nodes works.

Runbook::
. Start IC with an NNS subnet with nodes that have a virtualized HostOS. To do this, start with a standard one-node NNS subnet, add the nodes with virtualized HostOS, wait for them to register, and then remove the original node.
. Add an SSH key as backup access to all NNS nodes to mirror the production setup (needed for recovery).
. Break the subnet by replacing the replica binary on f+1 nodes.
. Run ic-recovery to replay consensus artifacts until the highest certification share height, manually inject a message upgrading the replica to a known working version, produce a CUP and registry local store corresponding to the new state and bundle them in a tarball.
. Upload the tarball to a local web server acting as DFINITY's upstreams, as well as a recovery GuestOS image (containing guestos-recovery-engine).
. Reboot nodes' HostOSes into recovery mode to trigger guestos-recovery-upgrader and download the recovery GuestOS iamge.
. This recovery GuestOS image will download the recovery artifacts from the local web server and launch the orchestrator, which will detect the upgrade message and upgrade to it.
  . It will also state sync the state indicated by the CUP.
. Observe that NNS subnet continues functioning.

Success::
. NNS subnet is functional after the recovery.

Variant::
. This test variant performs the recovery assuming the DFINITY-owned node is broken/lagging behind.

end::catalog[] */

use anyhow::Result;
use ic_nested_nns_recovery_common::{
    DKG_INTERVAL, SUBNET_SIZE, SetupConfig, TestConfig, setup, test,
};
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|env| {
            setup(
                env,
                SetupConfig {
                    impersonate_upstreams: true,
                    use_mainnet_state: false,
                    subnet_size: SUBNET_SIZE,
                    dkg_interval: DKG_INTERVAL,
                },
            )
        })
        .add_test(systest!(test; TestConfig {
            local_recovery: false,
            break_dfinity_owned_node: true,
            add_and_bless_upgrade_version: true,
            fix_dfinity_owned_node_like_np: false,
            sequential_np_actions: false,
        }))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .execute_from_args()?;

    Ok(())
}
