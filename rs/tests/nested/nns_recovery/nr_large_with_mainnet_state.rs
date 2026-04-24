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
. This test variant performs the recovery on a large NNS subnet holding mainnet state, better reflecting the production setup.

end::catalog[] */

use anyhow::Result;
use ic_nested_nns_recovery_common::{
    LARGE_DKG_INTERVAL, LARGE_F, LARGE_SUBNET_SIZE, SetupConfig, TestConfig, setup, test,
};
use ic_system_test_driver::{
    driver::group::SystemTestGroup,
    driver::ic::{NrOfVCPUs, VmResourceOverrides},
    systest,
};
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(|env| {
            setup(
                env,
                SetupConfig {
                    impersonate_upstreams: true,
                    use_mainnet_state: true,
                    subnet_size: LARGE_SUBNET_SIZE,
                    dkg_interval: LARGE_DKG_INTERVAL,
                    nested_nodes_vm_resource_overrides: VmResourceOverrides {
                        // NOTE: This test is quite sensitive to loaded Farm
                        // hosts. To limit the number of of these VMs that can
                        // be scheduled to a given Farm host, we request 64
                        // vCPUs (resulting in approx. 4 VMs per host).
                        //
                        // In theory, these VMs should be able to run with 20
                        // or fewer vCPUs. (16 GuestOS + 4 HostOS)
                        vcpus: Some(NrOfVCPUs::new(64)),
                        ..Default::default()
                    },
                },
            )
        })
        .add_test(systest!(test; TestConfig {
            use_mainnet_state: true,
            local_recovery: true,
            break_dfinity_owned_node: false,
            num_broken_nodes: LARGE_F + 1,
            add_upgrade_version: true,
            fix_dfinity_owned_node_like_np: false,
            sequential_np_actions: false,
        }))
        .with_timeout_per_test(Duration::from_mins(120))
        .execute_from_args()?;

    Ok(())
}
