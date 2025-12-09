use anyhow::bail;
use ic_system_test_driver::{
    driver::{
        nested::{HasNestedVms, NestedNodes},
        test_env::TestEnv,
        test_env_api::*,
    },
    retry_with_msg,
    util::block_on,
};
use slog::info;

pub mod util;
use util::{NODE_REGISTRATION_BACKOFF, NODE_REGISTRATION_TIMEOUT, setup_ic_infrastructure};

pub const HOST_VM_NAME: &str = "host-1";

/// Prepare the environment for nested tests.
/// SetupOS -> HostOS -> GuestOS
pub fn setup(env: TestEnv) {
    setup_ic_infrastructure(&env, /*dkg_interval=*/ None, /*is_fast=*/ true);

    NestedNodes::new(&[HOST_VM_NAME])
        .setup_and_start(&env)
        .unwrap();
}

/// Minimal setup that only creates a nested VM without any IC infrastructure.
/// This is much faster than the full setup() setup.
pub fn simple_setup(env: TestEnv) {
    NestedNodes::new(&[HOST_VM_NAME])
        .setup_and_start(&env)
        .unwrap();
}

/// Allow the nested GuestOS to install and launch, and check that it can
/// successfully join the testnet.
pub fn registration(env: TestEnv) {
    let logger = env.logger();

    let initial_topology = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(1)),
    )
    .unwrap();

    // Check that there are initially no unassigned nodes.
    let num_unassigned_nodes = initial_topology.unassigned_nodes().count();
    assert_eq!(num_unassigned_nodes, 0);

    let nested_vms = env.get_all_nested_vms().unwrap();
    let n = nested_vms.len();
    for node in nested_vms {
        let node_name = &node.vm_name();
        info!(
            logger,
            "Asserting that the GuestOS was started with direct kernel boot on node {node_name} ..."
        );
        let guest_kernel_cmdline = env
            .get_nested_vm(node_name)
            .expect("Unable to find HostOS node.")
            .get_guest_ssh()
            .unwrap()
            .block_on_bash_script("cat /proc/cmdline")
            .expect("Could not read /proc/cmdline from GuestOS");
        assert!(
            guest_kernel_cmdline.contains("initrd=initrd"),
            "GuestOS kernel command line does not contain 'initrd=initrd'. This is likely caused by \
            the guest not being started with direct kernel boot but rather with the GRUB \
            bootloader. guest_kernel_cmdline: '{guest_kernel_cmdline}'"
        );
    }

    // If the nodes are able to join successfully, the registry will be updated,
    // and the new node IDs will enter the unassigned pool.
    let mut new_topology = initial_topology;
    retry_with_msg!(
        format!("Waiting for all {n} nodes to join ..."),
        logger.clone(),
        NODE_REGISTRATION_TIMEOUT,
        NODE_REGISTRATION_BACKOFF,
        || {
            new_topology = block_on(
                new_topology.block_for_newer_registry_version_within_duration(
                    NODE_REGISTRATION_TIMEOUT,
                    NODE_REGISTRATION_BACKOFF,
                ),
            )
            .unwrap();
            let num_unassigned_nodes = new_topology.unassigned_nodes().count();
            if num_unassigned_nodes == n {
                Ok(())
            } else {
                bail!("Expected {n} unassigned nodes, but found {num_unassigned_nodes}. Waiting for the rest to register ...");
            }
        }
    ).unwrap();
    info!(logger, "All {n} nodes successfully came up and registered.");

    std::thread::sleep(std::time::Duration::from_secs(60 * 60));
}
