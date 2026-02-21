use anyhow::bail;
use bare_metal_deployment::BareMetalIpmiSession;
use ic_system_test_driver::{
    driver::{
        nested::{HasNestedVms, NestedNodes},
        test_env::TestEnv,
        test_env_api::*,
    },
    retry_with_msg,
    util::block_on,
};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use slog::info;

pub mod util;
use util::{
    NODE_REGISTRATION_BACKOFF, NODE_REGISTRATION_TIMEOUT, NODE_REGISTRATION_VERSION_BACKOFF,
    setup_ic_infrastructure,
};

use ic_system_test_driver::driver::test_env::{SshKeyGen, TestEnvAttribute};

pub const HOST_VM_NAME: &str = "host-1";
const BARE_METAL_HOST_SECRETS: &str = "BARE_METAL_HOST_SECRETS";

#[derive(Serialize, Deserialize)]
pub struct IpmiProcessId(i32);

impl TestEnvAttribute for IpmiProcessId {
    fn attribute_name() -> String {
        "ipmi_process_id".to_string()
    }
}

/// Prepare the environment for nested tests.
/// SetupOS -> HostOS -> GuestOS
pub fn setup(env: TestEnv) {
    setup_ic_infrastructure(&env, /*dkg_interval=*/ None, /*is_fast=*/ true);
    if std::env::var("TRUSTED_EXECUTION_ENVIRONMENT").is_ok() {
        simple_bare_metal_with_trusted_execution_environment_setup(env);
    } else {
        simple_setup(env);
    }
}

/// Minimal setup that only creates a nested VM without any IC infrastructure.
/// This is much faster than the full setup() setup.
fn simple_setup(env: TestEnv) {
    NestedNodes::new([HOST_VM_NAME])
        .setup_and_start(&env)
        .unwrap();
}

/// Minimal setup that sets up a bare metal instance without any IC infrastructure.
/// This is much faster than the full setup() setup.
fn simple_bare_metal_with_trusted_execution_environment_setup(env: TestEnv) {
    let bare_metal_secrets_file = std::env::var(BARE_METAL_HOST_SECRETS)
        .expect("Could not read env var BARE_METAL_HOST_SECRETS");
    let bare_metal_secrets = std::fs::read_to_string(bare_metal_secrets_file)
        .expect("Could not read baremetal secrets file");
    let bare_metal_login_info =
        bare_metal_deployment::parse_login_info_from_ini(&bare_metal_secrets)
            .expect("Failed to parse baremetal login info");
    let mut bare_metal = BareMetalIpmiSession::start(&bare_metal_login_info)
        .expect("Failed to start baremetal session");
    bare_metal
        .inject_ssh_key(
            &env.get_ssh_public_key()
                .expect("Could not get SSH public key"),
        )
        .expect("Failed to inject SSH key");
    let mut nodes = NestedNodes::single_bare_metal(
        HOST_VM_NAME,
        bare_metal.hostos_address(),
        bare_metal.mgmt_mac(),
        /*enable_trusted_execution_environment*/ true,
    );
    nodes.setup_and_start(&env).unwrap();

    // Remember process ID of the IMPI session so we can clean it up in teardown()
    IpmiProcessId(bare_metal.process_id()).write_attribute(&env);
    bare_metal.keep_alive_after_drop();
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
                    NODE_REGISTRATION_VERSION_BACKOFF,
                    NODE_REGISTRATION_BACKOFF,
                ),
            )?;
            let num_unassigned_nodes = new_topology.unassigned_nodes().count();
            if num_unassigned_nodes == n {
                Ok(())
            } else {
                bail!("Expected {n} unassigned nodes, but found {num_unassigned_nodes}. Waiting for the rest to register ...");
            }
        }
    ).unwrap();
    info!(logger, "All {n} nodes successfully came up and registered.");
}

/// Clean up the environment after nested tests.
pub fn teardown(env: TestEnv) {
    if let Ok(pid) = IpmiProcessId::try_read_attribute(&env) {
        let _ = nix::sys::signal::kill(Pid::from_raw(pid.0), Signal::SIGTERM);
    }
}
