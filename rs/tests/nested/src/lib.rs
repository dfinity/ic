use std::time::Duration;

use anyhow::bail;
use bare_metal_deployment::{BareMetalIpmiSession, LoginInfo};
use ic_system_test_driver::driver::nested::NestedNode;
use ic_system_test_driver::driver::test_env::SshKeyGen;
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
use util::{NODE_REGISTRATION_BACKOFF, NODE_REGISTRATION_TIMEOUT, setup_ic_infrastructure};

pub mod util;

pub const HOST_VM_NAME: &str = "host-1";
const BARE_METAL_HOST_SECRETS: &str = "BARE_METAL_HOST_SECRETS";

/// Prepare the environment for nested tests.
/// SetupOS -> HostOS -> GuestOS
pub fn setup(env: TestEnv) {
    setup_ic_infrastructure(&env, /*dkg_interval=*/ None, /*is_fast=*/ true);

    if std::env::var("TRUSTED_EXECUTION_ENVIRONMENT").is_ok() {
        let bare_metal = create_bare_metal_session(&env);
        let mut nodes = NestedNodes {
            nodes: vec![create_bare_metal_tee_node(&bare_metal)],
        };
        nodes.setup_and_start(&env).unwrap();
    } else {
        simple_setup(env);
    }
}

/// Minimal setup that only creates a nested VM without any IC infrastructure.
/// This is much faster than the full setup().
pub fn simple_setup(env: TestEnv) {
    NestedNodes::new([HOST_VM_NAME])
        .setup_and_start(&env)
        .unwrap();
}

/// Starts a bare metal IPMI session and injects the SSH key from `env`.
pub fn create_bare_metal_session(env: &TestEnv) -> BareMetalIpmiSession {
    let bare_metal_login_info = get_bare_metal_login_info();
    let mut bare_metal = BareMetalIpmiSession::start(&bare_metal_login_info)
        .expect("Failed to start baremetal session");
    bare_metal
        .inject_ssh_key(
            &env.get_ssh_public_key()
                .expect("Could not get SSH public key"),
        )
        .expect("Failed to inject SSH key");
    bare_metal
}

/// Creates a bare-metal nested node. Set `enable_trusted_execution_environment` when the host
/// runs AMD SEV-SNP (same meaning as the `TRUSTED_EXECUTION_ENVIRONMENT` env var in `setup()`).
pub fn create_bare_metal_node(
    bare_metal: &BareMetalIpmiSession,
    enable_trusted_execution_environment: bool,
) -> NestedNode {
    NestedNode::new_bare_metal(
        HOST_VM_NAME.to_string(),
        bare_metal.hostos_address(),
        bare_metal.mgmt_mac(),
        enable_trusted_execution_environment,
    )
}

/// Creates a `NestedNodes` with a single bare metal TEE (SEV-SNP) node.
pub fn create_bare_metal_tee_node(bare_metal: &BareMetalIpmiSession) -> NestedNode {
    create_bare_metal_node(bare_metal, true)
}

pub fn get_bare_metal_login_info() -> LoginInfo {
    let bare_metal_secrets_file = std::env::var(BARE_METAL_HOST_SECRETS)
        .expect("Could not read env var BARE_METAL_HOST_SECRETS");
    let bare_metal_secrets = std::fs::read_to_string(bare_metal_secrets_file)
        .expect("Could not read baremetal secrets file");
    bare_metal_deployment::parse_login_info_from_ini(&bare_metal_secrets)
        .expect("Failed to parse baremetal login info")
}

pub fn registration(env: TestEnv) {
    registration_with_timeout(env, NODE_REGISTRATION_TIMEOUT);
}

/// Allow the nested GuestOS to install and launch, and check that it can
/// successfully join the testnet.
pub fn registration_with_timeout(env: TestEnv, timeout: Duration) {
    let logger = env.logger();

    let initial_topology = env.topology_snapshot();

    // Keep track of the initial number of unassigned nodes.
    let initial_num_unassigned_nodes = initial_topology.unassigned_nodes().count();

    let nested_vms = env.get_all_nested_vms().unwrap();
    let n = nested_vms.len();

    // If the nodes are able to join successfully, the registry will be updated,
    // and the new node IDs will enter the unassigned pool.
    let mut new_topology = initial_topology;
    let expected_num_unassigned_nodes = initial_num_unassigned_nodes + n;
    retry_with_msg!(
        format!("Waiting for all {n} nodes to join ..."),
        logger.clone(),
        timeout,
        NODE_REGISTRATION_BACKOFF,
        || {
            new_topology = block_on(
                new_topology.block_for_newer_registry_version_within_duration(
                    timeout,
                    NODE_REGISTRATION_BACKOFF,
                ),
            )
            .unwrap();
            let num_unassigned_nodes = new_topology.unassigned_nodes().count();
            if num_unassigned_nodes == expected_num_unassigned_nodes {
                Ok(())
            } else {
                bail!("Expected {expected_num_unassigned_nodes} unassigned nodes, but found {num_unassigned_nodes}. Waiting for the rest to register ...");
            }
        }
    ).unwrap();
    info!(logger, "All {n} nodes successfully came up and registered.");
}
