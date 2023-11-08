use std::str::FromStr;

use canister_test::PrincipalId;

use crate::driver::bootstrap::setup_and_start_nested_vms;
use crate::driver::farm::Farm;
use crate::driver::nested::{NestedNode, NestedVms};
use crate::driver::resource::{allocate_resources, get_resource_request_for_nested_nodes};
use crate::driver::test_env::HasIcPrepDir;
use crate::driver::test_env::{TestEnv, TestEnvAttribute};
use crate::driver::test_setup::GroupSetup;
use crate::driver::{ic::InternetComputer, test_env_api::*};
use crate::orchestrator::utils::rw_message::install_nns_and_check_progress;
use crate::util::{block_on, get_nns_node};
use ic_registry_subnet_type::SubnetType;

/// Prepare the environment for nested tests.
/// SetupOS -> HostOS -> GuestOS
pub fn config(env: TestEnv) {
    let logger = env.logger();
    let farm_url = env.get_farm_url().expect("Unable to get Farm url.");
    let farm = Farm::new(farm_url, logger.clone());
    let group_setup = GroupSetup::read_attribute(&env);
    let group_name: String = group_setup.farm_group_name;
    let principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();

    // Setup "testnet"
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_node_provider(principal)
        .with_node_operator(principal)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let nns_node = get_nns_node(&env.topology_snapshot());
    let nns_url = nns_node.get_public_url();
    let nns_public_key =
        std::fs::read_to_string(env.prep_dir("").unwrap().root_public_key_path()).unwrap();

    // Setup nested GuestOS
    let nodes = vec![NestedNode::new("host-1".to_string())];

    let res_request = get_resource_request_for_nested_nodes(&nodes, &env, &group_name, &farm)
        .expect("Failed to build resource request for nested test.");
    let res_group = allocate_resources(&farm, &res_request)
        .expect("Failed to allocate resources for nested test.");

    for (name, vm) in res_group.vms.iter() {
        env.write_nested_vm(name, vm)
            .expect("Unable to write nested VM.");
    }

    setup_and_start_nested_vms(&nodes, &env, &farm, &group_name, &nns_url, &nns_public_key)
        .expect("Unable to start nested VMs.");

    install_nns_and_check_progress(env.topology_snapshot());
}

/// Allow the nested GuestOS to install and launch, and check that it can
/// successfully join the testnet.
pub fn registration(env: TestEnv) {
    // Check that there are initially no unassigned nodes.
    let num_unassigned_nodes = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(1)),
    )
    .unwrap()
    .unassigned_nodes()
    .count();
    assert_eq!(num_unassigned_nodes, 0);

    // Wait for SetupOS to install
    std::thread::sleep(std::time::Duration::from_secs(10 * 60));

    // Check that this node joined successfully.
    let num_unassigned_nodes = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(2)),
    )
    .unwrap()
    .unassigned_nodes()
    .count();
    assert_eq!(num_unassigned_nodes, 1);
}
