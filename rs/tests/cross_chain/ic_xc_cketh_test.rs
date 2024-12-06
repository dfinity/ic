use anyhow::{anyhow, bail, Result};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, HasTopologySnapshot, IcNodeContainer, NnsCustomizations,
            SshSession,
        },
        universal_vm::{UniversalVm, UniversalVms},
    },
    systest,
};
use std::env;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_system_and_application_subnets)
        .add_test(systest!(ic_xc_cketh_test))
        .execute_from_args()?;
    Ok(())
}

fn setup_with_system_and_application_subnets(env: TestEnv) {
    foundry_config(env.clone());
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

fn ic_xc_cketh_test(env: TestEnv) {
    let logger = env.logger();
    let topology_snapshot = env.topology_snapshot();
}

fn foundry_config(env: TestEnv) {
    const UNIVERSAL_VM_NAME: &str = "foundry";

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_img(get_dependency_path(
            env::var("CKETH_UVM_CONFIG_PATH").expect("CKETH_UVM_CONFIG_PATH not set"),
        ))
        .start(&env)
        .expect("failed to setup universal VM");

    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let foundry_node_ipv6 = universal_vm.ipv6;

    println!(
        "{}",
        deployed_universal_vm
            .block_on_bash_script(&format!(
                r#"
# Run nginx auto proxy
docker load -i /config/foundry.tar
"#
            ))
            .unwrap()
    );
}
