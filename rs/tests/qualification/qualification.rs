use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_tests::qualification_setup::{
    ConfigurableSubnet, ConfigurableUnassignedNodes, IcConfig, SubnetSimple,
};
use std::time::Duration;

// 2 Hours
const OVERALL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

pub fn main() -> anyhow::Result<()> {
    // setup env variable for config
    let initial_version = std::env::var("INITIAL_VERSION")?;

    let config = IcConfig {
        subnets: Some(vec![
            ConfigurableSubnet::Simple(SubnetSimple {
                subnet_type: ic_registry_subnet_type::SubnetType::System,
                num_nodes: 4,
            }),
            ConfigurableSubnet::Simple(SubnetSimple {
                subnet_type: ic_registry_subnet_type::SubnetType::Application,
                num_nodes: 4,
            }),
            ConfigurableSubnet::Simple(SubnetSimple {
                subnet_type: ic_registry_subnet_type::SubnetType::Application,
                num_nodes: 4,
            }),
        ]),
        unassigned_nodes: Some(ConfigurableUnassignedNodes::Simple(4)),
        boundary_nodes: None,
        initial_version: Some(initial_version),
    };

    SystemTestGroup::new()
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_setup(|env| ic_tests::qualification_setup::setup(env, config))
        .execute_from_args()
}
