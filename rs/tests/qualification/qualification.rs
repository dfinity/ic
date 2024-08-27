use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    test_env_api::{read_dependency_from_env_to_string, read_dependency_to_string},
};
use ic_tests::qualification::{
    defs::QualificationExecutorBuilder, ConfigurableSubnet, ConfigurableUnassignedNodes, IcConfig,
    SubnetSimple,
};
use std::time::Duration;

// 2 Hours
const OVERALL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

pub fn main() -> anyhow::Result<()> {
    // setup env variable for config
    let initial_version = match std::env::var("INITIAL_VERSION") {
        Ok(v) => v,
        Err(_) => read_dependency_to_string("testnet/mainnet_nns_revision.txt").map_err(|_| anyhow::anyhow!("Didn't find initial version specified in `testnet/mainnet_nns_revision.txt` nur in `INITIAL_VERSION` env variable"))?,
    };

    let qualifier = QualificationExecutorBuilder::default()
        .with_from_version(&initial_version)
        .with_to_version(read_dependency_from_env_to_string(
            "ENV_DEPS__IC_VERSION_FILE",
        )?)
        .build()?;

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
        .with_setup(|env| ic_tests::qualification::setup(env, config))
        .add_test(ic_system_test_driver::driver::dsl::TestFunction::new(
            "qualification",
            move |env| qualifier.qualify(env).expect("Failed to qualify"),
        ))
        .execute_from_args()
}
