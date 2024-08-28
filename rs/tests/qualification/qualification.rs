use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    test_env_api::{read_dependency_from_env_to_string, read_dependency_to_string},
};
use ic_tests::qualification::{
    defs::QualificationExecutor,
    steps::{
        ensure_blessed_version::EnsureBlessedVersion,
        retire_blessed_version::RetireBlessedVersions, update_subnet_type::UpdateSubnetType,
    },
    ConfigurableSubnet, ConfigurableUnassignedNodes, IcConfig, SubnetSimple,
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
        initial_version: Some(initial_version.clone()),
    };

    let to_version = match std::env::var("TO_VERSION") {
        Ok(v) => v,
        Err(_) => read_dependency_from_env_to_string("ENV_DEPS__IC_VERSION_FILE").map_err(|_| anyhow::anyhow!("Didn't find version being qualified specified in `ENV_DEPS__IC_VERSION_FILE` nur in `TO_VERSION` env variable"))?,
    };

    SystemTestGroup::new()
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_setup(|env| ic_tests::qualification::setup(env, config))
        .add_test(ic_system_test_driver::driver::dsl::TestFunction::new(
            "qualification",
            move |env| {
                let qualifier = QualificationExecutor::new(
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(16)
                        .max_blocking_threads(16)
                        .enable_all()
                        .build()
                        .expect("Should be able to build runtime"),
                    vec![
                        // Ensure that the initial version is blessed
                        // Since we are using our config this should
                        // always be the case.
                        Box::new(EnsureBlessedVersion {
                            version: initial_version.clone(),
                        }),
                        // Ensure that application subnets are on the
                        // initial version. As the step above, this
                        // should always be true
                        Box::new(UpdateSubnetType {
                            subnet_type: SubnetType::Application,
                            version: initial_version.clone(),
                        }),
                        // Ensure that system subnet is on the
                        // initial version. As the step above, this
                        // should always be true
                        Box::new(UpdateSubnetType {
                            subnet_type: SubnetType::System,
                            version: initial_version.clone(),
                        }),
                        // Ensure that the new version is blessed
                        Box::new(EnsureBlessedVersion {
                            version: to_version.clone(),
                        }),
                        // Ensure that application subnets are on the
                        // new version.
                        Box::new(UpdateSubnetType {
                            subnet_type: SubnetType::Application,
                            version: to_version.clone(),
                        }),
                        // Ensure that system subnet is on the
                        // new version.
                        Box::new(UpdateSubnetType {
                            subnet_type: SubnetType::System,
                            version: to_version.clone(),
                        }),
                        // Retire the initial versions because
                        // it used a disk-img
                        Box::new(RetireBlessedVersions {
                            versions: vec![initial_version.clone()],
                        }),
                        // Re-bless the initial version with
                        // update-imgs
                        Box::new(EnsureBlessedVersion {
                            version: initial_version.clone(),
                        }),
                        // Downgrade to the inital version
                        Box::new(UpdateSubnetType {
                            subnet_type: SubnetType::Application,
                            version: initial_version.clone(),
                        }),
                        Box::new(UpdateSubnetType {
                            subnet_type: SubnetType::System,
                            version: initial_version.clone(),
                        }),
                    ],
                );
                qualifier.qualify(env).expect("Failed to qualify")
            },
        ))
        .execute_from_args()
}
