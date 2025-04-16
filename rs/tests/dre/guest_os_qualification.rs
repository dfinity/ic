use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    test_env_api::{get_mainnet_nns_revision, read_dependency_from_env_to_string},
};
use os_qualification_utils::{
    defs::QualificationExecutor,
    steps::{
        ensure_elected_version::EnsureElectedVersion,
        retire_elected_version::RetireElectedVersions,
        update_subnet_type::{UpdateApiBoundaryNodes, UpdateSubnetType},
        workload::{ApiBoundaryNodeWorkload, Workload},
        xnet::XNet,
    },
    ConfigurableApiBoundaryNodes, ConfigurableSubnet, ConfigurableUnassignedNodes, IcConfig,
    SubnetSimple,
};
use std::time::Duration;

// 4 Hours
const OVERALL_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);

pub fn main() -> anyhow::Result<()> {
    // setup env variable for config
    let old_version = match std::env::var("OLD_VERSION") {
        Ok(v) => v,
        Err(_) => get_mainnet_nns_revision(),
    };
    let new_version = std::env::var("NEW_VERSION").ok();

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
        api_boundary_nodes: Some(ConfigurableApiBoundaryNodes::Simple(2)),
        // If both versions are specified its safe to start from
        // the old version. If we didn't specify the new version
        // it means that we are running from the tip of the branch
        // and images will not be present.
        initial_version: new_version.is_some().then_some(old_version.clone()),
    };

    // If both versions are specified do:
    //  1. upgrade
    //  2. testing
    //  3. downgrade
    //  4. testing
    // If only old version is specified:
    //  1. downgrade
    //  2. testing
    //  3. upgrade
    //  4. testing
    let (initial_version, to_version) = match new_version {
        Some(new_version) => (old_version, new_version),
        None => (
            // Should be: 0000000000000000000000000000000000000000
            read_dependency_from_env_to_string("ENV_DEPS__IC_VERSION_FILE")?,
            old_version,
        ),
    };

    SystemTestGroup::new()
        .with_timeout_per_test(OVERALL_TIMEOUT)
        .with_setup(|env| os_qualification_utils::setup(env, config))
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
                        Box::new(EnsureElectedVersion {
                            version: initial_version.clone(),
                        }),
                        // Ensure that application subnets are on the
                        // initial version. As the step above, this
                        // should always be true
                        Box::new(UpdateSubnetType {
                            subnet_type: Some(SubnetType::Application),
                            version: initial_version.clone(),
                        }),
                        // Ensure that system subnet is on the
                        // initial version. As the step above, this
                        // should always be true
                        Box::new(UpdateSubnetType {
                            subnet_type: Some(SubnetType::System),
                            version: initial_version.clone(),
                        }),
                        // Ensure that unassigned nodes are on the
                        // initial version. As the step above, this
                        // should always be true
                        Box::new(UpdateSubnetType {
                            subnet_type: None,
                            version: initial_version.clone(),
                        }),
                        // Ensure that API boundary nodes are on the
                        // initial version. As the step above, this
                        // should always be true
                        Box::new(UpdateApiBoundaryNodes {
                            version: initial_version.clone(),
                        }),
                        // Ensure that the new version is blessed
                        Box::new(EnsureElectedVersion {
                            version: to_version.clone(),
                        }),
                        // Ensure that application subnets are on the
                        // new version.
                        Box::new(UpdateSubnetType {
                            subnet_type: Some(SubnetType::Application),
                            version: to_version.clone(),
                        }),
                        // Ensure that system subnet is on the
                        // new version.
                        Box::new(UpdateSubnetType {
                            subnet_type: Some(SubnetType::System),
                            version: to_version.clone(),
                        }),
                        // Ensure that unassigned nodes are on the
                        // new version.
                        Box::new(UpdateSubnetType {
                            subnet_type: None,
                            version: to_version.clone(),
                        }),
                        // Ensure that the API boundary nodes are healthy and
                        // ensure that we can make one successful request for
                        // each type (status, query, update, read_state):
                        // API BN on "initial version" to replica on "to version"
                        Box::new(ApiBoundaryNodeWorkload {}),
                        // Ensure that API boundary nodes are on the
                        // new version.
                        Box::new(UpdateApiBoundaryNodes {
                            version: to_version.clone(),
                        }),
                        // Run workload tests
                        // Maps to `rs/tests/consensus/consensus_performance.rs` small
                        Box::new(Workload {
                            message_size: 1_000,
                            rps: 500.0,
                        }),
                        // Run xnet tests
                        // uses `rs/tests/src/message_routing/global_reboot_test`
                        Box::new(XNet::default()),
                        // Ensure that the API boundary nodes are healthy and
                        // ensure that we can make one successful request for
                        // each type (status, query, update, read_state):
                        // API BN on "to version" to replica on "to version"
                        Box::new(ApiBoundaryNodeWorkload {}),
                        // Retire old version if it has disk-img
                        Box::new(RetireElectedVersions {
                            versions: vec![initial_version.clone()],
                        }),
                        // Ensure that the old version is blessed
                        // if it was retired previously
                        Box::new(EnsureElectedVersion {
                            version: initial_version.clone(),
                        }),
                        // Downgrade to the inital version
                        Box::new(UpdateSubnetType {
                            subnet_type: Some(SubnetType::Application),
                            version: initial_version.clone(),
                        }),
                        Box::new(UpdateSubnetType {
                            subnet_type: Some(SubnetType::System),
                            version: initial_version.clone(),
                        }),
                        Box::new(UpdateSubnetType {
                            subnet_type: None,
                            version: initial_version.clone(),
                        }),
                        // Ensure that the API boundary nodes are healthy and
                        // ensure that we can make one successful request for
                        // each type (status, query, update, read_state):
                        // API BN on "to version" to replica on "initial version"
                        Box::new(ApiBoundaryNodeWorkload {}),
                        // Downgrade the API Boundary Nodes to the inital version
                        Box::new(UpdateApiBoundaryNodes {
                            version: initial_version.clone(),
                        }),
                        // Run workload tests again
                        // Maps to `rs/tests/consensus/consensus_performance.rs` small
                        Box::new(Workload {
                            message_size: 1_000,
                            rps: 500.0,
                        }),
                        // Run xnet tests
                        Box::new(XNet::default()),
                    ],
                );
                qualifier.qualify(env).expect("Failed to qualify")
            },
        ))
        .execute_from_args()
}
