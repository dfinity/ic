use ic_protobuf::registry::subnet::v1::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    test_env_api::{
        get_current_branch_version, get_guestos_initial_launch_measurements,
        get_guestos_initial_update_img_sha256, get_guestos_initial_update_img_url,
        get_guestos_launch_measurements, get_guestos_update_img_sha256, get_guestos_update_img_url,
        get_mainnet_nns_revision,
    },
};
use ic_types::ReplicaVersion;
use os_qualification_utils::{
    ConfigurableApiBoundaryNodes, ConfigurableSubnet, ConfigurableUnassignedNodes, IcConfig,
    SubnetSimple,
    defs::QualificationExecutor,
    mock_env_variables,
    steps::{
        ensure_elected_version::EnsureElectedVersion,
        retire_elected_version::RetireElectedVersions,
        update_subnet_type::{UpdateApiBoundaryNodes, UpdateSubnetType},
        workload::{ApiBoundaryNodeWorkload, Workload},
        xnet::XNet,
    },
};
use std::time::Duration;

// 4 Hours
const OVERALL_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);

pub fn main() -> anyhow::Result<()> {
    // setup env variable for config
    let old_version = match std::env::var("OLD_VERSION") {
        Ok(v) => ReplicaVersion::try_from(v)?,
        Err(_) => get_mainnet_nns_revision()?,
    };
    let new_version = std::env::var("NEW_VERSION")
        .ok()
        .map(ReplicaVersion::try_from)
        .transpose()?;

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
    let (initial_version, target_version) = match &new_version {
        Some(new_version) => (old_version.clone(), new_version.clone()),
        None => (
            // Should be: 0000000000000000000000000000000000000000
            get_current_branch_version(),
            old_version.clone(),
        ),
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
        api_boundary_nodes: Some(ConfigurableApiBoundaryNodes::Simple(2)),
        // If both versions are specified its safe to start from
        // the old version. If we didn't specify the new version
        // it means that we are running from the tip of the branch
        // and images will not be present.
        initial_version: new_version.is_some().then_some(old_version),
        target_version: target_version.clone(),
    };

    // NOTE: This mocks the required IC OS image variables for testing.
    mock_env_variables(&config);

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
                            url: get_guestos_initial_update_img_url(),
                            sha256: get_guestos_initial_update_img_sha256(),
                            guest_launch_measurements: Some(
                                get_guestos_initial_launch_measurements(),
                            ),
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
                            version: target_version.clone(),
                            url: get_guestos_update_img_url(),
                            sha256: get_guestos_update_img_sha256(),
                            guest_launch_measurements: Some(get_guestos_launch_measurements()),
                        }),
                        // Ensure that application subnets are on the
                        // new version.
                        Box::new(UpdateSubnetType {
                            subnet_type: Some(SubnetType::Application),
                            version: target_version.clone(),
                        }),
                        // Ensure that system subnet is on the
                        // new version.
                        Box::new(UpdateSubnetType {
                            subnet_type: Some(SubnetType::System),
                            version: target_version.clone(),
                        }),
                        // Ensure that unassigned nodes are on the
                        // new version.
                        Box::new(UpdateSubnetType {
                            subnet_type: None,
                            version: target_version.clone(),
                        }),
                        // Ensure that the API boundary nodes are healthy and
                        // ensure that we can make one successful request for
                        // each type (status, query, update, read_state):
                        // API BN on "initial version" to replica on "target_version"
                        Box::new(ApiBoundaryNodeWorkload {}),
                        // Ensure that API boundary nodes are on the
                        // new version.
                        Box::new(UpdateApiBoundaryNodes {
                            version: target_version.clone(),
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
                        // API BN on "target_version" to replica on "target_version"
                        Box::new(ApiBoundaryNodeWorkload {}),
                        // Retire old version if it has disk-img
                        Box::new(RetireElectedVersions {
                            versions: vec![initial_version.clone()],
                        }),
                        // Ensure that the old version is blessed
                        // if it was retired previously
                        Box::new(EnsureElectedVersion {
                            version: initial_version.clone(),
                            url: get_guestos_initial_update_img_url(),
                            sha256: get_guestos_initial_update_img_sha256(),
                            guest_launch_measurements: Some(
                                get_guestos_initial_launch_measurements(),
                            ),
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
                        // API BN on "target_version" to replica on "initial version"
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
