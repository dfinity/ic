use ic_consensus_system_test_liveness_test_common::test;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::farm::HostFeature;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmAllocationStrategy,
    VmResources,
};
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use ic_types::malicious_behaviour::MaliciousBehaviour;

use anyhow::Result;

fn setup(env: TestEnv) {
    let resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(33560000)), // 32GiB
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };

    let malicious_behaviour =
        MaliciousBehaviour::new(true).set_maliciously_propose_equivocating_blocks();
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(11)
                .add_malicious_nodes(2, malicious_behaviour),
        )
        .with_required_host_features(vec![HostFeature::Performance])
        .with_default_vm_resources(resources)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.sync_with_prometheus();
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
