// Set up a testnet containing:
//   one 1-node System subnet and a p8s (with grafana) VM.
// All replica nodes use the following resources: 64 vCPUs, 480GiB of RAM, and 500 GiB disk.
//
// You can setup this testnet by executing the following commands:
//
//   $ ./ci/tools/container-run.sh
//   $ bazel run //rs/tests/testnets:single_large_node --test_tmpdir=./single_large_node
//
// The --test_tmpdir=./single_large_node will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i single_large_node/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Note that you can get the $ipv6 address of the IC node from the farm_vm_created_events in the output.
//
// To get access to P8s and Grafana look for the following lines in the output:
//
//     prometheus: Prometheus Web UI at http://prometheus.single_large_node--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.single_large_node--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.single_large_node--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResourceOverrides,
};
use ic_system_test_driver::driver::test_env::TestEnv;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_resource_overrides(VmResourceOverrides {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .add_nodes(1),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}
