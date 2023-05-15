// Set up a testnet containing a p8s (with grafana) VM
// and a 1-node application subnet where the node uses the full resources of its host machine:
// 64 vCPUs, 488GiB of RAM and 500 GiB disk.
//
// You can setup this testnet by executing the following commands:
//
//   $ gitlab-ci/container/container-run.sh
//   $ ict testnet single_app_large_node -- --test_tmpdir=./single_app_large_node
//
// The --test_tmpdir=./single_app_large_node will store the test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i single_app_large_node/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Note that you can get the $ipv6 address of the IC node by looking for a log line like:
//
//   Apr 11 15:34:10.175 INFO[rs/tests/src/driver/farm.rs:94:0]
//     VM(h2tf2-odxlp-fx5uw-kvn43-bam4h-i4xmw-th7l2-xxwvv-dxxpz-bs3so-iqe)
//     Host: ln1-dll10.ln1.dfinity.network
//     IPv6: 2a0b:21c0:4003:2:5051:85ff:feec:6864
//     vCPUs: 64
//     Memory: 512142680 KiB
//
// To get access to P8s and Grafana look for the following log lines:
//
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:168:0]
//     Prometheus Web UI at http://prometheus.single_app_large_node--1681227226065.testnet.farm.dfinity.systems
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:169:0]
//     Grafana at http://grafana.single_app_large_node--1681227226065.testnet.farm.dfinity.systems
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:170:0]
//     IC Progress Clock at http://grafana.single_app_large_node--1681227226065.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now
//
// Happy benchmarking!

use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::group::SystemTestGroup;
use ic_tests::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_tests::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_tests::driver::test_env::TestEnv;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .add_nodes(1),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.sync_prometheus_config_with_topology();
}
