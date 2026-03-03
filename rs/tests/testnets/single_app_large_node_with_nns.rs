// Set up a testnet containing:
//   one 1-node system subnet, one 1-node application subnet, and a p8s (with grafana) VM.
// The system node uses the following resources: 6 vCPUs, 24GiB of RAM, and 50 GiB disk.
// The application node uses the following resources: 64 vCPUs, 480GiB of RAM, and 500 GiB disk.
//
// You can setup this testnet by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create single_app_large_node_with_nns --output-dir=./single_app_large_node_with_nns -- --test_tmpdir=./single_app_large_node_with_nns
//
// The --output-dir=./single_app_large_node_with_nns will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./single_app_large_node_with_nns will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i single_app_large_node_with_nns/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
//
// Note that you can get the  address of the IC node from the ict console output:
//
//   {
//     "nodes": [
//       {
//         "id": "cih2o-jl3r2-wvb2k-qerwu-iup6c-ponia-3buxi-pjiaj-v6ecb-3edpk-uae",
//         "ipv6": "2a0b:21c0:4003:2:5077:f2ff:fe9b:c8ad"
//       }
//     ],
//     "subnet_id": "sjik6-qp5qz-ecosx-dve3n-s3pl4-kn2py-vvcmw-z3rdw-opd2j-kpsml-pqe",
//     "subnet_type": "system"
//   },
//   {
//     "nodes": [
//       {
//         "id": "oqacy-wgpnp-raef3-e4ca5-elarh-kqzxv-ma3lx-2hsnn-w6gca-dn44x-nae",
//         "ipv6": "2600:c00:2:100:509c:bff:fea4:8349"
//       }
//     ],
//     "subnet_id": "bb3h5-7e2gj-herzn-nksth-scfdv-dw6kg-ty72j-uf2ru-rvw2t-o5j7c-6qe",
//     "subnet_type": "application"
//   }
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.single_app_large_node_with_nns--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.single_app_large_node_with_nns--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.single_app_large_node_with_nns--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{HasTopologySnapshot, NnsCustomizations};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
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
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
}
