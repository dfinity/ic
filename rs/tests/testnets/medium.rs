// Set up a testnet containing:
//   one 4-node System and one 4-node Application subnets, one unassigned node, single API boundary node, single ic-gateway and a p8s (with grafana) VM.
// All replica nodes use the following resources: 6 vCPUs, 24GiB of RAM, and 50 GiB disk.
//
// You can setup this testnet with a lifetime of 180 mins by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create medium --lifetime-mins=180 --output-dir=./medium -- --test_tmpdir=./medium
//
// The --output-dir=./medium will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./medium will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i medium/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@
//
// Note that you can get the  address of the IC node from the ict console output:
//
//   {
//     "nodes": [
//       {
//         "id": "g47v4-zoq32-p47if-t7x33-2gz2d-jeypp-bbp4q-xyhbv-grdb7-gqbxv-zae",
//         "ipv6": "2a0b:21c0:4003:2:50a9:4bff:fe98:3df0"
//       },
//       {
//         "id": "2s2bb-usha5-fowjz-jyeyf-vejpo-n652p-q5kyg-52uqt-abtat-mkzg2-qqe",
//         "ipv6": "2a0b:21c0:4003:2:5045:c7ff:fe7a:c238"
//       },
//       {
//         "id": "3z3nq-pmhud-jqsxo-eg7fq-b763j-dhi4a-4s7m7-eq43u-t7eo4-md4rp-tae",
//         "ipv6": "2a0b:21c0:4003:2:503d:bbff:fe04:f06a"
//       },
//       {
//         "id": "roojr-se27p-d4o73-677xm-kq6v3-blmvv-mcqd4-zmwc7-6z2vf-5rp4w-dqe",
//         "ipv6": "2a0b:21c0:4003:2:5041:a0ff:fe67:99fa"
//       }
//     ],
//     "subnet_id": "uvyxl-j4r6h-whosj-53i5h-3xmm5-hceei-4mq4a-lpilk-bt3mq-dx4jp-4ae",
//     "subnet_type": "application"
//   }
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.medium--1692597750709.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.medium--1692597750709.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.medium--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10su0026from=now-5mu0026to=now,
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    ic_gateway_vm::{IC_GATEWAY_VM_NAME, IcGatewayVm},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, NnsCustomizations},
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(4))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(4))
        .with_unassigned_nodes(1)
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");
    env.sync_with_prometheus();
}
