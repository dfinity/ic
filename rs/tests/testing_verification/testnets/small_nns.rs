// Set up a testnet similar to the "small" testnet containing:
// 1-node System and Application subnets, single unassigned node, single boundary node and a p8s (with grafana) VM.
// All nodes use the following resources: 4 vCPUs, 24GiB of RAM and 50 GiB disk.
//
// In addition to the "small" testnet this testnet additionally installs the NNS
// and the NNS and II frontend canisters.
//
// You can setup this testnet by executing the following commands:
//
//   $ gitlab-ci/container/container-run.sh
//   $ ict testnet small_nns -- --test_tmpdir=./small_nns
//
// The --test_tmpdir=./small_nns will store the test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i small_nns/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Note that you can get the $ipv6 address of the IC node by looking for a log line like:
//
//   Apr 11 15:34:10.175 INFO[rs/tests/src/driver/farm.rs:94:0]
//     VM(h2tf2-odxlp-fx5uw-kvn43-bam4h-i4xmw-th7l2-xxwvv-dxxpz-bs3so-iqe)
//     Host: ln1-dll10.ln1.dfinity.network
//     IPv6: 2a0b:21c0:4003:2:5051:85ff:feec:6864
//     vCPUs: 4
//     Memory: 25165824 KiB
//
// To get access to P8s and Grafana look for the following log lines:
//
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:168:0]
//     Prometheus Web UI at http://prometheus.small_nns--1681227226065.testnet.farm.dfinity.systems
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:169:0]
//     Grafana at http://grafana.small_nns--1681227226065.testnet.farm.dfinity.systems
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:170:0]
//     IC Progress Clock at http://grafana.small_nns--1681227226065.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now
//
// To access the NNS or II dapps look for the following log lines:
//
//   2023-05-03 11:06:27.948 INFO[setup:rs/tests/src/nns_dapp.rs:99:0]
//     Internet Identity: https://qhbym-qaaaa-aaaaa-aaafq-cai.ic0.farm.dfinity.systems
//   2023-05-03 11:06:27.948 INFO[setup:rs/tests/src/nns_dapp.rs:103:0]
//     NNS frontend dapp: https://qsgjb-riaaa-aaaaa-aaaga-cai.ic0.farm.dfinity.systems
//
// Happy testing!

use anyhow::Result;

use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::{
    boundary_node::BoundaryNode,
    group::SystemTestGroup,
    ic::{InternetComputer, Subnet},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{await_boundary_node_healthy, HasTopologySnapshot, NnsCanisterWasmStrategy},
};
use ic_tests::nns_dapp::{
    install_ii_and_nns_dapp, nns_dapp_customizations, set_authorized_subnets,
};
use ic_tests::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

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
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        nns_dapp_customizations(),
    );
    BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .allocate_vm(&env)
        .expect("Allocation of BoundaryNode failed.")
        .for_ic(&env, "")
        .use_real_certs_and_dns()
        .start(&env)
        .expect("failed to setup BoundaryNode VM");
    install_ii_and_nns_dapp(&env, BOUNDARY_NODE_NAME);
    set_authorized_subnets(&env);
    env.sync_prometheus_config_with_topology();
    await_boundary_node_healthy(&env, BOUNDARY_NODE_NAME);
}
