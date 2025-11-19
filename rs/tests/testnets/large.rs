// Set up a testnet containing:
//   one 4-node System, one 4-node Application, and one 1-node Application subnets, a single API boundary node, single ic-gateway/s and a p8s (with grafana) VM.
// All replica nodes use the following resources: 64 vCPUs, 480GiB of RAM, and 2,000 GiB disk.
//
// You can setup this testnet with a lifetime of 180 mins by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ ict testnet create large --lifetime-mins=180 --output-dir=./large -- --test_tmpdir=./large
//
// The --output-dir=./large will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./large will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i large/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
//
// Note that you can get the $ipv6 address of the IC node from the ict console output:
//
//   {
//     "nodes": [
//       {
//         "id": "y4g5e-dpl4n-swwhv-la7ec-32ngk-w7f3f-pr5bt-kqw67-2lmfy-agipc-zae",
//         "ipv6": "2a0b:21c0:4003:2:5034:46ff:fe3c:e76f"
//       },
//       {
//         "id": "df2nt-xpdbh-kekha-igdy2-t2amw-ui36p-dqrte-ojole-syd4u-sfhqz-3ae",
//         "ipv6": "2a0b:21c0:4003:2:50d2:3ff:fe24:32fe"
//       }
//     ],
//     "subnet_id": "5hv4k-srndq-xgw53-r6ldt-wtv4x-6xvbj-6lvpf-sbu5n-sqied-63bgv-eqe",
//     "subnet_type": "application"
//   },
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     "prometheus": "Prometheus Web UI at http://prometheus.large--1692597750709.testnet.farm.dfinity.systems",
//     "grafana": "Grafana at http://grafana.large--1692597750709.testnet.farm.dfinity.systems",
//     "progress_clock": "IC Progress Clock at http://grafana.large--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s\u0026from=now-5m\u0026to=now",
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_system_test_driver::driver::ic_gateway_vm::{HasIcGatewayVm, IcGatewayVm};
use ic_system_test_driver::driver::{
    group::SystemTestGroup,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, IcNodeContainer},
};
use ic_system_test_driver::sns_client::add_all_wasms_to_sns_wasm;
use nns_dapp::{
    install_ii_nns_dapp_and_subnet_rental, install_sns_aggregator, nns_dapp_customizations,
    set_authorized_subnets, set_sns_subnet,
};

const NUM_FULL_CONSENSUS_APP_SUBNETS: u64 = 1;
const NUM_SINGLE_NODE_APP_SUBNETS: u64 = 1;
const NUM_IC_GATEWAYS: u64 = 1;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    // start p8s for metrics and dashboards
    PrometheusVm::default()
        .start(&env)
        .expect("Failed to start prometheus VM");
    // set up IC overriding the default resources to be more powerful
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(480 << 20)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(2000)),
    };
    let mut ic = InternetComputer::new()
        .with_api_boundary_nodes(1)
        .with_default_vm_resources(vm_resources);
    ic = ic.add_subnet(Subnet::new(SubnetType::System).add_nodes(4));
    for _ in 0..NUM_FULL_CONSENSUS_APP_SUBNETS {
        ic = ic.add_subnet(Subnet::new(SubnetType::Application).add_nodes(4));
    }
    for _ in 0..NUM_SINGLE_NODE_APP_SUBNETS {
        ic = ic.add_subnet(Subnet::new(SubnetType::Application).add_nodes(1));
    }
    ic.setup_and_start(&env)
        .expect("Failed to setup IC under test");

    // set up NNS canisters
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        nns_dapp_customizations(),
    );

    set_authorized_subnets(&env);

    // deploys the ic-gateway/s
    for i in 0..NUM_IC_GATEWAYS {
        let ic_gatway_name = format!("ic-gateway-{i}");
        IcGatewayVm::new(&ic_gatway_name)
            .start(&env)
            .expect("failed to setup ic-gateway");
    }
    let ic_gateway = env.get_deployed_ic_gateway("ic-gateway-0").unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();
    let ic_gateway_domain = ic_gateway_url.domain().unwrap();
    env.sync_with_prometheus_by_name("", Some(ic_gateway_domain.to_string()));

    // pick an SNS subnet among the application subnets
    let topology = env.topology_snapshot();
    let mut app_subnets = topology
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application);
    let sns_subnet = app_subnets.next().unwrap();

    // install the SNS aggregator canister onto the SNS subnet
    let sns_node = sns_subnet.nodes().next().unwrap();
    let sns_aggregator_canister_id = install_sns_aggregator(&env, &ic_gateway_url, sns_node);

    // register the SNS subnet with the NNS
    set_sns_subnet(&env, sns_subnet.subnet_id);

    // upload SNS canister WASMs to the SNS-W canister
    add_all_wasms_to_sns_wasm(&env);

    // install II, NNS dapp, and Subnet Rental Canister
    install_ii_nns_dapp_and_subnet_rental(&env, &ic_gateway_url, Some(sns_aggregator_canister_id));
}
