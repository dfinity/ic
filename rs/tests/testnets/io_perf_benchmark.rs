// This test is designed for scenarios where high IO performance is essential.
// It leverages dedicated performance hosts with LVM partitions composed of multiple high-performance SSDs, mirroring production environments.
// Specify the hosts via the PERF_HOSTS environment variable; each listed host will be allocated to a replica node.
//
// Set up a testnet containing:
//   one System subnet with the hosts specified in the PERF_HOSTS environment variable,
//   a single API boundary node, single ic-gateway/s and a p8s (with grafana) VM.
// All replica nodes use the following resources: 64 vCPUs, 480GiB of RAM, and 5 TiB disk.
//
// You can setup this testnet with a lifetime of 180 mins by executing the following commands:
//
//   $ ./ci/tools/docker-run
//   $ PERF_HOSTS="dm1-dll29.dm1.dfinity.network" ict testnet create io_perf_benchmark --lifetime-mins=1440 --output-dir=./io_perf_benchmark -- --test_tmpdir=./io_perf_benchmark --test_env=PERF_HOSTS
//
// The --output-dir=./io_perf_benchmark will store the debug output of the test driver in the specified directory.
// The --test_tmpdir=./io_perf_benchmark will store the remaining test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i io_perf_benchmark/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
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
//     "subnet_type": "system"
//   },
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     "prometheus": "Prometheus Web UI at http://prometheus.io_perf_benchmark--1692597750709.testnet.farm.dfinity.systems",
//     "grafana": "Grafana at http://grafana.io_perf_benchmark--1692597750709.testnet.farm.dfinity.systems",
//     "progress_clock": "IC Progress Clock at http://grafana.io_perf_benchmark--1692597750709.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s\u0026from=now-5m\u0026to=now",
//
// Happy testing!

use anyhow::Result;

use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_system_test_driver::driver::ic_gateway_vm::{HasIcGatewayVm, IcGatewayVm};
use ic_system_test_driver::driver::pot_dsl::PotSetupFn;
use ic_system_test_driver::driver::vector_vm::VectorVm;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    group::SystemTestGroup,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::HasTopologySnapshot,
};
use nns_dapp::{nns_dapp_customizations, set_authorized_subnets, set_icp_xdr_exchange_rate};
use slog::info;

const NUM_IC_GATEWAYS: u64 = 1;
const DEFAULT_IMAGE_SIZE_GIB: u64 = 5120;

fn main() -> Result<()> {
    // No default value is set for PERF_HOSTS to ensure users consciously select dedicated performance hosts and understand their significance.
    let perf_hosts = std::env::var("PERF_HOSTS").unwrap_or_else(|_| {
        panic!("PERF_HOSTS environment variable must be set (comma-separated list of host names)")
    });

    // By default, the image size is set to 5 TiB, which supports testing up to 2 TiB of state under heavy write workloads.
    // Note: Migrating such a large image to the LVM partition on the hosts can be time-consuming.
    // To use a different image size, set the IMAGE_SIZE_GIB environment variable.
    let image_size_gib = std::env::var("IMAGE_SIZE_GIB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_IMAGE_SIZE_GIB);

    let perf_hosts: Vec<String> = perf_hosts.split(',').map(|s| s.to_string()).collect();
    let config = Config::new(perf_hosts, image_size_gib);

    SystemTestGroup::new()
        .with_setup(config.build())
        .execute_from_args()?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Config {
    hosts: Vec<String>,
    image_size_gib: u64,
}

impl Config {
    pub fn new(hosts: Vec<String>, image_size_gib: u64) -> Config {
        Config {
            hosts,
            image_size_gib,
        }
    }

    /// Builds the IC instance.
    pub fn build(self) -> impl PotSetupFn {
        move |env: TestEnv| setup(env, self)
    }
}

pub fn setup(env: TestEnv, config: Config) {
    // start p8s for metrics and dashboards
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("Failed to start prometheus VM");
    let mut vector_vm = VectorVm::new().with_required_host_features(vec![HostFeature::Performance]);
    vector_vm.start(&env).expect("Failed to start Vector VM");

    // set up IC overriding the default resources to be more powerful
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(config.image_size_gib)),
    };
    let mut ic = InternetComputer::new()
        .with_api_boundary_nodes(1)
        .with_default_vm_resources(vm_resources);
    let mut subnet = Subnet::new(SubnetType::System);
    let logger = env.logger();
    info!(
        logger,
        "Adding {} nodes with hosts: {:?}",
        config.hosts.len(),
        config.hosts
    );
    for host in config.hosts.iter() {
        subnet = subnet.add_node_with_required_host_features(vec![HostFeature::Host(host.clone())]);
    }
    ic = ic.add_subnet(subnet);

    ic.setup_and_start(&env)
        .expect("Failed to setup IC under test");

    // set up NNS canisters
    // Installing the NNS canisters enables submitting proposals to upgrade the replica version without needing to redeploy the testnet.
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        nns_dapp_customizations(),
    );

    // sets the exchange rate to 12 XDR per 1 ICP
    set_icp_xdr_exchange_rate(&env, 12_0000);

    // sets the exchange rate to 12 XDR per 1 ICP
    set_authorized_subnets(&env);

    // deploys the ic-gateway/s
    for i in 0..NUM_IC_GATEWAYS {
        let ic_gateway_name = format!("ic-gateway-{}", i);
        IcGatewayVm::new(&ic_gateway_name)
            .with_required_host_features(vec![HostFeature::Performance])
            .start(&env)
            .expect("failed to setup ic-gateway");
    }
    let ic_gateway = env.get_deployed_ic_gateway("ic-gateway-0").unwrap();
    let ic_gateway_url = ic_gateway.get_public_url();
    let ic_gateway_domain = ic_gateway_url.domain().unwrap();
    env.sync_with_prometheus_by_name("", Some(ic_gateway_domain.to_string()));
    vector_vm
        .sync_targets(&env)
        .expect("Failed to sync Vector targets");
}
