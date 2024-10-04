// This is a template showing how to run performance tests. Once a specific metric of interest
// is identified, one can create a separate test that displays it in a reproducible manner.
// For example throughput_with_small_messages.rs or throughput_with_large_messages.rs.
//
// Set up a testnet for interactive performance testing allocated in our performance DC (dm1):
// 26-node System subnet, single boundary node and a p8s (with grafana) VM.
// All nodes use the following resources: 64 vCPUs, 488GiB of RAM and 500 GiB disk.
//
// This test additionally installs the NNS.
//
// You can setup this test by executing the following commands:
//
//   $ ci/container/container-run.sh
//   $ ict test consensus_performance_colocate --keepalive -- --test_tmpdir=./performance
//
// The --test_tmpdir=./performance will store the test output in the specified directory.
// This is useful to have access to in case you need to SSH into an IC node for example like:
//
//   $ ssh -i performance/_tmp/*/setup/ssh/authorized_priv_keys/admin admin@$ipv6
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
//     Prometheus Web UI at http://prometheus.performance--1681227226065.testnet.farm.dfinity.systems
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:170:0]
//     IC Progress Clock at http://grafana.performance--1681227226065.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now
//   Apr 11 15:33:58.903 INFO[rs/tests/src/driver/prometheus_vm.rs:169:0]
//     Grafana at http://grafana.performance--1681227226065.testnet.farm.dfinity.systems
//
// To access the NNS or II dapps look for the following log lines:
//
//   2023-05-03 11:06:27.948 INFO[setup:rs/tests/src/nns_dapp.rs:99:0]
//     Internet Identity: https://qhbym-qaaaa-aaaaa-aaafq-cai.ic0.farm.dfinity.systems
//   2023-05-03 11:06:27.948 INFO[setup:rs/tests/src/nns_dapp.rs:103:0]
//     NNS frontend dapp: https://qsgjb-riaaa-aaaaa-aaaga-cai.ic0.farm.dfinity.systems
//
// Happy testing!

use ic_consensus_system_test_utils::performance::persist_metrics;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::dsl::TestFunction;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::simulate_network::ProductionSubnetTopology;
use ic_system_test_driver::driver::test_env_api::read_dependency_from_env_to_string;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    simulate_network::{FixedNetworkSimulation, SimulateNetwork},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, NnsCustomizations},
};
use ic_system_test_driver::util::get_app_subnet_and_node;
use ic_types::Height;

use anyhow::Result;
use slog::info;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

const MAX_RUNTIME_THREADS: usize = 64;
const MAX_RUNTIME_BLOCKING_THREADS: usize = MAX_RUNTIME_THREADS;

const NODES_COUNT: usize = 13;
const DKG_INTERVAL: u64 = 999;
// Network parameters
const PRODUCTION_SUBNET_TO_SIMULATE: ProductionSubnetTopology = ProductionSubnetTopology::LHG73;
const BANDWIDTH_MBITS: u32 = 300; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(200); // artificial added latency
const FIXED_NETWORK_SIMULATION: FixedNetworkSimulation = FixedNetworkSimulation::new()
    .with_latency(LATENCY)
    .with_bandwidth(BANDWIDTH_MBITS);
const USE_FIXED_NETWORK_SIMULATION: bool = true;

fn setup(env: TestEnv) {
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("Failed to start prometheus VM");
    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512142680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(VmResources {
                    vcpus: Some(NrOfVCPUs::new(64)),
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                // Force to use [`ic_limits::INITIAL_NOTARY_DELAY_APP_SUBNET`], otherwise for
                // subnets of size larger than [`ic_limits::SMALL_APP_SUBNET_MAX_SIZE`] we would
                // use [`ic_limits::INITIAL_NOTARY_DELAY_NNS_SUBNET].
                .with_initial_notary_delay(ic_limits::INITIAL_NOTARY_DELAY_APP_SUBNET)
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );
    env.sync_with_prometheus();

    let topology_snapshot = env.topology_snapshot();
    let (app_subnet, _) = get_app_subnet_and_node(&topology_snapshot);

    if USE_FIXED_NETWORK_SIMULATION {
        app_subnet.apply_network_settings(FIXED_NETWORK_SIMULATION);
    } else {
        app_subnet.apply_network_settings(PRODUCTION_SUBNET_TO_SIMULATE);
    }
}

fn test(env: TestEnv, message_size: usize, rps: f64) {
    let logger = env.logger();

    // create the runtime that lives until this variable is dropped.
    info!(
        env.logger(),
        "Set tokio runtime: worker_threads={}, blocking_threads={}",
        MAX_RUNTIME_THREADS,
        MAX_RUNTIME_BLOCKING_THREADS
    );
    let rt: Runtime = Builder::new_multi_thread()
        .worker_threads(MAX_RUNTIME_THREADS)
        .max_blocking_threads(MAX_RUNTIME_BLOCKING_THREADS)
        .enable_all()
        .build()
        .unwrap();

    let test_metrics = ic_consensus_system_test_utils::performance::test_with_rt_handle(
        env,
        message_size,
        rps,
        rt.handle().clone(),
        true,
    )
    .unwrap();
    if cfg!(feature = "upload_perf_systest_results") {
        let branch_version = read_dependency_from_env_to_string("ENV_DEPS__IC_VERSION_FILE")
            .expect("tip-of-branch IC version");

        rt.block_on(persist_metrics(
            branch_version,
            test_metrics,
            message_size,
            rps,
            &logger,
        ));
    }
}

fn test_case(test_name: &str, ingress_message_size: usize, rps: f64) -> TestFunction {
    TestFunction::new(test_name, move |env| test(env, ingress_message_size, rps))
}

#[allow(dead_code)]
fn download_prometheus_data(env: TestEnv) {
    env.download_prometheus_data_dir_if_exists();
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        // Since we setup VMs in sequence it takes more than the default timeout
        // of 10 minutes to setup this large testnet so let's increase the timeout:
        .with_timeout_per_test(Duration::from_secs(60 * 30))
        .with_setup(setup)
        .add_test(test_case("few_small_messages", 1, 1.0))
        .add_test(test_case("many_small_messages", 4_000, 500.0))
        .add_test(test_case("large_messages", 950_000, 4.0))
        // Uncomment this to download the prometheus data.
        // To see the grafana dashboard first locate the `prometheus-data-dir.tar.zst` file in the
        // test output directory and then run the `/ic/rs/tests/run-p8s.sh` script.
        //.add_test(systest!(download_prometheus_data))
        .execute_from_args()?;
    Ok(())
}
