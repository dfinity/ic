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
//   $ ict test consensus_performance_colocate --keepalive -- --test_tmpdir=./performance --test_env DOWNLOAD_P8S_DATA=1
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
// To inspect the metrics after the test has finished, exit the dev container
// and run a local p8s and Grafana on the downloaded p8s data directory using:
//
//   $ rs/tests/run-p8s.sh --grafana-dashboards-dir ~/k8s/bases/apps/ic-dashboards performance/_tmp/*/setup/colocated_test/tests/test/universal_vms/prometheus/prometheus-data-dir.tar.zst
//
// Note this this script requires Nix so make sure it's installed (https://nixos.org/download/).
// The script also requires a local clone of https://github.com/dfinity-ops/k8s containing the Grafana dashboards.
//
// Then, on your laptop, forward the Grafana port 3000 to your devenv:
//
//   $ ssh devenv -L 3000:localhost:3000 -N
//
// and load http://localhost:3000/ in your browser to inspect the dashboards.
//
// To access the NNS or II dapps look for the following log lines:
//
//   2023-05-03 11:06:27.948 INFO[setup:rs/tests/src/nns_dapp.rs:99:0]
//     Internet Identity: https://qhbym-qaaaa-aaaaa-aaafq-cai.ic0.farm.dfinity.systems
//   2023-05-03 11:06:27.948 INFO[setup:rs/tests/src/nns_dapp.rs:103:0]
//     NNS frontend dapp: https://qsgjb-riaaa-aaaaa-aaaga-cai.ic0.farm.dfinity.systems
//
// Happy testing!

use ic_consensus_system_test_utils::performance::{persist_metrics, setup_jaeger_vm};
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::get_current_branch_version;
use ic_system_test_driver::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::HasPrometheus,
    simulate_network::{FixedNetworkSimulation, SimulateNetwork},
    test_env::TestEnv,
    test_env_api::{HasTopologySnapshot, NnsCustomizations},
};
use ic_system_test_driver::systest;
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
const BANDWIDTH_MBITS: u32 = 300; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(150); // artificial added latency
const NETWORK_SIMULATION: FixedNetworkSimulation = FixedNetworkSimulation::new()
    .with_latency(LATENCY)
    .with_bandwidth(BANDWIDTH_MBITS);

/// When set to `true` a [Jaeger](https://www.jaegertracing.io/) instance will be spawned.
/// Look for "Jaeger frontend available at: $URL" in the logs and follow the link to visualize &
/// analyze traces.
const SHOULD_SPAWN_JAEGER_VM: bool = false;

fn setup(env: TestEnv) {
    let mut ic_builder = InternetComputer::new();

    if SHOULD_SPAWN_JAEGER_VM {
        let jaeger_ipv6 = setup_jaeger_vm(&env);
        ic_builder = ic_builder.with_jaeger_addr(std::net::SocketAddr::new(
            std::net::IpAddr::V6(jaeger_ipv6),
            4317,
        ));
    }

    ic_builder
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
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );

    let topology_snapshot = env.topology_snapshot();
    let (app_subnet, _) = get_app_subnet_and_node(&topology_snapshot);

    app_subnet.apply_network_settings(NETWORK_SIMULATION);
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
        let branch_version = get_current_branch_version();

        rt.block_on(persist_metrics(
            branch_version,
            test_metrics,
            message_size,
            rps,
            LATENCY,
            BANDWIDTH_MBITS * 1_000_000,
            NODES_COUNT,
            &logger,
        ));
    }
}

fn test_few_small_messages(env: TestEnv) {
    test(env, 1, 1.0)
}

fn test_small_messages(env: TestEnv) {
    test(env, 4_000, 500.0)
}

fn test_few_large_messages(env: TestEnv) {
    test(env, 1_999_000, 1.0)
}

fn test_large_messages(env: TestEnv) {
    test(env, 950_000, 4.0)
}

fn teardown(env: TestEnv) {
    let should_download_prometheus_data =
        std::env::var("DOWNLOAD_P8S_DATA").is_ok_and(|v| v == "true" || v == "1");
    if should_download_prometheus_data {
        env.download_prometheus_data_dir_if_exists();
        env.emit_report(String::from(
            "Downloaded prometheus data to 'prometheus-data-dir.tar.zst' in the test output \
            directory. You can now use `rs/tests/run-p8s.sh` script to play with the metrics",
        ));
    } else {
        env.emit_report(String::from(
            "Not downloading the prometheus data. \
            If you want to download it on the next test run, \
            please pass `--test_env DOWNLOAD_P8S_DATA=1` as an argument to the `ict` command",
        ));
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        // Since we setup VMs in sequence it takes more than the default timeout
        // of 10 minutes to setup this large testnet so let's increase the timeout:
        .with_timeout_per_test(Duration::from_secs(60 * 30))
        .with_setup(setup)
        .add_test(systest!(test_few_small_messages))
        .add_test(systest!(test_small_messages))
        .add_test(systest!(test_few_large_messages))
        .add_test(systest!(test_large_messages))
        .with_teardown(teardown)
        .execute_from_args()?;
    Ok(())
}
