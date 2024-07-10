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
//   $ gitlab-ci/container/container-run.sh
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

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::consensus::consensus_performance_test::{custom_message_test, setup};

use anyhow::Result;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        // Since we setup VMs in sequence it takes more than the default timeout
        // of 10 minutes to setup this large testnet so let's increase the timeout:
        .with_timeout_per_test(Duration::from_secs(60 * 30))
        .with_setup(setup)
        .add_test(systest!(custom_message_test))
        .execute_from_args()?;
    Ok(())
}
