// This test displays in Grafana the update requests throughput of the consensus subsystem.
// In order to run it use following commands:
//   gitlab-ci/container/container-run.sh
// then in the container run:
//   ict test //rs/tests/consensus:throughput_with_small_messages_colocate --keepalive
// then in the log search for a line like this:
//   2023-06-01 16:46:15.994 INFO[setup:rs/tests/src/driver/prometheus_vm.rs:169:0]
//     IC Progress Clock at http://grafana.throughput_with_small_messages_colocate--1685637895775.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now

use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_tests::consensus::consensus_performance_test::{setup, test_small_messages};

use anyhow::Result;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        // Since we setup VMs in sequence it takes more than the default timeout
        // of 10 minutes to setup this large testnet so let's increase the timeout:
        .with_timeout_per_test(Duration::from_secs(60 * 30))
        .with_setup(setup)
        .add_test(systest!(test_small_messages))
        .execute_from_args()?;
    Ok(())
}
