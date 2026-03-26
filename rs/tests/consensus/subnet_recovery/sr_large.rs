use anyhow::Result;
use std::time::Duration;

use ic_consensus_system_test_subnet_recovery::common::{
    setup_large_chain_keys as setup, test_large_no_upgrade_with_chain_keys as test,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::{prometheus_vm::HasPrometheus, test_env::TestEnv};
use ic_system_test_driver::systest;

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
        .with_setup(setup)
        .with_overall_timeout(Duration::from_secs(55 * 60))
        .with_timeout_per_test(Duration::from_secs(50 * 60))
        .without_assert_no_replica_restarts()
        .add_test(systest!(test))
        .with_teardown(teardown)
        .execute_from_args()?;
    Ok(())
}
