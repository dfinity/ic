use anyhow::Result;
use std::time::Duration;

use ic_system_test_driver::{
    driver::{group::SystemTestGroup, simulate_network::ProductionSubnetTopology},
    systest,
};
use ic_tests::networking::p2p_performance_workload::{config, test};

// Test parameters
const RPS: usize = 0;
const PAYLOAD_SIZE_BYTES: usize = 1024 * 1024;
const WORKLOAD_RUNTIME: Duration = Duration::from_secs(20 * 60);
const NNS_SUBNET_MAX_SIZE: usize = 1;
const APP_SUBNET_MAX_SIZE: usize = 40;
const DOWNLOAD_PROMETHEUS_DATA: bool = true;
// Timeout parameters
const TASK_TIMEOUT_DELTA: Duration = Duration::from_secs(3600);
const OVERALL_TIMEOUT_DELTA: Duration = Duration::from_secs(3600);
// Network topology
const NETWORK_SIMULATION: Option<ProductionSubnetTopology> = Some(ProductionSubnetTopology::TDB26);

fn main() -> Result<()> {
    let per_task_timeout: Duration = WORKLOAD_RUNTIME + TASK_TIMEOUT_DELTA;
    let overall_timeout: Duration = per_task_timeout + OVERALL_TIMEOUT_DELTA;
    let config = |env| {
        config(
            env,
            NNS_SUBNET_MAX_SIZE,
            APP_SUBNET_MAX_SIZE,
            NETWORK_SIMULATION,
            None,
        )
    };
    let test = |env| {
        test(
            env,
            RPS,
            PAYLOAD_SIZE_BYTES,
            WORKLOAD_RUNTIME,
            DOWNLOAD_PROMETHEUS_DATA,
        )
    };
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(test))
        .with_timeout_per_test(per_task_timeout) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(overall_timeout) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}
