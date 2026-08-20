use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use std::time::Duration;
use xnet_slo_test_lib::Config;

const SUBNETS: usize = 120;
const NODES_PER_SUBNET: usize = 1;
const RUNTIME: Duration = Duration::from_secs(600);
const REQUEST_RATE: usize = 10;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(800);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(1400);

fn main() -> Result<()> {
    let config = Config::new(SUBNETS, NODES_PER_SUBNET, RUNTIME, REQUEST_RATE)
        // Guaranteed-response calls and best-effort calls with 30 second timeout.
        .with_call_timeouts(&[None, Some(30)])
        // With 120 single-node subnets colocated on shared performance hardware, the
        // per-subnet block production rate varies between runs. On loaded runs a few
        // "straggler" subnets dip just below the default 0.3 send rate threshold (down
        // to ~0.28), while on unloaded runs the minimum is ~0.43. Lower the threshold to
        // 0.2 to absorb this hardware variance while still catching systemic XNet
        // regressions (the median send rate is ~0.7).
        .with_send_rate_threshold(0.2);
    let test = config.clone().test();

    SystemTestGroup::new()
        .with_setup(config.build())
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TASK_TIMEOUT) // each task (including the setup function) may take up to `per_task_timeout`.
        .with_overall_timeout(OVERALL_TIMEOUT) // the entire group may take up to `overall_timeout`.
        .execute_from_args()?;
    Ok(())
}
