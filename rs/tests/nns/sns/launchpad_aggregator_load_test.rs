use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use sns_system_test_lib::sns_aggregator::{
    benchmark_config_with_aggregator, validate_aggregator_data, wait_until_aggregator_finds_sns,
    workload_via_aggregator,
};
use std::time::Duration;

const WORKLOAD_DURATION: Duration = Duration::from_secs(2 * 60);

fn workload_via_aggregator_rps60(env: TestEnv) {
    let rps = 60;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

fn workload_via_aggregator_rps120(env: TestEnv) {
    let rps = 120;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

fn workload_via_aggregator_rps240(env: TestEnv) {
    let rps = 240;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

fn workload_via_aggregator_rps480(env: TestEnv) {
    let rps = 480;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

fn workload_via_aggregator_rps960(env: TestEnv) {
    let rps = 960;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

fn workload_via_aggregator_rps1200(env: TestEnv) {
    let rps = 1200;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

fn workload_via_aggregator_rps2400(env: TestEnv) {
    let rps = 2400;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

fn workload_via_aggregator_rps4800(env: TestEnv) {
    let rps = 4800;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

fn workload_via_aggregator_rps9600(env: TestEnv) {
    let rps = 9600;
    let duration = WORKLOAD_DURATION;
    workload_via_aggregator(env, rps, duration);
}

/// This is a non-interactive load test. We model the behavior of (multiple) web-browsers
/// that use the aggregator canister to interact with the SNS.
///
/// See https://github.com/dfinity/nns-dapp/blob/6b85f56b6f5261bf0d1e4a1848752828ff0f4238/frontend/src/lib/services/%24public/sns.services.ts#L82
///
/// 1. Install NNS, SNS, and the Aggregator canister
/// 2. Wait until the aggregator finds the SNS
/// 3. Initiate the token swap
/// 4. Wait until the aggregator finds swap params, and validate these params
/// 5. Generate workload (http requests to aggregator) at various RPSs
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(60 * 60))
        .with_timeout_per_test(Duration::from_secs(60 * 60))
        .with_setup(benchmark_config_with_aggregator)
        .add_test(systest!(wait_until_aggregator_finds_sns))
        .add_test(systest!(validate_aggregator_data))
        .add_test(systest!(workload_via_aggregator_rps60))
        .add_test(systest!(workload_via_aggregator_rps120))
        .add_test(systest!(workload_via_aggregator_rps240))
        .add_test(systest!(workload_via_aggregator_rps480))
        .add_test(systest!(workload_via_aggregator_rps960))
        .add_test(systest!(workload_via_aggregator_rps1200))
        .add_test(systest!(workload_via_aggregator_rps2400))
        .add_test(systest!(workload_via_aggregator_rps4800))
        .add_test(systest!(workload_via_aggregator_rps9600))
        .execute_from_args()?;
    Ok(())
}
