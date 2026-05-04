use anyhow::Result;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use sns_system_test_lib::sns_aggregator::{benchmark_config_with_auth, workload_direct_auth};
use std::time::Duration;

const WORKLOAD_DURATION: Duration = Duration::from_secs(2 * 60);

fn workload_direct_auth_rps600(env: TestEnv) {
    let rps = 600;
    let duration = WORKLOAD_DURATION;
    workload_direct_auth(env, rps, duration);
}

fn workload_direct_auth_rps1200(env: TestEnv) {
    let rps = 1200;
    let duration = WORKLOAD_DURATION;
    workload_direct_auth(env, rps, duration);
}

fn workload_direct_auth_rps2400(env: TestEnv) {
    let rps = 2400;
    let duration = WORKLOAD_DURATION;
    workload_direct_auth(env, rps, duration);
}

fn workload_direct_auth_rps4800(env: TestEnv) {
    let rps = 4800;
    let duration = WORKLOAD_DURATION;
    workload_direct_auth(env, rps, duration);
}

fn workload_direct_auth_rps9600(env: TestEnv) {
    let rps = 9600;
    let duration = WORKLOAD_DURATION;
    workload_direct_auth(env, rps, duration);
}

/// This is a non-interactive load test. We model the behavior of (multiple) web-browsers
/// that, for some reason, cannot (or do not want to) use the aggregator canister,
/// so they resort to interacting with the SNS directly.
///
/// See https://github.com/dfinity/nns-dapp/blob/6b85f56b6f5261bf0d1e4a1848752828ff0f4238/frontend/src/lib/services/%24public/sns.services.ts#L82
///
/// 1. Install NNS and SNS
/// 2. Initiate the token swap
/// 3. Generate workload (mimicking nns-dapp frontend) at various RPSs
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_overall_timeout(Duration::from_secs(60 * 60))
        .with_timeout_per_test(Duration::from_secs(60 * 60))
        .with_setup(benchmark_config_with_auth)
        .add_test(systest!(workload_direct_auth_rps600))
        .add_test(systest!(workload_direct_auth_rps1200))
        .add_test(systest!(workload_direct_auth_rps2400))
        .add_test(systest!(workload_direct_auth_rps4800))
        .add_test(systest!(workload_direct_auth_rps9600))
        .execute_from_args()?;
    Ok(())
}
