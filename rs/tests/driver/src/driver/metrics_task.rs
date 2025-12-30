use crate::driver::test_env::HasIcPrepDir;
use crate::driver::{
    constants::{GROUP_SETUP_DIR, KEEPALIVE_INTERVAL},
    context::GroupContext,
    farm::HostFeature,
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
};
use slog::{debug, info, warn};
use std::time::Duration;

pub(crate) const METRICS_TASK_NAME: &str = "metrics";

pub(crate) fn metrics_task(group_ctx: GroupContext) -> () {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> metrics_fn");
    let setup_dir = group_ctx.group_dir.join(GROUP_SETUP_DIR);
    let env = TestEnv::new_without_duplicating_logger(setup_dir.clone(), logger.clone());
    while !setup_dir.exists() || env.prep_dir("").is_none() {
        info!(logger, "Setup and/or prep directories not created yet.");
        std::thread::sleep(KEEPALIVE_INTERVAL);
    }

    let host_features: Vec<HostFeature> = std::env::var("PROMETHEUS_VM_REQUIRED_HOST_FEATURES")
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .unwrap_or_default();

    let prometheus_scrape_interval = std::env::var("PROMETHEUS_SCRAPE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10));

    info!(logger, "Setting up PrometheusVm ...");

    PrometheusVm::default()
        .with_required_host_features(host_features)
        .with_scrape_interval(prometheus_scrape_interval)
        .start(&env)
        .expect("failed to start prometheus VM");
    loop {
        if let Err(e) = env.sync_with_prometheus_result() {
            warn!(logger, "Failed to sync with PrometheusVm due to: {:?}", e);
        }

        std::thread::sleep(KEEPALIVE_INTERVAL);
    }
}
