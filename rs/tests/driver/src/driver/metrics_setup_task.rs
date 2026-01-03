use crate::driver::test_env::HasIcPrepDir;
use crate::driver::{
    constants::GROUP_SETUP_DIR, context::GroupContext, farm::HostFeature, ic::VmResources,
    prometheus_vm::PrometheusVm, test_env::TestEnv,
};
use slog::{debug, info};
use std::time::Duration;

pub(crate) const METRICS_SETUP_TASK_NAME: &str = "metrics_setup";

pub(crate) fn metrics_setup_task(group_ctx: GroupContext) {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> metrics_setup_fn");
    let setup_dir = group_ctx.group_dir.join(GROUP_SETUP_DIR);
    let env = TestEnv::new_without_duplicating_logger(setup_dir.clone(), logger.clone());
    while !setup_dir.exists() || env.prep_dir("").is_none() {
        info!(logger, "Setup and/or prep directories not created yet.");
        std::thread::sleep(Duration::from_secs(2));
    }

    let host_features: Vec<HostFeature> = std::env::var("PROMETHEUS_VM_REQUIRED_HOST_FEATURES")
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
        .unwrap_or_default();

    let vm_resources: VmResources = std::env::var("PROMETHEUS_VM_RESOURCES")
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
        .with_vm_resources(vm_resources)
        .with_scrape_interval(prometheus_scrape_interval)
        .start(&env)
        .expect("failed to start prometheus VM");

    info!(logger, "PrometheusVm setup complete.");
}
