use crate::driver::test_env::HasIcPrepDir;
use crate::driver::{
    constants::GROUP_SETUP_DIR, context::GroupContext, prometheus_vm::HasPrometheus,
    test_env::TestEnv,
};
use slog::{debug, info, warn};
use std::time::Duration;

pub(crate) const METRICS_SYNC_TASK_NAME: &str = "metrics_sync";

pub(crate) fn metrics_sync_task(group_ctx: GroupContext) {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> metrics_sync_fn");
    let setup_dir = group_ctx.group_dir.join(GROUP_SETUP_DIR);
    let env = TestEnv::new_without_duplicating_logger(setup_dir.clone(), logger.clone());
    while !setup_dir.exists() || env.prep_dir("").is_none() {
        info!(logger, "Setup and/or prep directories not created yet.");
        std::thread::sleep(Duration::from_secs(2));
    }
    loop {
        if let Err(e) = env.sync_with_prometheus() {
            warn!(
                logger,
                "Failed to sync with PrometheusVm due to: {}",
                e.to_string()
            );
        }
        std::thread::sleep(Duration::from_secs(10));
    }
}
