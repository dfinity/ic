use crate::driver::test_env::HasIcPrepDir;
use crate::driver::vector_vm::VectorVm;
use crate::driver::{
    constants::{GROUP_SETUP_DIR, KEEPALIVE_INTERVAL},
    context::GroupContext,
    test_env::TestEnv,
};
use chrono::{DateTime, Utc};
use slog::{debug, info, warn};

pub(crate) const VECTOR_LOGGING_TASK_NAME: &str = "vector_logging";

pub(crate) fn vector_logging_task(group_ctx: GroupContext, start_time: DateTime<Utc>) -> () {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> {VECTOR_LOGGING_TASK_NAME}");
    let setup_dir = group_ctx.group_dir.join(GROUP_SETUP_DIR);
    let env = TestEnv::new_without_duplicating_logger(setup_dir.clone(), logger.clone());
    while !setup_dir.exists() || env.prep_dir("").is_none() {
        info!(logger, "Setup and/or prep directories not created yet.");
        std::thread::sleep(KEEPALIVE_INTERVAL);
    }

    let mut vector_vm = VectorVm::new().with_start_time(start_time);
    vector_vm.start(&env).expect("Failed to start Vector VM");

    loop {
        if let Err(e) = vector_vm.sync_with_vector(&env) {
            warn!(logger, "Failed to sync with vector vm due to: {:?}", e);
        }

        std::thread::sleep(KEEPALIVE_INTERVAL);
    }
}
