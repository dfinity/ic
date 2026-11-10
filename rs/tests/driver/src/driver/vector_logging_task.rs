use crate::driver::vector_vm::VectorVm;
use crate::driver::{
    config::NODES_INFO,
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
    let env = TestEnv::new_without_duplicating_logger(
        group_ctx.group_dir.join(GROUP_SETUP_DIR),
        logger.clone(),
    );
    // `nodes_info.json` is written once the first IC (named or not) starts its
    // node VMs; a group without IC nodes never gets a Vector VM.
    while !env.get_json_path(NODES_INFO).exists() {
        info!(
            logger,
            "Waiting for IC nodes to be deployed before starting the Vector VM."
        );
        std::thread::sleep(KEEPALIVE_INTERVAL);
    }

    let mut vector_vm = VectorVm::new().with_start_time(start_time);
    vector_vm.start(&env).expect("Failed to start Vector VM");

    loop {
        if let Err(e) = vector_vm.sync_with_vector(&env) {
            warn!(logger, "Failed to sync with vector vm due to: {}", e);
        }

        std::thread::sleep(KEEPALIVE_INTERVAL);
    }
}
