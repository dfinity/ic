use ic_recovery::get_node_metrics;
use ic_system_test_driver::{
    driver::test_env_api::{set_var_to_path, HasPublicApiUrl, IcNodeSnapshot},
    util::block_on,
};
use ic_types::Height;
use slog::{info, warn, Logger};
use std::path::PathBuf;

pub mod node;
pub mod performance;
pub mod rw_message;
pub mod ssh_access;
pub mod subnet;
pub mod upgrade;

pub fn set_sandbox_env_vars(dir: PathBuf) {
    set_var_to_path("SANDBOX_BINARY", dir.join("canister_sandbox"));
    set_var_to_path("LAUNCHER_BINARY", dir.join("sandbox_launcher"));
    set_var_to_path("COMPILER_BINARY", dir.join("compiler_sandbox"));
}

pub fn assert_node_is_making_progress(
    node: &IcNodeSnapshot,
    logger: &Logger,
    height_delta: Height,
) {
    info!(
        logger,
        "Verifying that the node {} is making progress", node.node_id
    );

    node.await_status_is_healthy()
        .expect("Should become healthy");

    let height = get_certification_height_from_metrics(node, logger);
    let target_height = height + height_delta;

    const MAX_RETRIES: u64 = 30;
    const SLEEP_TIME_SECS: u64 = 10;

    info!(
        logger,
        "Waiting until node {} progresses past height {}", node.node_id, target_height
    );

    for retry in 1..=MAX_RETRIES {
        std::thread::sleep(std::time::Duration::from_secs(SLEEP_TIME_SECS));
        let new_height = get_certification_height_from_metrics(node, logger);

        if new_height >= target_height {
            info!(
                logger,
                "Node {} progressed from height {} to height {}", node.node_id, height, new_height
            );

            return;
        }

        warn!(
            logger,
            "Node {} didn't make enough progress in {} seconds and is at height {}",
            node.node_id,
            retry * SLEEP_TIME_SECS,
            new_height,
        );
    }

    panic!(
        "Node {} didn't make enough progress in {} seconds",
        node.node_id,
        MAX_RETRIES * SLEEP_TIME_SECS,
    );
}

fn get_certification_height_from_metrics(node: &IcNodeSnapshot, logger: &Logger) -> Height {
    block_on(get_node_metrics(logger, &node.get_ip_addr()))
        .expect("Should get node metrics")
        .certification_height
}
