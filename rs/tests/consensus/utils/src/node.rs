use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, IcNodeSnapshot, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
};
use ic_types::Height;

use anyhow::{anyhow, bail};
use slog::Logger;

pub fn await_node_certified_height(node: &IcNodeSnapshot, target_height: Height, log: Logger) {
    ic_system_test_driver::retry_with_msg!(
        format!(
            "check if node {} is at height {}",
            node.node_id, target_height
        ),
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            node.status()
                .and_then(|response| match response.certified_height {
                    Some(height) if height > target_height => Ok(()),
                    Some(height) => bail!(
                        "Target height not yet reached, height: {}, target: {}",
                        height,
                        target_height
                    ),
                    None => bail!("Certified height not available"),
                })
        }
    )
    .expect("The node did not reach the specified height in time")
}

pub fn get_node_certified_height(node: &IcNodeSnapshot, log: Logger) -> Height {
    ic_system_test_driver::retry_with_msg!(
        format!("get certified height of node {}", node.node_id),
        log,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || {
            node.status().and_then(|response| {
                response
                    .certified_height
                    .ok_or_else(|| anyhow!("Certified height not available"))
            })
        }
    )
    .expect("Should be able to retrieve the certified height")
}
