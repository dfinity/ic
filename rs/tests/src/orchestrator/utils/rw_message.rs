use crate::driver::test_env_api::*;
use crate::util::*;
use anyhow::bail;
use candid::Principal;
use reqwest::Url;
use slog::{debug, info, Logger};
use std::time::Duration;

pub(crate) fn store_message(url: &Url, msg: &str) -> Principal {
    block_on(async {
        let bytes = msg.as_bytes();
        let agent = assert_create_agent(url.as_str()).await;
        let ucan = UniversalCanister::new(&agent).await;
        // send an update call to it
        ucan.store_to_stable(0, bytes).await;
        ucan.canister_id()
    })
}

/// Try to store the given message within the next 30 seconds, return true if successful
pub(crate) fn can_store_msg(log: &Logger, url: &Url, canister_id: Principal, msg: &str) -> bool {
    let bytes = msg.as_bytes();
    block_on(async {
        match create_agent(url.as_str()).await {
            Ok(agent) => {
                debug!(log, "Try to get canister reference");
                let ucan = UniversalCanister::from_canister_id(&agent, canister_id);
                debug!(log, "Success, will try to write next");
                ucan.try_store_to_stable(0, bytes, create_delay(500, 30))
                    .await
                    .is_ok()
            }
            Err(e) => {
                debug!(log, "Could not create agent: {:?}", e,);
                false
            }
        }
    })
}

/// Try to store the given message. Retry for 300 seconds or until update was unsuccessful
pub(crate) fn cannot_store_msg(log: Logger, url: &Url, canister_id: Principal, msg: &str) -> bool {
    retry(log.clone(), secs(300), secs(10), || {
        if can_store_msg(&log, url, canister_id, msg) {
            bail!("retry...")
        } else {
            Ok(())
        }
    })
    .is_ok()
}

pub(crate) fn can_read_msg(log: &Logger, url: &Url, canister_id: Principal, msg: &str) -> bool {
    block_on(can_read_msg_impl(log, url, canister_id, msg, 0))
}

pub(crate) fn can_read_msg_with_retries(
    log: &Logger,
    url: &Url,
    canister_id: Principal,
    msg: &str,
    retries: usize,
) -> bool {
    block_on(can_read_msg_impl(log, url, canister_id, msg, retries))
}

async fn can_read_msg_impl(
    log: &Logger,
    url: &Url,
    canister_id: Principal,
    msg: &str,
    retries: usize,
) -> bool {
    let bytes = msg.as_bytes();
    for i in 0..retries + 1 {
        debug!(log, "Try to create agent for node {:?}...", url.as_str());
        match create_agent(url.as_str()).await {
            Ok(agent) => {
                debug!(log, "Try to get canister reference");
                let ucan = UniversalCanister::from_canister_id(&agent, canister_id);
                debug!(log, "Success, will try to read next");
                if ucan.read_stable(0, msg.len() as u32).await == Ok(bytes.to_vec()) {
                    return true;
                } else {
                    info!(
                        log,
                        "Could not read expected message, will retry {:?} times",
                        retries - i
                    );
                }
            }
            Err(e) => {
                debug!(
                    log,
                    "Could not create agent: {:?}, will retry {:?} times",
                    e,
                    retries - i
                );
            }
        };
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    false
}

pub(crate) fn can_install_canister(url: &url::Url) -> Result<(), String> {
    block_on(async {
        let agent = assert_create_agent(url.as_str()).await;
        UniversalCanister::try_new(&agent).await.map(|_| ())
    })
}

pub(crate) fn can_install_canister_with_retries(
    url: &url::Url,
    logger: &slog::Logger,
    timeout: Duration,
    backoff: Duration,
) {
    retry(logger.clone(), timeout, backoff, || {
        info!(logger, "Try to install canister...");
        if let Err(e) = can_install_canister(url) {
            bail!("Cannot install canister: {}", e);
        } else {
            info!(logger, "Installing canister is possible.");
            Ok(())
        }
    })
    .expect("Canister installation should work!");
}

pub(crate) fn install_nns_and_universal_canisters(topology: TopologySnapshot) {
    check_or_init_ic(topology, true)
}

fn check_or_init_ic(topology: TopologySnapshot, install_canisters: bool) {
    let logger = topology.test_env().logger();

    if install_canisters {
        topology
            .root_subnet()
            .nodes()
            .next()
            .unwrap()
            .install_nns_canisters()
            .expect("NNS canisters not installed");
        info!(logger, "NNS canisters are installed.");
    }

    topology.subnets().for_each(|subnet| {
        if subnet.subnet_id != topology.root_subnet_id() {
            subnet.nodes().for_each(|node| {
                // make sure node is healty
                node.await_status_is_healthy()
                    .expect("Timeout while waiting for all subnets to be healthy");
                // make sure the node is participating in a subnet
                if install_canisters {
                    can_install_canister_with_retries(
                        &node.get_public_url(),
                        &logger,
                        secs(600),
                        secs(10),
                    );
                }
            });
        }
    });

    topology.unassigned_nodes().for_each(|node| {
        node.await_can_login_as_admin_via_ssh()
            .expect("Timeout while waiting for all unassigned nodes to be healthy");
    });
    info!(logger, "IC is healthy and ready.");
}
