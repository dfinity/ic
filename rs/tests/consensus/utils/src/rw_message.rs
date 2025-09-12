use anyhow::bail;
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_system_test_driver::{driver::test_env_api::*, util::*};
use reqwest::Url;
use slog::{Logger, debug, info};
use std::time::Duration;

pub fn store_message(
    url: &Url,
    effective_canister_id: PrincipalId,
    msg: &str,
    log: &Logger,
) -> Principal {
    info!(
        log,
        "Storing a message in canister with id {} at {}", effective_canister_id, url
    );

    block_on(async {
        let agent = assert_create_agent(url.as_str()).await;
        let mcan = MessageCanister::new(&agent, effective_canister_id).await;
        // send an update call to it
        mcan.store_msg(msg.to_string()).await;
        mcan.canister_id()
    })
}

pub fn store_message_with_retries(
    url: &Url,
    effective_canister_id: PrincipalId,
    msg: &str,
    log: &Logger,
) -> Principal {
    info!(
        log,
        "Storing a message in canister with id {} at {}", effective_canister_id, url
    );

    block_on(async {
        let agent = assert_create_agent(url.as_str()).await;
        let mcan = MessageCanister::new_with_retries(
            &agent,
            effective_canister_id,
            log,
            secs(300),
            secs(10),
        )
        .await;
        // send an update call to it
        mcan.store_msg(msg.to_string()).await;
        mcan.canister_id()
    })
}

/// Try to store the given message within the next 30 seconds, return true if successful
pub fn can_store_msg(log: &Logger, url: &Url, canister_id: Principal, msg: &str) -> bool {
    block_on(async {
        match create_agent(url.as_str()).await {
            Ok(agent) => {
                debug!(log, "Try to get canister reference");
                let mcan = MessageCanister::from_canister_id(&agent, canister_id);
                debug!(log, "Success, will try to write next");
                matches!(
                    tokio::time::timeout(
                        Duration::from_secs(30),
                        mcan.try_store_msg(msg.to_string()),
                    )
                    .await,
                    Ok(Ok(_))
                )
            }
            Err(e) => {
                debug!(log, "Could not create agent: {:?}", e,);
                false
            }
        }
    })
}

/// Try to store the given message. Retry for 300 seconds or until update was unsuccessful
pub fn cannot_store_msg(log: Logger, url: &Url, canister_id: Principal, msg: &str) -> bool {
    ic_system_test_driver::retry_with_msg!(
        format!(
            "store message in canister {} via {}",
            canister_id,
            url.to_string()
        ),
        log.clone(),
        secs(300),
        secs(10),
        || {
            if can_store_msg(&log, url, canister_id, msg) {
                bail!("Message could still be stored.")
            } else {
                Ok(())
            }
        }
    )
    .is_ok()
}

pub fn can_read_msg(log: &Logger, url: &Url, canister_id: Principal, msg: &str) -> bool {
    block_on(can_read_msg_impl(
        log,
        url,
        canister_id,
        msg,
        /*retries=*/ 0,
    ))
}

pub fn can_read_msg_with_retries(
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
    expected_msg: &str,
    retries: usize,
) -> bool {
    info!(
        log,
        "Checking if we can read a message from canister with id {} at {}", canister_id, url
    );

    for i in 0..=retries {
        debug!(log, "Try to create agent for node {}...", url);

        match create_agent(url.as_str()).await {
            Ok(agent) => {
                debug!(log, "Try to get canister reference");
                let mcan = MessageCanister::from_canister_id(&agent, canister_id);
                debug!(log, "Success, will try to read next");
                match mcan.try_read_msg().await {
                    Ok(Some(msg)) if msg == expected_msg => {
                        return true;
                    }
                    Ok(Some(msg)) => debug!(
                        log,
                        "Received unexpected message: '{}', expected: '{}'", msg, expected_msg
                    ),
                    Ok(None) => debug!(log, "Received an empty message"),
                    Err(err) => debug!(log, "Failed reading a message. Error: {}", err),
                }
            }
            Err(err) => debug!(log, "Could not create agent: {:?}", err),
        };

        debug!(log, "Will retry {} more times", retries - i);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    false
}

pub fn get_cert_time(url: &url::Url, effective_canister_id: PrincipalId) -> Result<u64, String> {
    use ic_agent::lookup_value;
    block_on(async {
        let path = vec!["time".into()];
        let paths = vec![path.clone()];
        let agent = assert_create_agent(url.as_str()).await;
        match agent
            .read_state_raw(paths.clone(), effective_canister_id.into())
            .await
        {
            Ok(cert) => match lookup_value(&cert, path.clone()) {
                Ok(mut t) => Ok(leb128::read::unsigned(&mut t).unwrap()),
                Err(err) => Err(err.to_string()),
            },
            Err(err) => Err(err.to_string()),
        }
    })
}

pub fn cert_state_makes_progress_with_retries(
    url: &url::Url,
    effective_canister_id: PrincipalId,
    logger: &slog::Logger,
    timeout: Duration,
    backoff: Duration,
) {
    let mut current_timestamp: Option<u64> = None;
    ic_system_test_driver::retry_with_msg!(
        format!(
            "checking if the certified time of canister {} on {} has advanced",
            effective_canister_id.to_string(),
            url.to_string()
        ),
        logger.clone(),
        timeout,
        backoff,
        || {
            info!(logger, "Performing read_state request...");
            let next_timestamp = {
                let timestamp = get_cert_time(url, effective_canister_id);
                if let Err(err) = timestamp {
                    bail!("Cannot perform read_state request: {}", err);
                };
                timestamp.ok()
            };
            // Set initial timestamp, if not yet set.
            if current_timestamp.is_none() {
                info!(logger, "Initial timestamp recorded!");
                current_timestamp = next_timestamp;
                bail!("Timestamp hasn't advanced yet!");
            } else if next_timestamp > current_timestamp {
                info!(logger, "Timestamp advanced!");
                Ok(())
            } else {
                bail!("Timestamp hasn't advanced yet!");
            }
        }
    )
    .expect("System should make progress!");
}

pub fn cert_state_makes_no_progress_with_retries(
    url: &url::Url,
    effective_canister_id: PrincipalId,
    logger: &slog::Logger,
    timeout: Duration,
    backoff: Duration,
) {
    let mut current_timestamp: Option<u64> = None;
    ic_system_test_driver::retry_with_msg!(
        format!(
            "checking if the certified time of canister {} on {} does not advance",
            effective_canister_id.to_string(),
            url.to_string()
        ),
        logger.clone(),
        timeout,
        backoff,
        || {
            info!(logger, "Performing read_state request...");
            let next_timestamp = {
                let timestamp = get_cert_time(url, effective_canister_id);
                if timestamp.is_err() {
                    return Ok(());
                };
                timestamp.ok()
            };
            if current_timestamp.is_none() {
                info!(logger, "Initial timestamp recorded!");
                current_timestamp = next_timestamp;
                bail!("No timestamp to compare with!");
            } else if next_timestamp > current_timestamp {
                info!(logger, "Current timestamp recorded!");
                current_timestamp = next_timestamp;
                bail!("Timestamp advanced!");
            } else {
                info!(logger, "Timestamp hasn't advanced!");
                Ok(())
            }
        }
    )
    .expect("System shouldn't make progress!");
}

pub fn install_nns_with_customizations_and_check_progress(
    topology: TopologySnapshot,
    customizations: NnsCustomizations,
) {
    let logger = topology.test_env().logger();
    // Perform IC checks prior to canister installation.
    info!(logger, "Checking if all subnet nodes are healthy");
    for subnet in topology.subnets() {
        if !subnet.raw_subnet_record().is_halted {
            info!(
                logger,
                "Checking if all nodes in subnet {} are healthy", subnet.subnet_id
            );
            for node in subnet.nodes() {
                node.await_status_is_healthy()
                    .expect("Node's status endpoint didn't report healthy");
            }
        } else {
            info!(
                logger,
                "Subnet {} is halted. Not checking if the nodes are healthy", subnet.subnet_id
            );
        }
    }

    info!(
        logger,
        "Checking if all unassigned nodes (if any) are healthy"
    );
    for node in topology.unassigned_nodes() {
        node.await_can_login_as_admin_via_ssh()
            .expect("Timeout while waiting for all unassigned nodes to be healthy");
    }

    info!(logger, "IC is healthy and ready.");

    let nns_node = topology.root_subnet().nodes().next().unwrap();
    NnsInstallationBuilder::new()
        .with_customizations(customizations)
        .install(&nns_node, &topology.test_env())
        .expect("NNS canisters not installed");
    info!(logger, "NNS canisters are installed.");

    for subnet in topology
        .subnets()
        .filter(|subnet| subnet.subnet_id != topology.root_subnet_id())
    {
        if !subnet.raw_subnet_record().is_halted {
            info!(
                logger,
                "Checking if all the nodes are participating in the subnet {}", subnet.subnet_id
            );
            for node in subnet.nodes() {
                cert_state_makes_progress_with_retries(
                    &node.get_public_url(),
                    node.effective_canister_id(),
                    &logger,
                    /*timeout=*/ secs(600),
                    /*backoff=*/ secs(2),
                );
            }
        } else {
            info!(
                logger,
                "Subnet {} is halted. \
                Not checking if all the nodes are participating in the subnet",
                subnet.subnet_id,
            );
        }
    }
}

pub fn install_nns_and_check_progress(topology: TopologySnapshot) {
    install_nns_with_customizations_and_check_progress(topology, NnsCustomizations::default());
}
