use crate::util::{assert_create_agent, block_on, create_agent, create_delay, UniversalCanister};
use candid::Principal;
use reqwest::Url;
use slog::{debug, info, Logger};

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

pub(crate) fn can_install_canister(url: &url::Url) -> bool {
    block_on(async {
        let agent = assert_create_agent(url.as_str()).await;
        UniversalCanister::try_new(&agent).await.is_ok()
    })
}
