use anyhow::{Result, anyhow};
use candid::{Decode, Encode};
use ic_canister_client::{Agent as CanisterClient, Sender};
use ic_consensus_system_test_utils::rw_message::cert_state_makes_progress_with_retries;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::*,
    },
    systest,
    util::{MessageCanister, assert_create_agent, block_on},
};
use ic_types::{
    CanisterId, PrincipalId,
    messages::{Blob, SenderInfo},
};
use slog::{Logger, info};
use std::time::Duration;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .setup_and_start(&env)
        .expect("Failed to set up IC under test");
}

fn nonce() -> Vec<u8> {
    use rand::Rng;
    let mut nonce = vec![0u8; 8];
    rand::thread_rng().fill(&mut nonce[..]);
    nonce
}

async fn store_with_retries(
    agent: &CanisterClient,
    logger: &Logger,
    effective_canister_id: &CanisterId,
    canister_id: &CanisterId,
    message: &str,
    sender_info: Option<SenderInfo>,
    timeout: Duration,
    backoff: Duration,
) -> Result<()> {
    ic_system_test_driver::retry_with_msg_async!(
        format!("storing message '{}' with sender_info={sender_info:?}", message),
        logger,
        timeout,
        backoff,
        || {
        let sender_info = sender_info.clone();
        async move {
            let payload =
                Encode!(&message.to_string()).unwrap();
            agent
                .execute_update_with_sender_info(
                    effective_canister_id,
                    canister_id,
                    "store",
                    payload,
                    nonce(),
                    sender_info,
                )
                .await
                .map(|_| ())
                .map_err(|e| anyhow!("update failed: {e}"))
        }
    })
    .await
}

async fn read_with_retries(
    agent: &CanisterClient,
    logger: &Logger,
    canister_id: &CanisterId,
) -> Result<Option<String>> {
    ic_system_test_driver::retry_with_msg_async!(
        format!("reading stored message from canister {canister_id}"),
        logger,
        secs(120),
        secs(5),
        || async move {
            let result = agent
                .execute_query(canister_id, "read", Encode!(&()).unwrap())
                .await
                .map_err(|e| anyhow!("query failed: {e}"))?
                .ok_or_else(|| anyhow!("empty reply from read"))?;
            Decode!(&result, Option<String>)
                .map_err(|e| anyhow!("failed to decode read result: {e}"))
        }
    )
    .await
}

fn test(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    let node = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .expect("No system subnet found")
        .nodes()
        .next()
        .expect("No nodes in system subnet");

    info!(logger, "Waiting for the system subnet to make progress");
    cert_state_makes_progress_with_retries(
        &node.get_public_url(),
        node.effective_canister_id(),
        &logger,
        secs(600),
        secs(2),
    );

    let agent = CanisterClient::new(
        node.get_public_url(),
        Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
    );

    let effective_canister_id = CanisterId::unchecked_from_principal(node.effective_canister_id());

    block_on(async {
        info!(logger, "Installing message canister");
        let install_agent = assert_create_agent(node.get_public_url().as_str()).await;
        let message_canister = MessageCanister::new_with_retries(&install_agent, node.effective_canister_id(), &logger, secs(300), secs(10)).await;
        let canister_id = CanisterId::unchecked_from_principal(
            PrincipalId::try_from(message_canister.canister_id()).unwrap(),
        );
        info!(logger, "Message canister installed: {}", canister_id);

        let msg = "Hello from canister_client!";
        info!(logger, "Storing message with sender_info=None: {}", msg);
        store_with_retries(
            &agent,
            &logger,
            &effective_canister_id,
            &canister_id,
            msg,
            None,
            secs(120),
            secs(5),
        )
        .await
        .expect("Failed to store message");

        info!(logger, "Reading message back");
        let read_msg = read_with_retries(&agent, &logger, &canister_id)
            .await
            .expect("Failed to read message");

        info!(logger, "Read message: {:?}", read_msg);
        assert_eq!(read_msg, Some(msg.to_string()));

        let msg_with_sender_info = "This should not overwrite old value";
        info!(
            logger,
            "Trying to store message with sender_info=Some(...) (expected to fail)"
        );
        let _update_error = store_with_retries(
            &agent,
            &logger,
            &effective_canister_id,
            &canister_id,
            msg_with_sender_info,
            Some(SenderInfo {
                info: Blob(vec![1, 2, 3]),
                signer: Blob(canister_id.get().into_vec()),
                sig: Blob(vec![4, 5, 6]),
            }),
            secs(10),
            secs(2),
        )
        .await
        .expect_err("Update with sender_info should fail for all retries");

        info!(logger, "Reading message after failed sender_info update");
        let read_msg_after_failed_update = read_with_retries(&agent, &logger, &canister_id)
            .await
            .expect("Failed to read message after failed sender_info update");
        assert_eq!(read_msg_after_failed_update, Some(msg.to_string()));
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()
}
