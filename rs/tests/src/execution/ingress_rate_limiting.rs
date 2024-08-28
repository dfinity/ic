/* tag::catalog[]
Title:: Rate limiting of ingress messages

Goal:: Canisters are able to rate-limit *update* calls.

Runbook::
. Deploy or re-use one subnet.
. Create two key pairs K1+K2, compute the principals.
. Deploy a canister that accepts messages from principal(K1) but rejects
   messages from principal(K2) via pay_ingress
. Send an update message from principal(K1), fail if not accepted.
. Send an update message from principal(K2), fail if accepted.


end::catalog[] */
use ic_agent::{agent::RejectCode, identity::Identity};
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl},
    },
    util::*,
};
use ic_universal_canister::wasm;

/// Not defining `canister_inspect_message` accepts all ingress messages.
pub fn canister_accepts_ingress_by_default(env: TestEnv) {
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            // Create a canister that does not expose the
            // `canister_inspect_message` method. It should accept ingress
            // messages sent to it.
            let wasm_module = wat::parse_str(
                r#"
                 (module
                 (import "ic0" "msg_reply" (func $msg_reply))

                 (func (export "canister_update hello")
                       (call $msg_reply)
                 )
                 (memory 1)
               )"#,
            )
            .unwrap();

            let canister_id =
                create_and_install(&agent, node.effective_canister_id(), &wasm_module).await;

            // Now send the canister an ingress message.  It should succeed.
            agent
                .update(&canister_id, "hello")
                .call_and_wait()
                .await
                .expect("should succeed");
        }
    })
}

/// Defining an empty `canister_inspect_message` rejects all messages.
pub fn empty_canister_inspect_rejects_all_messages(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            canister
                .update(wasm().set_inspect_message(wasm().noop()).reply())
                .await
                .unwrap();

            // Now send the canister an ingress message. It should fail.
            assert_http_submit_fails(
                agent
                    .update(&canister.canister_id(), "update")
                    .with_arg(wasm().reply().build())
                    .call()
                    .await,
                RejectCode::CanisterReject,
            );
        }
    })
}

/// Defining a `canister_inspect_message` that accepts all messages.
pub fn canister_can_accept_ingress(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            // Explicitly accepts all ingress messages.
            canister
                .update(wasm().set_inspect_message(wasm().accept_message()).reply())
                .await
                .unwrap();

            // Now send the canister an ingress message.  It should succeed.
            canister
                .update(wasm().reply())
                .await
                .expect("should succeed");
        }
    })
}

/// Defining a `canister_inspect_message` that only accepts messages with
/// payload.
pub fn canister_only_accepts_ingress_with_payload(env: TestEnv) {
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            // Create a canister that exposes the `canister_inspect_message`
            // method which rejects all ingress messages.
            let wasm_module = wat::parse_str(
                r#"
                 (module
                 (import "ic0" "msg_reply" (func $msg_reply))
                 (import "ic0" "accept_message" (func $accept_message))
                 (import "ic0" "msg_arg_data_size"
                    (func $msg_arg_data_size (result i32)))

                 (func (export "canister_update hello")
                       (call $msg_reply)
                 )
                 (func (export "canister_inspect_message")
                   (if (i32.ne (i32.const 0) (call $msg_arg_data_size))
                       (then call $accept_message))
                 )
                 (memory 1)
               )"#,
            )
            .unwrap();

            let canister_id =
                create_and_install(&agent, node.effective_canister_id(), &wasm_module).await;

            // Send the canister an ingress message without payload.  It should fail.
            assert_http_submit_fails(
                agent.update(&canister_id, "hello").call().await,
                RejectCode::CanisterReject,
            );

            // Send the canister an ingress message with payload.  It should succeed.
            agent
                .update(&canister_id, "hello")
                .with_arg(vec![1])
                .call_and_wait()
                .await
                .expect("should succeed");
        }
    })
}

pub fn canister_rejects_ingress_only_from_one_caller(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    block_on({
        async move {
            let user1 = random_ed25519_identity();
            let user1_principal = user1.sender().unwrap();
            let agent1 = agent_with_identity(node.get_public_url().as_str(), user1)
                .await
                .unwrap();
            let canister =
                UniversalCanister::new_with_retries(&agent1, node.effective_canister_id(), &logger)
                    .await;

            // Explicitly accepts all ingress messages except of those from user 1.
            canister
                .update(
                    wasm()
                        .set_inspect_message(
                            wasm()
                                .caller()
                                .trap_if_eq(user1_principal, "keep out")
                                .accept_message(),
                        )
                        .reply(),
                )
                .await
                .unwrap();

            // Now send the canister an ingress message. Should fail.
            assert_http_submit_fails(
                agent1
                    .update(&canister.canister_id(), "update")
                    .call()
                    .await,
                RejectCode::CanisterError,
            );

            // Send an ingress from user 2. Should succeed.
            let user2 = random_ed25519_identity();
            let agent2 = agent_with_identity(node.get_public_url().as_str(), user2)
                .await
                .unwrap();
            let canister = UniversalCanister::from_canister_id(&agent2, canister.canister_id());
            canister
                .update(wasm().reply())
                .await
                .expect("should succeed");
        }
    })
}

// TODO(EXC-186): Enable this test.
pub fn message_to_canister_with_not_enough_balance_is_rejected(env: TestEnv) {
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            // A canister is created with just the freeze balance reserve. An ingress
            // message to it should get rejected.
            let canister = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                app_node.effective_canister_id(),
                CANISTER_FREEZE_BALANCE_RESERVE,
                &env.logger(),
            )
            .await;

            assert_http_submit_fails(
                agent.update(&canister.canister_id(), "update").call().await,
                RejectCode::CanisterReject,
            );
        }
    })
}
