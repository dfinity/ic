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
use crate::util::*;
use ic_agent::identity::Identity;
use ic_fondue::ic_manager::IcHandle;
use ic_universal_canister::wasm;
use reqwest::StatusCode;

/// Not defining `canister_inspect_message` accepts all ingress messages.
pub fn canister_accepts_ingress_by_default(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            // Create a canister that does not expose the
            // `canister_inspect_message` method. It should accept ingress
            // messages sent to it.
            let wasm_module = wabt::wat2wasm(
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

            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister_id = create_and_install(&agent, &wasm_module).await;

            // Now send the canister an ingress message.  It should succeed.
            agent
                .update(&canister_id, "hello")
                .call_and_wait(delay())
                .await
                .expect("should succeed");
        }
    })
}

/// Defining an empty `canister_inspect_message` rejects all messages.
pub fn empty_canister_inspect_rejects_all_messages(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;
            canister
                .update(wasm().set_inspect_message(wasm().noop()).reply())
                .await
                .unwrap();

            // Now send the canister an ingress message.  It should fail.
            assert_http_submit_fails(
                agent
                    .update(&canister.canister_id(), "update")
                    .with_arg(wasm().reply().build())
                    .call()
                    .await,
                StatusCode::FORBIDDEN,
            );
        }
    })
}

/// Defining a `canister_inspect_message` that accepts all messages.
pub fn canister_can_accept_ingress(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;

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
pub fn canister_only_accepts_ingress_with_payload(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            // Create a canister that exposes the `canister_inspect_message`
            // method which rejects all ingress messages.
            let wasm_module = wabt::wat2wasm(
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
                       (call $accept_message))
                 )
                 (memory 1)
               )"#,
            )
            .unwrap();

            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister_id = create_and_install(&agent, &wasm_module).await;

            // Send the canister an ingress message without payload.  It should fail.
            assert_http_submit_fails(
                agent.update(&canister_id, "hello").call().await,
                StatusCode::FORBIDDEN,
            );

            // Send the canister an ingress message with payload.  It should succeed.
            agent
                .update(&canister_id, "hello")
                .with_arg(vec![1])
                .call_and_wait(delay())
                .await
                .expect("should succeed");
        }
    })
}

pub fn canister_rejects_ingress_only_from_one_caller(handle: IcHandle, ctx: &fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let user1 = random_ed25519_identity();
            let user1_principal = user1.sender().unwrap();
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent1 = agent_with_identity(endpoint.url.as_str(), user1)
                .await
                .unwrap();
            let canister = UniversalCanister::new(&agent1).await;

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
                StatusCode::FORBIDDEN,
            );

            // Send an ingress from user 2. Should succeed.
            let user2 = random_ed25519_identity();
            let agent2 = agent_with_identity(endpoint.url.as_str(), user2)
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
pub fn message_to_canister_with_not_enough_balance_is_rejected(
    handle: IcHandle,
    ctx: &fondue::pot::Context,
) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_application_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;
            let agent = assert_create_agent(endpoint.url.as_str()).await;

            // A canister is created with just the freeze balance reserve. An ingress
            // message to it should get rejected.
            let canister =
                UniversalCanister::new_with_cycles(&agent, CANISTER_FREEZE_BALANCE_RESERVE).await;

            assert_http_submit_fails(
                agent.update(&canister.canister_id(), "update").call().await,
                StatusCode::FORBIDDEN,
            );
        }
    })
}
