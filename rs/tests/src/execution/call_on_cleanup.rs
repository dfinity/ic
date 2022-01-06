use crate::types::*;
use crate::util::*;
use assert_matches::assert_matches;
use ic_agent::AgentError;
use ic_fondue::ic_manager::IcHandle;
use ic_universal_canister::{call_args, wasm};

pub fn is_called_if_reply_traps(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;

            let agent = assert_create_agent(endpoint.url.as_str()).await;

            let canister = UniversalCanister::new(&agent).await;

            assert_matches!(
                canister
                    .update(
                        wasm().inter_update(
                            canister.canister_id(),
                            call_args()
                                // Trap in `on_reply`. This should invoke `on_cleanup`.
                                .on_reply(wasm().trap())
                                .on_cleanup(wasm().stable_write(0, b"x")),
                        ),
                    )
                    .await,
                Err(AgentError::ReplicaError {
                    reject_code,
                    reject_message,
                }) if reject_code == RejectCode::CanisterError as u64
                    // Verify that the error message being returned is the original.
                    && reject_message.contains("trapped explicitly")
            );

            // Verify that `call_on_cleanup` was invoked.
            assert_eq!(
                canister
                    .query(wasm().stable_read(0, 1).append_and_reply())
                    .await
                    .unwrap(),
                b"x"
            );
        }
    });
}

pub fn is_called_if_reject_traps(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;

            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;

            assert_reject(
                canister
                    .update(
                        wasm().inter_update(
                            canister.canister_id(),
                            call_args()
                                .other_side(wasm().reject())
                                // Trap in `on_reject`. This should invoke `on_cleanup`.
                                .on_reject(wasm().trap())
                                .on_cleanup(wasm().stable_write(0, b"x")),
                        ),
                    )
                    .await,
                RejectCode::CanisterError,
            );

            // Verify that `call_on_cleanup` was invoked.
            assert_eq!(
                canister
                    .query(wasm().stable_read(0, 1).append_and_reply())
                    .await
                    .unwrap(),
                b"x"
            );
        }
    });
}

pub fn changes_are_discarded_if_trapped(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;

            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;

            assert_matches!(
                canister
                    .update(
                        wasm()
                            .inter_update(
                                canister.canister_id(),
                                call_args()
                                    // Trap in `on_reply`. This should invoke `on_cleanup`.
                                    .on_reply(wasm().trap_with_blob(b"in on_reply"))
                                    // Write to stable memory, then trap. Changes should not be
                                    // preserved.
                                    .on_cleanup(wasm().stable_write(0, b"x").trap_with_blob(b"in on_call_cleanup")),
                            )
                    )
                    .await,
                Err(AgentError::ReplicaError {
                    reject_code,
                    reject_message,
                }) if reject_code == RejectCode::CanisterError as u64
                    // Verify that the original error message as well as the on_cleanup error is
                    // returned.
                    && reject_message.contains("trapped explicitly: in on_reply")
                    && reject_message.contains("trapped explicitly: in on_call_cleanup")
            );

            // Changes by call_on_cleanup were discarded.
            assert_eq!(
                canister
                    .query(wasm().stable_read(0, 1).append_and_reply())
                    .await
                    .unwrap(),
                &[0]
            );
        }
    });
}

pub fn changes_are_discarded_in_query(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;

            let agent = assert_create_agent(endpoint.url.as_str()).await;
            let canister = UniversalCanister::new(&agent).await;

            assert_reject(
                canister
                    .query(
                        wasm().inter_query(
                            canister.canister_id(),
                            call_args()
                                // Trap in `on_reply`. This should invoke `on_cleanup`.
                                .on_reply(wasm().trap())
                                .on_cleanup(wasm().stable_write(0, b"x")),
                        ),
                    )
                    .await,
                RejectCode::CanisterError,
            );

            // Verify that changes by `call_on_cleanup` are discarded.
            assert_eq!(
                canister
                    .query(wasm().stable_read(0, 1).append_and_reply())
                    .await
                    .unwrap(),
                &[0],
            );

            assert_reject(
                canister
                    .query(
                        wasm().inter_query(
                            canister.canister_id(),
                            call_args()
                                .other_side(wasm().reject())
                                // Trap in `on_reject`. This should invoke `on_cleanup`.
                                .on_reject(wasm().trap())
                                .on_cleanup(wasm().stable_write(0, b"x")),
                        ),
                    )
                    .await,
                RejectCode::CanisterError,
            );

            // Verify that changes by `call_on_cleanup` are discarded.
            assert_eq!(
                canister
                    .query(wasm().stable_read(0, 1).append_and_reply())
                    .await
                    .unwrap(),
                &[0],
            );
        }
    });
}

pub fn is_called_in_query(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let endpoint = get_random_node_endpoint(&handle, &mut rng);
            endpoint.assert_ready(ctx).await;

            let agent = assert_create_agent(endpoint.url.as_str()).await;

            let canister_a = UniversalCanister::new(&agent).await;
            let canister_b = UniversalCanister::new(&agent).await;

            // In order to observe that `call_on_cleanup` has been called, two
            // queries are sent from A to B in parallel.
            //
            // When the first response is received, Canister A traps since the stable
            // hasn't been written to. The trap causes the `call_on_cleanup` closure
            // to be invoked, writing to stable memory.
            //
            // The second query would be able to read the newly written value from
            // stable memory and return it gracefully.
            let query_call_args = call_args()
                .on_reply(
                    wasm()
                        .stable_read(0, 1)
                        .trap_if_eq(&[0], "")
                        .stable_read(0, 1)
                        .append_and_reply(),
                )
                .on_cleanup(wasm().stable_write(0, b"x"));

            assert_eq!(
                canister_a
                    .query(
                        wasm()
                            .inter_query(canister_b.canister_id(), query_call_args.clone(),)
                            .inter_query(canister_b.canister_id(), query_call_args,),
                    )
                    .await
                    .unwrap(),
                // Verify that the response received is what `call_on_cleanup` wrote in stable
                // memory.
                b"x"
            );
        }
    });
}
