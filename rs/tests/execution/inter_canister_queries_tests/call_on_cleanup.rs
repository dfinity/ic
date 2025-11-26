use assert_matches::assert_matches;
use ic_agent::{
    AgentError,
    agent::{RejectCode, RejectResponse},
};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::util::*;
use ic_universal_canister::{call_args, wasm};

pub fn is_called_if_reply_traps(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

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
                Err(AgentError::CertifiedReject {reject: RejectResponse{
                    reject_code,
                    reject_message,
                    ..
                }, .. }) if reject_code == RejectCode::CanisterError
                    // Verify that the error message being returned is the original.
                    && reject_message.contains("called `ic0.trap` with message")
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

pub fn is_called_if_reject_traps(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

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

pub fn changes_are_discarded_if_trapped(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

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
                Err(AgentError::CertifiedReject { reject: RejectResponse {
                    reject_code,
                    reject_message,
                    ..
                }, ..}) if reject_code == RejectCode::CanisterError
                    // Verify that the original error message as well as the on_cleanup error is
                    // returned.
                    && reject_message.contains("called `ic0.trap` with message: 'in on_reply")
                    && reject_message.contains("called `ic0.trap` with message: 'in on_call_cleanup")
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

pub fn changes_are_discarded_in_query(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

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

pub fn is_called_in_query(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let canister_b =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

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
                        .trap_if_eq([0], "")
                        .stable_read(0, 1)
                        .append_and_reply(),
                )
                .on_cleanup(wasm().stable_write(0, b"x"));

            assert_eq!(
                canister_a
                    .composite_query(
                        wasm()
                            .composite_query(canister_b.canister_id(), query_call_args.clone(),)
                            .composite_query(canister_b.canister_id(), query_call_args,),
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
