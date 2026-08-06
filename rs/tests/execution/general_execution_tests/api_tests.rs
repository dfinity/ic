/* tag::catalog[]
end::catalog[] */

use candid::Decode;
use ic_agent::{Agent, agent::RejectCode};
use ic_base_types::PrincipalId;
use ic_management_canister_types_private::{self as ic00, EmptyBlob, Method, Payload};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::driver::test_env_api::IcNodeSnapshot;
use ic_system_test_driver::util::*;
use ic_types_cycles::Cycles;
use ic_universal_canister::{call_args, wasm};
use slog::Logger;

/// Helper function to setup an NNS node and an agent.
fn setup_nns_node_and_agent(env: &TestEnv) -> (IcNodeSnapshot, Agent) {
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    (nns_node, agent)
}

/// Helper function to setup an application node and an agent.
fn setup_app_node_and_agent(env: &TestEnv) -> (IcNodeSnapshot, Agent) {
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    (app_node, agent)
}

pub fn test_raw_rand_api(env: TestEnv) {
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;

            let call_raw_rand_payload = wasm().call_simple(
                ic00::IC_00,
                Method::RawRand,
                call_args().other_side(EmptyBlob.encode()),
            );

            // Calling raw_rand in a query fails.
            let result_query = canister.query(call_raw_rand_payload.clone()).await;

            assert_reject(result_query, RejectCode::CanisterError);

            // Calling raw_rand in an update succeeds and returns different blobs (of length 32 bytes) every time.
            let raw_rand_bytes = || async {
                let res = canister
                    .update(call_raw_rand_payload.clone())
                    .await
                    .unwrap();
                let bytes = Decode!(&res, Vec<u8>).unwrap();
                assert_eq!(bytes.len(), 32);
                bytes
            };
            let bytes = raw_rand_bytes().await;
            let other_bytes = raw_rand_bytes().await;
            assert_ne!(bytes, other_bytes);
        }
    })
}

pub fn test_controller(env: TestEnv) {
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    let logger = env.logger();
    block_on({
        async move {
            let canister_a = UniversalCanister::new_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                &logger,
            )
            .await;
            let canister_b = UniversalCanister::new_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                &logger,
            )
            .await;

            set_controller(&canister_a.canister_id(), &canister_b.canister_id(), &agent).await;

            // canister_b is the controller of the canister_a, hence we
            // expect 1 to be returned.
            assert_eq!(
                canister_a
                    .update(
                        wasm()
                            .is_controller(canister_b.canister_id().as_ref())
                            .reply_int(),
                    )
                    .await
                    .unwrap(),
                vec![1_u8, 0_u8, 0_u8, 0_u8]
            );

            // Passed Principal ID is not the controller canister_a, hence we
            // expect 0 to be returned.
            assert_eq!(
                canister_a
                    .update(
                        wasm()
                            .is_controller(PrincipalId::new_user_test_id(15).0.as_ref())
                            .reply_int(),
                    )
                    .await
                    .unwrap(),
                vec![0_u8; 4]
            );

            // The passed argument is not Principal ID, hence we
            // expect is_controller to be rejected.
            assert_reject(
                canister_a
                    .update(wasm().is_controller(&[0_u8; 128]).reply_int())
                    .await,
                RejectCode::CanisterError,
            );
        }
    })
}

pub fn test_in_replicated_execution(env: TestEnv) {
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;

            const REPLICATED_EXECUTION: [u8; 4] = [1_u8, 0_u8, 0_u8, 0_u8];
            const NON_REPLICATED_EXECUTION: [u8; 4] = [0_u8, 0_u8, 0_u8, 0_u8];

            // Assert update is in replicated execution.
            assert_eq!(
                canister
                    .update(wasm().in_replicated_execution().reply_int())
                    .await
                    .unwrap(),
                REPLICATED_EXECUTION
            );

            // Assert replicated query is in replicated execution.
            assert_eq!(
                canister
                    .replicated_query(wasm().in_replicated_execution().reply_int())
                    .await
                    .unwrap(),
                REPLICATED_EXECUTION
            );

            // Assert query is NOT in replicated execution.
            assert_eq!(
                canister
                    .query(wasm().in_replicated_execution().reply_int())
                    .await
                    .unwrap(),
                NON_REPLICATED_EXECUTION
            );

            // Assert composite query is NOT in replicated execution.
            assert_eq!(
                canister
                    .composite_query(wasm().in_replicated_execution().reply_int())
                    .await
                    .unwrap(),
                NON_REPLICATED_EXECUTION
            );
        }
    })
}

pub fn test_cycles_burn(env: TestEnv) {
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    let logger = env.logger();
    block_on({
        async move {
            let balance_initial = 1_000_000_000;
            let canister_a = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                Cycles::new(balance_initial),
                &logger,
            )
            .await;
            let amount_to_burn = 1_000_000;
            assert_eq!(
                canister_a
                    .update(
                        wasm()
                            .cycles_burn128(Cycles::new(amount_to_burn))
                            .reply_data_append()
                            .reply()
                            .build()
                    )
                    .await
                    .unwrap(),
                amount_to_burn.to_le_bytes()
            );

            assert_eq!(
                balance_initial - amount_to_burn,
                get_balance(&canister_a.canister_id(), &agent).await
            );
        }
    })
}

/// Decodes a `subnet_metrics` reply and returns it, asserting the fields are
/// plausible.
fn decode_subnet_metrics(bytes: &[u8]) -> ic00::SubnetMetricsResponse {
    let response = Decode!(bytes, ic00::SubnetMetricsResponse).unwrap();
    // The subnet has processed at least the blocks that carried this call.
    assert!(response.block_height > 0_u64);
    response
}

pub fn subnet_metrics_own_subnet_succeeds(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    let subnet_id = app_node.subnet_id().unwrap().get();
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            // Act.
            let result = canister
                .update(wasm().call_simple(
                    ic00::IC_00,
                    Method::SubnetMetrics,
                    call_args().other_side(ic00::SubnetMetricsArgs { subnet_id }.encode()),
                ))
                .await;
            // Assert.
            let bytes = result.expect("subnet_metrics call failed");
            let mut response = decode_subnet_metrics(&bytes);
            // The universal canister itself is on the subnet, and `num_canisters`
            // and `update_transactions_total` are written at the end of every
            // round, so both are non-zero as soon as the canister exists.
            assert!(response.num_canisters > 0_u64);
            assert!(response.update_transactions_total > 0_u64);
            // `canister_state_bytes` is different: it is refreshed only on rounds
            // whose batch number is a multiple of 10
            // (`rs/messaging/src/message_routing.rs`), so it legitimately reads 0
            // for the first rounds after a subnet's first canister appears —
            // measured in-process as 0 at heights 5 and 9, non-zero from height 17.
            // Whether the first read lands before or after a refresh is a race, so
            // re-read until it is populated instead of assuming. Each update
            // advances at least one round, so this terminates well inside the
            // bound; exhausting it means the field never refreshed, which is a
            // real failure.
            for _ in 0..30 {
                if response.canister_state_bytes > 0_u64 {
                    break;
                }
                let bytes = canister
                    .update(wasm().call_simple(
                        ic00::IC_00,
                        Method::SubnetMetrics,
                        call_args().other_side(ic00::SubnetMetricsArgs { subnet_id }.encode()),
                    ))
                    .await
                    .expect("subnet_metrics call failed");
                response = decode_subnet_metrics(&bytes);
            }
            assert!(
                response.canister_state_bytes > 0_u64,
                "canister_state_bytes never refreshed off 0 across 30 rounds; \
                 expected a multiple-of-10 batch to have refreshed it by now"
            );
        }
    })
}

/// A canister on the application subnet calls `subnet_metrics` naming a
/// *different* subnet. Message routing delivers the call to that subnet, which
/// executes it and answers with **its own** metrics.
///
/// The attribution half is what this test is really for, and asserting only that
/// a reply arrives would not test it: a subnet answering a foreign `subnet_id`
/// with its *own* metrics — exactly what the own-subnet check exists to prevent —
/// also replies successfully. So the test perturbs only the *remote* subnet, by
/// installing a canister there, and asserts the remote reading moves. Under that
/// bug the two readings would be local and a remote canister creation could not
/// move them.
///
/// Note also: unlike `node_metrics_history_another_subnet_succeeds`, which calls
/// `get_first_healthy_application_node_snapshot()` twice and so ends up naming its
/// *own* subnet (the test group's `setup` configures a single application subnet),
/// this test names the verified-application subnet, so the call really does cross
/// a subnet boundary.
pub fn subnet_metrics_another_subnet_succeeds(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let other_node = env.get_first_healthy_verified_application_node_snapshot();
    let other_agent = other_node.build_default_agent();
    let logger = env.logger();
    let other_subnet_id = other_node.subnet_id().unwrap().get();
    assert_ne!(other_subnet_id, app_node.subnet_id().unwrap().get());
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;

            let read_remote = || async {
                let result = canister
                    .update(
                        wasm().call_simple(
                            ic00::IC_00,
                            Method::SubnetMetrics,
                            call_args().other_side(
                                ic00::SubnetMetricsArgs {
                                    subnet_id: other_subnet_id,
                                }
                                .encode(),
                            ),
                        ),
                    )
                    .await;
                decode_subnet_metrics(&result.expect("cross-subnet subnet_metrics call failed"))
            };

            // Act.
            let before = read_remote().await;
            // Perturb only the remote subnet.
            let _remote_canister = UniversalCanister::new_with_retries(
                &other_agent,
                other_node.effective_canister_id(),
                &logger,
            )
            .await;
            let after = read_remote().await;

            // Assert: the reply reports the *target* subnet's population, so
            // creating a canister there moves it.
            //
            // Note the direction of the assertion. The tests of this group are
            // registered via `SystemTestGroup::add_parallel(SystemTestSubGroup..)`
            // in `general_execution_test.rs`, and both of those compose under
            // `EvalOrder::Parallel` (`rs/tests/driver/src/driver/group.rs`:
            // `add_parallel` → `add_group(_, EvalOrder::Parallel)`, and
            // `SystemTestSubGroup::new()` sets `ordering: EvalOrder::Parallel`,
            // which `add_test` preserves). So siblings *do* run concurrently and
            // can create canisters on the remote subnet meanwhile — but that can
            // only make `num_canisters` larger, never smaller, so a strict `>`
            // cannot fail spuriously.
            assert!(
                after.num_canisters > before.num_canisters,
                "cross-subnet subnet_metrics did not report the target subnet's \
                 canister population: num_canisters was {} before and {} after \
                 creating a canister on subnet {other_subnet_id}",
                before.num_canisters,
                after.num_canisters,
            );
            // Sanity: the counters advance on the target subnet too.
            assert!(after.block_height > before.block_height);
            assert!(after.update_transactions_total > before.update_transactions_total);
        }
    })
}

pub fn subnet_metrics_non_existing_subnet_fails(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    // Create non existing subnet id.
    let subnet_id = PrincipalId::new_subnet_test_id(1);
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            // Act.
            let result = canister
                .update(wasm().call_simple(
                    ic00::IC_00,
                    Method::SubnetMetrics,
                    call_args().other_side(ic00::SubnetMetricsArgs { subnet_id }.encode()),
                ))
                .await;
            // Assert. The universal canister masks the inner `DestinationInvalid`
            // reject as a `CanisterReject`.
            assert_reject(result, RejectCode::CanisterReject);
        }
    })
}

pub fn subnet_metrics_query_fails(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    let subnet_id = app_node.subnet_id().unwrap().get();
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            // Act.
            let result = canister
                .query(wasm().call_simple(
                    ic00::IC_00,
                    Method::SubnetMetrics,
                    call_args().other_side(ic00::SubnetMetricsArgs { subnet_id }.encode()),
                ))
                .await;
            // Assert. Note that this message comes from `ic0.call_new` being
            // unavailable in a non-replicated query and is method-agnostic, so
            // this test would also pass against a stub implementation. It exists
            // for parity with `node_metrics_history_query_fails`;
            // `subnet_metrics_composite_query_fails` is the test that actually
            // exercises the new code in a query context.
            assert_reject_msg(
                result,
                RejectCode::CanisterError,
                "cannot be executed in non replicated query mode",
            );
        }
    })
}

/// A composite query calling `subnet_metrics` is rejected with a method-specific
/// message.
///
/// Composite-query calls to the management canister do not go through
/// `resolve_destination` at all: `apply_changes` short-circuits them to the caller's
/// own subnet (`rs/embedders/src/wasmtime_embedder/system_api/sandbox_safe_system_state.rs`),
/// where the query handler accepts only the methods listed in `QueryMethod`.
/// `subnet_metrics` is deliberately absent from that allowlist, so the inner call is
/// rejected with `"Query method subnet_metrics not found."`, the universal canister's
/// `on_reject` re-rejects with that message, and the caller sees it.
///
/// Keeping `subnet_metrics` out of `QueryMethod` is load-bearing rather than
/// incidental: the query path has no round-instruction accounting, so the
/// `O(|hot canisters|)` fold would run unmetered on query threads, against a
/// different state snapshot. This test is what fails if it is ever added there.
pub fn subnet_metrics_composite_query_fails(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    let subnet_id = app_node.subnet_id().unwrap().get();
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            // Act.
            let result = canister
                .composite_query(
                    wasm().call_simple(
                        ic00::IC_00,
                        Method::SubnetMetrics,
                        call_args()
                            .other_side(ic00::SubnetMetricsArgs { subnet_id }.encode())
                            // Surfaces the inner reject message, which is what makes
                            // this assertion method-specific rather than a generic
                            // "the query did not succeed" check.
                            .on_reject(wasm().reject_message().reject()),
                    ),
                )
                .await;
            // Assert. The message names the method, so this fails if
            // `subnet_metrics` is ever added to `QueryMethod`.
            assert_reject_msg(
                result,
                RejectCode::CanisterReject,
                "Query method subnet_metrics not found",
            );
        }
    })
}

pub fn node_metrics_history_query_fails(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    let subnet_id = app_node.subnet_id().unwrap().get();
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            // Act.
            let result = canister
                .query(
                    wasm().call_simple(
                        ic00::IC_00,
                        Method::NodeMetricsHistory,
                        call_args().other_side(
                            ic00::NodeMetricsHistoryArgs {
                                subnet_id,
                                start_at_timestamp_nanos: 0,
                            }
                            .encode(),
                        ),
                    ),
                )
                .await;
            // Assert.
            assert_reject_msg(
                result,
                RejectCode::CanisterError,
                "cannot be executed in non replicated query mode",
            );
        }
    })
}

pub fn node_metrics_history_another_subnet_succeeds(env: TestEnv) {
    // Arrange.
    let (app_node_1, agent_1) = setup_app_node_and_agent(&env);
    // Create another subnet and use its id in the request.
    let (app_node_2, _agent_2) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    let subnet_id = app_node_2.subnet_id().unwrap().get();
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent_1,
                app_node_1.effective_canister_id(),
                &logger,
            )
            .await;
            // Act.
            let result = canister
                .update(
                    wasm().call_simple(
                        ic00::IC_00,
                        Method::NodeMetricsHistory,
                        call_args().other_side(
                            ic00::NodeMetricsHistoryArgs {
                                subnet_id,
                                start_at_timestamp_nanos: 0,
                            }
                            .encode(),
                        ),
                    ),
                )
                .await;
            // Assert.
            assert!(result.is_ok());
            assert!(!result.ok().unwrap().is_empty()); // Assert it has some non zero data.
        }
    })
}

pub fn node_metrics_history_non_existing_subnet_fails(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let logger = env.logger();
    // Create non existing subnet id.
    let subnet_id = PrincipalId::new_subnet_test_id(1);
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            // Act.
            let result = canister
                .update(
                    wasm().call_simple(
                        ic00::IC_00,
                        Method::NodeMetricsHistory,
                        call_args().other_side(
                            ic00::NodeMetricsHistoryArgs {
                                subnet_id,
                                start_at_timestamp_nanos: 0,
                            }
                            .encode(),
                        ),
                    ),
                )
                .await;
            // Assert.
            assert_reject(result, RejectCode::CanisterReject);
        }
    })
}

fn root_key_test(agent: &Agent, effective_canister_id: PrincipalId, logger: &Logger) {
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(agent, effective_canister_id, logger).await;
            let result = canister.update(wasm().root_key().append_and_reply()).await;
            let root_key = result.unwrap();
            assert_eq!(root_key, agent.read_root_key());
        }
    })
}

pub fn root_key_on_nns_subnet(env: TestEnv) {
    let (nns_node, agent) = setup_nns_node_and_agent(&env);
    root_key_test(&agent, nns_node.effective_canister_id(), &env.logger());
}

pub fn root_key_on_non_nns_subnet(env: TestEnv) {
    let (app_node, agent) = setup_app_node_and_agent(&env);
    root_key_test(&agent, app_node.effective_canister_id(), &env.logger());
}
