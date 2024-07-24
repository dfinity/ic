/* tag::catalog[]
end::catalog[] */

use candid::Principal;
use ic_agent::{agent::RejectCode, Agent, AgentError};
use ic_base_types::PrincipalId;
use ic_management_canister_types::{self as ic00, EmptyBlob, Method, Payload};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::GetFirstHealthyNodeSnapshot;
use ic_system_test_driver::driver::test_env_api::HasPublicApiUrl;
use ic_system_test_driver::driver::test_env_api::IcNodeSnapshot;
use ic_system_test_driver::util::*;
use ic_types::Cycles;
use ic_universal_canister::{call_args, wasm};

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

            // Calling raw_rand as a query fails.
            let result_query = canister
                .query(wasm().call_simple(
                    ic00::IC_00,
                    Method::RawRand,
                    call_args().other_side(EmptyBlob.encode()),
                ))
                .await;

            assert_reject(result_query, RejectCode::CanisterError);

            // Calling raw_rand as an update succeeds.
            canister
                .update(wasm().call_simple(
                    ic00::IC_00,
                    Method::RawRand,
                    call_args().other_side(EmptyBlob.encode()),
                ))
                .await
                .unwrap();
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
                vec![1u8, 0u8, 0u8, 0u8]
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
                vec![0u8; 4]
            );

            // The passed argument is not Principal ID, hence we
            // expect is_controller to be rejected.
            assert_reject(
                canister_a
                    .update(wasm().is_controller(&[0u8; 128]).reply_int())
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

            const REPLICATED_EXECUTION: [u8; 4] = [1u8, 0u8, 0u8, 0u8];
            const NON_REPLICATED_EXECUTION: [u8; 4] = [0u8, 0u8, 0u8, 0u8];

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

pub fn node_metrics_history_update_succeeds(env: TestEnv) {
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

pub fn node_metrics_history_ingress_update_fails(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let subnet_id = app_node.subnet_id().unwrap().get();
    block_on({
        async move {
            // Act.
            let result = agent
                .update(&Principal::management_canister(), "node_metrics_history")
                .with_arg(
                    ic00::NodeMetricsHistoryArgs {
                        subnet_id,
                        start_at_timestamp_nanos: 0,
                    }
                    .encode(),
                )
                .call_and_wait()
                .await;
            // Assert.
            assert_reject_msg(
                result,
                RejectCode::CanisterReject,
                "ic00 method node_metrics_history can not be called via ingress messages",
            );
        }
    })
}

pub fn node_metrics_history_ingress_query_fails(env: TestEnv) {
    // Arrange.
    let (app_node, agent) = setup_app_node_and_agent(&env);
    let subnet_id = app_node.subnet_id().unwrap().get();
    block_on({
        async move {
            // Act.
            let result = agent
                .query(&Principal::management_canister(), "node_metrics_history")
                .with_arg(
                    ic00::NodeMetricsHistoryArgs {
                        subnet_id,
                        start_at_timestamp_nanos: 0,
                    }
                    .encode(),
                )
                .call()
                .await;
            // Assert.
            assert_eq!(result, Err(AgentError::CertificateNotAuthorized()));
        }
    })
}
