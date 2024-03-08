use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SubnetConfig;
use ic_management_canister_types::{
    CanisterInstallMode, CanisterLogRecord, CanisterSettingsArgs, CanisterSettingsArgsBuilder,
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibility, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    ErrorCode, PrincipalId, StateMachine, StateMachineBuilder, StateMachineConfig,
    SubmitIngressError, UserError,
};
use ic_test_utilities::universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};
use ic_test_utilities_execution_environment::get_reply;
use ic_types::{ingress::WasmResult, CanisterId, Cycles};
use proptest::{prelude::ProptestConfig, prop_assume};
use std::time::Duration;

const MAX_LOG_MESSAGE_LEN: usize = 4 * 1024;

fn setup(
    canister_logging: FlagStatus,
    settings: CanisterSettingsArgs,
) -> (StateMachine, CanisterId) {
    let subnet_type = SubnetType::Application;
    let config = StateMachineConfig::new(
        SubnetConfig::new(subnet_type),
        ExecutionConfig {
            canister_logging,
            ..ExecutionConfig::default()
        },
    );
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .with_checkpoints_enabled(false)
        .build();
    let canister_id =
        env.create_canister_with_cycles(None, Cycles::from(100_000_000_000_u128), Some(settings));
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
    )
    .unwrap();

    (env, canister_id)
}

fn setup_with_controller(
    fetch_canister_logs: FlagStatus,
) -> (StateMachine, CanisterId, PrincipalId) {
    let controller = PrincipalId::new_user_test_id(42);
    let (env, canister_id) = setup(
        fetch_canister_logs,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Controllers)
            .with_controller(controller)
            .build(),
    );
    (env, canister_id, controller)
}

fn restart_node(env: StateMachine, canister_logging: FlagStatus) -> StateMachine {
    env.restart_node_with_config(StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        ExecutionConfig {
            canister_logging,
            ..ExecutionConfig::default()
        },
    ))
}

#[test]
fn test_fetch_canister_logs_via_submit_ingress() {
    // Test fetch_canister_logs API call results depending on the feature flag.
    let error = Err(SubmitIngressError::UserError(UserError::new(
        ErrorCode::CanisterRejectedMessage,
        "fetch_canister_logs API is only accessible in non-replicated mode",
    )));
    let test_cases = vec![
        // (feature flag, expected result)
        (FlagStatus::Disabled, error.clone()),
        (FlagStatus::Enabled, error),
    ];
    for (feature_flag, expected_result) in test_cases {
        let (env, canister_id) = setup(
            feature_flag,
            CanisterSettingsArgsBuilder::new()
                .with_log_visibility(LogVisibility::Public)
                .build(),
        );
        let actual_result = env.submit_ingress_as(
            PrincipalId::new_anonymous(), // Any public user.
            CanisterId::ic_00(),
            "fetch_canister_logs",
            FetchCanisterLogsRequest::new(canister_id).encode(),
        );
        assert_eq!(actual_result, expected_result);
    }
}

#[test]
fn test_fetch_canister_logs_via_execute_ingress() {
    // Test fetch_canister_logs API call results depending on the feature flag.
    let error = Err(UserError::new(
        ErrorCode::CanisterRejectedMessage,
        "fetch_canister_logs API is only accessible in non-replicated mode",
    ));
    let test_cases = vec![
        // (feature flag, expected result)
        (FlagStatus::Disabled, error.clone()),
        (FlagStatus::Enabled, error),
    ];
    for (feature_flag, expected_result) in test_cases {
        let (env, canister_id) = setup(
            feature_flag,
            CanisterSettingsArgsBuilder::new()
                .with_log_visibility(LogVisibility::Public)
                .build(),
        );
        let actual_result = env.execute_ingress_as(
            PrincipalId::new_anonymous(), // Any public user.
            CanisterId::ic_00(),
            "fetch_canister_logs",
            FetchCanisterLogsRequest::new(canister_id).encode(),
        );
        assert_eq!(actual_result, expected_result);
    }
}

#[test]
fn test_fetch_canister_logs_via_query_call() {
    // Test fetch_canister_logs API call results depending on the feature flag.
    let test_cases = vec![
        // (feature flag, expected result)
        (
            FlagStatus::Disabled,
            Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                "fetch_canister_logs API is not enabled on this subnet",
            )),
        ),
        (
            FlagStatus::Enabled,
            Ok(WasmResult::Reply(
                FetchCanisterLogsResponse {
                    canister_log_records: vec![],
                }
                .encode(),
            )),
        ),
    ];
    for (feature_flag, expected_result) in test_cases {
        let (env, canister_id) = setup(
            feature_flag,
            CanisterSettingsArgsBuilder::new()
                .with_log_visibility(LogVisibility::Public)
                .build(),
        );
        let actual_result = env.query_as(
            PrincipalId::new_anonymous(), // Any public user.
            CanisterId::ic_00(),
            "fetch_canister_logs",
            FetchCanisterLogsRequest::new(canister_id).encode(),
        );
        assert_eq!(actual_result, expected_result);
    }
}

#[test]
fn test_log_visibility_of_fetch_canister_logs() {
    // Test combinations of log_visibility and sender for fetch_canister_logs API call.
    let controller = PrincipalId::new_user_test_id(27);
    let not_a_controller = PrincipalId::new_user_test_id(42);
    let ok = Ok(WasmResult::Reply(
        FetchCanisterLogsResponse {
            canister_log_records: vec![],
        }
        .encode(),
    ));
    let error = Err(UserError::new(
        ErrorCode::CanisterRejectedMessage,
        format!(
            "Caller {not_a_controller} is not allowed to query ic00 method fetch_canister_logs"
        ),
    ));
    let test_cases = vec![
        // (log_visibility, sender, expected_result)
        (LogVisibility::Public, controller, ok.clone()),
        (LogVisibility::Public, not_a_controller, ok.clone()),
        (LogVisibility::Controllers, controller, ok),
        (LogVisibility::Controllers, not_a_controller, error),
    ];
    for (log_visibility, sender, expected_result) in test_cases {
        let (env, canister_id) = setup(
            FlagStatus::Enabled,
            CanisterSettingsArgsBuilder::new()
                .with_log_visibility(log_visibility)
                .with_controller(controller)
                .build(),
        );
        let actual_result = env.query_as(
            sender,
            CanisterId::ic_00(),
            "fetch_canister_logs",
            FetchCanisterLogsRequest::new(canister_id).encode(),
        );
        assert_eq!(actual_result, expected_result);
    }
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_replied_update_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().debug_print(message.as_bytes()).reply().build(),
    );
    let result = env.query_as(
        controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: 1620328630000000000,
                content: message.as_bytes().to_vec()
            }]
        }
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_trapped_update_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().debug_print(message.as_bytes()).trap().build(),
    );
    let result = env.query_as(
        controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: 1620328630000000000,
                content: message.as_bytes().to_vec()
            }]
        }
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_replied_replicated_query_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let _ = env.execute_ingress(
        canister_id,
        "query",
        wasm().debug_print(message.as_bytes()).reply().build(),
    );
    let result = env.query_as(
        controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: 1620328630000000000,
                content: message.as_bytes().to_vec()
            }]
        }
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_trapped_replicated_query_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let _ = env.execute_ingress(
        canister_id,
        "query",
        wasm().debug_print(message.as_bytes()).trap().build(),
    );
    let result = env.query_as(
        controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: 1620328630000000000,
                content: message.as_bytes().to_vec()
            }]
        }
    );
}

#[test]
fn test_canister_log_record_index_increment_for_different_calls() {
    // Test that the index of the log records is incremented for each log message,
    // both for logging them in the same and different update calls.
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .debug_print(b"message 0")
            .debug_print(b"message 1")
            .reply()
            .build(),
    );
    env.advance_time(Duration::from_nanos(123_456));
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .debug_print(b"message 2")
            .debug_print(b"message 3")
            .reply()
            .build(),
    );
    let result = env.query_as(
        controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: 1620328630000000000,
                    content: b"message 0".to_vec()
                },
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: 1620328630000000000,
                    content: b"message 1".to_vec()
                },
                CanisterLogRecord {
                    idx: 2,
                    timestamp_nanos: 1620328630000123456,
                    content: b"message 2".to_vec()
                },
                CanisterLogRecord {
                    idx: 3,
                    timestamp_nanos: 1620328630000123456,
                    content: b"message 3".to_vec()
                }
            ],
        }
    );
}

#[test]
fn test_canister_log_record_index_increment_after_node_restart() {
    // Test that the index of the log records is incremented for each log message
    // even after checkpoint and node restart.
    let canister_logging = FlagStatus::Enabled;
    let (env, canister_id, controller) = setup_with_controller(canister_logging);
    env.set_checkpoints_enabled(true);

    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .debug_print(b"message 0")
            .debug_print(b"message 1")
            .reply()
            .build(),
    );

    let env = restart_node(env, canister_logging);
    env.advance_time(Duration::from_nanos(123_456));

    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .debug_print(b"message 2")
            .debug_print(b"message 3")
            .reply()
            .build(),
    );
    let result = env.query_as(
        controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: 1620328630000000000,
                    content: b"message 0".to_vec()
                },
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: 1620328630000000000,
                    content: b"message 1".to_vec()
                },
                CanisterLogRecord {
                    idx: 2,
                    timestamp_nanos: 1620328630000123456,
                    content: b"message 2".to_vec()
                },
                CanisterLogRecord {
                    idx: 3,
                    timestamp_nanos: 1620328630000123456,
                    content: b"message 3".to_vec()
                }
            ],
        }
    );
}
