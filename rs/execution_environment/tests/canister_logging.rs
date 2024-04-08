use ic_config::embedders::{Config as EmbeddersConfig, FeatureFlags};
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SubnetConfig;
use ic_management_canister_types::{
    CanisterInstallMode, CanisterLogRecord, CanisterSettingsArgs, CanisterSettingsArgsBuilder,
    DataSize, FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibility, Payload,
    MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE,
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
use std::time::{Duration, SystemTime};

const MAX_LOG_MESSAGE_LEN: usize = 4 * 1024;

fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn default_config_with_canister_logging(canister_logging: FlagStatus) -> ExecutionConfig {
    ExecutionConfig {
        embedders_config: EmbeddersConfig {
            feature_flags: FeatureFlags {
                canister_logging,
                ..FeatureFlags::default()
            },
            ..EmbeddersConfig::default()
        },
        ..ExecutionConfig::default()
    }
}

fn setup(
    canister_logging: FlagStatus,
    settings: CanisterSettingsArgs,
) -> (StateMachine, CanisterId) {
    let subnet_type = SubnetType::Application;
    let config = StateMachineConfig::new(
        SubnetConfig::new(subnet_type),
        default_config_with_canister_logging(canister_logging),
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
        default_config_with_canister_logging(canister_logging),
    ))
}

fn fetch_canister_logs(
    env: StateMachine,
    sender: PrincipalId,
    canister_id: CanisterId,
) -> Result<WasmResult, UserError> {
    env.query_as(
        sender,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    )
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
        let actual_result = fetch_canister_logs(env, sender, canister_id);
        assert_eq!(actual_result, expected_result);
    }
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_replied_update_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let now = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().debug_print(message.as_bytes()).reply().build(),
    );
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: system_time_to_nanos(now),
                content: message.as_bytes().to_vec()
            }]
        }
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_trapped_update_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let now = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().debug_print(message.as_bytes()).trap().build(),
    );
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: system_time_to_nanos(now),
                    content: message.as_bytes().to_vec()
                },
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: system_time_to_nanos(now),
                    content: b"[TRAP]: (no message)".to_vec()
                }
            ]
        }
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_replied_replicated_query_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let now = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "query",
        wasm().debug_print(message.as_bytes()).reply().build(),
    );
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: system_time_to_nanos(now),
                content: message.as_bytes().to_vec()
            }]
        }
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_trapped_replicated_query_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let now = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "query",
        wasm().debug_print(message.as_bytes()).trap().build(),
    );
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: system_time_to_nanos(now),
                    content: message.as_bytes().to_vec()
                },
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: system_time_to_nanos(now),
                    content: b"[TRAP]: (no message)".to_vec()
                }
            ]
        }
    );
}

#[test]
fn test_canister_log_record_index_increment_for_different_calls() {
    // Test that the index of the log records is incremented for each log message,
    // both for logging them in the same and different update calls.
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let now_01 = env.time_of_next_round();
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
    let now_23 = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .debug_print(b"message 2")
            .debug_print(b"message 3")
            .reply()
            .build(),
    );
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: system_time_to_nanos(now_01),
                    content: b"message 0".to_vec()
                },
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: system_time_to_nanos(now_01),
                    content: b"message 1".to_vec()
                },
                CanisterLogRecord {
                    idx: 2,
                    timestamp_nanos: system_time_to_nanos(now_23),
                    content: b"message 2".to_vec()
                },
                CanisterLogRecord {
                    idx: 3,
                    timestamp_nanos: system_time_to_nanos(now_23),
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

    let now_01 = env.time_of_next_round();
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

    let now_23 = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .debug_print(b"message 2")
            .debug_print(b"message 3")
            .reply()
            .build(),
    );
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: system_time_to_nanos(now_01),
                    content: b"message 0".to_vec()
                },
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: system_time_to_nanos(now_01),
                    content: b"message 1".to_vec()
                },
                CanisterLogRecord {
                    idx: 2,
                    timestamp_nanos: system_time_to_nanos(now_23),
                    content: b"message 2".to_vec()
                },
                CanisterLogRecord {
                    idx: 3,
                    timestamp_nanos: system_time_to_nanos(now_23),
                    content: b"message 3".to_vec()
                }
            ],
        }
    );
}

#[test]
fn test_logging_in_trapped_wasm_execution() {
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    // Grow stable memory by 1 page (64kb), reading outside of the page should trap.
    let now = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().stable_grow(1).stable_read(0, 70_000).build(),
    );
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: system_time_to_nanos(now),
                content: b"[TRAP]: stable memory out of bounds".to_vec()
            }]
        }
    );
}

#[test]
fn test_logging_explicit_canister_trap_without_message() {
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let now = env.time_of_next_round();
    let _ = env.execute_ingress(canister_id, "update", wasm().trap().build());
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: system_time_to_nanos(now),
                content: b"[TRAP]: (no message)".to_vec()
            }]
        }
    );
}

#[test]
fn test_logging_explicit_canister_trap_with_message() {
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let now = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().trap_with_blob(b"some text").build(),
    );
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![CanisterLogRecord {
                idx: 0,
                timestamp_nanos: system_time_to_nanos(now),
                content: b"[TRAP]: some text".to_vec()
            }]
        }
    );
}

#[test]
fn test_canister_log_stays_within_limit() {
    // Test that the total size of canister log records stays within the limit
    // even if the are many log messages sent in different calls.
    const MESSAGES_NUMBER: usize = 10;
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    for _ in 0..MESSAGES_NUMBER {
        env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .debug_print(&[42; MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE])
                .reply()
                .build(),
        )
        .unwrap();
        env.tick();
    }
    let result = fetch_canister_logs(env, controller, canister_id);
    let response = FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap();
    // Expect that the total size of the log records is less than the limit.
    assert!(response.canister_log_records.data_size() <= MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE);
}

#[test]
fn test_canister_log_stays_empty_when_feature_is_disabled() {
    // Test that the total size of canister log in canister state is empty
    // even if the are many log messages sent in different calls (both via print and trap).
    const MESSAGES_NUMBER: usize = 10;
    let (env, canister_id, _controller) = setup_with_controller(FlagStatus::Disabled);
    for _ in 0..MESSAGES_NUMBER {
        let _ = env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .debug_print(&[b'd'; MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE])
                .trap_with_blob(&[b't'; MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE])
                .reply()
                .build(),
        );
    }
    // Expect that the total size of the log in canister state is zero.
    assert_eq!(env.canister_log(canister_id).used_space(), 0);
}

#[test]
fn test_canister_log_in_state_stays_within_limit() {
    // Test that the total size of canister log in canister state stays within the limit
    // even if the are many log messages sent in different calls (both via print and trap).
    const MESSAGES_NUMBER: usize = 10;
    let (env, canister_id, _controller) = setup_with_controller(FlagStatus::Enabled);
    for _ in 0..MESSAGES_NUMBER {
        let _ = env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .debug_print(&[b'd'; MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE])
                .trap_with_blob(&[b't'; MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE])
                .reply()
                .build(),
        );
    }
    // Expect that the total size of the log in canister state is not zero and less than the limit.
    let log_size = env.canister_log(canister_id).used_space();
    assert!(0 < log_size);
    assert!(log_size <= MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE);
}

#[test]
fn test_logging_trap_in_heartbeat() {
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let heartbeat = wasm()
        .debug_print(b"before trap")
        .trap_with_blob(b"heartbeat trap!")
        .build();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().set_heartbeat(heartbeat).build(),
    );
    let now = env.time_of_next_round();
    env.tick();
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: system_time_to_nanos(now),
                    content: b"before trap".to_vec()
                },
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: system_time_to_nanos(now),
                    content: b"[TRAP]: heartbeat trap!".to_vec()
                }
            ]
        }
    );
}

#[test]
fn test_logging_trap_in_timer() {
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    let timer = wasm()
        .debug_print(b"before trap")
        .trap_with_blob(b"timer trap!")
        .build();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .set_global_timer_method(timer)
            .api_global_timer_set(1)
            .build(),
    );
    let now = env.time_of_next_round();
    env.tick();
    let result = fetch_canister_logs(env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: system_time_to_nanos(now),
                    content: b"before trap".to_vec()
                },
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: system_time_to_nanos(now),
                    content: b"[TRAP]: timer trap!".to_vec()
                }
            ]
        }
    );
}

#[test]
fn test_canister_log_preserved_after_disabling_and_enabling_again() {
    // Test that the logs are recorded when the feature is enabled
    // and preserved (not deleted) when the feature gets disabled.
    let (env, canister_id, controller) = setup_with_controller(FlagStatus::Enabled);
    env.set_checkpoints_enabled(true);

    // Feature is enabled, batch #1.
    let now_1 = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().debug_print(b"message 1").reply().build(),
    );

    // Disable the feature and log batch #2.
    let env = restart_node(env, FlagStatus::Disabled);
    env.advance_time(Duration::from_nanos(111_111));
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().debug_print(b"message 2").reply().build(),
    );

    // Enable the feature again and log batch #3.
    let env = restart_node(env, FlagStatus::Enabled);
    env.advance_time(Duration::from_nanos(222_222));
    let now_3 = env.time_of_next_round();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm().debug_print(b"message 3").reply().build(),
    );

    // Expect only batches 1 and 3.
    let result = fetch_canister_logs(env, controller, canister_id);
    let data = FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap();
    assert_eq!(data.canister_log_records.len(), 2);
    assert_eq!(
        data,
        FetchCanisterLogsResponse {
            canister_log_records: vec![
                // Batch #1.
                CanisterLogRecord {
                    idx: 0,
                    timestamp_nanos: system_time_to_nanos(now_1),
                    content: b"message 1".to_vec()
                },
                // No batch #2 records.
                // Batch #3.
                CanisterLogRecord {
                    idx: 1,
                    timestamp_nanos: system_time_to_nanos(now_3),
                    content: b"message 3".to_vec()
                },
            ],
        }
    );
}
