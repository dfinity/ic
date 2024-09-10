use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_management_canister_types::{
    self as ic00, BoundedAllowedViewers, CanisterIdRecord, CanisterInstallMode, CanisterLogRecord,
    CanisterSettingsArgs, CanisterSettingsArgsBuilder, DataSize, EmptyBlob,
    FetchCanisterLogsRequest, FetchCanisterLogsResponse, LogVisibilityV2, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    ErrorCode, PrincipalId, StateMachine, StateMachineBuilder, StateMachineConfig,
    SubmitIngressError, UserError,
};
use ic_test_utilities::universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use ic_test_utilities_execution_environment::{get_reply, wat_canister, wat_fn};
use ic_test_utilities_metrics::{fetch_histogram_stats, fetch_histogram_vec_stats, labels};
use ic_types::{
    ingress::WasmResult, CanisterId, Cycles, NumInstructions, MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE,
};
use more_asserts::{assert_le, assert_lt};
use proptest::{prelude::ProptestConfig, prop_assume};
use std::time::{Duration, SystemTime};

const MAX_LOG_MESSAGE_LEN: usize = 4 * 1024;
const TIME_STEP: Duration = Duration::from_nanos(111_111);

// Change limits in order not to duplicate prod values.
const B: u64 = 1_000_000_000;
const MAX_INSTRUCTIONS_PER_ROUND: NumInstructions = NumInstructions::new(5 * B);
const MAX_INSTRUCTIONS_PER_MESSAGE: NumInstructions = NumInstructions::new(20 * B);
const MAX_INSTRUCTIONS_PER_SLICE: NumInstructions = NumInstructions::new(B);

fn system_time_to_nanos(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn canister_log_response(data: Vec<(u64, u64, Vec<u8>)>) -> FetchCanisterLogsResponse {
    FetchCanisterLogsResponse {
        canister_log_records: data
            .into_iter()
            .map(|(idx, timestamp_nanos, content)| CanisterLogRecord {
                idx,
                timestamp_nanos,
                content,
            })
            .collect(),
    }
}

fn setup(settings: CanisterSettingsArgs) -> (StateMachine, CanisterId) {
    let subnet_type = SubnetType::Application;
    let mut subnet_config = SubnetConfig::new(subnet_type);
    subnet_config.scheduler_config.max_instructions_per_round = MAX_INSTRUCTIONS_PER_ROUND;
    subnet_config.scheduler_config.max_instructions_per_message = MAX_INSTRUCTIONS_PER_MESSAGE;
    subnet_config.scheduler_config.max_instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE;
    let config = StateMachineConfig::new(subnet_config, ExecutionConfig::default());
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .with_checkpoints_enabled(false)
        .build();
    let canister_id =
        env.create_canister_with_cycles(None, Cycles::from(100_000_000_000_u128), Some(settings));

    (env, canister_id)
}

fn setup_and_install_wasm(
    settings: CanisterSettingsArgs,
    wasm: Vec<u8>,
) -> (StateMachine, CanisterId) {
    let (env, canister_id) = setup(settings);
    env.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, vec![])
        .unwrap();

    (env, canister_id)
}

fn setup_with_controller(wasm: Vec<u8>) -> (StateMachine, CanisterId, PrincipalId) {
    let controller = PrincipalId::new_user_test_id(42);
    let (env, canister_id) = setup_and_install_wasm(
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibilityV2::Controllers)
            .with_controllers(vec![controller])
            .build(),
        wasm,
    );
    (env, canister_id, controller)
}

fn restart_node(env: StateMachine) -> StateMachine {
    env.restart_node_with_config(StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        ExecutionConfig::default(),
    ))
}

fn fetch_canister_logs(
    env: &StateMachine,
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
    let (env, canister_id) = setup_and_install_wasm(
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibilityV2::Public)
            .build(),
        wat_canister().build_wasm(),
    );
    let result = env.submit_ingress_as(
        PrincipalId::new_anonymous(), // Any public user.
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        result,
        Err(SubmitIngressError::UserError(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            "ic00 method fetch_canister_logs can not be called via ingress messages",
        )))
    );
}

#[test]
fn test_fetch_canister_logs_via_execute_ingress() {
    // Test fetch_canister_logs API call results.
    let (env, canister_id) = setup_and_install_wasm(
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibilityV2::Public)
            .build(),
        wat_canister().build_wasm(),
    );
    let result = env.execute_ingress_as(
        PrincipalId::new_anonymous(), // Any public user.
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            "ic00 method fetch_canister_logs can not be called via ingress messages",
        ))
    );
}

#[test]
fn test_fetch_canister_logs_via_query_call() {
    // Test fetch_canister_logs API call results.
    let (env, canister_id) = setup_and_install_wasm(
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibilityV2::Public)
            .build(),
        wat_canister().build_wasm(),
    );
    let result = env.query_as(
        PrincipalId::new_anonymous(), // Any public user.
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest::new(canister_id).encode(),
    );
    assert_eq!(
        result,
        Ok(WasmResult::Reply(
            FetchCanisterLogsResponse {
                canister_log_records: vec![],
            }
            .encode(),
        ))
    );
}

#[test]
fn test_metrics_for_fetch_canister_logs_via_query_call() {
    fn fetch_canister_logs_count(env: &StateMachine) -> u64 {
        fetch_histogram_vec_stats(
            &env.metrics_registry(),
            "execution_subnet_query_message_duration_seconds",
        )
        .get(&labels(&[(
            "method_name",
            "query_ic00_fetch_canister_logs",
        )]))
        .map_or(0, |stats| stats.count)
    }
    let (env, canister_id, controller) = setup_with_controller(wat_canister().build_wasm());

    assert_eq!(fetch_canister_logs_count(&env), 0);
    let _ = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(fetch_canister_logs_count(&env), 1);
}

#[test]
fn test_fetch_canister_logs_via_composite_query_call() {
    // Test that fetch_canister_logs API is not accessible via composite query call.
    // There are 3 actors with the following controller relatioship: user -> canister_a -> canister_b.
    // The user uses composite_query to canister_a to fetch logs of canister_b, which should fail.
    let (env, canister_a, user) = setup_with_controller(UNIVERSAL_CANISTER_WASM.to_vec());

    // Create canister_b controlled by canister_a.
    let canister_b = env.create_canister_with_cycles(
        None,
        Cycles::from(100_000_000_000_u128),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![canister_a.get()])
                .build(),
        ),
    );

    // User attempts to fetch logs of canister_b via canister_a.
    let actual_result = env.query_as(
        user,
        canister_a,
        "composite_query",
        wasm()
            .call_simple(
                CanisterId::ic_00(),
                "fetch_canister_logs",
                call_args()
                    .other_side(FetchCanisterLogsRequest::new(canister_b).encode())
                    .on_reject(wasm().reject_message().reject()),
            )
            .build(),
    );

    // This is expected to fail, because fetch_canister_logs is not accessible via composite query.
    let error = actual_result.unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterDidNotReply);
    // TODO(EXC-1655): fix reject response propagation.
    let expected_error_message = "did not produce a response";
    assert!(
        error.description().contains(expected_error_message),
        "Expected: {}\nActual: {}",
        expected_error_message,
        error.description()
    );
}

#[test]
fn test_log_visibility_of_fetch_canister_logs() {
    // Test combinations of log_visibility and sender for fetch_canister_logs API call.
    let controller = PrincipalId::new_user_test_id(1);
    let not_a_controller = PrincipalId::new_user_test_id(2);
    let allowed_viewer = PrincipalId::new_user_test_id(3);
    let not_allowed_viewer = PrincipalId::new_user_test_id(4);
    let allowed_viewers = BoundedAllowedViewers::new(vec![allowed_viewer]);
    let ok = Ok(WasmResult::Reply(
        FetchCanisterLogsResponse {
            canister_log_records: vec![],
        }
        .encode(),
    ));
    fn not_allowed_error(caller: &PrincipalId) -> Result<WasmResult, UserError> {
        Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!("Caller {caller} is not allowed to query ic00 method fetch_canister_logs"),
        ))
    }
    let test_cases = vec![
        // (log_visibility, sender, expected_result)
        (LogVisibilityV2::Public, controller, ok.clone()),
        (LogVisibilityV2::Public, not_a_controller, ok.clone()),
        (LogVisibilityV2::Controllers, controller, ok.clone()),
        (
            LogVisibilityV2::Controllers,
            not_a_controller,
            not_allowed_error(&not_a_controller),
        ),
        (
            LogVisibilityV2::AllowedViewers(allowed_viewers.clone()),
            allowed_viewer,
            // TODO(EXC-1675): when disabled works as for controllers, change to ok when enabled.
            not_allowed_error(&allowed_viewer),
        ),
        (
            LogVisibilityV2::AllowedViewers(allowed_viewers.clone()),
            not_allowed_viewer,
            not_allowed_error(&not_allowed_viewer),
        ),
        (
            LogVisibilityV2::AllowedViewers(allowed_viewers),
            controller,
            ok,
        ),
    ];
    for (log_visibility, sender, expected_result) in test_cases {
        let (env, canister_id) = setup_and_install_wasm(
            CanisterSettingsArgsBuilder::new()
                .with_log_visibility(log_visibility.clone())
                .with_controllers(vec![controller])
                .build(),
            wat_canister().build_wasm(),
        );
        let actual_result = fetch_canister_logs(&env, sender, canister_id);
        assert_eq!(
            actual_result, expected_result,
            "Failed for log_visibility: {log_visibility:?}, sender: {sender}"
        );
    }
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_replied_update_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update("test", wat_fn().debug_print(message.as_bytes()))
            .build_wasm(),
    );
    let timestamp = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![(0, timestamp, message.as_bytes().to_vec())])
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_trapped_update_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update("test", wat_fn().debug_print(message.as_bytes()).trap())
            .build_wasm(),
    );
    let timestamp = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp, message.as_bytes().to_vec()),
            (1, timestamp, b"[TRAP]: (no message)".to_vec())
        ])
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_replied_replicated_query_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .query("test", wat_fn().debug_print(message.as_bytes()))
            .build_wasm(),
    );
    let timestamp = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![(0, timestamp, message.as_bytes().to_vec())])
    );
}

#[test_strategy::proptest(ProptestConfig { cases: 5, ..ProptestConfig::default() })]
fn test_appending_logs_in_trapped_replicated_query_call(#[strategy("\\PC*")] message: String) {
    prop_assume!(message.len() < MAX_LOG_MESSAGE_LEN);
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .query("test", wat_fn().debug_print(message.as_bytes()).trap())
            .build_wasm(),
    );
    let timestamp = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp, message.as_bytes().to_vec()),
            (1, timestamp, b"[TRAP]: (no message)".to_vec().to_vec()),
        ])
    );
}

#[test]
fn test_canister_log_record_index_increment_for_different_calls() {
    // Test that the index of the log records is incremented for each log message,
    // both for logging them in the same and different update calls.
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update(
                "test1",
                wat_fn().debug_print(b"message 0").debug_print(b"message 1"),
            )
            .update(
                "test2",
                wat_fn().debug_print(b"message 2").debug_print(b"message 3"),
            )
            .build_wasm(),
    );

    // First call.
    let timestamp_01 = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test1", vec![]);

    // Second call.
    env.advance_time(Duration::from_nanos(123_456));
    let timestamp_23 = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test2", vec![]);

    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_01, b"message 0".to_vec()),
            (1, timestamp_01, b"message 1".to_vec()),
            (2, timestamp_23, b"message 2".to_vec()),
            (3, timestamp_23, b"message 3".to_vec()),
        ])
    );
}

#[test]
fn test_canister_log_record_index_increment_after_node_restart() {
    // Test that the index of the log records is incremented for each log message
    // even after checkpoint and node restart.
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update(
                "test1",
                wat_fn().debug_print(b"message 0").debug_print(b"message 1"),
            )
            .update(
                "test2",
                wat_fn().debug_print(b"message 2").debug_print(b"message 3"),
            )
            .build_wasm(),
    );
    env.set_checkpoints_enabled(true);

    // First call.
    let timestamp_01 = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test1", vec![]);

    // Node restart.
    let env = restart_node(env);
    env.advance_time(Duration::from_nanos(123_456));

    // Second call.
    let timestamp_23 = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test2", vec![]);

    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_01, b"message 0".to_vec()),
            (1, timestamp_01, b"message 1".to_vec()),
            (2, timestamp_23, b"message 2".to_vec()),
            (3, timestamp_23, b"message 3".to_vec()),
        ])
    );
}

#[test]
fn test_logging_in_trapped_wasm_execution() {
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update("test", wat_fn().stable_grow(1).stable_read(0, 70_000))
            .build_wasm(),
    );
    // Grow stable memory by 1 page (64kb), reading outside of the page should trap.
    let timestamp = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![(
            0,
            timestamp,
            b"[TRAP]: stable memory out of bounds".to_vec()
        )])
    );
}

#[test]
fn test_logging_explicit_canister_trap_without_message() {
    let (env, canister_id, controller) =
        setup_with_controller(wat_canister().update("test", wat_fn().trap()).build_wasm());
    let timestamp = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![(0, timestamp, b"[TRAP]: (no message)".to_vec())])
    );
}

#[test]
fn test_logging_explicit_canister_trap_with_message() {
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update("test", wat_fn().trap_with_blob(b"some text"))
            .build_wasm(),
    );
    let timestamp = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![(0, timestamp, b"[TRAP]: some text".to_vec())])
    );
}

#[test]
fn test_canister_log_stays_within_limit() {
    // Test that the total size of canister log records stays within the limit
    // even if the are many log messages sent in different calls.
    const MESSAGES_NUMBER: usize = 10;
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update(
                "test",
                wat_fn().debug_print(&[42; MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE]),
            )
            .build_wasm(),
    );
    for _ in 0..MESSAGES_NUMBER {
        let _ = env.execute_ingress(canister_id, "test", vec![]);
        env.tick();
    }
    let result = fetch_canister_logs(&env, controller, canister_id);
    let response = FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap();
    // Expect records' total size to be under the limit, excluding the outer vector's static size.
    assert_le!(
        response
            .canister_log_records
            .iter()
            .map(|r| r.data_size())
            .sum::<usize>(),
        MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE
    );
}

#[test]
fn test_canister_log_in_state_stays_within_limit() {
    // Test that the total size of canister log in canister state stays within the limit
    // even if the are many log messages sent in different calls (both via print and trap).
    const MESSAGES_NUMBER: usize = 10;
    let (env, canister_id, _controller) = setup_with_controller(
        wat_canister()
            .update(
                "test",
                wat_fn()
                    .debug_print(&[b'd'; MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE])
                    .trap_with_blob(&[b't'; MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE]),
            )
            .build_wasm(),
    );
    for _ in 0..MESSAGES_NUMBER {
        let _ = env.execute_ingress(canister_id, "test", vec![]);
    }
    // Expect that the total size of the log in canister state is not zero and less than the limit.
    let log_size = env.canister_log(canister_id).used_space();
    assert_lt!(0, log_size);
    assert_le!(log_size, MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE);
}

#[test]
fn test_logging_trap_in_heartbeat() {
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .heartbeat(
                wat_fn()
                    .debug_print(b"before trap")
                    .trap_with_blob(b"heartbeat trap!"),
            )
            .build_wasm(),
    );
    let timestamp = system_time_to_nanos(env.time());
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp, b"before trap".to_vec()),
            (1, timestamp, b"[TRAP]: heartbeat trap!".to_vec())
        ])
    );
}

#[test]
fn test_logging_trap_in_timer() {
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .init(wat_fn().api_global_timer_set(1))
            .global_timer(
                wat_fn()
                    .debug_print(b"before trap")
                    .trap_with_blob(b"timer trap!"),
            )
            .build_wasm(),
    );
    let timestamp = system_time_to_nanos(env.time());
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp, b"before trap".to_vec()),
            (1, timestamp, b"[TRAP]: timer trap!".to_vec())
        ])
    );
}

#[test]
fn test_deleting_logs_on_reinstall() {
    // Test logs are deleted on canister reinstall.
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .start(wat_fn().debug_print(b"start_1"))
            .init(wat_fn().debug_print(b"init_1"))
            .update("test_1", wat_fn().debug_print(b"test_1"))
            .build_wasm(),
    );
    let timestamp_1_init = system_time_to_nanos(env.time());
    env.advance_time(TIME_STEP);

    // Prepopulate log.
    let timestamp_1_update = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test_1", vec![]);
    env.advance_time(TIME_STEP);

    // Expect the log record from cansiter version #1.
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_1_init, b"start_1".to_vec()),
            (1, timestamp_1_init, b"init_1".to_vec()),
            (2, timestamp_1_update, b"test_1".to_vec())
        ])
    );

    // Reinstall canister to version #2.
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Reinstall,
        wat_canister()
            .start(wat_fn().debug_print(b"start_2"))
            .init(wat_fn().debug_print(b"init_2"))
            .update("test_2", wat_fn().debug_print(b"test_2"))
            .build_wasm(),
        vec![],
    )
    .unwrap();
    env.advance_time(TIME_STEP);

    // Populate log after reinstall.
    let timestamp_2_update = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test_2", vec![]);
    env.advance_time(TIME_STEP);

    // Expect only the log records after reinstall.
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![(5, timestamp_2_update, b"test_2".to_vec())])
    );
}

#[test]
fn test_deleting_logs_on_uninstall() {
    // Test logs are deleted when the canister is uninstalled.
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .start(wat_fn().debug_print(b"start_1"))
            .init(wat_fn().debug_print(b"init_1"))
            .update("test_1", wat_fn().debug_print(b"test_1"))
            .build_wasm(),
    );
    let timestamp_1_init = system_time_to_nanos(env.time());
    env.advance_time(TIME_STEP);

    // Prepopulate log.
    let timestamp_1_update = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test_1", vec![]);
    env.advance_time(TIME_STEP);

    // Stop canister.
    env.stop_canister_as(controller, canister_id).unwrap();

    // Expect logs to be available.
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_1_init, b"start_1".to_vec()),
            (1, timestamp_1_init, b"init_1".to_vec()),
            (2, timestamp_1_update, b"test_1".to_vec())
        ])
    );

    // Uninstall canister.
    env.execute_ingress_as(
        controller,
        CanisterId::ic_00(),
        "uninstall_code",
        (CanisterIdRecord::from(canister_id)).encode(),
    )
    .unwrap();

    // Expect logs to be deleted.
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![])
    );
}

#[test]
fn test_logging_debug_print_persists_over_upgrade() {
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .start(wat_fn().debug_print(b"start_1"))
            .init(wat_fn().debug_print(b"init_1"))
            .pre_upgrade(wat_fn().debug_print(b"pre_upgrade_1"))
            .post_upgrade(wat_fn().debug_print(b"post_upgrade_1"))
            .update("test", wat_fn().debug_print(b"update_1"))
            .build_wasm(),
    );
    let timestamp_init = system_time_to_nanos(env.time());
    env.advance_time(TIME_STEP);

    // Pre-populate log.
    let timestamp_before_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    env.advance_time(TIME_STEP);

    // Upgrade canister.
    let timestamp_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.upgrade_canister(
        canister_id,
        wat_canister()
            .start(wat_fn().debug_print(b"start_2"))
            .init(wat_fn().debug_print(b"init_2"))
            .pre_upgrade(wat_fn().debug_print(b"pre_upgrade_2"))
            .post_upgrade(wat_fn().debug_print(b"post_upgrade_2"))
            .update("test", wat_fn().debug_print(b"update_2"))
            .build_wasm(),
        vec![],
    );
    env.advance_time(TIME_STEP);

    let timestamp_after_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    env.advance_time(TIME_STEP);

    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_init, b"start_1".to_vec()),
            (1, timestamp_init, b"init_1".to_vec()),
            (2, timestamp_before_upgrade, b"update_1".to_vec()),
            // Preserved log records before the upgrade and continued incrementing the index.
            (3, timestamp_upgrade, b"pre_upgrade_1".to_vec()),
            (4, timestamp_upgrade, b"start_2".to_vec()),
            (5, timestamp_upgrade, b"post_upgrade_2".to_vec()),
            (6, timestamp_after_upgrade, b"update_2".to_vec()),
        ])
    );
}

#[test]
fn test_logging_trap_at_install_start() {
    let (env, canister_id) = setup(
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibilityV2::Public)
            .build(),
    );
    env.advance_time(TIME_STEP);

    // Install canister with a trap in the start function.
    let timestamp_install = system_time_to_nanos(env.time_of_next_round());
    let result = env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        wat_canister()
            .start(wat_fn().debug_print(b"start_1").trap_with_blob(b"start_1"))
            .init(wat_fn().debug_print(b"init_1"))
            .build_wasm(),
        vec![],
    );
    // Assert install fails due to trap.
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterCalledTrap);

    let result = fetch_canister_logs(&env, canister_id.into(), canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_install, b"start_1".to_vec()),
            (1, timestamp_install, b"[TRAP]: start_1".to_vec()),
        ])
    );
}

#[test]
fn test_logging_trap_at_install_init() {
    let (env, canister_id) = setup(
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibilityV2::Public)
            .build(),
    );
    env.advance_time(TIME_STEP);

    // Install canister with a trap in the init function.
    let timestamp_install = system_time_to_nanos(env.time_of_next_round());
    let result = env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        wat_canister()
            .start(wat_fn().debug_print(b"start_1"))
            .init(wat_fn().debug_print(b"init_1").trap_with_blob(b"init_1"))
            .build_wasm(),
        vec![],
    );
    // Assert install fails due to trap.
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterCalledTrap);

    let result = fetch_canister_logs(&env, canister_id.into(), canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_install, b"start_1".to_vec()),
            (1, timestamp_install, b"init_1".to_vec()),
            (2, timestamp_install, b"[TRAP]: init_1".to_vec()),
        ])
    );
}

#[test]
fn test_logging_trap_in_pre_upgrade() {
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .start(wat_fn().debug_print(b"start_1"))
            .init(wat_fn().debug_print(b"init_1"))
            .pre_upgrade(
                wat_fn()
                    .debug_print(b"pre_upgrade_1")
                    .trap_with_blob(b"pre_upgrade_1"),
            )
            .post_upgrade(wat_fn().debug_print(b"post_upgrade_1"))
            .update("test", wat_fn().debug_print(b"update_1"))
            .build_wasm(),
    );
    let timestamp_init = system_time_to_nanos(env.time());
    env.advance_time(TIME_STEP);

    // Pre-populate log.
    let timestamp_before_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    env.advance_time(TIME_STEP);

    // Upgrade canister.
    let timestamp_upgrade = system_time_to_nanos(env.time_of_next_round());
    let result = env.upgrade_canister(
        canister_id,
        wat_canister()
            .start(wat_fn().debug_print(b"start_2"))
            .init(wat_fn().debug_print(b"init_2"))
            .pre_upgrade(wat_fn().debug_print(b"pre_upgrade_2"))
            .post_upgrade(wat_fn().debug_print(b"post_upgrade_2"))
            .update("test", wat_fn().debug_print(b"update_2"))
            .build_wasm(),
        vec![],
    );
    // Assert upgrade to fail due to trap.
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterCalledTrap);
    env.advance_time(TIME_STEP);

    // Populate log after failed upgrade.
    let timestamp_after_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    env.advance_time(TIME_STEP);

    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_init, b"start_1".to_vec()),
            (1, timestamp_init, b"init_1".to_vec()),
            (2, timestamp_before_upgrade, b"update_1".to_vec()),
            // Preserved log records before the upgrade and continued incrementing the index.
            (3, timestamp_upgrade, b"pre_upgrade_1".to_vec()),
            (4, timestamp_upgrade, b"[TRAP]: pre_upgrade_1".to_vec()),
            // Log messages after failed upgrade from version #1 of the canister.
            (5, timestamp_after_upgrade, b"update_1".to_vec()),
        ])
    );
}

#[test]
fn test_logging_trap_after_upgrade_in_start() {
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .start(wat_fn().debug_print(b"start_1"))
            .init(wat_fn().debug_print(b"init_1"))
            .pre_upgrade(wat_fn().debug_print(b"pre_upgrade_1"))
            .post_upgrade(wat_fn().debug_print(b"post_upgrade_1"))
            .update("test", wat_fn().debug_print(b"update_1"))
            .build_wasm(),
    );
    let timestamp_init = system_time_to_nanos(env.time());
    env.advance_time(TIME_STEP);

    // Pre-populate log.
    let timestamp_before_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    env.advance_time(TIME_STEP);

    // Upgrade canister.
    let timestamp_upgrade = system_time_to_nanos(env.time_of_next_round());
    let result = env.upgrade_canister(
        canister_id,
        wat_canister()
            .start(wat_fn().debug_print(b"start_2").trap_with_blob(b"start_2"))
            .init(wat_fn().debug_print(b"init_2"))
            .pre_upgrade(wat_fn().debug_print(b"pre_upgrade_2"))
            .post_upgrade(wat_fn().debug_print(b"post_upgrade_2"))
            .update("test", wat_fn().debug_print(b"update_2"))
            .build_wasm(),
        vec![],
    );
    // Assert upgrade to fail due to trap.
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterCalledTrap);
    env.advance_time(TIME_STEP);

    // Populate log after failed upgrade.
    let timestamp_after_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    env.advance_time(TIME_STEP);

    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_init, b"start_1".to_vec()),
            (1, timestamp_init, b"init_1".to_vec()),
            (2, timestamp_before_upgrade, b"update_1".to_vec()),
            // Preserved log records before the upgrade and continued incrementing the index.
            (3, timestamp_upgrade, b"pre_upgrade_1".to_vec()),
            (4, timestamp_upgrade, b"start_2".to_vec()),
            (5, timestamp_upgrade, b"[TRAP]: start_2".to_vec()),
            // Log messages after failed upgrade from version #1 of the canister.
            (6, timestamp_after_upgrade, b"update_1".to_vec()),
        ])
    );
}

#[test]
fn test_logging_trap_after_upgrade_in_post_upgrade() {
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .start(wat_fn().debug_print(b"start_1"))
            .init(wat_fn().debug_print(b"init_1"))
            .pre_upgrade(wat_fn().debug_print(b"pre_upgrade_1"))
            .post_upgrade(wat_fn().debug_print(b"post_upgrade_1"))
            .update("test", wat_fn().debug_print(b"update_1"))
            .build_wasm(),
    );
    let timestamp_init = system_time_to_nanos(env.time());
    env.advance_time(TIME_STEP);

    // Pre-populate log.
    let timestamp_before_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    env.advance_time(TIME_STEP);

    // Upgrade canister.
    let timestamp_upgrade = system_time_to_nanos(env.time_of_next_round());
    let result = env.upgrade_canister(
        canister_id,
        wat_canister()
            .start(wat_fn().debug_print(b"start_2"))
            .init(wat_fn().debug_print(b"init_2"))
            .pre_upgrade(wat_fn().debug_print(b"pre_upgrade_2"))
            .post_upgrade(
                wat_fn()
                    .debug_print(b"post_upgrade_2")
                    .trap_with_blob(b"post_upgrade_2"),
            )
            .update("test", wat_fn().debug_print(b"update_2"))
            .build_wasm(),
        vec![],
    );
    // Assert upgrade to fail due to trap.
    assert_eq!(result.unwrap_err().code(), ErrorCode::CanisterCalledTrap);
    env.advance_time(TIME_STEP);

    // Populate log after failed upgrade.
    let timestamp_after_upgrade = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(canister_id, "test", vec![]);
    env.advance_time(TIME_STEP);

    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_init, b"start_1".to_vec()),
            (1, timestamp_init, b"init_1".to_vec()),
            (2, timestamp_before_upgrade, b"update_1".to_vec()),
            // Preserved log records before the upgrade and continued incrementing the index.
            (3, timestamp_upgrade, b"pre_upgrade_1".to_vec()),
            (4, timestamp_upgrade, b"start_2".to_vec()),
            (5, timestamp_upgrade, b"post_upgrade_2".to_vec()),
            (6, timestamp_upgrade, b"[TRAP]: post_upgrade_2".to_vec()),
            // Log messages after failed upgrade from version #1 of the canister.
            (7, timestamp_after_upgrade, b"update_1".to_vec()),
        ])
    );
}

#[test]
fn test_logging_debug_print_over_dts() {
    // Test canister logging debug_print messages (without traps) in separated DTS slices.
    // Check that log messages are available only after the message is finished.
    let number_of_slices = 4;
    let instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE.get() as i64;
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update(
                "test",
                wat_fn()
                    .debug_print(b"slice_0")
                    .wait(instructions_per_slice)
                    .debug_print(b"slice_1")
                    .wait(instructions_per_slice)
                    .debug_print(b"slice_2")
                    .wait(instructions_per_slice)
                    .debug_print(b"slice_3"),
            )
            .build_wasm(),
    );

    let timestamp = system_time_to_nanos(env.time_of_next_round());
    // Slice #0 is processed inside `send_ingress` in round #0.
    let _msg_id = env.send_ingress(PrincipalId::new_anonymous(), canister_id, "test", vec![]);
    // Since one slice was processed in `send_ingress` iterate over one slice less.
    for i in 1..number_of_slices {
        let result = fetch_canister_logs(&env, controller, canister_id);
        assert_eq!(
            FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
            canister_log_response(vec![]),
            "Expect no log messages after round #{}",
            i
        );
        env.advance_time(TIME_STEP);
        env.tick();
    }

    // Expect all the log messages after the last slice is processed with the timestamp of the first slice.
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp, b"slice_0".to_vec()),
            (1, timestamp, b"slice_1".to_vec()),
            (2, timestamp, b"slice_2".to_vec()),
            (3, timestamp, b"slice_3".to_vec())
        ])
    );
}

#[test]
fn test_logging_trap_over_dts() {
    // Test canister logging debug_print messages (with a trap) in separated DTS slices.
    // Check that log messages are available only after the message is finished.
    let number_of_slices = 4;
    let instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE.get() as i64;
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update(
                "test",
                wat_fn()
                    .debug_print(b"slice_0")
                    .wait(instructions_per_slice)
                    .debug_print(b"slice_1")
                    .wait(instructions_per_slice)
                    .debug_print(b"slice_2")
                    .wait(instructions_per_slice)
                    .trap_with_blob(b"slice_3"),
            )
            .build_wasm(),
    );

    let timestamp = system_time_to_nanos(env.time_of_next_round());
    // Slice #0 is processed inside `send_ingress` in round #0.
    let _msg_id = env.send_ingress(PrincipalId::new_anonymous(), canister_id, "test", vec![]);
    // Since one slice was processed in `send_ingress` iterate over one slice less.
    for i in 1..number_of_slices {
        let result = fetch_canister_logs(&env, controller, canister_id);
        assert_eq!(
            FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
            canister_log_response(vec![]),
            "Expect no log messages after round #{}",
            i
        );
        env.advance_time(TIME_STEP);
        env.tick();
    }

    // Expect all the log messages after the last slice is processed with the timestamp of the first slice.
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp, b"slice_0".to_vec()),
            (1, timestamp, b"slice_1".to_vec()),
            (2, timestamp, b"slice_2".to_vec()),
            (3, timestamp, b"[TRAP]: slice_3".to_vec())
        ])
    );
}

#[test]
fn test_logging_of_long_running_dts_over_checkpoint() {
    // Test canister logging long and short messages with DTS over a checkpoint.
    let number_of_slices = 5;
    let checkpoint_slice_idx = 3;
    assert_lt!(1, checkpoint_slice_idx); // This is due to using `send_ingress` 2 times for sending long and short messages.
    assert_lt!(checkpoint_slice_idx, number_of_slices);
    let instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE.get() as i64;
    let (env, canister_id, controller) = setup_with_controller(
        wat_canister()
            .update(
                "test_long",
                wat_fn()
                    .debug_print(b"long_slice_0")
                    .wait(instructions_per_slice)
                    .debug_print(b"long_slice_1")
                    .wait(instructions_per_slice)
                    .debug_print(b"long_slice_2")
                    .wait(instructions_per_slice)
                    .debug_print(b"long_slice_3")
                    .wait(instructions_per_slice)
                    .debug_print(b"long_slice_4"),
            )
            .update("test_short", wat_fn().debug_print(b"short"))
            .build_wasm(),
    );

    // Round #A0: slice #0 is processed inside `send_ingress`.
    let _msg_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "test_long",
        vec![],
    );
    env.advance_time(TIME_STEP);
    // Round #A1: slice #1 is processed inside `send_ingress` and short message is added to the queue.
    let _msg_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "test_short",
        vec![],
    );
    env.advance_time(TIME_STEP);
    // Round #A2 and further: process slices until the checkpoint.
    for i in 2..number_of_slices {
        if i == checkpoint_slice_idx {
            // Execute checkpoint round.
            env.set_checkpoints_enabled(true);
            env.tick();
            env.set_checkpoints_enabled(false);
            env.advance_time(TIME_STEP);
            break;
        } else {
            env.tick();
            env.advance_time(TIME_STEP);
        }
    }
    // Expect no log messages right after the checkpoint round, since the message did not finish.
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![])
    );

    // Rounds #B0 and further: Afther the checkpoint process the message again through all the slices.
    let timestamp_after_checkpoint = system_time_to_nanos(env.time_of_next_round());
    for i in 0..number_of_slices {
        let result = fetch_canister_logs(&env, controller, canister_id);
        assert_eq!(
            FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
            canister_log_response(vec![]),
            "Expect no log messages after round #{}",
            i
        );
        env.tick();
        env.advance_time(TIME_STEP);
    }
    // Round to process short message.
    let timestamp_short = system_time_to_nanos(env.time_of_next_round());
    env.tick();
    env.advance_time(TIME_STEP);

    // Expect all the log messages after the last slice is processed with the timestamp of the first slice.
    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_after_checkpoint, b"long_slice_0".to_vec()),
            (1, timestamp_after_checkpoint, b"long_slice_1".to_vec()),
            (2, timestamp_after_checkpoint, b"long_slice_2".to_vec()),
            (3, timestamp_after_checkpoint, b"long_slice_3".to_vec()),
            (4, timestamp_after_checkpoint, b"long_slice_4".to_vec()),
            (5, timestamp_short, b"short".to_vec())
        ])
    );
}

#[test]
fn test_canister_log_memory_usage_bytes() {
    // Test canister logging metrics record the size of the log.
    let metric = "canister_log_memory_usage_bytes_v2";
    const PAYLOAD_SIZE: usize = 1_000;
    let (env, canister_id, _controller) = setup_with_controller(
        wat_canister()
            .update("test", wat_fn().debug_print(&[37; PAYLOAD_SIZE]))
            .build_wasm(),
    );
    // Assert canister log size metric is zero initially.
    let stats = fetch_histogram_stats(env.metrics_registry(), metric).unwrap();
    assert_eq!(stats.sum, 0.0);

    // Add log message.
    let _ = env.execute_ingress(canister_id, "test", vec![]);

    // Assert canister log size metric is within the expected range.
    let stats = fetch_histogram_stats(env.metrics_registry(), metric).unwrap();
    assert_le!(PAYLOAD_SIZE as f64, stats.sum);
    assert_le!(stats.sum, 1.05 * (PAYLOAD_SIZE as f64));
}

#[test]
fn test_canister_log_on_reply() {
    // Test that the log is recorded inside response callback.
    let (env, canister_id, controller) = setup_with_controller(UNIVERSAL_CANISTER_WASM.to_vec());

    let instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE.get();
    let timestamp_init = system_time_to_nanos(env.time_of_next_round());
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .debug_print(b"before_call")
            .call_with_cycles(
                ic00::IC_00,
                ic00::Method::RawRand,
                call_args().other_side(EmptyBlob.encode()).on_reply(
                    wasm()
                        .debug_print(b"on_reply slice_0")
                        .instruction_counter_is_at_least(instructions_per_slice)
                        .debug_print(b"on_reply slice_1")
                        .instruction_counter_is_at_least(2 * instructions_per_slice)
                        .debug_print(b"on_reply slice_2"),
                ),
                Cycles::new(0),
            )
            .debug_print(b"after_call")
            .build(),
    );
    // The call and its response are processed in different rounds.
    // All the response slices will have the same initial timestamp of a response round.
    let call_response_rounds = 2;
    let round_time_increment = StateMachine::EXECUTE_ROUND_TIME_INCREMENT.as_nanos() as u64;
    let timestamp_response = timestamp_init + call_response_rounds * round_time_increment;

    // Assert time since the response round advanced by the number of slices minus one.
    let number_of_slices = 3;
    let diff_since_response_round = system_time_to_nanos(env.time()) - timestamp_response;
    assert_eq!(
        diff_since_response_round,
        (number_of_slices - 1) * round_time_increment
    );

    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_init, b"before_call".to_vec()),
            (1, timestamp_init, b"after_call".to_vec()),
            (2, timestamp_response, b"on_reply slice_0".to_vec()),
            (3, timestamp_response, b"on_reply slice_1".to_vec()),
            (4, timestamp_response, b"on_reply slice_2".to_vec()),
        ])
    );
}

#[test]
fn test_canister_log_on_cleanup() {
    // Test that the log is recorded inside cleanup callback.
    let (env, canister_id, controller) = setup_with_controller(UNIVERSAL_CANISTER_WASM.to_vec());

    let timestamp_init = system_time_to_nanos(env.time_of_next_round());
    let instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE.get();
    let _ = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .debug_print(b"before_call")
            .call_with_cycles(
                ic00::IC_00,
                ic00::Method::RawRand,
                call_args()
                    .other_side(EmptyBlob.encode())
                    .on_reply(
                        wasm()
                            .debug_print(b"on_reply slice_0")
                            .instruction_counter_is_at_least(instructions_per_slice)
                            .debug_print(b"on_reply slice_1")
                            .instruction_counter_is_at_least(2 * instructions_per_slice)
                            .debug_print(b"on_reply slice_2")
                            .trap_with_blob(b"on_reply trap"),
                    )
                    .on_cleanup(wasm().debug_print(b"on_cleanup")),
                Cycles::new(0),
            )
            .debug_print(b"after_call")
            .build(),
    );
    // The call and its response are processed in different rounds.
    // All the response slices will have the same initial timestamp of a response round.
    let call_response_rounds = 2;
    let round_time_increment = StateMachine::EXECUTE_ROUND_TIME_INCREMENT.as_nanos() as u64;
    let timestamp_response = timestamp_init + call_response_rounds * round_time_increment;

    // Assert time since the response round advanced by the number of slices minus one.
    let number_of_slices = 3;
    let diff_since_response_round = system_time_to_nanos(env.time()) - timestamp_response;
    assert_eq!(
        diff_since_response_round,
        (number_of_slices - 1) * round_time_increment
    );

    let result = fetch_canister_logs(&env, controller, canister_id);
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        canister_log_response(vec![
            (0, timestamp_init, b"before_call".to_vec()),
            (1, timestamp_init, b"after_call".to_vec()),
            (2, timestamp_response, b"on_reply slice_0".to_vec()),
            (3, timestamp_response, b"on_reply slice_1".to_vec()),
            (4, timestamp_response, b"on_reply slice_2".to_vec()),
            (5, timestamp_response, b"[TRAP]: on_reply trap".to_vec()),
            (6, timestamp_response, b"on_cleanup".to_vec()),
        ])
    );
}
