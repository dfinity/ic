use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SubnetConfig;
use ic_management_canister_types::{
    CanisterInstallMode, CanisterSettingsArgsBuilder, FetchCanisterLogsRequest,
    FetchCanisterLogsResponse, LogVisibility, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    ErrorCode, PrincipalId, StateMachine, StateMachineBuilder, StateMachineConfig,
    SubmitIngressError, UserError,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_test_utilities_execution_environment::get_reply;
use ic_types::{CanisterId, Cycles};

fn setup(canister_logging: FlagStatus) -> (StateMachine, CanisterId) {
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
        env.create_canister_with_cycles(None, Cycles::from(100_000_000_000_u128), None);
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
    )
    .unwrap();

    (env, canister_id)
}

#[test]
fn test_fetch_canister_logs_disabled_submit_ingress_fails() {
    // Arrange.
    // - disable the fetch_canister_logs API
    // - set the log visibility to public so that any user can read the logs
    let (env, canister_id) = setup(FlagStatus::Disabled);
    let not_a_controller = PrincipalId::new_user_test_id(42);
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Public)
            .build(),
    )
    .unwrap();
    // Act.
    let result = env.submit_ingress_as(
        not_a_controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest {
            canister_id: canister_id.into(),
        }
        .encode(),
    );
    // Assert.
    // Expect to get an error because the fetch_canister_logs API is disabled,
    // despite the fact that the log visibility is set to public.
    assert_eq!(
        result,
        Err(SubmitIngressError::UserError(UserError::new(
            ErrorCode::CanisterContractViolation,
            "fetch_canister_logs API is not enabled on this subnet"
        )))
    );
}

#[test]
fn test_fetch_canister_logs_disabled_execute_ingress_fails() {
    // Arrange.
    // - disable the fetch_canister_logs API
    // - set the log visibility to public so that any user can read the logs
    let (env, canister_id) = setup(FlagStatus::Disabled);
    let not_a_controller = PrincipalId::new_user_test_id(42);
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Public)
            .build(),
    )
    .unwrap();
    // Act.
    // Make an update call.
    let result = env.execute_ingress_as(
        not_a_controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest {
            canister_id: canister_id.into(),
        }
        .encode(),
    );
    // Assert.
    // Expect to get an error because the fetch_canister_logs API is disabled,
    // despite the fact that the log visibility is set to public.
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterContractViolation,
            "fetch_canister_logs API is not enabled on this subnet"
        ))
    );
}

#[test]
fn test_fetch_canister_logs_enabled_submit_ingress_rejected() {
    // Arrange.
    // - enable the fetch_canister_logs API
    // - set the log visibility to public so that any user can read the logs
    let (env, canister_id) = setup(FlagStatus::Enabled);
    let not_a_controller = PrincipalId::new_user_test_id(42);
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Public)
            .build(),
    )
    .unwrap();
    // Act.
    let result = env.submit_ingress_as(
        not_a_controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest {
            canister_id: canister_id.into(),
        }
        .encode(),
    );
    // Assert.
    // Expect error because an update calls are not allowed.
    assert_eq!(
        result,
        Err(SubmitIngressError::UserError(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            "fetch_canister_logs API is only accessible in non-replicated mode"
        )))
    );
}

#[test]
fn test_fetch_canister_logs_enabled_execute_ingress_rejected() {
    // Arrange.
    // - enable the fetch_canister_logs API
    // - set the log visibility to public so that any user can read the logs
    let (env, canister_id) = setup(FlagStatus::Enabled);
    let not_a_controller = PrincipalId::new_user_test_id(42);
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Public)
            .build(),
    )
    .unwrap();
    // Act.
    // Make an update call.
    let result = env.execute_ingress_as(
        not_a_controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest {
            canister_id: canister_id.into(),
        }
        .encode(),
    );
    // Assert.
    // Expect error because an update calls are not allowed.
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            "fetch_canister_logs API is only accessible in non-replicated mode"
        ))
    );
}

#[test]
fn test_fetch_canister_logs_disabled_query_fails() {
    // Arrange.
    // - disable the fetch_canister_logs API
    // - set the log visibility to public so that any user can read the logs
    let (env, canister_id) = setup(FlagStatus::Disabled);
    let not_a_controller = PrincipalId::new_user_test_id(42);
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Public)
            .build(),
    )
    .unwrap();
    // Act.
    // Make a query call.
    let result = env.query_as(
        not_a_controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest {
            canister_id: canister_id.into(),
        }
        .encode(),
    );
    // Assert.
    // Expect to get an error because the fetch_canister_logs API is disabled,
    // despite the fact that the log visibility is set to public.
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterContractViolation,
            "fetch_canister_logs API is not enabled on this subnet"
        ))
    );
}

#[test]
fn test_fetch_canister_logs_enabled_query_log_visibility_public_succeeds() {
    // Arrange.
    // - enable the fetch_canister_logs API
    // - set the log visibility to public so that any user can read the logs
    let (env, canister_id) = setup(FlagStatus::Enabled);
    let not_a_controller = PrincipalId::new_user_test_id(42);
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Public)
            .build(),
    )
    .unwrap();
    // Act.
    // Make a query call.
    let result = env.query_as(
        not_a_controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest {
            canister_id: canister_id.into(),
        }
        .encode(),
    );
    // Assert.
    // Expect some non-empty result.
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![]
        }
    );
}

#[test]
fn test_fetch_canister_logs_enabled_query_log_visibility_invalid_controller_fails() {
    // Arrange.
    // - enable the fetch_canister_logs API
    // - restrict log visibility to controllers only
    let (env, canister_id) = setup(FlagStatus::Enabled);
    let not_a_controller = PrincipalId::new_user_test_id(42);
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Controllers)
            .build(),
    )
    .unwrap();
    // Act.
    // Make a query call from a non-controller.
    let result = env.query_as(
        not_a_controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest {
            canister_id: canister_id.into(),
        }
        .encode(),
    );
    // Assert.
    // Expect an error because the caller is not a controller.
    assert_eq!(
        result,
        Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!(
                "Caller {not_a_controller} is not allowed to query ic00 method fetch_canister_logs"
            ),
        ))
    );
}

#[test]
fn test_fetch_canister_logs_enabled_query_log_visibility_valid_controller_succeeds() {
    // Arrange.
    // - enable the fetch_canister_logs API
    // - restrict log visibility to controllers only
    // - add new controller
    let (env, canister_id) = setup(FlagStatus::Enabled);
    let new_controller = PrincipalId::new_user_test_id(42);
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_log_visibility(LogVisibility::Controllers)
            .with_controller(new_controller)
            .build(),
    )
    .unwrap();
    // Act.
    // Make a query call from a controller.
    let result = env.query_as(
        new_controller,
        CanisterId::ic_00(),
        "fetch_canister_logs",
        FetchCanisterLogsRequest {
            canister_id: canister_id.into(),
        }
        .encode(),
    );
    // Assert.
    // Expect some non-empty result.
    assert_eq!(
        FetchCanisterLogsResponse::decode(&get_reply(result)).unwrap(),
        FetchCanisterLogsResponse {
            canister_log_records: vec![]
        }
    );
}
