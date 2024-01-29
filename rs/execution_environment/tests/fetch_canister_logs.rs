use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SubnetConfig;
use ic_ic00_types::{
    CanisterInstallMode, CanisterSettingsArgsBuilder, FetchCanisterLogsRequest, LogVisibility,
    Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    ErrorCode, PrincipalId, StateMachine, StateMachineBuilder, StateMachineConfig, UserError,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_types::{CanisterId, Cycles};

fn setup(fetch_canister_logs: FlagStatus) -> (StateMachine, CanisterId) {
    let subnet_type = SubnetType::Application;
    let config = StateMachineConfig::new(
        SubnetConfig::new(subnet_type),
        ExecutionConfig {
            fetch_canister_logs,
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
fn test_fetch_canister_logs_ingress_disabled() {
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
fn test_fetch_canister_logs_ingress_enabled() {
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

// TODO(IC-272): add query call tests.
