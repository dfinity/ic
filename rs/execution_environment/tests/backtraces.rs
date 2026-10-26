use candid::Encode;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_management_canister_types_private::{
    BoundedVec, CanisterSettingsArgsBuilder, LogVisibilityV2,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{ErrorCode, StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::{CanisterId, PrincipalId};
use ic_types_cycles::Cycles;
use regex_lite::RegexBuilder;

const B: u128 = 1_000 * 1_000 * 1_000;

const CONTROLLER: PrincipalId = PrincipalId::new(29, [0xfc; 29]);
const OTHER1: PrincipalId = PrincipalId::new(29, [0xab; 29]);
const OTHER2: PrincipalId = PrincipalId::new(29, [0xbc; 29]);

const UNREACHABLE_BACKTRACE: &str = r#"unreachable
Canister Backtrace:.*
_wasm_backtrace_canister::unreachable::inner_2
_wasm_backtrace_canister::unreachable::inner
_wasm_backtrace_canister::unreachable::outer
"#;

const IC0_TRAP_ERROR: &str =
    r#"Panicked at 'uh oh', rs/rust_canisters/backtrace_canister/src/main.rs:47:5"#;

const IC0_TRAP_BACKTRACE: &str = r#"
Canister Backtrace:.*
_wasm_backtrace_canister::ic0_trap::inner_2
_wasm_backtrace_canister::ic0_trap::inner
_wasm_backtrace_canister::ic0_trap::outer
"#;

fn env_with_backtrace_canister_and_visibility(
    visibility: LogVisibilityV2,
    canister_name: &str,
) -> (StateMachine, CanisterId) {
    let wasm = canister_test::Project::cargo_bin_maybe_from_env(canister_name, &[]);
    let hypervisor_config = HypervisorConfig::default();
    let subnet_type = SubnetType::Application;

    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            SubnetConfig::new(subnet_type),
            hypervisor_config,
        )))
        .with_subnet_type(subnet_type)
        .build();

    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister_settings = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![CONTROLLER])
        .with_log_visibility(visibility)
        .build();
    let canister_id = env
        .install_canister_with_cycles(
            wasm.bytes(),
            vec![],
            Some(canister_settings),
            initial_cycles,
        )
        .unwrap();

    (env, canister_id)
}

fn env_with_backtrace_canister() -> (StateMachine, CanisterId) {
    env_with_backtrace_canister_and_visibility(LogVisibilityV2::Controllers, "backtrace_canister")
}

/// Check that calling `method` returns an error with code `code`, `message` and
/// `backtrace` in the reject message, and `backtrace` in the log.
fn assert_error(
    env: StateMachine,
    canister_id: CanisterId,
    method: &str,
    code: ErrorCode,
    message: &str,
    backtrace: &str,
) {
    let result = env
        .execute_ingress_as(CONTROLLER, canister_id, method, Encode!(&()).unwrap())
        .unwrap_err();
    result.assert_matches(code, &format!("{message}.*{backtrace}.*"));
    let logs = env.canister_log_records(canister_id);
    let last_error = std::str::from_utf8(&logs.last().as_ref().unwrap().content).unwrap();
    let backtrace_regex = RegexBuilder::new(&format!(".*{backtrace}.*"))
        .dot_matches_new_line(true)
        .build()
        .unwrap();
    assert!(
        backtrace_regex.is_match(last_error),
        "Last log:\n----------\n{last_error}\n----------\ndoesn't match backtrace regex: {backtrace}"
    );
}

#[test]
fn unreachable_instr_backtrace() {
    let (env, canister_id) = env_with_backtrace_canister();
    assert_error(
        env,
        canister_id,
        "unreachable",
        ErrorCode::CanisterTrapped,
        "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister trapped: ",
        UNREACHABLE_BACKTRACE,
    );
}

#[test]
fn no_backtrace_without_name_section() {
    let (env, canister_id) = env_with_backtrace_canister_and_visibility(
        LogVisibilityV2::Controllers,
        "backtrace_canister_without_names",
    );
    let result = env
        .execute_ingress_as(
            CONTROLLER,
            canister_id,
            "unreachable",
            Encode!(&()).unwrap(),
        )
        .unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterTrapped,
        "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister trapped: unreachable",
    );
    assert!(
        !result.description().contains("Backtrace"),
        "Result message: {} cointains unexpected 'Backtrace'",
        result.description(),
    );
    let logs = env.canister_log_records(canister_id);
    for log in &logs {
        let log = std::str::from_utf8(&log.content).unwrap();
        assert!(
            !log.contains("Backtrace"),
            "Canister log: {log} cointains unexpected 'Backtrace'",
        );
    }
}

#[test]
fn oob_backtrace() {
    let (env, canister_id) = env_with_backtrace_canister();
    assert_error(
        env,
        canister_id,
        "oob",
        ErrorCode::CanisterTrapped,
        "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister trapped: ",
        r#"heap out of bounds
Canister Backtrace:.*
_wasm_backtrace_canister::oob::inner_2
_wasm_backtrace_canister::oob::inner
_wasm_backtrace_canister::oob::outer
"#,
    )
}

#[test]
fn backtrace_test_ic0_trap() {
    let (env, canister_id) = env_with_backtrace_canister();
    assert_error(
        env,
        canister_id,
        "ic0_trap",
        ErrorCode::CanisterCalledTrap,
        &format!(
            "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister called `ic0.trap` with message: '{IC0_TRAP_ERROR}'"
        ),
        IC0_TRAP_BACKTRACE,
    );
}

#[test]
fn backtrace_test_stable_oob() {
    let (env, canister_id) = env_with_backtrace_canister();
    assert_error(
        env,
        canister_id,
        "stable_oob",
        ErrorCode::CanisterTrapped,
        "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister trapped: ",
        r#"stable memory out of bounds
Canister Backtrace:.*
stable64_write
_wasm_backtrace_canister::stable_oob::inner_2
_wasm_backtrace_canister::stable_oob::inner
_wasm_backtrace_canister::stable_oob::outer
"#,
    )
}

#[test]
fn backtrace_visibility_after_paused_execution() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    let settings = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![CONTROLLER])
        .with_log_visibility(LogVisibilityV2::AllowedViewers(BoundedVec::new(vec![])))
        .build();
    // The application subnet executes at most 2B instructions per slice
    // and 4B instructions per round, so a 5B-instruction execution is
    // still paused at the end of the first round.
    // Give the Wasm function a name so a visible trap includes a backtrace.
    let named_wasm = wat::parse_str(
        r#"(module
            (import "ic0" "performance_counter" (func $performance_counter (param i32) (result i64)))
            (import "ic0" "trap" (func $trap (param i32 i32)))
            (memory 1)
            (func $update (export "canister_update update")
                (loop $wait
                    (br_if $wait
                        (i64.lt_u
                            (call $performance_counter (i32.const 0))
                            (i64.const 5000000000))))
                (call $trap (i32.const 0) (i32.const 0))))"#,
    )
    .unwrap();
    let canister_id = env
        .install_canister_with_cycles(
            named_wasm,
            vec![],
            Some(settings),
            Cycles::new(1_000_000 * B),
        )
        .unwrap();
    // Executes the update method and asserts that the execution
    // is still paused (i.e., not yet completed) after the first round.
    let execute_paused = |caller: PrincipalId| {
        let msg_id = env.send_ingress(caller, canister_id, "update", vec![]);
        env.tick();
        assert!(
            env.get_latest_state()
                .canister_state(&canister_id)
                .unwrap()
                .has_paused_execution(),
            "Expected paused execution after one round"
        );
        let status = env.ingress_status(&msg_id);
        assert!(
            matches!(
                status,
                IngressStatus::Known {
                    state: IngressState::Processing,
                    ..
                }
            ),
            "Expected ingress message to be processing after one round, got {status:?}"
        );
        env.await_ingress(msg_id, 10).unwrap_err()
    };

    let err = execute_paused(OTHER1);
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(
        !err.description().contains("Canister Backtrace:"),
        "Unexpected backtrace in error: {err}"
    );

    let err = execute_paused(CONTROLLER);
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(
        err.description().contains("Canister Backtrace:"),
        "Missing backtrace in controller error: {err}"
    );
}

mod visibility {
    use super::*;

    // Check that the backtrace is seen or not seen by the caller. It should
    // always be present in the logs.
    fn check_visibility(
        caller: PrincipalId,
        visibility: LogVisibilityV2,
        backtrace_should_be_visible: bool,
        method: &str,
        error_code: ErrorCode,
        backtrace: &str,
    ) {
        let backtrace_regex = RegexBuilder::new(&format!(".*{backtrace}.*"))
            .dot_matches_new_line(true)
            .build()
            .unwrap();
        let (env, canister_id) =
            env_with_backtrace_canister_and_visibility(visibility, "backtrace_canister");
        // Call from anonymous principal
        let result = env
            .execute_ingress_as(caller, canister_id, method, Encode!(&()).unwrap())
            .unwrap_err();
        result.assert_contains(
            error_code,
            "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai:",
        );
        if backtrace_should_be_visible {
            assert!(
                backtrace_regex.is_match(result.description()),
                "Result message: {} doesn't contain backtrace: {}",
                result.description(),
                backtrace
            );
        } else {
            // There should be no backtrace in the error.
            assert!(
                !backtrace_regex.is_match(result.description()),
                "Result message: {} cointains unexpected 'Backtrace'",
                result.description(),
            );
        }
        // The backtrace should still be in the logs.
        let logs = env.canister_log_records(canister_id);
        let last_error = std::str::from_utf8(&logs.last().as_ref().unwrap().content).unwrap();
        assert!(
            backtrace_regex.is_match(last_error),
            "Last log:\n----------\n{last_error}\n----------\ndoesn't contain backtrace: {backtrace}"
        );
    }

    #[test]
    fn unreachable_non_controller_and_private() {
        check_visibility(
            OTHER1,
            LogVisibilityV2::Controllers,
            false,
            "unreachable",
            ErrorCode::CanisterTrapped,
            UNREACHABLE_BACKTRACE,
        );
    }

    #[test]
    fn unreachable_not_in_viewer_list() {
        check_visibility(
            OTHER1,
            LogVisibilityV2::AllowedViewers(BoundedVec::new(vec![CONTROLLER, OTHER2])),
            false,
            "unreachable",
            ErrorCode::CanisterTrapped,
            UNREACHABLE_BACKTRACE,
        );
    }

    #[test]
    fn unreachable_in_viewer_list() {
        check_visibility(
            OTHER2,
            LogVisibilityV2::AllowedViewers(BoundedVec::new(vec![CONTROLLER, OTHER2])),
            true,
            "unreachable",
            ErrorCode::CanisterTrapped,
            UNREACHABLE_BACKTRACE,
        );
    }

    #[test]
    fn unreachale_public() {
        check_visibility(
            OTHER1,
            LogVisibilityV2::Public,
            true,
            "unreachable",
            ErrorCode::CanisterTrapped,
            UNREACHABLE_BACKTRACE,
        );
    }

    #[test]
    fn ic0_non_controller_and_private() {
        check_visibility(
            OTHER1,
            LogVisibilityV2::Controllers,
            false,
            "ic0_trap",
            ErrorCode::CanisterCalledTrap,
            IC0_TRAP_BACKTRACE,
        );
    }

    #[test]
    fn ic0_not_in_viewer_list() {
        check_visibility(
            OTHER1,
            LogVisibilityV2::AllowedViewers(BoundedVec::new(vec![CONTROLLER, OTHER2])),
            false,
            "ic0_trap",
            ErrorCode::CanisterCalledTrap,
            IC0_TRAP_BACKTRACE,
        );
    }

    #[test]
    fn ic0_in_viewer_list() {
        check_visibility(
            OTHER2,
            LogVisibilityV2::AllowedViewers(BoundedVec::new(vec![CONTROLLER, OTHER2])),
            true,
            "ic0_trap",
            ErrorCode::CanisterCalledTrap,
            IC0_TRAP_BACKTRACE,
        );
    }

    #[test]
    fn ic0_public() {
        check_visibility(
            OTHER1,
            LogVisibilityV2::Public,
            true,
            "ic0_trap",
            ErrorCode::CanisterCalledTrap,
            IC0_TRAP_BACKTRACE,
        );
    }
}
