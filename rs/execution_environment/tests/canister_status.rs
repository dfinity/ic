use ic_base_types::PrincipalId;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_management_canister_types_private::{
    BoundedAllowedViewers, CanisterSettingsArgsBuilder, CanisterStatusResultV2, StatusVisibility,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    ErrorCode, StateMachine, StateMachineBuilder, StateMachineConfig, UserError,
};
use ic_test_utilities_metrics::{fetch_histogram_vec_stats, labels};
use ic_test_utilities_types::ids::user_test_id;
use ic_types::CanisterId;
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};

/// The call path used to invoke the `canister_status` management endpoint.
#[derive(Clone, Copy, Debug)]
enum CallPath {
    /// Replicated update call via an ingress message.
    Update,
    /// Non-replicated query call.
    Query,
}

/// Sets up an application subnet with the given `subnet_admin`.
fn setup(subnet_admin: PrincipalId) -> StateMachine {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            HypervisorConfig::default(),
        )))
        .with_subnet_type(SubnetType::Application)
        .with_cost_schedule(CanisterCyclesCostSchedule::Free)
        .with_subnet_admins(vec![subnet_admin])
        .build()
}

/// Calls the `canister_status` endpoint via the given call path as `sender`.
fn canister_status(
    env: &StateMachine,
    call_path: CallPath,
    sender: PrincipalId,
    canister_id: CanisterId,
) -> Result<Result<CanisterStatusResultV2, String>, UserError> {
    match call_path {
        CallPath::Update => env.canister_status_as(sender, canister_id),
        CallPath::Query => env.canister_status_query_as(sender, canister_id),
    }
}

/// Returns the number of successful `canister_status` query calls recorded in
/// the subnet query message duration metrics.
fn canister_status_query_success_count(env: &StateMachine) -> u64 {
    fetch_histogram_vec_stats(
        env.metrics_registry(),
        "execution_subnet_query_message_duration_seconds",
    )
    .get(&labels(&[
        ("method_name", "query_ic00_canister_status"),
        ("status", "success"),
    ]))
    .map_or(0, |stats| stats.count)
}

#[test]
fn test_status_visibility_of_canister_status() {
    // Test combinations of status_visibility, sender, and call path for the
    // `canister_status` management endpoint.
    let controller = user_test_id(1).get();
    let subnet_admin = user_test_id(100).get();
    let allowed_viewer = user_test_id(3).get();
    // A principal that is neither a controller, nor a subnet admin, nor an
    // allowed viewer.
    let other = user_test_id(4).get();
    let allowed_viewers = BoundedAllowedViewers::new(vec![allowed_viewer]);

    // (status_visibility, sender, sender_label, expected_allowed)
    let test_cases = vec![
        // Controllers (default): only controllers and subnet admins have access.
        (
            StatusVisibility::Controllers,
            controller,
            "controller",
            true,
        ),
        (
            StatusVisibility::Controllers,
            subnet_admin,
            "subnet_admin",
            true,
        ),
        (
            StatusVisibility::Controllers,
            allowed_viewer,
            "allowed_viewer",
            false,
        ),
        (StatusVisibility::Controllers, other, "other", false),
        // Public: everyone has access.
        (StatusVisibility::Public, controller, "controller", true),
        (StatusVisibility::Public, subnet_admin, "subnet_admin", true),
        (
            StatusVisibility::Public,
            allowed_viewer,
            "allowed_viewer",
            true,
        ),
        (StatusVisibility::Public, other, "other", true),
        // AllowedViewers: controllers, subnet admins, and the listed viewers.
        (
            StatusVisibility::AllowedViewers(allowed_viewers.clone()),
            controller,
            "controller",
            true,
        ),
        (
            StatusVisibility::AllowedViewers(allowed_viewers.clone()),
            subnet_admin,
            "subnet_admin",
            true,
        ),
        (
            StatusVisibility::AllowedViewers(allowed_viewers.clone()),
            allowed_viewer,
            "allowed_viewer",
            true,
        ),
        (
            StatusVisibility::AllowedViewers(allowed_viewers.clone()),
            other,
            "other",
            false,
        ),
    ];

    for (status_visibility, sender, sender_label, expected_allowed) in test_cases {
        let env = setup(subnet_admin);
        // The subnet uses a free cost schedule, so no cycles are needed.
        let canister_id = env.create_canister_with_cycles(
            None,
            Cycles::zero(),
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![controller])
                    .with_status_visibility(status_visibility.clone())
                    .build(),
            ),
        );
        assert_ne!(sender, canister_id.get());

        for call_path in [CallPath::Update, CallPath::Query] {
            let query_success_before = canister_status_query_success_count(&env);
            let result = canister_status(&env, call_path, sender, canister_id);
            if expected_allowed {
                let status = result
                    .expect("expected access to be granted")
                    // `canister_status` invoked via an ingress or query call never
                    // produces a reject response (a reject is only possible for an
                    // inter-canister call), so this layer is expected to be unreachable.
                    .expect("unexpected reject response");
                assert_eq!(
                    status.settings().status_visibility(),
                    &status_visibility,
                    "unexpected status_visibility for status_visibility: \
                     {status_visibility:?}, sender: {sender_label}, call path: {call_path:?}"
                );
            } else {
                let err = result.expect_err(&format!(
                    "expected access to be denied for status_visibility: \
                     {status_visibility:?}, sender: {sender_label}, call path: {call_path:?}"
                ));
                assert_eq!(
                    err.code(),
                    ErrorCode::CanisterStatusAccessDenied,
                    "unexpected error for status_visibility: {status_visibility:?}, \
                     sender: {sender_label}, call path: {call_path:?}"
                );
                assert!(
                    err.description().contains(&format!(
                        "Caller {sender} is not allowed to read the canister status"
                    )),
                    "unexpected error description for status_visibility: {status_visibility:?}, \
                     sender: {sender_label}, call path: {call_path:?}, description: {}",
                    err.description()
                );
            }

            // The successful `canister_status` query metric must increment
            // exactly once for an allowed query call, and must not increment for
            // a denied query call or for an update call (which is not recorded
            // as a query message).
            let expected_query_success_delta = match (call_path, expected_allowed) {
                (CallPath::Query, true) => 1,
                _ => 0,
            };
            assert_eq!(
                canister_status_query_success_count(&env) - query_success_before,
                expected_query_success_delta,
                "unexpected successful query metric delta for status_visibility: \
                 {status_visibility:?}, sender: {sender_label}, call path: {call_path:?}"
            );
        }
    }
}
