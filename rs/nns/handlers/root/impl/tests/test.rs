use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid;
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types_private::CanisterInstallMode::Upgrade;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResult,
};
use ic_nervous_system_proxied_canister_calls_tracker::ProxiedCanisterCallsTracker;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_handler_root::{
    PROXIED_CANISTER_CALLS_TRACKER, encode_metrics, init::RootCanisterInitPayloadBuilder,
};
use ic_nns_test_utils::itest_helpers::{
    forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_root_canister,
    set_up_universal_canister,
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use maplit::btreeset;
use pretty_assertions::assert_eq;
use std::{collections::BTreeSet, str::FromStr};

/// Verifies that an anonymous user can get the status of any NNS canister
/// through the root handler.
#[test]
fn test_get_status() {
    local_test_on_nns_subnet(|runtime| async move {
        let root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;

        // Create some NNS canister to be own by the root
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controller(root.canister_id().get())
            .await
            .unwrap();

        // Get the status of an NNS canister
        let status: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(universal.canister_id()),),
            )
            .await
            .unwrap();
        assert_eq!(status.settings.controllers, vec![root.canister_id().get()]);

        Ok(())
    });
}

/// Verifies that an anonymous user can get the status of any canister controlled by root, and
/// this supports multiple controllers.
#[test]
fn test_get_status_multiple_controllers() {
    local_test_on_nns_subnet(|runtime| async move {
        let root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;
        let other_controller = PrincipalId::new_user_test_id(1000);

        // Create some NNS canister to be own by the root and another controller
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controllers(vec![root.canister_id().get(), other_controller])
            .await
            .unwrap();

        // Get the status of an NNS canister
        let status: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(universal.canister_id()),),
            )
            .await
            .unwrap();
        let actual_controllers: BTreeSet<PrincipalId> =
            status.settings.controllers.iter().cloned().collect();
        let expected_controllers = btreeset! {other_controller, root.canister_id().get()};

        assert_eq!(actual_controllers, expected_controllers);

        Ok(())
    });
}

#[test]
fn test_the_anonymous_user_cannot_change_an_nns_canister() {
    local_test_on_nns_subnet(|runtime| async move {
        let mut root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;

        // Create some NNS canister to be own by the root
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controller(root.canister_id().get())
            .await
            .unwrap();

        let change_canister_request =
            ChangeCanisterRequest::new(false, Upgrade, universal.canister_id())
                .with_wasm(UNIVERSAL_CANISTER_WASM.to_vec());

        // The anonymous end-user tries to upgrade an NNS canister a subnet, bypassing
        // the proposals This should be rejected.
        let response: Result<(), String> = root
            .update_(
                "change_nns_canister",
                candid,
                (change_canister_request.clone(),),
            )
            .await;
        assert_matches!(response,
                            Err(s) if s.contains("Only the Governance canister is allowed to call this method"));

        // Go through an upgrade cycle, and verify that it still works the same
        root.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = root
            .update_(
                "change_nns_canister",
                candid,
                (change_canister_request.clone(),),
            )
            .await;
        assert_matches!(response,
                            Err(s) if s.contains("Only the Governance canister is allowed to call this method"));

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_change_an_nns_canister() {
    local_test_on_nns_subnet(|runtime| async move {
        let root =
            set_up_root_canister(&runtime, RootCanisterInitPayloadBuilder::new().build()).await;

        // Create some NNS canister to be own by the root
        let universal = set_up_universal_canister(&runtime).await;
        universal
            .set_controller(root.canister_id().get())
            .await
            .unwrap();

        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );
        let change_canister_request =
            ChangeCanisterRequest::new(false, Upgrade, universal.canister_id())
                .with_wasm(UNIVERSAL_CANISTER_WASM.to_vec());

        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &root,
                "change_nns_canister",
                Encode!(&change_canister_request).unwrap()
            )
            .await
        );

        Ok(())
    });
}

#[test]
fn test_encode_metrics() {
    // Some arbitrary test values.
    let caller = PrincipalId::new_user_test_id(226_278);
    let callee = CanisterId::from(103_413);

    // Phase A: Track call to some_method.
    // -----------------------------------

    // Step 1A: Prepare the world.
    let _some_method_tracker = ProxiedCanisterCallsTracker::start_tracking(
        &PROXIED_CANISTER_CALLS_TRACKER,
        caller,
        callee,
        "some_method",
        &[],
    );

    // Step 2A: Run code under test.
    let now_millis = 42;
    let mut metrics = ic_metrics_encoder::MetricsEncoder::new(vec![], now_millis);
    encode_metrics(&mut metrics).expect("Encoding metrics.");
    let metrics = metrics.into_inner();
    let metrics = String::from_utf8_lossy(&metrics);

    // Step 3A: Inspect results.
    fn get_metric_value_does_not_capture(now_millis: i64, metrics: &str, line_prefix: &str) -> f64 {
        let lines = metrics
            .lines()
            .filter_map(|line| line.strip_prefix(line_prefix))
            .collect::<Vec<_>>();
        assert_eq!(
            lines.len(),
            1,
            "line_prefix = {:?}\n\
             metrics:\n\
             {}",
            line_prefix,
            metrics,
        );

        let metric_value = lines[0]
            .strip_suffix(&format!(" {now_millis}"))
            .unwrap_or_else(|| {
                panic!(
                    "line = {:?}\n\
                 \n\
                 Unable to strip timestamp suffix (now_millis = {}).",
                    lines[0], now_millis,
                )
            });
        f64::from_str(metric_value).unwrap_or_else(|err| {
            panic!("{err}\n\nError caused by trying to parse {metric_value:?} as a float")
        })
    }

    // Capture some common stuff.
    let get_metric_value = |line_prefix: &str| -> f64 {
        get_metric_value_does_not_capture(now_millis, &metrics, line_prefix)
    };

    fn assert_less_than_50_ms(seconds: f64) {
        assert!(0.0 < seconds && seconds < 0.050, "{}", seconds);
    }

    assert_less_than_50_ms(get_metric_value(&format!(
        r#"nns_root_in_flight_proxied_canister_call_max_age_seconds{{caller="{caller}",callee="{callee}",method_name="some_method"}} "#,
    )));

    assert_eq!(
        get_metric_value(&format!(
            r#"nns_root_in_flight_proxied_canister_call_count{{method_name="some_method",caller="{caller}",callee="{callee}"}} "#
        )),
        1.0,
    );

    assert_eq!(
        get_metric_value("nns_root_open_canister_status_calls_count "),
        0.0
    );

    assert_eq!(
        metrics
            .lines()
            .filter(|line| line.starts_with("nns_root_open_canister_status_calls "))
            .count(),
        0,
    );

    // Phase B: Track another call, this time to canister_status.
    // ----------------------------------------------------------

    // Step 1B: Further modify the world.
    let canister_status_tracker = ProxiedCanisterCallsTracker::start_tracking(
        &PROXIED_CANISTER_CALLS_TRACKER,
        caller,
        callee, // For realism, this should be the management canister, but it doesn't matter too much for this test.
        "canister_status",
        &[],
    );
    let now_millis = 77;

    // Step 2B: Run the code under test (again).
    let mut metrics = ic_metrics_encoder::MetricsEncoder::new(vec![], now_millis);
    encode_metrics(&mut metrics).expect("Encoding metrics.");
    let metrics = metrics.into_inner();
    let metrics = String::from_utf8_lossy(&metrics);

    // Step 3B: Inspect second batch of results.

    // Re-capture.
    let get_metric_value = |line_prefix: &str| -> f64 {
        get_metric_value_does_not_capture(now_millis, &metrics, line_prefix)
    };

    assert_less_than_50_ms(get_metric_value(&format!(
        r#"nns_root_in_flight_proxied_canister_call_max_age_seconds{{caller="{caller}",callee="{callee}",method_name="some_method"}} "#,
    )));

    assert_less_than_50_ms(get_metric_value(&format!(
        r#"nns_root_in_flight_proxied_canister_call_max_age_seconds{{caller="{caller}",callee="{callee}",method_name="canister_status"}} "#,
    )));

    assert_eq!(
        get_metric_value(&format!(
            r#"nns_root_in_flight_proxied_canister_call_count{{method_name="some_method",caller="{caller}",callee="{callee}"}} "#
        )),
        1.0,
    );

    assert_eq!(
        get_metric_value(&format!(
            r#"nns_root_in_flight_proxied_canister_call_count{{method_name="canister_status",caller="{caller}",callee="{callee}"}} "#
        )),
        1.0,
    );

    assert_eq!(
        get_metric_value("nns_root_open_canister_status_calls_count "),
        1.0
    );

    assert_eq!(
        get_metric_value(&format!(
            r#"nns_root_open_canister_status_calls{{canister_id="{caller}"}} "#,
        )),
        1.0,
    );

    // Phase C: canister_status call ends -> it should no longer be tracked.
    // ---------------------------------------------------------------------

    // Step 1C: Further modify the world.
    drop(canister_status_tracker);

    // Step 2C: Run the code under test (again).
    let mut metrics = ic_metrics_encoder::MetricsEncoder::new(vec![], now_millis);
    encode_metrics(&mut metrics).expect("Encoding metrics.");
    let metrics = metrics.into_inner();
    let metrics = String::from_utf8_lossy(&metrics);

    // Step 3C: Inspect second batch of results.

    // Re-capture metrics.
    let get_metric_value = |line_prefix: &str| -> f64 {
        get_metric_value_does_not_capture(now_millis, &metrics, line_prefix)
    };

    assert_less_than_50_ms(get_metric_value(&format!(
        r#"nns_root_in_flight_proxied_canister_call_max_age_seconds{{caller="{caller}",callee="{callee}",method_name="some_method"}} "#,
    )));

    assert_eq!(
        metrics
            .lines()
            .filter(|line| line.starts_with(&format!(
                r#"nns_root_in_flight_proxied_canister_call_max_age_seconds{{caller="{caller}",callee="{callee}",method_name="canister_status"}} "#,
            )))
            .count(),
        0,
    );

    assert_eq!(
        get_metric_value(&format!(
            r#"nns_root_in_flight_proxied_canister_call_count{{method_name="some_method",caller="{caller}",callee="{callee}"}} "#
        )),
        1.0,
    );

    assert_eq!(
        metrics
            .lines()
            .filter(|line| line.starts_with(&format!(
                r#"nns_root_in_flight_proxied_canister_call_count{{method_name="canister_status",caller="{caller}",callee="{callee}"}} "#
            )))
            .count(),
        0,
    );

    assert_eq!(
        get_metric_value("nns_root_open_canister_status_calls_count "),
        0.0,
    );

    assert_eq!(
        metrics
            .lines()
            .filter(|line| line.starts_with(&format!(
                r#"nns_root_open_canister_status_calls{{canister_id="{caller}"}} "#,
            )))
            .count(),
        0,
    );
}
