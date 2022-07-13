use ic_config::{embedders::Config as EmbeddersConfig, flag_status::FlagStatus};
use ic_test_utilities::execution_environment::ExecutionTestBuilder;
use ic_test_utilities_metrics::fetch_histogram_stats;

#[test]
fn compilation_metrics_are_recorded_during_installation() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat1 = r#"
        (module
            (func (result i64)
                (i64.const 1)
                (i64.add (i64.const 1))
                (i64.add (i64.const 1))
                (i64.add (i64.const 1))
            )
            (func)
        )"#;
    let wat2 = "(module)";
    test.canister_from_wat(wat1).unwrap();
    test.canister_from_wat(wat2).unwrap();
    let largest_function_metric = fetch_histogram_stats(
        test.metrics_registry(),
        "hypervisor_largest_function_instruction_count",
    )
    .unwrap();
    assert_eq!(largest_function_metric.count, 2);
    assert_eq!(largest_function_metric.sum, 8.0);
    let compilation_time_metric = fetch_histogram_stats(
        test.metrics_registry(),
        "hypervisor_wasm_compile_time_seconds",
    )
    .unwrap();
    assert_eq!(compilation_time_metric.count, 2);
}

#[test]
fn compilation_metrics_are_recorded_during_update() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func $go 
                (i64.const 1)
                (i64.add (i64.const 1))
                (i64.add (i64.const 1))
                (i64.add (i64.const 1))
                (drop)
                (call $msg_reply)
            )
            (export "canister_update go" (func $go))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let canister_state = test.canister_state_mut(canister_id);
    // Clear caches so that we are forced to recompile.
    canister_state
        .execution_state
        .as_mut()
        .unwrap()
        .wasm_binary
        .clear_compilation_cache();
    test.execution_environment()
        .clear_compilation_cache_for_testing();
    test.ingress(canister_id, "go", vec![]).unwrap();
    let largest_function_metric = fetch_histogram_stats(
        test.metrics_registry(),
        "hypervisor_largest_function_instruction_count",
    )
    .unwrap();
    // Compiled once for install and once for execution.
    assert_eq!(largest_function_metric.count, 2);
    assert_eq!(largest_function_metric.sum, 20.0);
    let compilation_time_metric = fetch_histogram_stats(
        test.metrics_registry(),
        "hypervisor_wasm_compile_time_seconds",
    )
    .unwrap();
    assert_eq!(compilation_time_metric.count, 2);
}

#[test]
fn compilation_shared_from_install_to_update() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func $go (call $msg_reply))
            (export "canister_update go" (func $go))
        )"#;

    // Install canister with wat.
    let canister_id1 = test.canister_from_wat(wat).unwrap();
    let canister_state = test.canister_state_mut(canister_id1);

    // Clear caches so that we are forced to recompile.
    canister_state
        .execution_state
        .as_mut()
        .unwrap()
        .wasm_binary
        .clear_compilation_cache();
    test.execution_environment()
        .clear_compilation_cache_for_testing();

    // Install second canister with same wat.
    let _canister_id2 = test.canister_from_wat(wat).unwrap();

    // Now an update on the first canister shouldn't require compilation. So we
    // get one compilation for each canister install.
    test.ingress(canister_id1, "go", vec![]).unwrap();
    let compilation_time_metric = fetch_histogram_stats(
        test.metrics_registry(),
        "hypervisor_wasm_compile_time_seconds",
    )
    .unwrap();
    match EmbeddersConfig::default().feature_flags.module_sharing {
        FlagStatus::Enabled => assert_eq!(compilation_time_metric.count, 2),
        FlagStatus::Disabled => assert_eq!(compilation_time_metric.count, 3),
    }
}

#[test]
fn compilation_shared_from_update_to_update() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func $go (call $msg_reply))
            (export "canister_update go" (func $go))
        )"#;

    // Install two canisters with the same wat.
    let canister_id1 = test.canister_from_wat(wat).unwrap();
    let canister_id2 = test.canister_from_wat(wat).unwrap();

    // Clear caches so that we are forced to recompile.
    test.canister_state_mut(canister_id1)
        .execution_state
        .as_mut()
        .unwrap()
        .wasm_binary
        .clear_compilation_cache();
    test.canister_state_mut(canister_id2)
        .execution_state
        .as_mut()
        .unwrap()
        .wasm_binary
        .clear_compilation_cache();
    test.execution_environment()
        .clear_compilation_cache_for_testing();

    // Now an update on one canister will require compilation, but not on the
    // second. So we get 2 compilations in total (1 for first install and 1 for
    // one of the updates).
    test.ingress(canister_id1, "go", vec![]).unwrap();
    test.ingress(canister_id2, "go", vec![]).unwrap();
    let compilation_time_metric = fetch_histogram_stats(
        test.metrics_registry(),
        "hypervisor_wasm_compile_time_seconds",
    )
    .unwrap();
    match EmbeddersConfig::default().feature_flags.module_sharing {
        FlagStatus::Enabled => assert_eq!(compilation_time_metric.count, 2),
        FlagStatus::Disabled => assert_eq!(compilation_time_metric.count, 4),
    }
}

#[test]
fn compilation_shared_from_install_to_install() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r"(module)";

    // Install two canisters with the same wat.
    let _canister_id1 = test.canister_from_wat(wat).unwrap();
    let _canister_id2 = test.canister_from_wat(wat).unwrap();

    // Compilation will have been shared so we should have only compiled once.
    let compilation_time_metric = fetch_histogram_stats(
        test.metrics_registry(),
        "hypervisor_wasm_compile_time_seconds",
    )
    .unwrap();
    match EmbeddersConfig::default().feature_flags.module_sharing {
        FlagStatus::Enabled => assert_eq!(compilation_time_metric.count, 1),
        FlagStatus::Disabled => assert_eq!(compilation_time_metric.count, 2),
    }
}

#[test]
fn compilation_shared_from_update_to_install() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func $go (call $msg_reply))
            (export "canister_update go" (func $go))
        )"#;

    let canister_id1 = test.canister_from_wat(wat).unwrap();

    // Clear caches so that we are forced to recompile.
    test.canister_state_mut(canister_id1)
        .execution_state
        .as_mut()
        .unwrap()
        .wasm_binary
        .clear_compilation_cache();
    test.execution_environment()
        .clear_compilation_cache_for_testing();

    // Now an update on one canister will require compilation, but a new install
    // with the same wasm won't require a compilation.
    test.ingress(canister_id1, "go", vec![]).unwrap();
    let _canister_id2 = test.canister_from_wat(wat).unwrap();
    let compilation_time_metric = fetch_histogram_stats(
        test.metrics_registry(),
        "hypervisor_wasm_compile_time_seconds",
    )
    .unwrap();
    match EmbeddersConfig::default().feature_flags.module_sharing {
        FlagStatus::Enabled => assert_eq!(compilation_time_metric.count, 2),
        FlagStatus::Disabled => assert_eq!(compilation_time_metric.count, 3),
    }
}
