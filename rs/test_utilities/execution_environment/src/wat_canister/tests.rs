use super::*;
use strum::IntoEnumIterator;

#[test]
fn test_fmt_wat_const() {
    assert_eq!(WatConst::I32(5).to_string(), r#"(i32.const 5)"#);
    assert_eq!(WatConst::I64(7).to_string(), r#"(i64.const 7)"#);
}

#[test]
fn test_fmt_wat_call() {
    let test_cases = vec![
        (
            WatCall::stable_grow(7),
            "(drop (call $ic0_stable_grow (i32.const 7)))",
        ),
        (
            WatCall::stable_read(0, 4, 7),
            "(call $ic0_stable_read (i32.const 0) (i32.const 4) (i32.const 7))",
        ),
        (
            WatCall::global_timer_set(42),
            "(drop (call $ic0_global_timer_set (i64.const 42)))",
        ),
        (
            WatCall::debug_print(0, 4),
            "(call $ic0_debug_print (i32.const 0) (i32.const 4))",
        ),
        (
            WatCall::trap(2, 4),
            "(call $ic0_trap (i32.const 2) (i32.const 4))",
        ),
        (WatCall::wait(10_000), "(call $_wait (i64.const 10000))"),
    ];
    for (call, expected) in test_cases.into_iter() {
        assert_eq!(call.to_string(), expected);
    }
}

#[test]
fn test_fmt_wat_data() {
    assert_eq!(
        WatData::new(3, b"hello world").to_string(),
        r#"(data (i32.const 3) "hello world")"#
    );
    assert_eq!(
        WatData::new(5, &[1, 2, 3]).to_string(),
        r#"(data (i32.const 5) "\01\02\03")"#
    );
    assert_eq!(
        WatData::new(7, &[0xc0, 0xff, 0xee]).to_string(),
        r#"(data (i32.const 7) "\C0\FF\EE")"#
    );
    assert_eq!(
        WatData::new(11, &[92, 198, 186, 50, 37]).to_string(),
        r#"(data (i32.const 11) "\5C\C6\BA\32\25")"#
    );
}

#[test]
#[should_panic(expected = "Method 'Start' with the name 'start' already exists")]
fn test_wat_func_unique_start() {
    wat_canister().start(wat_fn()).start(wat_fn());
}

#[test]
#[should_panic(expected = "Method 'Init' with the name 'init' already exists")]
fn test_wat_func_unique_init() {
    wat_canister().init(wat_fn()).init(wat_fn());
}

#[test]
#[should_panic(expected = "Method 'PreUpgrade' with the name 'pre_upgrade' already exists")]
fn test_wat_func_unique_pre_upgrade() {
    wat_canister().pre_upgrade(wat_fn()).pre_upgrade(wat_fn());
}

#[test]
#[should_panic(expected = "Method 'PostUpgrade' with the name 'post_upgrade' already exists")]
fn test_wat_func_unique_post_upgrade() {
    wat_canister().post_upgrade(wat_fn()).post_upgrade(wat_fn());
}

#[test]
#[should_panic(expected = "Method 'InspectMessage' with the name 'inspect_message' already exists")]
fn test_wat_func_unique_inspect_message() {
    wat_canister()
        .inspect_message(wat_fn())
        .inspect_message(wat_fn());
}

#[test]
#[should_panic(expected = "Method 'Heartbeat' with the name 'heartbeat' already exists")]
fn test_wat_func_unique_heartbeat() {
    wat_canister().heartbeat(wat_fn()).heartbeat(wat_fn());
}

#[test]
#[should_panic(expected = "Method 'GlobalTimer' with the name 'global_timer' already exists")]
fn test_wat_func_unique_global_timer() {
    wat_canister().global_timer(wat_fn()).global_timer(wat_fn());
}

#[test]
#[should_panic(expected = "Method 'Update' with the name 'test_3' already exists")]
fn test_wat_func_unique_update() {
    wat_canister()
        .update("test_1", wat_fn())
        .update("test_2", wat_fn());
    wat_canister()
        .update("test_3", wat_fn())
        .update("test_3", wat_fn());
}

#[test]
#[should_panic(expected = "Method 'Query' with the name 'test_3' already exists")]
fn test_wat_func_unique_query() {
    wat_canister()
        .query("test_1", wat_fn())
        .query("test_2", wat_fn());
    wat_canister()
        .query("test_3", wat_fn())
        .query("test_3", wat_fn());
}

#[test]
#[should_panic(expected = "Method 'CompositeQuery' with the name 'test_3' already exists")]
fn test_wat_func_unique_composite_query() {
    wat_canister()
        .composite_query("test_1", wat_fn())
        .composite_query("test_2", wat_fn());
    wat_canister()
        .composite_query("test_3", wat_fn())
        .composite_query("test_3", wat_fn());
}

#[test]
fn test_fmt_wat_func_no_calls() {
    for (method, expected) in Method::iter().zip(vec![
        r#"(start $start)
            (func $start)"#,
        r#"(func $init (export "canister_init"))"#,
        r#"(func $pre_upgrade (export "canister_pre_upgrade"))"#,
        r#"(func $post_upgrade (export "canister_post_upgrade"))"#,
        r#"(func $inspect_message (export "canister_inspect_message"))"#,
        r#"(func $heartbeat (export "canister_heartbeat"))"#,
        r#"(func $global_timer (export "canister_global_timer"))"#,
        r#"(func $custom_name (export "canister_update custom_name"))"#,
        r#"(func $custom_name (export "canister_query custom_name"))"#,
        r#"(func $custom_name (export "canister_composite_query custom_name"))"#,
    ]) {
        assert_eq!(
            WatFunc {
                method,
                name: "custom_name".to_string(),
                calls: vec![],
            }
            .to_string(),
            *expected
        );
    }
}

#[test]
fn test_fmt_wat_func_one_call() {
    assert_eq!(
        WatFunc {
            method: Method::Update,
            name: "test".to_string(),
            calls: vec![WatCall::debug_print(0, 4)],
        }
        .to_string(),
        r#"
            (func $test (export "canister_update test")
                (call $ic0_debug_print (i32.const 0) (i32.const 4))
            )"#
    );
}

#[test]
fn test_fmt_wat_func_many_calls() {
    assert_eq!(
        WatFunc {
            method: Method::Update,
            name: "test".to_string(),
            calls: vec![
                WatCall::stable_grow(1),
                WatCall::stable_read(0, 4, 7),
                WatCall::global_timer_set(1),
                WatCall::debug_print(0, 4),
                WatCall::trap(10, 4),
                WatCall::wait(10_000),
            ],
        }
        .to_string(),
        r#"
            (func $test (export "canister_update test")
                (drop (call $ic0_stable_grow (i32.const 1)))
                (call $ic0_stable_read (i32.const 0) (i32.const 4) (i32.const 7))
                (drop (call $ic0_global_timer_set (i64.const 1)))
                (call $ic0_debug_print (i32.const 0) (i32.const 4))
                (call $ic0_trap (i32.const 10) (i32.const 4))
                (call $_wait (i64.const 10000))
            )"#
    );
}

#[test]
fn test_wat_canister_builder() {
    let wat = wat_canister()
        .start(wat_fn().debug_print(b"start"))
        .init(wat_fn().debug_print(b"init").api_global_timer_set(1))
        .pre_upgrade(wat_fn().debug_print(b"pre_upgrade"))
        .post_upgrade(wat_fn().debug_print(b"post_upgrade"))
        .inspect_message(wat_fn().debug_print(b"inspect_message"))
        .heartbeat(wat_fn().debug_print(b"heartbeat"))
        .global_timer(wat_fn().debug_print(b"global_timer"))
        .update(
            "test_1",
            wat_fn()
                .debug_print(b"aa")
                .debug_print(b"aa")
                .debug_print(b"bbb")
                .wait(5_000)
                .debug_print(b"cccc")
                .trap_with_blob(b"bbb"),
        )
        .query(
            "test_2",
            wat_fn()
                .debug_print(b"cccc")
                .wait(10_000)
                .trap_with_blob(b"query"),
        )
        .composite_query("test_3", wat_fn().trap_with_blob(b"composite_query"))
        .build();

    let wasm_module = wat::parse_str(wat.clone()).unwrap();
    assert!(!wasm_module.is_empty());
    assert_eq!(
        wat,
        r#"
        (module
            ;; Import functions
            (import "ic0" "stable_grow" (func $ic0_stable_grow (param $pages i32) (result i32)))
            (import "ic0" "stable_read" (func $ic0_stable_read (param i32 i32 i32)))
            (import "ic0" "global_timer_set" (func $ic0_global_timer_set (param i64) (result i64)))
            (import "ic0" "performance_counter" (func $ic0_performance_counter (param i32) (result i64)))
            (import "ic0" "debug_print" (func $ic0_debug_print (param i32) (param i32)))
            (import "ic0" "trap" (func $ic0_trap (param i32) (param i32)))

            ;; Define functions
            (func $_wait (param $instructions i64)
                ;; Calculate the instruction limit
                (local $limit i64)
                (local.set $limit (i64.add (call $ic0_performance_counter (i32.const 0)) (local.get $instructions)))
                (loop $loop
                    (if (i64.lt_s
                            (call $ic0_performance_counter (i32.const 0))
                            (local.get $limit))
                        (then
                            ;; Placeholder instruction for simulating work
                            (memory.fill (i32.const 0) (i32.const 0) (i32.const 100))
                            (br $loop)
                        )
                    )
                )
            )
            
            (start $start)
            (func $start
                (call $ic0_debug_print (i32.const 1000) (i32.const 5))
            )

            (func $init (export "canister_init")
                (call $ic0_debug_print (i32.const 1005) (i32.const 4))
                (drop (call $ic0_global_timer_set (i64.const 1)))
            )

            (func $pre_upgrade (export "canister_pre_upgrade")
                (call $ic0_debug_print (i32.const 1009) (i32.const 11))
            )

            (func $post_upgrade (export "canister_post_upgrade")
                (call $ic0_debug_print (i32.const 1020) (i32.const 12))
            )

            (func $inspect_message (export "canister_inspect_message")
                (call $ic0_debug_print (i32.const 1032) (i32.const 15))
            )

            (func $heartbeat (export "canister_heartbeat")
                (call $ic0_debug_print (i32.const 1047) (i32.const 9))
            )

            (func $global_timer (export "canister_global_timer")
                (call $ic0_debug_print (i32.const 1056) (i32.const 12))
            )

            (func $test_1 (export "canister_update test_1")
                (call $ic0_debug_print (i32.const 1068) (i32.const 2))
                (call $ic0_debug_print (i32.const 1068) (i32.const 2))
                (call $ic0_debug_print (i32.const 1070) (i32.const 3))
                (call $_wait (i64.const 5000))
                (call $ic0_debug_print (i32.const 1073) (i32.const 4))
                (call $ic0_trap (i32.const 1070) (i32.const 3))
            )

            (func $test_2 (export "canister_query test_2")
                (call $ic0_debug_print (i32.const 1073) (i32.const 4))
                (call $_wait (i64.const 10000))
                (call $ic0_trap (i32.const 1077) (i32.const 5))
            )

            (func $test_3 (export "canister_composite_query test_3")
                (call $ic0_trap (i32.const 1082) (i32.const 15))
            )

            ;; Define memory
            (memory $memory 1)
            (export "memory" (memory $memory))

            ;; Initialize memory with data
            (data (i32.const 1000) "start")
            (data (i32.const 1005) "init")
            (data (i32.const 1009) "pre_upgrade")
            (data (i32.const 1020) "post_upgrade")
            (data (i32.const 1032) "inspect_message")
            (data (i32.const 1047) "heartbeat")
            (data (i32.const 1056) "global_timer")
            (data (i32.const 1068) "aa")
            (data (i32.const 1070) "bbb")
            (data (i32.const 1073) "cccc")
            (data (i32.const 1077) "query")
            (data (i32.const 1082) "composite_query")
        )"#
    );
}
