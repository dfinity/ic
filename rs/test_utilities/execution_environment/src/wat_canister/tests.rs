use super::*;

#[test]
fn test_empty_canister_builds() {
    let wat = wat_canister().build();
    let wasm_module = wat::parse_str(wat).unwrap();
    assert!(!wasm_module.is_empty());
}

#[test]
fn test_single_method_export() {
    let wat = wat_canister().update("foo", wat_fn()).build();

    wat::parse_str(&wat).unwrap();
    assert!(wat.contains(r#"(export "canister_update foo")"#));
}

#[test]
fn test_instruction_emission() {
    let wat = wat_canister()
        .update(
            "test_instructions",
            wat_fn()
                .stable_grow(1)
                .stable_read(0, 4, 7)
                .api_global_timer_set(42)
                .debug_print(b"hi")
                .trap_with_blob(b"error")
                .trap()
                .wait(10_000),
        )
        .build();

    wat::parse_str(&wat).unwrap();

    // Check that memory definitions are injected
    assert!(wat.contains(r#"(data (i32.const 1000) "hi")"#));
    assert!(wat.contains(r#"(data (i32.const 1002) "error")"#));

    // Check that calls are present in the function
    assert!(wat.contains(r#"(call $ic0_stable_grow (i32.const 1))"#));
    assert!(wat.contains(r#"(call $ic0_stable_read (i32.const 0) (i32.const 4) (i32.const 7))"#));
    assert!(wat.contains(r#"(call $ic0_global_timer_set (i64.const 42))"#));
    assert!(wat.contains(r#"(call $ic0_debug_print (i32.const 1000) (i32.const 2))"#));
    assert!(wat.contains(r#"(call $ic0_trap (i32.const 1002) (i32.const 5))"#));
    assert!(wat.contains(r#"(call $ic0_trap (i32.const 1007) (i32.const 0))"#));
    assert!(wat.contains(r#"(call $_wait (i64.const 10000))"#));
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
#[should_panic(expected = "Memory limit exceeded")]
fn test_memory_limit_exceeded() {
    let large_message = vec![0u8; 65_536];
    wat_canister()
        .update("trigger_panic", wat_fn().debug_print(&large_message))
        .build();
}

#[test]
fn test_memory_deduplication() {
    let wat = wat_canister()
        .update("foo", wat_fn().debug_print(b"duplicate"))
        .query("bar", wat_fn().debug_print(b"duplicate"))
        .build();

    wat::parse_str(&wat).unwrap();

    let data_blocks: Vec<_> = wat
        .lines()
        .filter(|line| line.contains(r#"(data "#) && line.contains(r#""duplicate""#))
        .collect();

    // Assert that exactly one data block was rendered for "duplicate",
    // proving the internal HashMap caches the offset.
    assert_eq!(data_blocks.len(), 1);
}

#[test]
fn test_comprehensive_integration() {
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
        .composite_query("test_3", wat_fn().trap_with_blob(b"composite_query").trap())
        .build();

    // The primary assertion is that this rich combination of methods
    // generates valid WebAssembly, without asserting exact formatting.
    let wasm_module = wat::parse_str(&wat).unwrap();
    assert!(!wasm_module.is_empty());

    // Basic heuristic checks to ensure exported functions are present
    assert!(wat.contains(r#"(export "canister_init")"#));
    assert!(wat.contains(r#"(export "canister_update test_1")"#));
    assert!(wat.contains(r#"(export "canister_query test_2")"#));
    assert!(wat.contains(r#"(export "canister_composite_query test_3")"#));
}

#[test]
fn test_loop_calls_scaling() {
    // Generate a Wasm file that loops 200,000 times.
    // This proves that `count` does not affect Wasm size or builder speed,
    // avoiding the parser memory blowups of O(n) unrolled loops.
    let wat = wat_canister()
        .update(
            "spam",
            wat_fn().repeat(200_000, wat_fn().debug_print(b"spam")),
        )
        .build();

    let wasm_module = wat::parse_str(&wat).unwrap();
    assert!(!wasm_module.is_empty());

    // Verify native loop constructs
    assert!(wat.contains("(local $loop_counter_0 i32)"));
    assert!(wat.contains("(loop $loop_label_0"));
    assert!(wat.contains("(i32.const 200000)"));
}

#[test]
fn test_loop_calls_nested() {
    let wat = wat_canister()
        .update(
            "nested",
            wat_fn().repeat(10, wat_fn().repeat(5, wat_fn().debug_print(b"inner"))),
        )
        .build();

    wat::parse_str(&wat).unwrap();

    // Verify it correctly allocated two distinct loop locals at the top boundary
    assert!(wat.contains("(local $loop_counter_0 i32)"));
    assert!(wat.contains("(local $loop_counter_1 i32)"));
    assert!(wat.contains("(loop $loop_label_0"));
    assert!(wat.contains("(loop $loop_label_1"));
}
