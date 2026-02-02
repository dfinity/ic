use canister_test::{Cycles, PrincipalId, WasmResult};
use ic_embedders::wasmtime_embedder::system_api::ApiType;
use ic_error_types::ErrorCode;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_test_utilities_execution_environment::ExecutionTestBuilder;
use ic_types::methods::{FuncRef, WasmMethod};
use ic_types::time::UNIX_EPOCH;

const GIB: u64 = 1024 * 1024 * 1024;

fn wat_with_imports(wat: &str) -> String {
    format!(
        r#"
	(module
      (import "ic0" "msg_reply" (func $msg_reply))
      (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32) (param i32)))
      (import "ic0" "msg_arg_data_copy"
        (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
      (import "ic0" "msg_arg_data_size"
        (func $ic0_msg_arg_data_size (result i32)))
      (import "ic0" "stable64_grow"
        (func $ic0_stable64_grow (param $pages i64) (result i64)))
      (import "ic0" "stable_read"
        (func $ic0_stable_read (param $dst i32) (param $offset i32) (param $size i32)))
      (import "ic0" "stable64_read"
        (func $ic0_stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
      (import "ic0" "stable_write"
        (func $ic0_stable_write (param $offset i32) (param $src i32) (param $size i32)))
      (import "ic0" "stable64_write"
        (func $ic0_stable64_write (param $offset i64) (param $src i64) (param $size i64)))

		{wat}
	)
	"#
    )
}

fn run_test(wat: &str) -> HypervisorResult<Option<WasmResult>> {
    let mut instance = WasmtimeInstanceBuilder::new()
        .with_api_type(ApiType::update(
            UNIX_EPOCH,
            vec![],
            Cycles::zero(),
            PrincipalId::new_user_test_id(0),
            0.into(),
        ))
        .with_wat(wat)
        .build();
    let run_result = instance.run(FuncRef::Method(WasmMethod::Update("go".to_string())));
    instance
        .store_data_mut()
        .system_api_mut()
        .unwrap()
        .take_execution_result(run_result.as_ref().err())
}

#[test]
fn can_grow_then_read_stable_memory() {
    let wat = r#"
	  (memory 1)
	  (func (export "canister_update go")
	    ;; Grow stable memory to one page
	  	(i64.ne (call $ic0_stable64_grow (i64.const 1)) (i64.const 0))
	  	(if (then unreachable))

		;; Assert that we can read an i64 from stable memory
	  	(call $ic0_stable64_read (i64.const 0) (i64.const 0) (i64.const 8))
	  	(i64.ne (i64.load (i32.const 0)) (i64.const 0))
	  	(if (then unreachable))

	  	(call $msg_reply)
	  )
	"#;
    assert_eq!(
        run_test(&wat_with_imports(wat)),
        Ok(Some(WasmResult::Reply(vec![])))
    );
}

#[test]
fn can_write_then_read_stable_memory_across_pages() {
    let wat = r#"
	  (memory 1)
	  (func (export "canister_update go")
	    ;; Grow stable memory to one page
	  	(i64.ne (call $ic0_stable64_grow (i64.const 1)) (i64.const 0))
	  	(if (then unreachable))

	  	;; Write to the end of the first page
	  	(i32.store (i32.const 0) (i32.const 55))
		(call $ic0_stable64_write (i64.const 4092) (i64.const 0) (i64.const 4))

		;; Read back data from first and second pages
	  	(call $ic0_stable64_read (i64.const 1000) (i64.const 4092) (i64.const 8))
	  	(i64.ne (i64.load (i32.const 1000)) (i64.const 55))
	  	(if (then unreachable))

	  	(call $msg_reply)
	  )
	"#;
    assert_eq!(
        run_test(&wat_with_imports(wat)),
        Ok(Some(WasmResult::Reply(vec![])))
    );
}

#[test]
fn can_read_from_accessed_and_unaccessed_pages() {
    let wat = r#"
	  (memory 1)
	  (func (export "canister_update go")
	    ;; Grow stable memory to one page
	  	(i64.ne (call $ic0_stable64_grow (i64.const 1)) (i64.const 0))
	  	(if (then unreachable))

	  	;; Read from the first page
	  	(call $ic0_stable64_read (i64.const 0) (i64.const 0) (i64.const 8))
	  	(i64.ne (i64.load (i32.const 0)) (i64.const 0))
	  	(if (then unreachable))

		;; Read from the first and second pages
	  	(call $ic0_stable64_read (i64.const 1000) (i64.const 4092) (i64.const 8))
	  	(i64.ne (i64.load (i32.const 1000)) (i64.const 0))
	  	(if (then unreachable))

	  	(call $msg_reply)
	  )
	"#;
    assert_eq!(
        run_test(&wat_with_imports(wat)),
        Ok(Some(WasmResult::Reply(vec![])))
    );
}

#[test]
fn stable_write_traps_after_failed_stable_grow_due_to_subnet_memory() {
    // Set up a subnet with a very small memory capacity to force stable_grow to fail.
    // Set subnet memory capacity to 20 GiB.
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(20 * GIB)
        .build();

    // Install a canister with a wasm that:
    // 1. Attempts to grow stable memory enough to use up all the subnet memory.
    // 2. Attempts to write to stable memory (should trap with out of bounds)
    let wat = format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_write" (func $stable64_write (param i64 i64 i64)))
            (memory 1)
            (func (export "canister_update go")
                (i64.ne (call $stable64_grow (i64.const {})) (i64.const -1))
                (if (then unreachable))

                ;; Try to write to stable memory (should trap with out of bounds)
                (call $stable64_write (i64.const 0) (i64.const 0) (i64.const 8))

                (call $msg_reply)
            )
        )
    "#,
        (20 * GIB) / (WASM_PAGE_SIZE_IN_BYTES as u64)
    );

    let canister_id = test
        .canister_from_cycles_and_wat(Cycles::new(10_000_000_000_000), wat)
        .unwrap();

    // Execute the update method and expect a trap with "stable memory out of bounds"
    let err = test.ingress(canister_id, "go", vec![]).unwrap_err();

    err.assert_contains(ErrorCode::CanisterTrapped, "stable memory out of bounds");
}
