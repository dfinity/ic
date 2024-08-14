use canister_test::{Cycles, PrincipalId, WasmResult};
use ic_interfaces::execution_environment::HypervisorResult;
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_types::methods::{FuncRef, WasmMethod};
use ic_types::time::UNIX_EPOCH;

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
        .with_api_type(ic_system_api::ApiType::update(
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
