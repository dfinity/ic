//! Test to validate that all existing function references are properly updated
//! after instrumentation.

use ic_embedders::wasmtime_embedder::system_api::ApiType;
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_types::{
    Cycles, PrincipalId,
    methods::{FuncRef, WasmMethod},
    time::UNIX_EPOCH,
};

fn run_go_export(wat: &str) {
    const LARGE_INSTRUCTION_LIMIT: u64 = 1_000_000_000_000;

    let mut instance = WasmtimeInstanceBuilder::new()
        .with_wat(wat)
        .with_api_type(ApiType::update(
            UNIX_EPOCH,
            vec![],
            Cycles::from(0_u128),
            PrincipalId::new_user_test_id(0),
            0.into(),
        ))
        .with_num_instructions(LARGE_INSTRUCTION_LIMIT.into())
        .build();

    instance
        .run(FuncRef::Method(WasmMethod::Update("go".to_string())))
        .unwrap();
}

#[test]
fn direct_call() {
    run_go_export(
        r#"
		(module
			(func $reply (import "ic0" "msg_reply"))
			(func $f (result i32) (i32.const 123))
			(func $go (export "canister_update go")
				(call $f)
				(i32.const 123)
				(i32.ne)
				(if (then unreachable))
				(call $reply)
		    )
		)
	"#,
    );
}

#[test]
fn element() {
    run_go_export(
        r#"
		(module
			(func $reply (import "ic0" "msg_reply"))
			(func $f (result i32) (i32.const 123))

			(type $f_type (func (result i32)))
			(table 1 funcref)
			(elem (i32.const 0) $f)

			(func $go (export "canister_update go")
				(call_indirect (type $f_type) (i32.const 0))
				(i32.const 123)
				(i32.ne)
				(if (then unreachable))
				(call $reply)
		    )
		)
	"#,
    );
}

#[test]
fn element_const_expr() {
    run_go_export(
        r#"
		(module
			(func $reply (import "ic0" "msg_reply"))
			(func $f (result i32) (i32.const 123))

			(type $f_type (func (result i32)))
			(table 1 funcref)
			(elem (i32.const 0) funcref (ref.func $f))

			(func $go (export "canister_update go")
				(call_indirect (type $f_type) (i32.const 0))
				(i32.const 123)
				(i32.ne)
				(if (then unreachable))
				(call $reply)
		    )
		)
	"#,
    );
}
