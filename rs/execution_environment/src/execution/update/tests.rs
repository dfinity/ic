use crate::execution::test_utilities::ExecutionTestBuilder;

const GB: u64 = 1024 * 1024 * 1024;

fn wat_writing_to_each_stable_memory_page(memory_amount: u64) -> String {
    format!(
        r#"
        (module
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update go") (local i64)
                (local.set 0 (i64.const 0))
                (drop (call $stable_grow (i64.const 131072))) (; maximum allowed ;)
                (loop $loop
                    (call $stable_write (local.get 0) (i64.const 0) (i64.const 1))
                    (local.set 0 (i64.add (local.get 0) (i64.const 4096))) (;increment by OS page size;)
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const {}))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (memory (export "memory") 1)
        )"#,
        memory_amount
    )
}

#[test]
#[allow(non_snake_case)]
fn can_write_to_each_page_in_stable_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = wat_writing_to_each_stable_memory_page(7 * GB);
    let canister_id = test.canister_from_wat(wat).unwrap();
    let _result = test.ingress(canister_id, "go", vec![]).unwrap();
}
