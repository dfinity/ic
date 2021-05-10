use canister_test::{local_test_e, WASM};
use criterion::Criterion;

const HELLO_WORLD: &str = r#"
            (module
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "msg_reply" (func $msg_reply))

              (func $read
                (call $msg_reply_data_append (i32.const 0) (i32.const 0))
                (call $msg_reply)
              )
              (memory 0)
              (export "canister_query read" (func $read)))"#;

fn main() {
    local_test_e(|r| async move {
        let mut criterion = Criterion::default().sample_size(10);
        {
            let mut group = criterion.benchmark_group("user calls");
            let canister = WASM::from_wat(HELLO_WORLD)
                .install(&r)
                .bytes(Vec::new())
                .await?;

            group.bench_function("single-node P2P/consensus update", |bench| {
                bench.iter(|| async {
                    let _ = canister
                        .update("read")
                        .bytes(b"Hello".to_vec())
                        .await
                        .unwrap();
                });
            });

            group.bench_function("query", |bench| {
                bench.iter(|| async {
                    let _ = canister.query("read").bytes(b"Hello".to_vec());
                });
            });
        }
        criterion.final_summary();
        Ok(())
    });
}
