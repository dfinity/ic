use ic_test_utilities::execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::{ingress::WasmResult, CanisterId};
use proptest::{
    prelude::*,
    test_runner::{TestRng, TestRunner},
};

fn make_module_wat(heap_size: usize) -> String {
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

      (func $memory_grow
        ;; copy the i32 `delta` to heap[0;4]
        (call $ic0_msg_arg_data_copy
          (i32.const 0) ;; dst
          (i32.const 0) ;; off
          (i32.const 4) ;; len
        )
        (drop (memory.grow (i32.load (i32.const 0))))
      )

      (func $dump_heap
        (call $msg_reply_data_append (i32.const 0) (i32.mul (memory.size) (i32.const 0x10000)))
        (call $msg_reply)
      )

      ;; write to memory
      (func $write_bytes
        ;; copy the i32 `addr` to heap[0;4]
        (call $ic0_msg_arg_data_copy
          (i32.const 0) ;; dst
          (i32.const 0) ;; off
          (i32.const 4) ;; len
        )
        ;; copy the remainder of the payload to the heap[addr;size]
        (call $ic0_msg_arg_data_copy
          ;; addr
          (i32.load (i32.const 0))
          ;; offset
          (i32.const 4)
          ;; size
          (i32.sub
            (call $ic0_msg_arg_data_size)
            (i32.const 4)
          )
        )
        (call $msg_reply)
      )

      (memory $memory {})
      (export "canister_query dump_heap" (func $dump_heap))
      (export "canister_update memory_grow" (func $memory_grow))
      (export "canister_update write_bytes" (func $write_bytes))
    )"#,
        heap_size
    )
}

#[derive(Debug)]
pub struct Write {
    dst: u32,
    bytes: Vec<u8>,
}

fn random_writes(heap_size: usize, num_writes: usize) -> impl Strategy<Value = Vec<Write>> {
    let write_strategy = (0..heap_size).prop_flat_map(move |dst| {
        let dst = dst as u32;
        // up to 128 bytes
        let remain = (heap_size - dst as usize) % 128;
        prop::collection::vec(any::<u8>(), 0..=remain).prop_map(move |bytes| Write { dst, bytes })
    });
    prop::collection::vec(write_strategy, 1..num_writes)
}

fn write_bytes(test: &mut ExecutionTest, canister_id: CanisterId, dst: u32, bytes: &[u8]) {
    println!("write_bytes(dst: {}, bytes: {:?})", dst, bytes);
    let mut payload = dst.to_le_bytes().to_vec();
    payload.extend(bytes.iter());
    let result = test.ingress(canister_id, "write_bytes", payload).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
}

fn dump_heap(test: &mut ExecutionTest, canister_id: CanisterId) -> Vec<u8> {
    println!("dump_heap()");
    let result = test.ingress(canister_id, "dump_heap", vec![]).unwrap();
    match result {
        WasmResult::Reply(canister_heap) => canister_heap,
        WasmResult::Reject(error) => {
            panic!("failed to dump heap: {}", error)
        }
    }
}

fn buf_apply_write(heap: &mut [u8], write: &Write) {
    // match the behavior of write_bytes: copy the i32 `addr` to heap[0;4]
    heap[0..4].copy_from_slice(&write.dst.to_le_bytes());
    heap[write.dst as usize..(write.dst as usize + write.bytes.len() as usize)]
        .copy_from_slice(&write.bytes)
}

const TEST_HEAP_SIZE_BYTES: usize = WASM_PAGE_SIZE_BYTES * TEST_NUM_PAGES;
// This limit is reduced to 32 pages to ensure that the maximum query response
// is not larger than 2MB. This is required because currently the size of the
// query response is bounded by the MAX_INTER_CANISTER_MESSAGE_IN_BYTES. To fix
// this, we could try one of the following two approaches: - Make the test dump
// the heap using multiple messages. - Set a different limit for query
// responses.
//const TEST_NUM_PAGES: usize = 400;
const TEST_NUM_PAGES: usize = 32;
const TEST_NUM_WRITES: usize = 20;
const WASM_PAGE_SIZE_BYTES: usize = 65536;

#[test]
// generate multiple writes of varying size to random memory locations, apply them both to a
// canister and a simple Vec buffer and compare the results.
fn test_orthogonal_persistence() {
    let config = ProptestConfig {
        cases: 20,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let algorithm = config.rng_algorithm;
    let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
    runner
        .run(
            &random_writes(TEST_HEAP_SIZE_BYTES, TEST_NUM_WRITES),
            |writes| {
                let mut test = ExecutionTestBuilder::new().build();
                let mut heap = vec![0; TEST_HEAP_SIZE_BYTES];
                let wat = make_module_wat(TEST_NUM_PAGES);
                let canister_id = test.canister_from_wat(wat).unwrap();

                for w in &writes {
                    buf_apply_write(&mut heap, w);
                    write_bytes(&mut test, canister_id, w.dst, &w.bytes);
                    // verify the heap
                    let canister_heap = dump_heap(&mut test, canister_id);
                    prop_assert_eq!(&heap[..], &canister_heap[..]);
                }
                Ok(())
            },
        )
        .unwrap();
}
