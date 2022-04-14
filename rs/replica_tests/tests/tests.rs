use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_error_types::ErrorCode;
use ic_ic00_types::{self as ic00, EmptyBlob, Method};
use ic_replica_tests as utils;
use ic_replica_tests::assert_reply;
use ic_replicated_state::{PageIndex, PageMap};
use ic_sys::PAGE_SIZE;
use ic_test_utilities::types::ids::canister_test_id;
use ic_test_utilities::universal_canister::{call_args, wasm};
use ic_types::{
    ingress::WasmResult, messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
    time::current_time_and_expiry_time, CanisterId, NumBytes, RegistryVersion,
};

const WASM_PAGE_SIZE: usize = 65536;
const CYCLES_BALANCE: u128 = 1 << 50;

#[test]
/// Tests a message can roundtrip through all layers
fn test_message_roundtrip() {
    utils::simple_canister_test(|canister| {
        assert_reply(
            canister.query(wasm().reply_data(b"Hello World!")),
            b"Hello World!",
        );

        assert_reply(
            canister.update(wasm().reply_data(b"Hello World!")),
            b"Hello World!",
        );
    })
}

#[test]
/// Tests that a duplicate message results in a noop.
fn test_duplicate_message_is_noop() {
    utils::canister_test(|test| {
        let canister_id = test.create_universal_canister();

        // Grow stable memory. Output should be the size of stable memory
        // before growing it (0).
        assert_eq!(
            test.ingress_with_nonce(
                canister_id,
                "update",
                wasm().stable_grow(1).reply_int(),
                2 // nonce
            ),
            Ok(WasmResult::Reply(vec![0, 0, 0, 0]))
        );

        let expiry_time = current_time_and_expiry_time().1;

        // Grow stable memory again. Output should be the size of stable memory
        // before growing it (1).
        assert_eq!(
            test.ingress_with_expiry_and_nonce(
                canister_id,
                "update",
                wasm().stable_grow(1).reply_int(),
                expiry_time,
                3, // nonce
            ),
            Ok(WasmResult::Reply(vec![1, 0, 0, 0]))
        );

        // Duplicate message. Should result in a no-op.
        // Note that currently the stable memory size is 2, so if the call isn't
        // a no-op the result would be 2.
        assert_eq!(
            test.ingress_with_expiry_and_nonce(
                canister_id,
                "update",
                wasm().stable_grow(1).reply_int(),
                expiry_time,
                3, // nonce
            ),
            Ok(WasmResult::Reply(vec![1, 0, 0, 0]))
        );
    })
}

#[test]
/// Tests that a canister correctly initializes itself
fn test_canister_init() {
    utils::canister_test(move |test| {
        // Store some data in stable memory on canister_init
        let bytes = b"hello from canister init";
        let canister_id = test.create_universal_canister_with_args(
            wasm().stable_grow(1).stable_write(10, bytes),
            CYCLES_BALANCE,
        );

        // Verify that the data written in canister_init is available.
        assert_reply(
            test.query(
                canister_id,
                "query",
                wasm()
                    .stable_read(10, bytes.len() as u32)
                    .reply_data_append()
                    .reply(),
            ),
            bytes,
        );
    })
}

#[test]
/// Tests debug.log from canister_init
fn test_canister_init_debug_print() {
    // installs a canister that uses debug.log from canister_init
    // and panics if an error has occurred.
    utils::canister_test(move |test| {
        test.create_universal_canister_with_args(wasm().debug_print(b"Hi!"), CYCLES_BALANCE);
    })
}

#[test]
/// Tests that a counter can be incremented on the heap
fn test_counter_heap() {
    utils::canister_test(|test| {
        let (canister_id, _) = test.create_and_install_canister(COUNTER_ON_HEAP, vec![]);
        let initial_val = test.query(canister_id, "read", vec![]).unwrap().bytes();
        test.ingress(canister_id, "inc", vec![]).unwrap();
        let final_val = test.query(canister_id, "read", vec![]).unwrap().bytes();
        assert_eq!(final_val[0], initial_val[0] + 1);
    })
}

#[test]
/// Tests that we can persist globals across multiple message executions.
fn can_persist_globals_across_multiple_message_executions() {
    utils::canister_test(|test| {
        let (canister_id, _) = test.create_and_install_canister(CANISTER_WITH_GLOBAL, vec![]);
        let initial_val = test.query(canister_id, "read", vec![]).unwrap().bytes()[0];
        assert_eq!(0, initial_val);

        test.ingress(canister_id, "write", vec![]).unwrap();

        let val_after_first_ingress = test.query(canister_id, "read", vec![]).unwrap().bytes()[0];
        assert_eq!(initial_val + 1, val_after_first_ingress);

        test.ingress(canister_id, "write", vec![]).unwrap();

        let val_after_second_ingress = test.query(canister_id, "read", vec![]).unwrap().bytes()[0];
        assert_eq!(val_after_first_ingress + 1, val_after_second_ingress);
    })
}

// This is a canister that keeps a counter on the heap (as opposed to
// CANISTER_WITH_GLOBAL). `inc`: increment the counter
// `read`: read the counter value
const COUNTER_ON_HEAP: &str = r#"
            (module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $inc

                ;; load the old counter value, increment, and store it back
                (i32.store

                  ;; store at the beginning of the heap
                  (i32.const 0) ;; store at the beginning of the heap

                  ;; increment heap[0]
                  (i32.add

                    ;; the old value at heap[0]
                    (i32.load (i32.const 0))

                    ;; "1"
                    (i32.const 1)
                  )
                )
                (call $msg_reply_data_append (i32.const 0) (i32.const 0))
                (call $msg_reply)
              )

              (func $read

                ;; now we copied the counter address into heap[0]
                (call $msg_reply_data_append
                  (i32.const 0) ;; the counter address from heap[0]
                  (i32.const 4) ;; length
                )
                (call $msg_reply)
              )

              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_update inc" (func $inc))
              (export "canister_query read" (func $read)))"#;

const CANISTER_WITH_GLOBAL: &str = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))

          (func $read
            (i32.store
              (i32.const 0)
              (global.get 0)
            )
            (call $msg_reply_data_append
              (i32.const 0)
              (i32.const 1)
            )
            (call $msg_reply)
          )

          (func $write
            (global.set 0
              (i32.add
                (global.get 0)
                (i32.const 1)
              )
            )
            (call $msg_reply_data_append (i32.const 0) (i32.const 1))
            (call $msg_reply)
          )

          (memory $memory 1)
          (export "memory" (memory $memory))
          (global (mut i32) (i32.const 0))
          (export "canister_query read" (func $read))
          (export "canister_update write" (func $write)))"#;

#[test]
fn test_read_query_does_not_modify_wasm_state() {
    // This canister exposes a single method that increments a counter at position 0
    // of the heap by 5.
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (func $test
            (i32.store
                (i32.const 0)
                (i32.add (i32.const 5) (i32.load (i32.const 0))))
            (call $msg_reply_data_append
              (i32.const 0)
              (i32.const 1)
            )
            (call $msg_reply)
          )
          (memory (;0;) 1)
          (export "memory" (memory 0))
          (export "canister_query test" (func $test)))"#;
    utils::canister_test(move |test| {
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);
        // This canister exposes a single method that increments a counter at position 0
        // of the heap by 5.
        //
        // Two read queries back to back should return the same result since no
        // modifications from the first one should be persisting in the canister's
        // state.
        let expected_val = test.query(canister_id, "test", vec![]);
        let val = test.query(canister_id, "test", vec![]);
        assert_eq!(val, expected_val);
    })
}

#[test]
fn test_bad_read_query_does_not_corrupt_state() {
    // This canister exposes a single method that increments a counter at position 0
    // of the heap by 5.
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (func $test
            (i32.store
                (i32.const 0)
                (i32.add (i32.const 5) (i32.load (i32.const 0))))
            (call $msg_reply_data_append
              (i32.const 0)
              (i32.const 1)
            )
            (call $msg_reply)
          )
          (memory (;0;) 1)
          (export "memory" (memory 0))
          (export "canister_query test" (func $test)))"#;
    utils::canister_test(move |test| {
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);
        std::thread::sleep(std::time::Duration::from_secs(60));
        // This canister exposes a single method that increments a counter at position 0
        // of the heap by 5.
        //
        // Two read queries back to back should return the same result since no
        // modifications from the first one should be persisting in the canister's
        // state.
        let expected_val = test.ingress(canister_id, "test_bad", vec![]);
        assert!(expected_val.is_err());
        let expected_val = test.ingress(canister_id, "test", vec![]);
        assert!(expected_val.is_ok());
        let val = test.ingress(canister_id, "test", vec![]);
        assert_eq!(val, expected_val);
    })
}

fn display_page_map(page_map: PageMap, page_range: std::ops::Range<u64>) -> String {
    let mut contents = Vec::new();
    for page in page_range {
        contents.extend_from_slice(page_map.get_page(PageIndex::from(page)));
    }
    format!("[{}]", ic_utils::rle::display(&contents[..]))
}

#[test]
fn test_trap_recovery() {
    utils::simple_canister_test(move |canister| {
        // Stable memory should now be [1, 0, 0, ...]
        canister
            .update(wasm().stable_grow(1).stable_write(0, &[1]).reply())
            .unwrap();

        // Trap explicitly
        assert_matches!(
            canister.update(wasm().trap()),
            Err(err) if err.code() == ErrorCode::CanisterCalledTrap
        );

        // Stable memory should be preserved and now be [1, 1, 0, ...]
        assert_eq!(
            canister.update(
                wasm()
                    .stable_write(1, &[1])
                    .stable_read(0, 3)
                    .append_and_reply()
            ),
            Ok(WasmResult::Reply(vec![1, 1, 0]))
        );
    });
}

#[test]
fn test_query_trap_recovery() {
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
              (func $msg_reply_data_append (param i32 i32)))

          (func (export "canister_query read")
            (call $msg_reply_data_append
              (i32.const 0)
              (i32.const 4))
            (call $msg_reply))

          (func (export "canister_query trap")
            unreachable)

          (memory $memory 1)
          (export "memory" (memory $memory)))"#;

    utils::canister_test(move |test| {
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);
        assert_reply(
            test.query(canister_id, "read", vec![]),
            &0u32.to_le_bytes()[..],
        );

        assert!(test.query(canister_id, "trap", vec![]).is_err());

        assert_reply(
            test.query(canister_id, "read", vec![]),
            &0u32.to_le_bytes()[..],
        );
    });
}

#[test]
/// Tests that a canister correctly initializes itself
fn test_memory_persistence() {
    utils::canister_test(|test| {
        let (canister_id, _) = test.create_and_install_canister(TEST_MEMORY, vec![]);
        // helper to make a query that writes some data to a given address
        let write_data_query = |addr: i32, data: Vec<u8>| {
            // payload[0;4] is the address: beginning of the last Wasm page
            let mut payload = addr.to_le_bytes().to_vec();
            // payload[4;8] is the data: [1, 2, .., 8]
            payload.extend(data);
            test.query(canister_id, "query_data", payload)
                .unwrap()
                .bytes()
        };

        let write_data_ingress = |addr: i32, data: Vec<u8>| {
            // payload[0;4] is the address: beginning of the last Wasm page
            let mut payload = addr.to_le_bytes().to_vec();
            // payload[4;8] is the data: [1, 2, .., 8]
            payload.extend(data);
            test.ingress(canister_id, "write_data", payload).unwrap()
        };

        let num_pages = (200 * WASM_PAGE_SIZE / PAGE_SIZE) as u64;

        // 1) Check initial memory size and contents
        let initial_memory_contents = display_page_map(
            test.canister_state(&canister_id)
                .execution_state
                .unwrap()
                .wasm_memory
                .page_map,
            0..num_pages,
        );
        assert_eq!(initial_memory_contents, "[13107200×00]");

        // 2) Write some data to the last page. The `target` address is written to
        //    heap[0;4] and the remainder of the payload is written where the `target`
        //    points to.
        write_data_query(199 * WASM_PAGE_SIZE as i32, (1u8..9).collect());
        // Query does *not* modify the memory file
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages
            ),
            "[13107200×00]"
        );

        // 3) Same message as 2) but this time as an ingress message and not a query
        write_data_ingress(199 * WASM_PAGE_SIZE as i32, (1u8..9).collect());
        let expected_after_ingress_1 =
            // heap[0;4] is the `target` address, i.e. beginning of the last Wasm page
            // heap[target;8] is where the payload [1, 2, .., 8] is written to
            "[2×00 1×c7 13041661×00 1×01 1×02 1×03 1×04 1×05 1×06 1×07 1×08 65528×00]"
            //^^^^^^^^^             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (1..9) payload
            //little-endian encoded target address: 13041664
            ;
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages
            ),
            expected_after_ingress_1
        );

        // 4) Another query. Does not modify the memory file.
        write_data_query(100 * WASM_PAGE_SIZE as i32, (1u8..17).collect());
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages
            ),
            expected_after_ingress_1
        );

        // 5) Same as 4) but this time as an ingress
        write_data_ingress(100 * WASM_PAGE_SIZE as i32, (1u8..5).collect());
        let expected_after_ingress_2 =
            "[2×00 1×64 6553597×00 1×01 1×02 1×03 1×04 6488060×00 1×01 1×02 1×03 1×04 1×05 1×06 1×07 1×08 65528×00]"
            //                                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            //                                                    payload from previous ingress
            //                     ^^^^^^^^^^^^^^^^^^^
            //^^^^^^^^^            (1..5) payload from current ingress
            //little endian encoded target address: 6553600
            ;
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages
            ),
            expected_after_ingress_2
        );
    })
}

const TEST_MEMORY: &str = r#"
    (module
      (import "ic0" "msg_arg_data_copy"
        (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
      (import "ic0" "msg_arg_data_size"
        (func $ic0_msg_arg_data_size (result i32)))
      (import "ic0" "msg_reply" (func $msg_reply))
      (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32 i32)))

      ;; payload[0;4] is the `target: i32` address
      ;; the remainder of the payload is written to `target`
      (func $write_data
        ;; copy `target` address from the payload to the heap[0]
        (call $ic0_msg_arg_data_copy
          (i32.const 0) ;; address
          (i32.const 0) ;; payload offset
          (i32.const 4) ;; size
        )
        ;; copy the remainder of the payload to the `target` address
        (call $ic0_msg_arg_data_copy
          (i32.load (i32.const 0))                       ;; address
          (i32.const 4)                                  ;; payload offset
          (i32.sub                                       ;; size
            (call $ic0_msg_arg_data_size)
            (i32.const 4)
          )
        )
        (call $msg_reply_data_append (i32.const 0) (i32.const 0))
        (call $msg_reply)
      )
      (export "canister_query query_data" (func $write_data))
      (export "canister_update write_data" (func $write_data))

      (memory 200 300)
    )
"#;

#[test]
fn test_heap_initialized_from_data_section_only_once() {
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (import "ic0" "msg_arg_data_copy"
            (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))

          ;; write i32 to heap[0]
          (func $write
            (call $ic0_msg_arg_data_copy
              (i32.const 0) ;; dst addr
              (i32.const 0) ;; payload offset
              (i32.const 4) ;; len
            )
            (call $read))

          ;; read i32 from heap[0]
          (func $read
            (call $msg_reply_data_append
              (i32.const 0)
              (i32.const 4))
            (call $msg_reply))

          (memory (;0;) 1)
          ;; heap[0;4] = 120 or 0x78
          (data (i32.const 0) "x\00\00\00")
          (export "memory" (memory 0))
          (export "canister_update write" (func $write))
          (export "canister_query read" (func $read))
        )"#;
    utils::canister_test(move |test| {
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);

        let num_pages = (WASM_PAGE_SIZE / PAGE_SIZE) as u64;

        // result[0;4] should be 120 and is initialized from the data section
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages
            ),
            "[1×78 65535×00]"
        );
        let result = test.query(canister_id, "read", vec![]).unwrap().bytes();
        let val = i32::from_le_bytes(std::convert::TryInto::try_into(&result[0..4]).unwrap());
        assert_eq!(val, 120);

        // result[0;4] is set to 0xbeef by the ingress message
        test.ingress(canister_id, "write", 0xbeefi32.to_le_bytes().to_vec())
            .unwrap();
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages
            ),
            "[1×ef 1×be 65534×00]"
        );

        // When we instantiate the canister for subsequent operations we don't set the
        // heap contents from data section anymore. Hence heap[0;4] stays 0xbeef
        let result = test.query(canister_id, "read", vec![]).unwrap().bytes();
        let val = i32::from_le_bytes(std::convert::TryInto::try_into(&result[0..4]).unwrap());
        assert_eq!(val, 0xbeef);
    })
}

#[test]
#[should_panic(expected = "heap out of bounds")]
fn test_memory_access_between_min_and_max_start() {
    let wat = r#"
        (module
          (func $start
            ;; attempt to read page(1)[0;4] which should fail
            (drop (i32.load (i32.const 0x10000)))
          )
          (start $start)
          (memory $memory 1 2)
        )"#;
    utils::canister_test(move |test| {
        println!("> install_canister()");
        test.create_and_install_canister(wat, vec![]).1.unwrap();
    });
}

#[test]
fn test_upgrade_canister_stable_memory_persists() {
    let wat = r#"
        ;; A canister that keeps a counter in stable memory.
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
          (import "ic0" "stable_read"
            (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
          (import "ic0" "stable_write"
            (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

          (func $inc
            ;; Load integer from stable memory to heap.
            (call $stable_read (i32.const 0) (i32.const 0) (i32.const 4))

            ;; Increment the counter.
            (i32.store
              (i32.const 0)
              (i32.add
                (i32.load (i32.const 0))
                (i32.const 1)
              )
            )

            ;; Store it back to stable memory.
            (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))

            (call $read)
          )

          (func $read
            (call $msg_reply_data_append
              (i32.const 0) ;; the counter from heap[0]
              (i32.const 4)) ;; length
            (call $msg_reply))

          (func $canister_init
            ;; Create a stable memory.
            (drop (call $stable_grow (i32.const 1))))

          (memory $memory 1)
          (export "memory" (memory $memory))
          (export "canister_update inc" (func $inc))
          (export "canister_query read" (func $read))
          (export "canister_query inc_read" (func $inc))
          (export "canister_init" (func $canister_init))
        )"#;
    utils::canister_test(move |test| {
        // Install the canister
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);

        // Increment the counter by 1.
        let res = test.ingress(canister_id, "inc", vec![]);

        // Counter now should be 1.
        assert_eq!(res, Ok(WasmResult::Reply(vec![1, 0, 0, 0])));

        // Upgrade the canister. Because the counter is in stable memory, it should be
        // persisted.
        test.upgrade_canister(&canister_id, wat, vec![]).unwrap();

        // Increment the counter by 1.
        let res = test.ingress(canister_id, "inc", vec![]);

        // Counter now should be 2.
        assert_eq!(res, Ok(WasmResult::Reply(vec![2, 0, 0, 0])));
    });
}

#[test]
#[should_panic(expected = "heap out of bounds")]
fn test_memory_access_between_min_and_max_canister_init() {
    let wat = r#"
        (module
          (func (export "canister_init")
            ;; attempt to read page(1)[0;4] which should fail
            (drop (i32.load (i32.const 0x10000)))
          )
          (memory $memory 1 2)
        )"#;
    utils::canister_test(move |test| {
        println!("> install_canister()");
        test.create_and_install_canister(wat, vec![]).1.unwrap();
    });
}

#[test]
#[should_panic(expected = "heap out of bounds")]
fn test_memory_access_between_min_and_max_ingress() {
    let wat = r#"
        (module
          (func $test
            ;; attempt to read page(1)[0;4] which should fail
            (drop (i32.load (i32.const 0x10000)))
          )
          (memory $memory 1 2)
          (export "canister_update test" (func $test))
        )"#;
    utils::canister_test(move |test| {
        println!("> install_canister()");
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);
        println!("> test()");
        test.ingress(canister_id, "test", vec![]).unwrap();
    });
}

#[test]
#[should_panic(expected = "heap out of bounds")]
// Grow memory beyond the maximum limit. Should throw an exception
// when attempting to write to it.
fn test_update_available_memory_1() {
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (func $grow
            (drop (memory.grow (i32.const 1)))
            ;; store page(1)[0;4] = 1i32
            (i32.store (i32.const 0x10000) (i32.const 1))
            (call $msg_reply_data_append (i32.const 0) (i32.const 0))
            (call $msg_reply))
          (memory $memory 1 1)
          (export "canister_update grow" (func $grow))
        )"#;
    utils::canister_test(move |test| {
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);
        test.ingress(canister_id, "grow", vec![]).unwrap();
    });
}

#[test]
// Grow memory beyond the maximum limit. Should throw an exception when
// attempting to read from it.
#[should_panic(expected = "heap out of bounds")]
fn test_update_available_memory_2() {
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (func $grow
            (drop (memory.grow (i32.const 1)))
            ;; load page(1)[0;4]
            (drop (i32.load (i32.const 0x10000)))
            (call $msg_reply_data_append (i32.const 0) (i32.const 0))
            (call $msg_reply))
          (memory $memory 1 1)
          (export "canister_update grow" (func $grow))
        )"#;
    utils::canister_test(move |test| {
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);
        test.ingress(canister_id, "grow", vec![]).unwrap();
    });
}

#[test]
// Grow memory multiple times, including beyond limit.
fn test_update_available_memory_3() {
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (import "ic0" "msg_arg_data_copy"
            (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))

          (func $grow_by_one (local $expected_size i32)
            (local.set $expected_size (i32.add (memory.size) (i32.const 1)))
            (drop (memory.grow (i32.const 1)))
            (i32.store
                ;; store 1i32 at the beginning of the newly grown memory page
                (i32.mul (i32.sub (local.get $expected_size) (i32.const 1)) (i32.const 65536))
                (global.get $counter))
            (global.set $counter (i32.add (global.get $counter) (i32.const 1)))
            (call $msg_reply_data_append (i32.const 0) (i32.const 0))
            (call $msg_reply))

          ;; reads a byte from the beginning of a memory page
          (func $read_byte
            ;; copy the i32 page number into heap[0;4]
            (call $ic0_msg_arg_data_copy
              (i32.const 0) ;; dst
              (i32.const 0) ;; off
              (i32.const 4) ;; len
            )
            ;; copy page(n)[0;1] to heap[0;1]
            ;; we do this to make a Wasm instruction access out-of-bounds memory area and not
            ;; msg.reply system call. Both should fail but the failure path is different.
            (i32.store8
              (i32.const 4)
              (i32.load (i32.mul (i32.load (i32.const 0)) (i32.const 65536)))
            )
            (call $msg_reply_data_append
              (i32.const 4)
              (i32.const 1))
            (call $msg_reply))

          (global $counter (mut i32) (i32.const 10))
          (memory $memory 1 3)
          (export "canister_update grow_by_one" (func $grow_by_one))
          (export "canister_query grow_by_one_query" (func $grow_by_one))
          (export "canister_query read_byte" (func $read_byte)))"#;
    // installs a canister that uses debug.log from canister_init
    // and check the received value
    utils::canister_test(move |test| {
        // 1. After install the memory size is equal to the declared memory minimum
        // size.
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);

        let num_pages = |n| (n * WASM_PAGE_SIZE / PAGE_SIZE) as u64;

        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages(1)
            ),
            "[65536×00]"
        );

        // 2. Grow the memory by one page and modify its contents.
        println!("> grow_by_one() memory.size = 1 -> memory.size = 2");
        test.ingress(canister_id, "grow_by_one", vec![]).unwrap();

        // memory.size = 2
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages(2)
            ),
            "[65536×00 1×0a 65535×00]"
        );

        // 3. Everything is still correct after a query.
        println!("> read_byte(page_num=1)");
        let val = test
            .query(canister_id, "read_byte", i32::to_le_bytes(1).to_vec())
            .unwrap()
            .bytes()[0];
        assert_eq!(val, 0xa, "query result");

        // memory.size = 2
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages(2)
            ),
            "[65536×00 1×0a 65535×00]"
        );

        // 4. Queries grow the memory but it does not modify the persisted memory.
        println!("> grow_by_one()");
        test.query(canister_id, "grow_by_one_query", vec![])
            .unwrap();

        // memory.size = 2
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages(2)
            ),
            "[65536×00 1×0a 65535×00]"
        );

        // 5. Grow the memory by another page and modify its contents.
        println!("> grow_by_one() memory.size = 2 -> memory.size = 3");
        test.ingress(canister_id, "grow_by_one", vec![]).unwrap();

        // memory.size = 3
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages(3)
            ),
            "[65536×00 1×0a 65535×00 1×0b 65535×00]"
        );

        // 6. Grow the memory by another page and modify its contents. Should fail since
        // we exceed the maximum meory size.
        println!("> grow_by_one() memory.size = 3 -> memory.size = 4 (over limit)");
        let err = test
            .ingress(canister_id, "grow_by_one", vec![])
            .expect_err("memory.grow beyond maximum");
        assert!(err.description().contains("heap out of bounds"), "{}", err);

        // If the ingress above succeeded then the beginning of page(3) would contain
        // 1xc. Here we check that the page(3) is empty (when page doesn't exist
        // PageMap returns zero initialized slice)
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages(4)
            ),
            "[65536×00 1×0a 65535×00 1×0b 131071×00]"
        );
    });
}

#[test]
// Grow memory multiple times first and write to newly added pages later.
fn test_update_available_memory_4() {
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (import "ic0" "msg_arg_data_copy"
            (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))

          (func $grow_by_one
            (drop (memory.grow (i32.const 1)))
            (call $msg_reply_data_append (i32.const 0) (i32.const 0))
            (call $msg_reply))

          ;; reads a byte from the beginning of a memory page
          (func $read_byte
            ;; copy the i32 page number into heap[0;4]
            (call $ic0_msg_arg_data_copy
              (i32.const 0) ;; dst
              (i32.const 0) ;; off
              (i32.const 4) ;; len
            )
            ;; copy page(n)[0;1] to heap[0;1]
            ;; we do this to make a Wasm instruction access out-of-bounds memory area and not
            ;; msg.reply system call. Both should fail but the failure path is different.
            (i32.store8
              (i32.const 4)
              (i32.load (i32.mul (i32.load (i32.const 0)) (i32.const 65536)))
            )
            (call $msg_reply_data_append
              (i32.const 4)
              (i32.const 1))
            (call $msg_reply))

          ;; writes a byte to the beginning of a memory page
          (func $write_byte
            ;; copy the i32 page number into heap[0;4]
            (call $ic0_msg_arg_data_copy
              (i32.const 0) ;; dst
              (i32.const 0) ;; off
              (i32.const 4) ;; len
            )
            ;; copy the u8 value heap[5;1]
            (call $ic0_msg_arg_data_copy
              (i32.const 4) ;; dst
              (i32.const 4) ;; off
              (i32.const 1) ;; len
            )
            (i32.store8
              ;; target address
              (i32.mul (i32.load (i32.const 0)) (i32.const 65536))
              ;; target value
              (i32.load8_u (i32.const 4))
            )
            (call $msg_reply_data_append (i32.const 0) (i32.const 0))
            (call $msg_reply))

          (global $counter (mut i32) (i32.const 10))
          (memory $memory 2 5)
          (export "canister_update grow_by_one" (func $grow_by_one))
          (export "canister_query read_byte" (func $read_byte))
          (export "canister_update write_byte" (func $write_byte))
        )"#;
    // installs a canister that uses debug.log from canister_init
    // and check the received value
    utils::canister_test(move |test| {
        let (canister_id, _) = test.create_and_install_canister(wat, vec![]);

        let num_pages = |n| (n * WASM_PAGE_SIZE / PAGE_SIZE) as u64;

        // memory.size = 3
        println!("> grow_by_one()");
        test.ingress(canister_id, "grow_by_one", vec![])
            .expect("grow memory to 3");
        // memory.size = 4
        println!("> grow_by_one()");
        test.ingress(canister_id, "grow_by_one", vec![])
            .expect("grow memory to 4");
        // memory.size = 5
        println!("> grow_by_one()");
        test.ingress(canister_id, "grow_by_one", vec![])
            .expect("grow memory to 4");
        // memory.size = 5 (max limit)
        println!("> grow_by_one()");
        test.ingress(canister_id, "grow_by_one", vec![])
            .expect("grow memory to 6 attempt 1");
        // memory.size = 5 (max limit)
        println!("> grow_by_one()");
        test.ingress(canister_id, "grow_by_one", vec![])
            .expect("grow memory to 6 attempt 2");

        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages(5)
            ),
            "[327680×00]"
        );

        let make_payload = |page_num: i32, value: u8| {
            let mut v = vec![];
            v.extend(page_num.to_le_bytes().to_vec());
            v.extend(value.to_le_bytes().to_vec());
            v
        };

        // Write to memory pages allocated to satisfy memory minimum size. We use
        // page(0) to unpack the payload so only write to page(1)
        println!("> write_byte(1, 7)");
        test.ingress(canister_id, "write_byte", make_payload(1, 7))
            .unwrap();
        println!(
            "> memory: {}",
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory
                    .page_map,
                0..num_pages(5)
            )
        );
        #[rustfmt::skip] // rustfmt breaks the explanatory comment at the bottom of thi assert
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory.page_map,
                0..num_pages(5)
            ),
            "[1×01 3×00 1×07 65531×00 1×07 262143×00]"
            //^^^^^^^^^^^^^^          ^^^
            //unpacked payload        value
        );

        let test_write_read = |page_num, value| {
            // 1. Grown memory page is zero-initialized
            println!("> read_byte({})", page_num);
            let result = test
                .query(
                    canister_id,
                    "read_byte",
                    i32::to_le_bytes(page_num).to_vec(),
                )
                .unwrap()
                .bytes()[0];
            println!(
                "> memory: {}",
                display_page_map(
                    test.canister_state(&canister_id)
                        .execution_state
                        .unwrap()
                        .wasm_memory
                        .page_map,
                    0..num_pages(5)
                )
            );
            assert_eq!(result, 0, "query result before write");
            // 2. Write a byte
            println!("> write_byte({}, {})", page_num, value);
            test.ingress(canister_id, "write_byte", make_payload(page_num, value))
                .unwrap();
            println!(
                "> memory: {}",
                display_page_map(
                    test.canister_state(&canister_id)
                        .execution_state
                        .unwrap()
                        .wasm_memory
                        .page_map,
                    0..num_pages(5)
                )
            );
            println!("> read_byte({})", page_num);
            // 3. Read it back
            let result = test
                .query(
                    canister_id,
                    "read_byte",
                    i32::to_le_bytes(page_num).to_vec(),
                )
                .unwrap()
                .bytes()[0];
            println!(
                "> memory: {}",
                display_page_map(
                    test.canister_state(&canister_id)
                        .execution_state
                        .unwrap()
                        .wasm_memory
                        .page_map,
                    0..num_pages(5)
                )
            );
            assert_eq!(result, value, "query result after write");
        };

        // Write data to the grown memory pages and read it back.
        test_write_read(3, 9);
        test_write_read(4, 10);
        test_write_read(2, 8);

        #[rustfmt::skip]
        assert_eq!(
            display_page_map(
                test.canister_state(&canister_id)
                    .execution_state
                    .unwrap()
                    .wasm_memory.page_map,
                0..num_pages(5)
            ),
            "[1×02 3×00 1×08 65531×00 1×07 65535×00 1×08 65535×00 1×09 65535×00 1×0a 65535×00]"
            //                        ^^^ page(1)   ^^^ page(2)   ^^^ page(3)   ^^^ page(4)
        );
    });
}

#[test]
#[should_panic(expected = "cannot be executed in init mode")]
fn test_call_forbidden_function_in_canister_init() {
    let wat = r#"
    (module
      (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32 i32)))
      (func (export "canister_init")
       (call $msg_reply_data_append
         (i32.const 0)
         (i32.const 0)))
      ;; since we call a function which accesses memory we need to delcare memory
      (memory 0)
    )"#;
    utils::canister_test(move |test| {
        test.create_and_install_canister(wat, vec![]).1.unwrap();
    });
}

#[test]
#[should_panic(expected = "Expected input params [] for 'canister_init', got [I32].")]
fn test_canister_init_invalid() {
    let wat = r#"
    (module
      (type (;0;) (func (param i32) (result i32)))
      (func (;0;) (type 0)
        i32.const 0)
      (export "canister_init" (func 0)))"#;
    utils::canister_test(move |test| {
        test.create_and_install_canister(wat, vec![]).1.unwrap();
    });
}

#[test]
fn test_canister_init_noop() {
    let wat = r#"(module)"#;
    utils::canister_test(move |test| {
        test.create_and_install_canister(wat, vec![]).1.unwrap();
    });
}

// converts canister id into an escaped byte string,
// to inject this string into a data section
fn escape(id: &CanisterId) -> String {
    escape_bytes(id.get_ref().as_slice())
}

fn escape_bytes(x: &[u8]) -> String {
    x.iter().fold(String::new(), |mut res, b| {
        res.push_str(&format!("\\{:02x}", b));
        res
    })
}

#[test]
// Tests that when the output queue of a canister is full, the system does not
// panic.
//
// The first canister keeps sending the second canister msgs till sending fails.
// The second canister simply reflects the payload back.  The first canister
// sums up all the responses and returns the sum when all the replies have been
// received.
//
// The first canister ensures that when call_simple fails, it fails with the
// appropriate error code and the test ensures that the ingress message
// eventually finishes running.
fn test_inter_canister_messaging_full_queues() {
    utils::canister_test(|test| {
        // This canister simply returns whatever value was received in an
        // inter-canister request.
        let (reflect_canister_id, _) = test.create_and_install_canister(
            r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $re
                    ;; heap[0] = payload[0]
                    (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 1))
                    ;; return
                    (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                    (call $msg_reply))

              (data (i32.const 0) "0")
              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_update re" (func $re)))"#,
            vec![]);

        // This canister keeps forwarding the value that was received in an
        // ingress msg to the reflector canister above till call_simple fails.
        // It sums up the reflected values and returns the sum.
        let (canister_id, _) = test.create_and_install_canister(
            &format!(
                r#"(module
              (import "ic0" "msg_arg_data_copy"
                (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "debug_print" (func $debug_print (param i32) (param i32)))
              (import "ic0" "call_simple"
                (func $ic0_call_simple
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                    (param $data_src i32)           (param $data_len i32)
                    (result i32)))

              (func $compute
                ;; heap[10] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 1))

                (block
                  (loop
                    ;; Call the reflector and store the return value in heap[30]
                    (i32.store
                      (i32.const 30)
                      (call $ic0_call_simple
                        (i32.const 100) (i32.const {})  ;; reflector canister id
                        (i32.const 0) (i32.const 2)     ;; refers to "re" on the heap
                        (i32.const 0) (i32.const 0)     ;; on_reply closure
                        (i32.const 0) (i32.const 0)     ;; on_reject closure
                        (i32.const 10) (i32.const 1)    ;; refers to byte copied from the payload
                      )
                    )

                    ;; If heap[30] == 2 then call failed due to full queues.  Break out of loop
                    (br_if
                      1
                      (i32.eq
                        (i32.load (i32.const 30))
                        (i32.const 2)
                      )
                    )

                    ;; If heap[30] != 0 then debug print the returned value
                    ;; (after adding 48 to convert to ascii) and then trap
                    (if
                      (i32.ne
                        (i32.load (i32.const 30))
                        (i32.const 0)
                      )
                      (then
                        (i32.store
                          (i32.const 30)
                          (i32.add
                             (i32.load (i32.const 30))
                             (i32.const 48)
                          )
                        )
                        (call $debug_print (i32.const 30) (i32.const 8))
                        unreachable
                      )
                    )

                    ;; Call succeeded, increment heap[20] and continue
                    (i32.store
                      (i32.const 20)
                      (i32.add
                        (i32.load (i32.const 20))
                        (i32.const 1)
                      )
                    )
                    (br 0)
                  )
                )
              )

              (func $callback (param $env i32)
                ;; heap[30] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 30) (i32.const 0) (i32.const 1))
                ;; heap[40] = heap[40] + heap[30]
                (i32.store
                  (i32.const 40)
                  (i32.add (i32.load (i32.const 40)) (i32.load (i32.const 30))))

                ;; heap[20] = heap[20] - 1
                (i32.store
                  (i32.const 20)
                  (i32.sub (i32.load (i32.const 20)) (i32.const 1)))

                ;; Send reply if all replies have been received
                (if
                  (i32.eq
                     (i32.load (i32.const 20))
                     (i32.const 0)
                  )
                  (then
                    (call $msg_reply_data_append (i32.const 40) (i32.const 1))
                    (call $msg_reply)
                  )
                )
              )

              (table funcref (elem $callback))
              (memory $memory 1)
              (data (i32.const 0) "re")
              (data (i32.const 100) "{}")
              (export "canister_update compute" (func $compute))
              (export "memory" (memory $memory)))"#,
                reflect_canister_id.get_ref().as_slice().len(),
                escape(&reflect_canister_id),
            ),
            vec![],
        );
        test.ingress(canister_id, "compute", vec![5]).unwrap();
    });
}

#[test]
// Tests 2 inter-canister message roundtrips:
// - canister A sends a number to canister B
// - canister B multiplies it by 3 and returns to A
// - canister A sends the new number to canister C
// - canister C adds 3 to the number and returns it to A
// - canister A stores the result on the heap
fn test_inter_canister_message_exchange_1() {
    utils::canister_test(|test| {
        let (multiplier_canister_id, _) = test.create_and_install_canister(
            r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $2x
                    ;; heap[0] = payload[0]
                    (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 1))
                    ;; heap[0] *= 2
                    (i32.store
                      (i32.const 0)
                      (i32.mul (i32.const 2) (i32.load (i32.const 0))))
                    ;; return
                    (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                    (call $msg_reply))

              (data (i32.const 0) "0")
              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_update 2x" (func $2x)))"#,
            vec![],
        );

        let (adder_canister_id, _) = test.create_and_install_canister(
            r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $plus3
                    ;; heap[0] = payload[0]
                    (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 1))
                    ;; heap[0] += 3
                    (i32.store
                      (i32.const 0)
                      (i32.add (i32.const 3) (i32.load (i32.const 0))))
                    ;; return
                    (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                    (call $msg_reply))

              (data (i32.const 0) "0")
              (memory $memory 1)
              (export "canister_update +3" (func $plus3))
              (export "memory" (memory $memory)))"#,
            vec![],
        );
        let (canister_id, _) = test.create_and_install_canister(&format!(
                r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "call_new"
                (func $ic0_call_new
                  (param i32 i32)
                  (param $method_name_src i32)    (param $method_name_len i32)
                  (param $reply_fun i32)          (param $reply_env i32)
                  (param $reject_fun i32)         (param $reject_env i32)
              ))
              (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
              (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))

              (func $compute
                ;; heap[10] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 1))
                ;; calls the multiplier canister
                (call $ic0_call_new
                    (i32.const 100) (i32.const {})  ;; multiplier canister id
                    (i32.const 0) (i32.const 2)     ;; refers to "2x" on the heap
                    (i32.const 0) (i32.const 0)     ;; on_reply closure
                    (i32.const 0) (i32.const 0)     ;; on_reject closure
                )
                (call $ic0_call_data_append
                    (i32.const 10) (i32.const 1)    ;; refers to byte copied from the payload
                )
                (call $ic0_call_perform)
                drop)

              ;; returns heap[20]
              (func $read
                (call $msg_reply_data_append (i32.const 20) (i32.const 1))
                (call $msg_reply))

              (func $mul_callback (param $env i32)
                ;; heap[20] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 20) (i32.const 0) (i32.const 1))
                ;; calls the adder canister
                (call $ic0_call_new
                    (i32.const 200) (i32.const {}) ;; adder canister id
                    (i32.const 3) (i32.const 2)   ;; refers to "+3" on the heap
                    (i32.const 1) (i32.const 0)   ;; on_reply closure
                    (i32.const 1) (i32.const 0)   ;; on_reject closure
                )
                (call $ic0_call_data_append
                    (i32.const 20) (i32.const 1)  ;; refers to byte copied from the payload of multiplier
                )
                (call $ic0_call_perform)
                drop)

              (func $add_callback (param $env i32)
                ;; heap[20] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 20) (i32.const 0) (i32.const 1))
                (call $read))

              (table funcref (elem $mul_callback $add_callback))
              (memory $memory 1)
              (data (i32.const 0) "2x +3")
              (data (i32.const 100) "{}")
              (data (i32.const 200) "{}")
              (export "canister_update compute" (func $compute))
              (export "canister_query read" (func $read))
              (export "memory" (memory $memory)))"#,
                multiplier_canister_id.get_ref().as_slice().len(),
                adder_canister_id.get_ref().as_slice().len(),
                escape(&multiplier_canister_id),
                escape(&adder_canister_id),
            ), vec![]);
        println!("Canister: {}", &canister_id);

        for num in &[5, 17, 113] {
            test.ingress(canister_id, "compute", vec![*num]).unwrap();
            let val = test.query(canister_id, "read", vec![]).unwrap().bytes();
            assert_eq!(val[0], 2 * num + 3, "computation for value {} failed", num);
        }
    })
}

#[test]
// Tests two inter-canister message roundtrips:
// - canister A sends a number to canister B and C
// - both canisters B and C multiply it by 2 and return to canister A
// - canister A sums the results and stores it on the heap
fn test_inter_canister_message_exchange_2() {
    utils::canister_test(|test| {
        let mut ids = Vec::new();
        for _ in 0..2 {
            let (id, _) = test.create_and_install_canister(
                r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $2x
                    ;; heap[0] = payload[0]
                    (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 1))
                    ;; heap[0] *= 2
                    (i32.store
                      (i32.const 0)
                      (i32.mul (i32.const 2) (i32.load (i32.const 0))))
                    (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                    (call $msg_reply))

              (data (i32.const 0) "0")
              (memory $memory 1)
              (export "canister_update 2x" (func $2x))
              (export "memory" (memory $memory)))"#,
                vec![],
            );
            ids.push(id);
        }

        let (canister_id, _) = test.create_and_install_canister(
            &format!(
                r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "call_simple"
                (func $ic0_call_simple
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                    (param $data_src i32)           (param $data_len i32)
                    (result i32)))

              (func $compute
                ;; heap[20] = 0
                (i32.store (i32.const 20) (i32.const 0))
                ;; heap[10] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 1))
                ;; sends heap[10] to one multiplier
                (call $ic0_call_simple
                    (i32.const 100) (i32.const {})  ;; multiplier canister id
                    (i32.const 0) (i32.const 2)     ;; refers to "2x" on the heap
                    (i32.const 0) (i32.const 0)     ;; on_reply closure
                    (i32.const 0) (i32.const 0)     ;; on_reject closure
                    (i32.const 10) (i32.const 1))   ;; refers to byte copied from the payload
                drop
                ;; sends heap[10] to another multiplier
                (call $ic0_call_simple
                    (i32.const 200) (i32.const {})  ;; multiplier canister id
                    (i32.const 0) (i32.const 2)     ;; refers to "2x" on the heap
                    (i32.const 0) (i32.const 0)     ;; on_reply closure
                    (i32.const 0) (i32.const 0)     ;; on_reject closure
                    (i32.const 10) (i32.const 1))   ;; refers to byte copied from the payload
                drop
                (global.set $ncalls (i32.const 2)))

              (func $read
                (call $msg_reply_data_append (i32.const 20) (i32.const 1))
                (call $msg_reply))

              (func $mul_callback (param $env i32)
                ;; heap[40] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 40) (i32.const 0) (i32.const 1))
                ;; heap[20] += heap[40]
                (i32.store
                    (i32.const 20)
                    (i32.add
                        (i32.load (i32.const 20))
                        (i32.load (i32.const 40))))
                (global.set $ncalls (i32.sub (global.get $ncalls) (i32.const 1)))
                (if (i32.eq (global.get $ncalls) (i32.const 0))
                  (then (call $read))))

              (table funcref (elem $mul_callback))
              (memory $memory 1)
              (data (i32.const 0) "2x")
              (data (i32.const 100) "{}")
              (data (i32.const 200) "{}")
              (global $ncalls (mut i32) (i32.const 0))
              (export "memory" (memory $memory))
              (export "canister_update compute" (func $compute))
              (export "canister_query read" (func $read)))"#,
                ids[0].get_ref().as_slice().len(),
                ids[1].get_ref().as_slice().len(),
                escape(&ids[0]), escape(&ids[1])
            ),
            vec![],
        );

        for num in &[5, 17, 50] {
            test.ingress(canister_id, "compute", vec![*num]).unwrap();
            let val = test.query(canister_id, "read", vec![]).unwrap().bytes();
            assert_eq!(val[0], 4 * num, "computation for value {} failed", num);
        }
    })
}

#[test]
// Tests two inter-canister message roundtrips:
// - canister A sends a number to canister B
// - canister B sends it to canister C
// - canister C multiplies it by 2 and returns to B
// - canister B multiplies it by 3 and returns to A
// - canister A multiplies it by 5 and stores on the heap
fn test_inter_canister_message_exchange_3() {
    utils::canister_test(|test| {
        let (canister_c, _) = test.create_and_install_canister(
                r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))

              (func $mul
                    ;; heap[0] = payload[0]
                    (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 1))
                    ;; heap[0] *= 2
                    (i32.store
                      (i32.const 0)
                      (i32.mul (i32.const 2) (i32.load (i32.const 0))))
                    (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                    (call $msg_reply))

              (data (i32.const 0) "0")
              (memory $memory 1)
              (export "canister_update mul" (func $mul))
              (export "memory" (memory $memory)))"#,
                vec![],
            );

        let (canister_b, _) = test.create_and_install_canister(
            &format!(
                r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "call_new"
                (func $ic0_call_new
                  (param i32 i32)
                  (param $method_name_src i32)    (param $method_name_len i32)
                  (param $reply_fun i32)          (param $reply_env i32)
                  (param $reject_fun i32)         (param $reject_env i32)
              ))
              (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
              (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param $amount i64)))
              (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))

              (func $mul
                ;; heap[10] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 1))
                ;; sends heap[10] to one multiplier
                (call $ic0_call_new
                    (i32.const 100) (i32.const {})  ;; multiplier canister id
                    (i32.const 0) (i32.const 3)     ;; refers to "mul" on the heap
                    (i32.const 0) (i32.const 0)     ;; on_reply closure
                    (i32.const 0) (i32.const 0)     ;; on_reject closure
                )
                (call $ic0_call_data_append
                    (i32.const 10) (i32.const 1)    ;; refers to byte copied from the payload
                )
                (call $ic0_call_cycles_add
                    (i64.const 123)
                )
                (call $ic0_call_perform)
                drop)

              (func $mul_callback (param $env i32)
                  ;; heap[20] = payload[0]
                  (call $ic0_msg_arg_data_copy (i32.const 20) (i32.const 0) (i32.const 1))
                  ;; heap[20] *= 3
                  (i32.store
                      (i32.const 20)
                      (i32.mul (i32.const 3) (i32.load (i32.const 20))))
                  ;; return
                  (call $msg_reply_data_append (i32.const 20) (i32.const 1))
                  (call $msg_reply))

              (table funcref (elem $mul_callback))
              (memory $memory 1)
              (data (i32.const 0) "mul")
              (data (i32.const 100) "{}")
              (export "memory" (memory $memory))
              (export "canister_update mul" (func $mul)))"#,
                canister_c.get_ref().as_slice().len(),
                escape(&canister_c),
            ),
            vec![],
        );

        let (canister_a, _) = test.create_and_install_canister(
            &format!(
                r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "call_simple"
                (func $ic0_call_simple
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                    (param $data_src i32)           (param $data_len i32)
                    (result i32)))

              (func $mul
                ;; heap[10] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 1))
                ;; sends heap[10] to one multiplier
                (call $ic0_call_simple
                    (i32.const 100) (i32.const {})  ;; multiplier canister id
                    (i32.const 0) (i32.const 3)     ;; refers to "mul" on the heap
                    (i32.const 0) (i32.const 0)     ;; on_reply closure
                    (i32.const 0) (i32.const 0)     ;; on_reject closure
                    (i32.const 10) (i32.const 1))   ;; refers to byte copied from the payload
                drop)

              (func $mul_callback (param $env i32)
                  ;; heap[20] = payload[0]
                  (call $ic0_msg_arg_data_copy (i32.const 20) (i32.const 0) (i32.const 1))
                  ;; heap[20] *= 5
                  (i32.store
                      (i32.const 20)
                      (i32.mul (i32.const 5) (i32.load (i32.const 20))))
                  (call $read))

              (func $read
                (call $msg_reply_data_append (i32.const 20) (i32.const 1))
                (call $msg_reply))

              (table funcref (elem $mul_callback))
              (memory $memory 1)
              (data (i32.const 0) "mul")
              (data (i32.const 100) "{}")
              (export "memory" (memory $memory))
              (export "canister_query read" (func $read))
              (export "canister_update mul" (func $mul)))"#,
                canister_b.get_ref().as_slice().len(),
                escape(&canister_b),
            ),
            vec![],
        );

        for num in &[7, 5, 1] {
            test.ingress(canister_a, "mul", vec![*num]).unwrap();
            let val = test.query(canister_a, "read", vec![]).unwrap().bytes();
            assert_eq!(
                val[0],
                2 * 3 * 5 * num,
                "computation for value {} failed",
                num
            );
        }
    })
}

#[test]
// A canister sends a message to itself, squaring a number in the callback
fn test_inter_canister_message_exchange_4() {
    utils::canister_test(|test| {
        let (id, _) = test.create_and_install_canister(r#"(module
              (import "ic0" "msg_arg_data_copy" (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
              (import "ic0" "canister_self_size" (func $canister_self_size (result i32)))
              (import "ic0" "canister_self_copy" (func $canister_self_copy (param i32 i32 i32)))
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "call_simple"
                (func $ic0_call_simple
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                    (param $data_src i32)           (param $data_len i32)
                    (result i32)))

              (func $compute
                ;; heap[10] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 10) (i32.const 0) (i32.const 1))
                ;; write own canister id to heap[100..]
                (call $canister_self_copy (i32.const 100) (i32.const 0) (call $canister_self_size))
                ;; calls the multiplier canister
                (call $ic0_call_simple
                    (i32.const 100) (call $canister_self_size)
                    (i32.const 0) (i32.const 6)     ;; refers to "square" on the heap
                    (i32.const 0) (i32.const 0)     ;; on_reply closure
                    (i32.const 0) (i32.const 0)     ;; on_reject closure
                    (i32.const 10) (i32.const 1))   ;; refers to byte copied from the payload
                drop)

              (func $square
                ;; heap[20] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 20) (i32.const 0) (i32.const 1))
                ;; heap[20] = heap[20]^2
                (i32.store
                      (i32.const 20)
                      (i32.mul (i32.load (i32.const 20)) (i32.load (i32.const 20))))
                (call $msg_reply_data_append (i32.const 20) (i32.const 1))
                (call $msg_reply))

              ;; returns heap[20]
              (func $read
                (call $msg_reply_data_append (i32.const 20) (i32.const 1))
                (call $msg_reply))

              (func $callback (param $env i32)
                ;; heap[60] = payload[0]
                (call $ic0_msg_arg_data_copy (i32.const 60) (i32.const 0) (i32.const 1))
                (call $msg_reply_data_append (i32.const 60) (i32.const 1))
                (call $msg_reply))

              (table funcref (elem $callback))
              (memory $memory 1)
              (data (i32.const 0) "square")
              (export "canister_update square" (func $square))
              (export "canister_update compute" (func $compute))
              (export "canister_query read" (func $read))
              (export "memory" (memory $memory)))"#,
            vec![],
        );

        for num in &[11, 7, 5, 1] {
            test.ingress(id, "compute", vec![*num]).unwrap();
            let val = test.query(id, "read", vec![]).unwrap().bytes();
            assert_eq!(val[0], num * num, "computation for value {} failed", num);
        }
    });
}

#[test]
fn test_no_response_is_an_error() {
    utils::canister_test(|test| {
        let (id, _) = test.create_and_install_canister(
            r#"
            (module
              (func (export "canister_update silent")))"#,
            vec![],
        );
        match test.ingress(id, "silent", vec![]) {
            Err(err) if err.code() == ErrorCode::CanisterDidNotReply => (),
            result => panic!(
                "Expected {:?} error, got: {:?}",
                ErrorCode::CanisterDidNotReply,
                result
            ),
        }
    });
}

#[test]
// A canister sends a message to itself and immediately replies.
fn test_reply_after_calling_self() {
    utils::simple_canister_test(|canister| {
        assert_eq!(
            canister.update(
                wasm()
                    .inter_update(
                        canister.canister_id(),
                        // Do nothing.
                        call_args()
                            .on_reply(wasm().noop())
                            .on_reject(wasm().noop())
                            .other_side(wasm().noop())
                    )
                    .reply_data(b"Reply")
            ),
            Ok(WasmResult::Reply(b"Reply".to_vec()))
        );
    });
}

#[test]
fn test_call_unknown_canister() {
    utils::simple_canister_test(|canister| {
        assert_matches!(
            canister.update(wasm().inter_update(
                canister_test_id(0x64),
                call_args().on_reject(wasm().reject_message().reject())
            )),
            Ok(WasmResult::Reject(s)) if s.contains(
                "Canister yjeau-xiaaa-aaaaa-aabsa-cai not found"
            )
        );
    });
}

#[test]
// A canister sends a message to itself and rejects
fn test_reject_callback() {
    utils::canister_test(|test| {
        let (id, _) = test.create_and_install_canister(
            r#"(module
                  (import "ic0" "canister_self_size"
                          (func $ic0_self_size (result i32)))

                  (import "ic0" "canister_self_copy"
                          (func $ic0_self_copy (param i32 i32 i32)))

                  (import "ic0" "call_simple"
                          (func $ic0_call_simple (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
                                                 (result i32)))

                  (import "ic0" "msg_reject" (func $msg_reject (param i32 i32)))

                  (import "ic0" "msg_reject_msg_size"
                    (func $msg_reject_msg_size (result i32)))
                  (import "ic0" "msg_reject_msg_copy"
                    (func $msg_reject_msg_copy (param i32 i32 i32)))

                  (table 2 funcref)
                  (elem (i32.const 0) $on_reply $on_reject)

                  (func (export "canister_update entry") (local $len i32)
                        (local.set $len (call $ic0_self_size))
                        (call $ic0_self_copy (i32.const 32) (i32.const 0) (local.get $len))
                        (drop (call $ic0_call_simple
                              (i32.const 32)            ;; callee_src
                              (local.get $len)          ;; callee_size
                              (i32.const 7)             ;; method_name_src
                              (i32.const 4)            ;; method_name_len
                              (i32.const 0)             ;; reply_fun
                              (i32.const 0)             ;; reply_env
                              (i32.const 1)             ;; reject_fun
                              (i32.const 0)             ;; reject_env
                              (i32.const 0)             ;; data_src
                              (i32.const 5)             ;; data_len
                              )))

                  (func (export "canister_update ping")
                        (call $msg_reject (i32.const 0) (i32.const 6)))

                  (func $on_reply (param i32) unreachable)
                  (func $on_reject (param i32)
                        ;; Reject with the same message
                        (call $msg_reject_msg_copy (i32.const 100) (i32.const 0) (call $msg_reject_msg_size))
                        (call $msg_reject (i32.const 100) (call $msg_reject_msg_size)))

                  (data (i32.const 0) "Reject ping")

                  (memory $mem 2)
                  (export "memory" (memory $mem)))"#,
            vec![],
        );
        assert_eq!(
            test.ingress(id, "entry", vec![]),
            Ok(WasmResult::Reject("Reject".to_string()))
        );
    });
}

// End user sends an update msg to canisterA; canisterA tries to send a very
// large message to canisterB, which fails.
// Commentd out due to RPL-269
// fn inter_canister_request_limit() {
//     utils::canister_test(|test| {
//         let canister_a = test.create_universal_canister();
//         let canister_b = test.create_universal_canister();

//         let large_payload: Vec<u8> =
//             vec![0; (MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get() + 1) as
// usize];         assert_matches!(
//             test.ingress(
//                 canister_a,
//                 "update",
//                 wasm()
//                     .inter_update(
//                         canister_b,
//
// call_args().other_side(wasm().reply_data(large_payload.as_slice())))),
//             Err(err) if err.description().contains("violated contract:
// ic0.call_data_append"));     });
// }

#[test]
// End user sends an update msg to canisterA; canisterA tries to send a very
// large reply and fails.
fn inter_canister_response_limit() {
    utils::canister_test(|test| {
        let size = MAX_INTER_CANISTER_PAYLOAD_IN_BYTES + NumBytes::from(1);
        let (canister_a, _) = test.create_and_install_canister(
            &format!(
                r#"(module
                    (import "ic0" "msg_reply" (func $msg_reply))
                    (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))

                    (func $hi
                      (call $msg_reply_data_append (i32.const 30) (i32.const {}))
                      (call $msg_reply)
                    )

                    (memory $memory 1)
                    (export "canister_update hi" (func $hi))
                    (export "memory" (memory $memory)))"#,
                size),
            vec![]);
        let err = test.ingress(canister_a, "hi", vec![5]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::CanisterContractViolation);
    });
}

#[test]
#[should_panic(expected = "CanisterMethodNotFound")]
fn query_call_on_update_method() {
    utils::canister_test(|test| {
        let canister_id = test.create_universal_canister();

        // Should panic given that the canister query method doesn't exist.
        test.query(canister_id, "update", vec![5]).unwrap();
    });
}

#[test]
fn raw_rand_response_is_encoded() {
    utils::simple_canister_test(|canister| {
        // Call raw_rand and make sure to get Ok(_).
        let response = canister
            .update(wasm().call_simple(
                ic00::IC_00,
                Method::RawRand,
                call_args().other_side(EmptyBlob::encode()),
            ))
            .unwrap();

        if let WasmResult::Reply(payload) = response {
            Decode!(&payload).unwrap();
        } else {
            unreachable!();
        }
    })
}

#[test]
fn consecutive_raw_rand_calls_from_a_canister_return_different_values() {
    utils::simple_canister_test(|canister| {
        // Call raw_rand twice and make sure to get Ok(_).
        let first_response = canister
            .update(wasm().call_simple(
                ic00::IC_00,
                Method::RawRand,
                call_args().other_side(EmptyBlob::encode()),
            ))
            .unwrap();

        let second_response = canister
            .update(wasm().call_simple(
                ic00::IC_00,
                Method::RawRand,
                call_args().other_side(EmptyBlob::encode()),
            ))
            .unwrap();

        // Assert that the responses are different.
        assert_ne!(first_response, second_response);
    });
}

// Testing if a DKG for a new subnet consisting of single node can be produced.
#[test]
fn setup_initial_dkg_method_interface() {
    utils::simple_canister_test(|canister| {
        // We must use one single node, otherwise the CSP would try to load the public
        // keys for other nodes, yet the test fixture instantiates the registry
        // for a single node.
        let node_ids = vec![canister.node_id()];
        let request_payload = ic00::SetupInitialDKGArgs::new(node_ids, RegistryVersion::new(1));
        let response = canister
            .update(wasm().call_simple(
                ic00::IC_00,
                Method::SetupInitialDKG,
                call_args().other_side(Encode!(&request_payload).unwrap()),
            ))
            .unwrap();

        match response {
            WasmResult::Reply(response_payload) => {
                let records = ic00::SetupInitialDKGResponse::decode(&response_payload).unwrap();
                assert_eq!(records.low_threshold_transcript_record.threshold, 1);
                assert_eq!(records.high_threshold_transcript_record.threshold, 1);
            }
            response => panic!("Unexpected response {:?}", response),
        }
    });
}
