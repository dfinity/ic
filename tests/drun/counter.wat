;; counter.wat ;;
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))
  (import "ic0" "msg_arg_data_copy"
    (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))

  (func $write (local $counter_addr i32)
    ;; copy the counter address into heap[0]
    (call $ic0_msg_arg_data_copy
      (i32.const 0) ;; heap dst = 0
      (i32.const 0) ;; payload offset = 0
      (i32.const 1) ;; length = 1
    )
    ;; store counter addr in a named local for readability
    (local.set $counter_addr (i32.load (i32.const 0)))

    ;; load old counter value, add 1, and store it back
    (i32.store
      (local.get $counter_addr)
      (i32.add (i32.const 1) (i32.load (local.get $counter_addr)))
    )
    (call $read)
  )

  (func $read
    (call $ic0_msg_arg_data_copy
      (i32.const 0) ;; heap dst = 0
      (i32.const 0) ;; payload offset = 0
      (i32.const 1) ;; length = 1
    )
    ;; now we copied the counter address into heap[0]
    (call $msg_reply_data_append
      (i32.load (i32.const 0)) ;; the counter address from heap[0]
      (i32.const 1))            ;; length
    (call $msg_reply))

  (memory $memory 1)
  (export "memory" (memory $memory))
  (export "canister_update write" (func $write))
  (export "canister_query read" (func $read)))
