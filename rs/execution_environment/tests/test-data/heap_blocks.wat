;; A Wasm64 test canister that grows its heap by one block per update call and
;; touches every OS page of the new block.
;;
;; `grow_and_touch`: the number of GiB to use is the *length* of the argument
;; (an argument of 5 bytes uses 5 GiB). The size is taken from the length so
;; that the call does not have to copy the argument into the heap: a copy would
;; touch one extra page, and a block of exactly the accessed page limit must
;; not touch anything else. The block is appended to the current heap with
;; `memory.grow`; if the heap cannot grow by the block the call rejects with an
;; empty message. Otherwise it writes one byte into every 4 KiB page of the
;; block and replies with the new heap size in bytes (8 bytes, little endian),
;; written into and sent from the first page of the block.
(module
  (import "ic0" "msg_arg_data_size" (func $msg_arg_data_size (result i64)))
  (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i64 i64)))
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reject" (func $msg_reject (param i64 i64)))

  ;; 18 GiB = 294912 Wasm pages of 64 KiB.
  (memory (export "memory") i64 0 294912)

  (func (export "canister_update grow_and_touch")
    (local $pages i64)
    (local $old_pages i64)
    (local $addr i64)
    (local $end i64)

    ;; Block size in Wasm pages: GiB * (1 GiB / 64 KiB).
    (local.set $pages (i64.mul (call $msg_arg_data_size) (i64.const 16384)))

    (local.set $old_pages (memory.grow (local.get $pages)))
    (if (i64.eq (local.get $old_pages) (i64.const -1))
      (then
        ;; The heap is full: reject with an empty message (no heap access).
        (call $msg_reject (i64.const 0) (i64.const 0))
        (return)))

    (local.set $addr (i64.mul (local.get $old_pages) (i64.const 65536)))
    (local.set $end (i64.add (local.get $addr) (i64.mul (local.get $pages) (i64.const 65536))))

    ;; Write one byte into every OS page of the block.
    (block $done
      (br_if $done (i64.ge_u (local.get $addr) (local.get $end)))
      (loop $touch
        (i32.store8 (local.get $addr) (i32.const 1))
        (local.set $addr (i64.add (local.get $addr) (i64.const 4096)))
        (br_if $touch (i64.lt_u (local.get $addr) (local.get $end)))))

    ;; Reply with the new heap size, staged in the first page of the block.
    (local.set $addr (i64.mul (local.get $old_pages) (i64.const 65536)))
    (i64.store (local.get $addr) (i64.mul (memory.size) (i64.const 65536)))
    (call $msg_reply_data_append (local.get $addr) (i64.const 8))
    (call $msg_reply))
)
