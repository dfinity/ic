(module
	(import "ic0" "msg_reply" (func $ic0_msg_reply))

	(func $read (param $address i32) (param $end i32) (param $step i32)
		;; Precondition: (end - address) % step == 0
		;; while (address != end) {
		;;   *address;
		;;   address += step;
		;; } 
		(loop $loop
			(drop (i64.load (local.get $address)))
			(local.tee $address (i32.add (local.get $address) (local.get $step)))
			(local.get $end)
			(i32.ne)
			(br_if $loop)
		)
	)

	(func $write (param $address i32) (param $end i32) (param $step i32)
		;; Precondition: (end - address) % step == 0
		;; let value = *address + 1;
		;; while (address != end) {
		;;   *address = value;
		;;   address += step;
		;; } 
		(local $value i64)
		(local.set $value (i64.load (local.get $address)))
		(local.set $value (i64.add (local.get $value) (i64.const 1)))
		(loop $loop
			(i64.store (local.get $address) (local.get $value))
			(local.tee $address (i32.add (local.get $address) (local.get $step)))
			(local.get $end)
			(i32.ne)
			(br_if $loop)
		)
	)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;; Query forward reads
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	(func (export "canister_query query_read_fwd_1gb")
		(call $read (i32.const 0) (i32.const 1073741824) (i32.const 8))
		(call $ic0_msg_reply)
	)

	(func (export "canister_query query_read_fwd_1gb_step_4kb")
		(call $read (i32.const 0) (i32.const 1073741824) (i32.const 4096))
		(call $ic0_msg_reply)
	)

	(func (export "canister_query query_read_fwd_1gb_step_16kb")
		(call $read (i32.const 0) (i32.const 1073741824) (i32.const 16384))
		(call $ic0_msg_reply)
	)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;; Query backward reads
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	(func (export "canister_query query_read_bwd_1gb")
		(call $read (i32.const 1073741816) (i32.const -8) (i32.const -8))
		(call $ic0_msg_reply)
	)

	(func (export "canister_query query_read_bwd_1gb_step_4kb")
		(call $read (i32.const 1073737728) (i32.const -4096) (i32.const -4096))
		(call $ic0_msg_reply)
	)

	(func (export "canister_query query_read_bwd_1gb_step_16kb")
		(call $read (i32.const 1073725440) (i32.const -16384) (i32.const -16384))
		(call $ic0_msg_reply)
	)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;; Update forward reads
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	(func (export "canister_update update_read_fwd_1gb")
		(call $read (i32.const 0) (i32.const 1073741824) (i32.const 8))
		(call $ic0_msg_reply)
	)

	(func (export "canister_update update_read_fwd_1gb_step_4kb")
		(call $read (i32.const 0) (i32.const 1073741824) (i32.const 4096))
		(call $ic0_msg_reply)
	)

	(func (export "canister_update update_read_fwd_1gb_step_16kb")
		(call $read (i32.const 0) (i32.const 1073741824) (i32.const 16384))
		(call $ic0_msg_reply)
	)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;; Update backward reads
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	(func (export "canister_update update_read_bwd_1gb")
		(call $read (i32.const 1073741816) (i32.const -8) (i32.const -8))
		(call $ic0_msg_reply)
	)
	(func (export "canister_update update_read_bwd_1gb_step_4kb")
		(call $read (i32.const 1073737728) (i32.const -4096) (i32.const -4096))
		(call $ic0_msg_reply)
	)
	(func (export "canister_update update_read_bwd_1gb_step_16kb")
		(call $read (i32.const 1073725440) (i32.const -16384) (i32.const -16384))
		(call $ic0_msg_reply)
	)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;; Query forward writes
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	(func (export "canister_query query_write_fwd_1gb")
		(call $write (i32.const 0) (i32.const 1073741824) (i32.const 8))
		(call $ic0_msg_reply)
	)

	(func (export "canister_query query_write_fwd_1gb_step_4kb")
		(call $write (i32.const 0) (i32.const 1073741824) (i32.const 4096))
		(call $ic0_msg_reply)
	)

	(func (export "canister_query query_write_fwd_1gb_step_16kb")
		(call $write (i32.const 0) (i32.const 1073741824) (i32.const 16384))
		(call $ic0_msg_reply)
	)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;; Query backward writes
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	(func (export "canister_query query_write_bwd_1gb")
		(call $write (i32.const 1073741816) (i32.const -8) (i32.const -8))
		(call $ic0_msg_reply)
	)

	(func (export "canister_query query_write_bwd_1gb_step_4kb")
		(call $write (i32.const 1073737728) (i32.const -4096) (i32.const -4096))
		(call $ic0_msg_reply)
	)

	(func (export "canister_query query_write_bwd_1gb_step_16kb")
		(call $read (i32.const 1073725440) (i32.const -16384) (i32.const -16384))
		(call $ic0_msg_reply)
	)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;; Update forward writes
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	(func (export "canister_update update_write_fwd_1gb")
		(call $write (i32.const 0) (i32.const 1073741824) (i32.const 8))
		(call $ic0_msg_reply)
	)

	(func (export "canister_update update_write_fwd_1gb_step_4kb")
		(call $write (i32.const 0) (i32.const 1073741824) (i32.const 4096))
		(call $ic0_msg_reply)
	)

	(func (export "canister_update update_write_fwd_1gb_step_16kb")
		(call $write (i32.const 0) (i32.const 1073741824) (i32.const 16384))
		(call $ic0_msg_reply)
	)

	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
	;; Update backward writes
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	(func (export "canister_update update_write_bwd_1gb")
		(call $write (i32.const 1073741816) (i32.const -8) (i32.const -8))
		(call $ic0_msg_reply)
	)

	(func (export "canister_update update_write_bwd_1gb_step_4kb")
		(call $write (i32.const 1073737728) (i32.const -4096) (i32.const -4096))
		(call $ic0_msg_reply)
	)

	(func (export "canister_update update_write_bwd_1gb_step_16kb")
		(call $read (i32.const 1073725440) (i32.const -16384) (i32.const -16384))
		(call $ic0_msg_reply)
	)

	(func (export "canister_update update_empty")
		(call $ic0_msg_reply)
	)

	(func (export "canister_init")
		(call $write (i32.const 0) (i32.const 1073741824) (i32.const 4096))
	)

	(memory (export "memory") 16384)
)
