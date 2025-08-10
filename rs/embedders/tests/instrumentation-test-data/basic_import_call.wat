(module
  (type $a (func(param i32 i32) (result i32)))   
  (type $b (func (param i64) (result i64)))
  (import "ic0" "msg_cycles_accept" (func $cycles_accept (type $b)))
  (func $addTwo (type $a)
    (i32.add
      (local.get 0)
      (local.get 1))
    (call $cycles_accept (i64.const 0))
    (drop))
  (export "addTwo" (func $addTwo)))
