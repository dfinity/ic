(module
  (type $a (func(param i32 i32) (result i32)))   
  (type $b (func(param i64)))
  (import "foo" "meter" (func $prev (type $b)))
  (func $addTwo (type $a)
    (i32.add
      (get_local 0)
      (get_local 1))
    (call $prev (i64.const 0)))
  (export "addTwo" (func $addTwo)))
