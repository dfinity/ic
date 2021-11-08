(module
  (type $a (func(param i32 i32) (result i32)))   
  (type $b (func(param i64)))
  (import "teat" "adf" (global i64))
  (func $addTwo (type $a)
    (i32.add
      (get_local 0)
      (get_local 1)))
  (export "addTwo" (func $addTwo)))
