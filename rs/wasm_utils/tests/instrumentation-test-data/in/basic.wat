(module
  (func $addTwo (param i32 i32) (result i32)
    (i32.add
      (get_local 0)
      (get_local 1)))
  (export "addTwo" (func $addTwo)))
