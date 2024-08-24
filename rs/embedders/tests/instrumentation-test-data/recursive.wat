(module
  (func $fac (param i64) (result i64)
    (i64.add (local.get 0) (local.get 0))
    (local.set 0)
    (if (result i64)
      (i64.lt_s (local.get 0) (i64.const 1))
      (then (i64.const 1))
      (else
        (i64.mul
          (local.get 0)
          (call $fac
            (i64.sub
              (local.get 0)
              (i64.const 1)))))))
  (export "fac" (func $fac)))

