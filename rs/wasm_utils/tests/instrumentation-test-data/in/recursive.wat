(module
  (func $fac (param i64) (result i64)
    (i64.add (get_local 0) (get_local 0))
    (set_local 0)
    (if (result i64)
      (i64.lt_s (get_local 0) (i64.const 1))
      (then (i64.const 1))
      (else
        (i64.mul
          (get_local 0)
          (call $fac
            (i64.sub
              (get_local 0)
              (i64.const 1)))))))
  (export "fac" (func $fac)))

