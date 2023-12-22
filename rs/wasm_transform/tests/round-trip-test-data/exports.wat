(module
  (memory (export "mem") 1)
  (table (export "table") 1 funcref)
  (global (export "global") i32 (i32.const 5))
  (func (export "func"))
)