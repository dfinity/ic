(module
  (import "dfinity" "memory" (memory 2 3))
  (func (export "run") (param i32) (result i32)
    (i32.store (i32.const 10) (i32.const 42))
    (i32.add (get_local 0) (i32.const 42))
  )
)
