(module
  (type (;0;) (func (param i32) (result i32)))
  (func $grow (type 0) (param i32)(result i32)
    (local i32 i32)
    local.get 0
    memory.grow
  )
  (memory (;0;) 17 100)
  (export "memory" (memory 0))
  (export "grow" (func $grow)))
