(module
  (type (;0;) (func))
  (type (;1;) (func (param i32 i32) (result i32)))
  (type (;2;) (func (param i64)))
  (type (;3;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 0)))
  (import "__" "update_available_memory" (func (;1;) (type 1)))
  (func (;2;) (type 0)
    loop  ;; label = @1
      global.get 0
      i64.const 1
      i64.sub
      global.set 0
      global.get 0
      i64.const 0
      i64.lt_s
      if  ;; label = @2
        call 0
      end
      br 0 (;@1;)
    end)
  (func (;3;) (type 2) (param i64)
    local.get 0
    global.set 0)
  (func (;4;) (type 3) (result i64)
    global.get 0)
  (memory (;0;) 1)
  (global (;0;) (mut i64) (i64.const 0))
  (export "canister_update test" (func 2))
  (export "memory" (memory 0))
  (export "canister counter_set" (func 3))
  (export "canister counter_get" (func 4))
  (export "canister counter_instructions" (global 0)))