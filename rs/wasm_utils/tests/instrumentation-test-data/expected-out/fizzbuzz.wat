(module
  (type (;0;) (func (param i32 i32)))
  (type (;1;) (func (param i32)))
  (type (;2;) (func))
  (type (;3;) (func (param i32 i32) (result i32)))
  (type (;4;) (func (param i64)))
  (type (;5;) (func (result i64)))
  (import "__" "out_of_instructions" (func (;0;) (type 2)))
  (import "__" "update_available_memory" (func (;1;) (type 3)))
  (import "js" "memory" (memory (;0;) 1))
  (import "js" "println" (func (;2;) (type 0)))
  (func (;3;) (type 1) (param i32)
    (local i32 i32 i32)
    global.get 0
    i64.const 6
    i64.sub
    global.set 0
    global.get 0
    i64.const 0
    i64.lt_s
    if  ;; label = @1
      call 0
    end
    i32.const 1
    local.set 1
    local.get 0
    i32.const 1
    i32.add
    local.set 0
    loop  ;; label = @1
      global.get 0
      i64.const 13
      i64.sub
      global.set 0
      global.get 0
      i64.const 0
      i64.lt_s
      if  ;; label = @2
        call 0
      end
      local.get 1
      i32.const 3
      i32.rem_u
      i32.eqz
      if  ;; label = @2
        global.get 0
        i64.const 5
        i64.sub
        global.set 0
        local.get 1
        i32.const 5
        i32.rem_u
        i32.eqz
        if  ;; label = @3
          global.get 0
          i64.const 3
          i64.sub
          global.set 0
          i32.const 8
          i32.const 8
          call 2
        else
          global.get 0
          i64.const 3
          i64.sub
          global.set 0
          i32.const 0
          i32.const 4
          call 2
        end
      else
        global.get 0
        i64.const 5
        i64.sub
        global.set 0
        local.get 1
        i32.const 5
        i32.rem_u
        i32.eqz
        if  ;; label = @3
          global.get 0
          i64.const 3
          i64.sub
          global.set 0
          i32.const 4
          i32.const 4
          call 2
        else
          global.get 0
          i64.const 20
          i64.sub
          global.set 0
          i32.const 16
          local.set 3
          local.get 1
          local.set 2
          local.get 1
          i32.const 9
          i32.gt_u
          if  ;; label = @4
            global.get 0
            i64.const 11
            i64.sub
            global.set 0
            local.get 3
            local.get 2
            i32.const 10
            i32.div_u
            i32.const 48
            i32.add
            i32.store
            local.get 3
            i32.const 1
            i32.add
            local.set 3
          end
          local.get 3
          local.get 2
          i32.const 10
          i32.rem_u
          i32.const 48
          i32.add
          i32.store
          i32.const 16
          local.get 3
          i32.const 15
          i32.sub
          call 2
        end
      end
      local.get 1
      i32.const 1
      i32.add
      local.set 1
      local.get 1
      local.get 0
      i32.lt_u
      br_if 0 (;@1;)
    end)
  (func (;4;) (type 4) (param i64)
    local.get 0
    global.set 0)
  (func (;5;) (type 5) (result i64)
    global.get 0)
  (global (;0;) (mut i64) (i64.const 0))
  (export "fizzbuzz" (func 3))
  (export "canister counter_set" (func 4))
  (export "canister counter_get" (func 5))
  (export "canister counter_instructions" (global 0)))
