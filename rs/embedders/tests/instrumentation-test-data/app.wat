(module
  (type (;0;) (func (param i32) (result i32)))
  (func $compute (type 0) (param i32) (result i32)
    (local i32 i32)
    i32.const 0
    local.set 1
    local.get 0
    local.get 0
    i32.mul
    i32.const 0
    local.get 0
    i32.sub
    local.get 0
    i32.const 666
    i32.gt_s
    select
    local.set 2
    block  ;; label = @1
      local.get 0
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      loop  ;; label = @2
        local.get 1
        i32.const -1
        i32.xor
        i32.const 1
        i32.and
        local.get 2
        i32.add
        local.set 2
        local.get 0
        local.get 1
        loop
            i32.const 1
            drop
            i32.const 1
            drop
            i32.const 1
            drop
            i32.const 1
            drop
        end
        i32.const 1
        i32.add
        local.tee 1
        i32.ne
        br_if 0 (;@2;)
      end
    end
    local.get 2
    i32.const 97
    i32.mul
    i32.const 100
    i32.div_s)
  (func $double (type 0) (param i32) (result i32)
    local.get 0
    local.get 0
    i32.mul)
  (memory (;0;) 17)
  (export "memory" (memory 0))
  (export "compute" (func $compute))
  (export "double" (func $double))
  (data (;1;) (i32.const 1049096) ""))
