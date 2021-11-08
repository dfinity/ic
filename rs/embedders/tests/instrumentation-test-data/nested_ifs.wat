(module
  (type (;0;) (func (param i64) (result i64)))
  (func $compute (type 0) (param $count i64) (result i64)
        local.get 0
        i64.const 1
        i64.and
        i32.wrap_i64
        if
            local.get 0
            i64.const -1
            i64.mul
            local.tee 0
            i64.const -50
            i64.lt_s
            if
                local.get 0
                i64.const 100
                i64.mul
                local.set 0
            else
                local.get 0
                i64.const -111
                i64.add
                local.set 0
                local.get 0
                local.set 0
            end
        else
            local.get 0
            i64.const 1
            i64.add
            i64.const 2
            i64.mul
            local.tee 0
            i64.const 50
            i64.lt_s
            if
                local.get 0
                i64.const 100
                i64.mul
                local.set 0
            else
                local.get 0
                i64.const 111
                i64.add
                local.set 0
                local.get 0
                local.set 0
            end
        end
        local.get 0)
  (export "compute" (func $compute)))
