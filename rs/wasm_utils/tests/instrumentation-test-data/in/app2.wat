(module
  (type (;0;) (func (param i64) (result i64)))
  (func $compute (type 0) (param $count i64) (result i64)
        (local $reg i64)
        (i64.mul (local.get $count) (i64.const 3))              ;; tmp = count * 3
        call $inc
        local.set 1                                             ;; reg = tmp
        block                                                   ;; @L1
            local.get 1                                         ;; tmp = reg
            i64.const 1
            i64.and                                             ;; tmp = tmp & 1
            i32.wrap_i64
            br_if 0                                             ;; if tmp == 0 goto end
            local.get 1                                         ;; tmp = reg
            i64.const 222
            i64.add                                             ;; tmp ++ 222
            local.set 1                                         ;; reg = tmp
            block                                               ;; @L2
                local.get 1                                     ;; tmp = reg
                i64.const 1                                     ;;
                i64.and                                         ;; tmp = tmp & 1
                i32.wrap_i64
                br_if 0                                         ;; if tmp == 0 goto end
                local.get 1
                i64.const 1666
                i64.gt_s
                br_if 1                                         ;; if tmp > 1666, goto @L1
                local.get 1                                     ;; tmp = reg
                i64.const 100
                i64.mul                                         ;; tmp *= 100
                local.tee 1
                i32.wrap_i64
                if
                    i64.const -1
                    local.get 1
                    i64.mul
                    local.set 1
                else
                    local.get 0
                    local.set 1
                end
            end
            local.get 1                                         ;; tmp = reg
            call $tenfold
            local.set 1                                         ;; reg = tmp
        end
        local.get 1                                             ;; return reg
        )
  (func $tenfold (type 0) (param i64) (result i64)
        i64.const 10
        local.get 0
        i64.mul)
  (func $inc (type 0) (param i64) (result i64)
        local.get 0
        i64.const 1
        i64.add)
  (export "compute" (func $compute))
  (export "tenfold" (func $tenfold))
  (export "inc" (func $inc)))

