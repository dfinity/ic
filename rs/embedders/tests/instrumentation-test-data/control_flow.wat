(module
    ;; import call_cycles_add function that accepts a single i32 argument
    (func $cycles_add (import "ic0" "call_cycles_add") (param i64))
    (memory 1)

    (func (export "loop")
        (local $i i64)
        (set_local $i (i64.const 0))
        (block $end
            (loop $start
                (br_if $end
                    (i64.eq
                        (local.get $i)
                        (i64.const 10)
                    )
                )
                (call $cycles_add
                    (local.get $i)
                )
                (set_local $i
                    (i64.add
                        (local.get $i)
                        (i64.const 1)
                    )
                )
                (br $start)
            )
        )
    )

    ;; call import on numbers from 0 to $max (not including $max)
    (func (export "countTo") (param $max i64)
        ;; define variable $c and initialize it to 0
        (local $c i64)
        (set_local $c (i64.const 0))

        ;; start a loop
        (loop $counting
            ;; call with current value of $c
            (call $cycles_add (local.get $c))
            ;; increment $c by 1
            (set_local $c (i64.add (local.get $c) (i64.const 1)))
            ;; repeat loop if $c is not equal to $max
            (br_if $counting (i64.ne (local.get $max) (local.get $c)))
        )
    )

    ;; call import with 3 if $i is 0, otherwise it will return 5
    (func (export "if_then_else") (param $i i64)
        (if (i64.eq (local.get $i) (i64.const 0))
            (then (call $cycles_add (i64.const 3)))
            (else (call $cycles_add (i64.const 5)))
        )
    )

)
