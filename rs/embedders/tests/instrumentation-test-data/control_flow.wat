(module
    ;; import trace function that accepts a single i32 argument
    (func $trace (import "imports" "trace") (param i32))
    (memory 1)

    (func (export "loop")
        (local $i i32)
        (set_local $i (i32.const 0))
        (block $end
            (loop $start
                (br_if $end
                    (i32.eq
                        (get_local $i)
                        (i32.const 10)
                    )
                )
                (call $trace
                    (get_local $i)
                )
                (set_local $i
                    (i32.add
                        (get_local $i)
                        (i32.const 1)
                    )
                )
                (br $start)
            )
        )
    )

    ;; prints numbers from 0 to $max (not including $max)
    (func (export "countTo") (param $max i32)
        ;; define variable $c and initialize it to 0
        (local $c i32)
        (set_local $c (i32.const 0))

        ;; start a loop
        (loop $counting
            ;; print current value of $c
            (call $trace (get_local $c))
            ;; increment $c by 1
            (set_local $c (i32.add (get_local $c) (i32.const 1)))
            ;; repeat loop if $c is not equal to $max
            (br_if $counting (i32.ne (get_local $max) (get_local $c)))
        )
    )

    ;; returns 3 if $i is 0, otherwise it will return 5
    (func (export "if_then_else") (param $i i32)
        (if (i32.eq (get_local $i) (i32.const 0))
            (then (call $trace (i32.const 3)))
            (else (call $trace (i32.const 5)))
        )
    )

)
