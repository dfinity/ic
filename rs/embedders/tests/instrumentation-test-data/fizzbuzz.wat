(module
	(import "ic0" "debug_print" (func $println (param i32) (param i32)))
    (memory 1)
    (data (i32.const 0) "Fizz")
    (data (i32.const 4) "Buzz")
    (data (i32.const 8) "FizzBuzz")

    (func (export "fizzbuzz") (param $max i32)
        (local $c i32)
        (local $tmp i32)
        (local $adr i32)

        (local.set $c (i32.const 1)) ;; start counting at 1
        (local.set $max (i32.add (local.get $max) (i32.const 1))) ;; adjust max, so we include the number provided by user

        (loop $loop
            (if (i32.eqz (i32.rem_u (local.get $c) (i32.const 3)))
                (then
                    (if (i32.eqz (i32.rem_u (local.get $c) (i32.const 5)))
                        (then (call $println (i32.const 8) (i32.const 8))) ;; fizzbuzz
                        (else (call $println (i32.const 0) (i32.const 4))) ;; fizz
                    )
                )
                (else
                    (if (i32.eqz (i32.rem_u (local.get $c) (i32.const 5)))
                        (then (call $println (i32.const 4) (i32.const 4))) ;; buzz
                        (else
                            (local.set $adr (i32.const 16))
                            (local.set $tmp (local.get $c))

                            ;; if 10 or larger, put number of 10s in first memory position
                            (if (i32.gt_u (local.get $c) (i32.const 9))
                                (then
                                    (i32.store
                                        (local.get $adr)
                                        (i32.add
                                            (i32.div_u (local.get $tmp) (i32.const 10)) ;; number of tens
                                            (i32.const 48) ;; convert to ASCII digit
                                        )
                                    )

                                    ;; move address pointer to where next digit will be written
                                    (local.set $adr (i32.add (local.get $adr) (i32.const 1)))
                                )
                            )

                            ;; store remainder (after division by 10) in next memory position
                            (i32.store
                                (local.get $adr)
                                (i32.add
                                    (i32.rem_u (local.get $tmp) (i32.const 10)) ;; number of ones
                                    (i32.const 48) ;; convert to ASCII digit
                                )
                            )

                            ;; print constructed string from memory
                            (call $println (i32.const 16) (i32.sub (local.get $adr) (i32.const 15)))
                        )
                    )
                )
            )

            ;; increment counter
            (local.set $c (i32.add (local.get $c) (i32.const 1)))

            ;; loop until counter reaches max
            (br_if $loop (i32.lt_u (local.get $c) (local.get $max)))
        )
    )
)
