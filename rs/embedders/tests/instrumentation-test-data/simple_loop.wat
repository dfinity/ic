(module
    (func $test
        loop  ;; label = @1                                                  
           br 0 (;@1;)                                                        
        end
    )

    (export "canister_update test" (func $test))
    (memory $memory 1)
    (export "memory" (memory $memory))
)
