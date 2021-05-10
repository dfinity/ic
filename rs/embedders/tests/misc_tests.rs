mod wasmtime_simple;

use ic_wasm_types::BinaryEncodedWasm;
use ic_wasm_utils::instrumentation::{instrument, InstructionCostTable};
use parity_wasm::elements::Module;

fn assert_memory_and_table_exports(module: &Module) {
    let export_section = module.export_section().unwrap();
    let mut memory_exported = false;
    let mut table_exported = false;
    for e in export_section.entries() {
        if let parity_wasm::elements::Internal::Table(_) = e.internal() {
            assert_eq!(e.field(), "table");
            memory_exported = true;
        } else if let parity_wasm::elements::Internal::Memory(_) = e.internal() {
            assert_eq!(e.field(), "memory");
            table_exported = true;
        }
    }
    assert!(memory_exported && table_exported);
}

#[test]
// Memory and table need to be exported as "memory" and "table". This tests
// checks that we rename "mem" to "memory" and "tab" to "table" during
// instrumentation.
fn test_instrument_module_rename_memory_table() {
    let output = instrument(
        &BinaryEncodedWasm::new(
            wabt::wat2wasm(
                r#"
                        (module
                            (memory (export "mem") 1 2)
                            (table (export "tab") 2 2 anyfunc)
                            (func $run (export "run") (result i32)
                                (i32.const 123)
                            )
                        )
                    "#,
            )
            .unwrap(),
        ),
        &InstructionCostTable::new(),
    )
    .unwrap();

    let module =
        parity_wasm::elements::deserialize_buffer::<Module>(output.binary.as_slice()).unwrap();
    assert_memory_and_table_exports(&module);
    // check that instrumented module instantiates correctly
    let result = wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
    assert_eq!(result[0].i32().unwrap(), 123);
}

#[test]
// Memory and table need to be exported as "memory" and "table". This test
// checks that we export them if they are not.
fn test_instrument_module_export_memory_table() {
    let output = instrument(
        &BinaryEncodedWasm::new(
            wabt::wat2wasm(
                r#"
                        (module
                            (memory 1 2)
                            (table 2 2 anyfunc)
                            (func $run (export "run") (result i32)
                                (i32.const 123)
                            )
                        )
                    "#,
            )
            .unwrap(),
        ),
        &InstructionCostTable::new(),
    )
    .unwrap();

    let module =
        parity_wasm::elements::deserialize_buffer::<Module>(output.binary.as_slice()).unwrap();
    assert_memory_and_table_exports(&module);
    // check that instrumented module instantiates correctly
    let result = wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
    assert_eq!(result[0].i32().unwrap(), 123);
}

#[test]
fn test_instrument_module_with_exported_global() {
    let output = instrument(
        &BinaryEncodedWasm::new(
            wabt::wat2wasm(
                r#"
                (module
                  (func $run (export "run") (result i32)
                    (global.get $counter)
                  )
                  (global $counter
                    (export "my_global_counter")
                    (mut i32) (i32.const 123)
                  )
                )"#,
            )
            .unwrap(),
        ),
        &InstructionCostTable::new(),
    )
    .unwrap();

    let result = wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
    assert_eq!(result[0].i32().unwrap(), 123);
}
