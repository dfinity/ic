mod wasmtime_simple;

use ic_embedders::wasm_utils::decoding::decode_wasm;
use ic_embedders::wasm_utils::instrumentation::{instrument, InstructionCostTable};
use ic_wasm_types::BinaryEncodedWasm;
use parity_wasm::elements::Module;
use std::sync::Arc;

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
                            (func $run (export "run") 
                                (drop (i32.const 123))
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
    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
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
                            (func $run (export "run") 
                                (drop (i32.const 123))
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
    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
}

#[test]
fn test_instrument_module_with_exported_global() {
    let output = instrument(
        &BinaryEncodedWasm::new(
            wabt::wat2wasm(
                r#"
                (module
                  (func $run (export "run")
                    (drop (global.get $counter))
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

    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
}

fn compressed_test_contents(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/compressed/{}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        name
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("couldn't open file {}: {}", path, e))
}

#[test]
#[should_panic(expected = "too large")]
fn test_decode_large_compressed_module() {
    // Try decoding 12MB of zeros
    decode_wasm(Arc::new(compressed_test_contents("zeros.gz"))).unwrap();
}

#[test]
#[should_panic(expected = "too large")]
fn test_decode_large_compressed_module_with_tweaked_size() {
    // We also tested decoding with a much larger file.
    // To save space and CI time, we do not include the larger archive file and
    // do not generate it in the test. To reproduce the test, execute the following
    // command:
    //
    // dd if=/dev/zero of=/dev/stdout bs=1048576 count=10240 | gzip -9 > zeroes.gz
    //
    // and replace the zeroes.gz file used in the test.
    let mut contents = compressed_test_contents("zeros.gz");
    let n = contents.len();
    contents[n - 4..n].copy_from_slice(&100u32.to_le_bytes());
    decode_wasm(Arc::new(contents)).unwrap();
}
