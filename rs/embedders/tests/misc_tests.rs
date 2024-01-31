mod wasmtime_simple;

use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    wasm_utils::{decoding::decode_wasm, validate_and_instrument_for_testing},
    WasmtimeEmbedder,
};
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_transform::Module;
use ic_wasm_types::BinaryEncodedWasm;
use std::sync::Arc;
use wasmparser::ExternalKind;

fn assert_memory_and_table_exports(module: &Module) {
    let export_section = &module.exports;
    let mut memory_exported = false;
    let mut table_exported = false;
    for e in export_section {
        if ExternalKind::Table == e.kind {
            assert_eq!(e.name, "table");
            table_exported = true;
        } else if ExternalKind::Memory == e.kind && e.name == "memory" {
            memory_exported = true;
        }
    }
    assert!(memory_exported && table_exported);
}

#[test]
// Memory and table need to be exported as "memory" and "table". This tests
// checks that we rename "mem" to "memory" and "tab" to "table" during
// instrumentation.
fn test_instrument_module_rename_memory_table() {
    let config = EmbeddersConfig::default();
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());
    let output = validate_and_instrument_for_testing(
        &embedder,
        &BinaryEncodedWasm::new(
            wat::parse_str(
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
    )
    .unwrap()
    .1;

    let module = Module::parse(output.binary.as_slice(), false).unwrap();
    assert_memory_and_table_exports(&module);
    // check that instrumented module instantiates correctly
    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
}

#[test]
// Memory and table need to be exported as "memory" and "table". This test
// checks that we export them if they are not.
fn test_instrument_module_export_memory_table() {
    let config = EmbeddersConfig::default();
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());
    let output = validate_and_instrument_for_testing(
        &embedder,
        &BinaryEncodedWasm::new(
            wat::parse_str(
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
    )
    .unwrap()
    .1;

    let module = Module::parse(output.binary.as_slice(), false).unwrap();
    assert_memory_and_table_exports(&module);
    // check that instrumented module instantiates correctly
    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
}

#[test]
fn test_instrument_module_with_exported_global() {
    let config = EmbeddersConfig::default();
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());
    let output = validate_and_instrument_for_testing(
        &embedder,
        &BinaryEncodedWasm::new(
            wat::parse_str(
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
    )
    .unwrap()
    .1;

    wasmtime_simple::wasmtime_instantiate_and_call_run(&output.binary);
}

fn compressed_test_contents(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/compressed/{}",
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
        name
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("couldn't open file {}: {}", path, e))
}

#[test]
#[should_panic(expected = "too large")]
fn test_decode_large_compressed_module() {
    // Try decoding 101MB of zeros
    //
    // We also tested decoding with a much larger file.
    // To save space and CI time, we do not include the larger archive file and
    // do not generate it in the test. To reproduce the test, execute the following
    // command:
    //
    // dd if=/dev/zero bs=1024 count=$((500 * 1024)) | gzip -9 > zeroes.gz
    //
    // and replace the zeroes.gz file used in the test.
    decode_wasm(Arc::new(compressed_test_contents("zeros.gz"))).unwrap();
}

#[test]
#[should_panic(expected = "specified uncompressed size 100 does not match extracted size 101")]
fn test_decode_large_compressed_module_with_tweaked_size() {
    let mut contents = compressed_test_contents("zeros.gz");
    let n = contents.len();
    contents[n - 4..n].copy_from_slice(&100u32.to_le_bytes());
    decode_wasm(Arc::new(contents)).unwrap();
}
