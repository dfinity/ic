use ic_embedders::wasm_utils::{
    instrumentation::{
        export_additional_symbols, instrument, ExportModuleData, InstructionCostTable, Segments,
    },
    validation::RESERVED_SYMBOLS,
};
use ic_sys::{PageIndex, PAGE_SIZE};
use ic_wasm_types::BinaryEncodedWasm;
use insta::assert_snapshot;
use parity_wasm::elements::{self, Module};
use pretty_assertions::assert_eq;
use std::fs;
use wabt::{wat2wasm, Features};

/// Assert what the output of wasm instrumentation should be using the [`insta`]
/// crate.
///
/// When making changes that alter the expected output, changes can be easily reviewed and acked using the [`insta` cli](https://insta.rs/docs/cli/).
/// Expected output is stored in `.snap` files in the `snapshots` folder.
/// When tests fail, the new output will be stored in a `.snap.new` file.
/// Instead of using the `insta` cli, you can review and make changes by
/// directly diffing the `.snap` and `.snap.new` files and save changes by
/// updating the `.snap` file.
fn inject_and_cmp(testname: &str, conf: &InstructionCostTable) {
    let filename = format!(
        "{}/tests/instrumentation-test-data/{}.wat",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        testname
    );
    let content = fs::read_to_string(filename).expect("couldn't read the input file");
    let mut features = Features::new();
    features.enable_bulk_memory();
    let buff = wabt::wat2wasm_with_features(content, features.clone())
        .expect("couldn't convert the input wat to Wasm");
    let output =
        instrument(&BinaryEncodedWasm::new(buff), conf).expect("couldn't instrument Wasm code");
    let module: Module = parity_wasm::elements::deserialize_buffer(output.binary.as_slice())
        .expect("couldn't deserialize module");
    let out = wabt::wasm2wat_with_features(
        elements::serialize(module).expect("couldn't serialize after metering"),
        features,
    )
    .expect("couldn't convert metered Wasm to wat");
    assert_snapshot!(out);
}

#[test]
fn metering_basic() {
    inject_and_cmp("basic", &InstructionCostTable::new());
}

#[test]
fn metering_basic_import() {
    inject_and_cmp("basic_import", &InstructionCostTable::new());
}

#[test]
fn metering_basic_import2() {
    inject_and_cmp("basic_import2", &InstructionCostTable::new());
}

#[test]
fn metering_basic_import_call() {
    inject_and_cmp("basic_import_call", &InstructionCostTable::new());
}

#[test]
fn metering_element() {
    inject_and_cmp("element", &InstructionCostTable::new());
}

#[test]
fn metering_fac() {
    inject_and_cmp("fac", &InstructionCostTable::new().with_default_cost(2));
}

#[test]
fn metering_recursive() {
    inject_and_cmp("recursive", &InstructionCostTable::new());
}

#[test]
fn metering_app() {
    let conf = InstructionCostTable::new()
        .with_instruction_cost("i32.const".to_string(), 100)
        .with_instruction_cost("local.get".to_string(), 30)
        .with_instruction_cost("i32.xor".to_string(), 2);
    inject_and_cmp("app", &conf);
}

#[test]
fn metering_app2() {
    inject_and_cmp("app2", &InstructionCostTable::new());
}

#[test]
fn metering_start() {
    inject_and_cmp("start", &InstructionCostTable::new());
}

#[test]
fn metering_mixed_imports() {
    inject_and_cmp("mixed_imports", &InstructionCostTable::new());
}

#[test]
fn metering_zero_cost_ops() {
    inject_and_cmp("zero_cost_ops", &InstructionCostTable::new());
}

#[test]
fn metering_control_flow() {
    inject_and_cmp("control_flow", &InstructionCostTable::new());
}

#[test]
fn metering_fizzbuzz() {
    inject_and_cmp("fizzbuzz", &InstructionCostTable::new());
}

#[test]
fn metering_nested_ifs() {
    inject_and_cmp("nested_ifs", &InstructionCostTable::new());
}

#[test]
fn export_mutable_globals() {
    inject_and_cmp("export_mutable_globals", &InstructionCostTable::new());
}

#[test]
fn memory_grow() {
    inject_and_cmp("memory_grow", &InstructionCostTable::new());
}

#[test]
fn simple_loop() {
    inject_and_cmp("simple_loop", &InstructionCostTable::new());
}

#[test]
fn metering_memory_fill() {
    inject_and_cmp("memory_fill", &InstructionCostTable::new());
}

#[test]
fn test_get_data() {
    let output = instrument(
        &BinaryEncodedWasm::new(
            wabt::wat2wasm(
                r#"(module
                (memory 1)
                (data (i32.const 2)  "a tree")
                (data (i32.const 11) "is known")
                (data (i32.const 23) "by its fruit")
            )"#,
            )
            .unwrap(),
        ),
        &InstructionCostTable::new(),
    )
    .unwrap();
    let data = output.data.as_slice();
    assert_eq!((2, b"a tree".to_vec()), data[0]);
    assert_eq!((11, b"is known".to_vec()), data[1]);
    assert_eq!((23, b"by its fruit".to_vec()), data[2]);
    let output = instrument(&output.binary, &InstructionCostTable::new()).unwrap();
    // the data should have been removed from the instrumented module
    assert_eq!(0, output.data.as_slice().len())
}

#[test]
fn test_chunks_to_pages() {
    let segs = Segments::from(vec![
        (0, vec![1; PAGE_SIZE + 10]), // The segment is larger than a page.
        (PAGE_SIZE + 5, vec![2; 10]), // Overlaps with the segment above.
        (PAGE_SIZE + PAGE_SIZE - 100, vec![3; 200]), // Crosses the page boundary.
    ]);
    let mut pages = segs.as_pages();
    // sort for determinism
    pages.sort_by_key(|p| p.0);
    assert_eq!(pages.len(), 3);
    assert_eq!(pages[0].0, PageIndex::new(0));
    assert_eq!(&pages[0].1[..], &[1; PAGE_SIZE]);
    assert_eq!(pages[1].0, PageIndex::new(1));
    assert_eq!(&pages[1].1[0..5], &[1; 5]);
    assert_eq!(&pages[1].1[5..15], &[2; 10]);
    assert_eq!(&pages[1].1[15..PAGE_SIZE - 100], &[0; PAGE_SIZE - 100 - 15]);
    assert_eq!(&pages[1].1[PAGE_SIZE - 100..PAGE_SIZE], &[3; 100]);
    assert_eq!(pages[2].0, PageIndex::new(2));
    assert_eq!(&pages[2].1[0..100], &[3; 100]);
    assert_eq!(&pages[2].1[100..PAGE_SIZE], &[0; PAGE_SIZE - 100]);
}

#[test]
fn test_exports_only_reserved_symbols() {
    let wasm = wat2wasm(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
                (func $test
                    (call $msg_reply)
                )
        )"#,
    )
    .map(BinaryEncodedWasm::new)
    .unwrap();

    let module = parity_wasm::deserialize_buffer::<Module>(wasm.as_slice()).unwrap();
    let module = export_additional_symbols(module, &ExportModuleData::default()).unwrap();

    let exports = module.export_section().unwrap().entries();
    for export in exports {
        assert!(RESERVED_SYMBOLS.contains(&export.field()))
    }
}
