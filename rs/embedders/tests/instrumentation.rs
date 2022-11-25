use ic_config::embedders::Config as EmbeddersConfig;
use ic_config::flag_status::FlagStatus;
use ic_embedders::{
    wasm_utils::{
        instrumentation::{export_additional_symbols, ExportModuleData},
        validate_and_instrument_for_testing,
        validation::RESERVED_SYMBOLS,
        Segments,
    },
    WasmtimeEmbedder,
};
use ic_logger::replica_logger::no_op_logger;
use ic_sys::{PageIndex, PAGE_SIZE};
use ic_wasm_types::BinaryEncodedWasm;
use insta::assert_snapshot;
use parity_wasm::elements::{self, Module, Section};
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
fn inject_and_cmp(testname: &str) {
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

    let mut config_old = EmbeddersConfig::default();
    config_old.feature_flags.new_wasm_transform_lib = FlagStatus::Disabled;
    let mut config_new = EmbeddersConfig::default();
    config_new.feature_flags.new_wasm_transform_lib = FlagStatus::Enabled;

    let output_old = validate_and_instrument_for_testing(
        &WasmtimeEmbedder::new(config_old, no_op_logger()),
        &BinaryEncodedWasm::new(buff.clone()),
    )
    .expect("couldn't instrument Wasm code")
    .1;

    let output = validate_and_instrument_for_testing(
        &WasmtimeEmbedder::new(config_new, no_op_logger()),
        &BinaryEncodedWasm::new(buff),
    )
    .expect("couldn't instrument Wasm code")
    .1;

    assert_eq!(
        output.exported_functions, output_old.exported_functions,
        "exported functions differ in old and new instrumentation"
    );
    assert_eq!(
        output.compilation_cost, output_old.compilation_cost,
        "compilation costs differ in old and new instrumentation"
    );
    assert_eq!(
        output.data, output_old.data,
        "data segments differ in old and new instrumentation"
    );

    let out = wabt::wasm2wat_with_features(output.binary.as_slice(), features.clone())
        .expect("couldn't convert metered Wasm to wat");

    let module: Module = parity_wasm::elements::deserialize_buffer(output_old.binary.as_slice())
        .expect("couldn't deserialize module");
    let out_old = wabt::wasm2wat_with_features(
        elements::serialize(module).expect("couldn't serialize after metering"),
        features,
    )
    .expect("couldn't convert metered Wasm to wat");
    assert_snapshot!(testname, out);
    assert_eq!(out, out_old);
}

#[test]
fn metering_basic() {
    inject_and_cmp("basic");
}

#[test]
fn metering_basic_import() {
    inject_and_cmp("basic_import");
}

#[test]
fn metering_basic_import_call() {
    inject_and_cmp("basic_import_call");
}

#[test]
fn metering_element() {
    inject_and_cmp("element");
}

#[test]
fn metering_fac() {
    inject_and_cmp("fac");
}

#[test]
fn metering_recursive() {
    inject_and_cmp("recursive");
}

#[test]
fn metering_app() {
    inject_and_cmp("app");
}

#[test]
fn metering_app2() {
    inject_and_cmp("app2");
}

#[test]
fn metering_start() {
    inject_and_cmp("start");
}

#[test]
fn metering_zero_cost_ops() {
    inject_and_cmp("zero_cost_ops");
}

#[test]
fn metering_control_flow() {
    inject_and_cmp("control_flow");
}

#[test]
fn metering_fizzbuzz() {
    inject_and_cmp("fizzbuzz");
}

#[test]
fn metering_nested_ifs() {
    inject_and_cmp("nested_ifs");
}

#[test]
fn export_mutable_globals() {
    inject_and_cmp("export_mutable_globals");
}

#[test]
fn memory_grow() {
    inject_and_cmp("memory_grow");
}

#[test]
fn simple_loop() {
    inject_and_cmp("simple_loop");
}

#[test]
fn metering_memory_fill() {
    inject_and_cmp("memory_fill");
}

#[test]
fn test_get_data() {
    let config = EmbeddersConfig::default();
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());
    let output = validate_and_instrument_for_testing(
        &embedder,
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
    )
    .unwrap()
    .1;
    let data = output.data.into_slice();
    assert_eq!((2, b"a tree".to_vec()), data[0]);
    assert_eq!((11, b"is known".to_vec()), data[1]);
    assert_eq!((23, b"by its fruit".to_vec()), data[2]);
    let module = parity_wasm::deserialize_buffer::<Module>(output.binary.as_slice()).unwrap();
    for section in module.sections() {
        if let Section::Data(_) = section {
            panic!("instrumentation should have removed data sections");
        }
    }
}

#[test]
fn test_chunks_to_pages() {
    let segs: Segments = vec![
        (0, vec![1; PAGE_SIZE + 10]), // The segment is larger than a page.
        (PAGE_SIZE + 5, vec![2; 10]), // Overlaps with the segment above.
        (PAGE_SIZE + PAGE_SIZE - 100, vec![3; 200]), // Crosses the page boundary.
    ]
    .into_iter()
    .collect();
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
