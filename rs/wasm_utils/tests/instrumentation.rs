use ic_wasm_types::BinaryEncodedWasm;
use ic_wasm_utils::instrumentation::{instrument, InstructionCostTable, Segments};
use parity_wasm::elements::{self, Module};
use pretty_assertions::assert_eq;
use std::fs;

fn inject_and_cmp(testname: &str, conf: &InstructionCostTable) {
    let filename = format!(
        "{}/tests/instrumentation-test-data/in/{}.wat",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        testname
    );
    let content = fs::read_to_string(filename).expect("couldn't read the input file");
    let buff = wabt::wat2wasm(content).expect("couldn't convert the input wat to Wasm");
    let output =
        instrument(&BinaryEncodedWasm::new(buff), conf).expect("couldn't instrument Wasm code");
    let module: Module = parity_wasm::elements::deserialize_buffer(&output.binary.as_slice())
        .expect("couldn't deserialize module");
    let out =
        wabt::wasm2wat(elements::serialize(module).expect("couldn't serialize after metering"))
            .expect("couldn't convert metered Wasm to wat");
    let filename = format!(
        "{}/tests/instrumentation-test-data/expected-out/{}.wat",
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        testname
    );
    // this is needed to remove the syntactic sugar
    // (labels, inlined fn call args, etc)
    let out_expected = wabt::wasm2wat(
        wabt::wat2wasm(
            fs::read_to_string(filename).expect("couldn't read from expected output file"),
        )
        .expect("couldn't convert expected wat to Wasm"),
    )
    .expect("couldn't convert expected Wasm to wat");
    assert_eq!(out_expected, out, "{}:\n{}", testname, out);
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
        (1, vec![1, 2, 3]),
        (5, vec![4, 5, 6]),
        (9, vec![7]),
        (10, vec![8]),
        (18, vec![9, 10, 11]),
        (43, vec![12, 13, 14]),
        (45, vec![15, 16, 17]), // overlaps with the chunk above
        (60, vec![18]),
    ]);
    let mut pages = segs.as_pages(10);
    // sort for determinism
    pages.sort_by_key(|p| p.0);
    assert_eq!(
        pages,
        vec![
            (0, vec![0, 1, 2, 3, 0, 4, 5, 6, 0, 7]),
            (1, vec![8, 0, 0, 0, 0, 0, 0, 0, 9, 10]),
            (2, vec![11, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (4, vec![0, 0, 0, 12, 13, 15, 16, 17, 0, 0]),
            (6, vec![18, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        ]
    );
}
