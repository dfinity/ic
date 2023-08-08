use ic_config::embedders::{Config as EmbeddersConfig, MeteringType};
use ic_config::subnet_config::SchedulerConfig;
use ic_embedders::{
    wasm_utils::{
        validate_and_instrument_for_testing, validation::RESERVED_SYMBOLS, wasm_transform::Module,
        Segments,
    },
    WasmtimeEmbedder,
};
use ic_logger::replica_logger::no_op_logger;
use ic_sys::{PageIndex, PAGE_SIZE};
use ic_wasm_types::BinaryEncodedWasm;
use insta::assert_snapshot;
use pretty_assertions::assert_eq;

use ic_embedders::wasm_utils::instrumentation::instruction_to_cost;
use ic_embedders::wasmtime_embedder::WasmtimeInstance;
use ic_interfaces::execution_environment::HypervisorError;
use ic_interfaces::execution_environment::SystemApi;
use ic_replicated_state::Global;
use ic_test_utilities::wasmtime_instance::WasmtimeInstanceBuilder;
use ic_types::{
    methods::{FuncRef, WasmMethod},
    NumInstructions,
};

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
    let buff = wat::parse_file(filename).expect("couldn't read the input file");

    let output = validate_and_instrument_for_testing(
        &WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger()),
        &BinaryEncodedWasm::new(buff),
    )
    .expect("couldn't instrument Wasm code")
    .1;

    let out = wasmprinter::print_bytes(output.binary.as_slice())
        .expect("couldn't convert metered Wasm to wat");

    assert_snapshot!(testname, out);
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
            wat::parse_str(
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
    let module = Module::parse(output.binary.as_slice(), false).unwrap();
    if !module.data.is_empty() {
        panic!("instrumentation should have removed data sections");
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
    let wasm = wat::parse_str(
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

    let (_, instrumentation_details) = validate_and_instrument_for_testing(
        &WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger()),
        &wasm,
    )
    .unwrap();
    let module = Module::parse(instrumentation_details.binary.as_slice(), true).unwrap();

    for export in module.exports {
        assert!(RESERVED_SYMBOLS.contains(&export.name))
    }
}

fn instr_used(instance: &mut WasmtimeInstance<impl SystemApi>) -> u64 {
    let instruction_counter = instance.instruction_counter();
    let system_api = &instance.store_data().system_api;
    system_api
        .slice_instructions_executed(instruction_counter)
        .get()
}

#[allow(clippy::field_reassign_with_default)]
fn new_instance(wat: &str, instruction_limit: u64) -> WasmtimeInstance<impl SystemApi> {
    let mut config = ic_config::embedders::Config::default();
    config.metering_type = MeteringType::New;
    config.dirty_page_overhead = SchedulerConfig::application_subnet().dirty_page_overhead;
    WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_num_instructions(NumInstructions::new(instruction_limit))
        .build()
}

fn func_ref(name: &str) -> FuncRef {
    FuncRef::Method(WasmMethod::Update(name.to_string()))
}
fn add_one() -> String {
    r#"(i64.add (i64.const 1))
"#
    .to_string()
}

// cost of the addition group (get glob, do adds, set glob)
fn cost_a(n: u64) -> u64 {
    let ca = instruction_to_cost(&wasmparser::Operator::I64Add);
    let cc = instruction_to_cost(&wasmparser::Operator::I64Const { value: 1 });
    let cg = instruction_to_cost(&wasmparser::Operator::GlobalSet { global_index: 0 })
        + instruction_to_cost(&wasmparser::Operator::GlobalGet { global_index: 0 });

    (ca + cc) * n + cg
}

#[test]
fn metering_plain() {
    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                global.get $g1
                {body}
                global.set $g1
            )
        )"#,
        body = add_one().repeat(10)
    );
    let mut instance = new_instance(&wat, 1000);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(10));

    let instructions_used = instr_used(&mut instance);
    assert_eq!(instructions_used, cost_a(10));

    // Now run the same with insufficient instructions
    let mut instance = new_instance(&wat, instructions_used - 1);
    let err = instance.run(func_ref("test")).unwrap_err();
    assert_eq!(err, HypervisorError::InstructionLimitExceeded);

    // with early return
    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                global.get $g1
                {p1}
                global.set $g1
                return
                global.get $g1
                {p2}
                global.set $g1
            )
        )"#,
        p1 = add_one().repeat(10),
        p2 = add_one().repeat(10),
    );
    let mut instance = new_instance(&wat, 30);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(10));

    let instructions_used = instr_used(&mut instance);
    let cret = instruction_to_cost(&wasmparser::Operator::Return);
    assert_eq!(instructions_used, cost_a(10) + cret);

    // Now run the same with insufficient instructions
    let mut instance = new_instance(&wat, instructions_used - 1);
    let err = instance.run(func_ref("test")).unwrap_err();
    assert_eq!(err, HypervisorError::InstructionLimitExceeded);

    // with early trap
    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                global.get $g1
                {p1}
                global.set $g1
                unreachable
                global.get $g1
                {p2}
                global.set $g1
            )
        )"#,
        p1 = add_one().repeat(10),
        p2 = add_one().repeat(10),
    );
    let mut instance = new_instance(&wat, 30);
    instance.run(func_ref("test")).unwrap_err();

    let instructions_used = instr_used(&mut instance);
    let ctrap = instruction_to_cost(&wasmparser::Operator::Unreachable);
    assert_eq!(instructions_used, cost_a(10) + ctrap);
}

#[test]
fn metering_block() {
    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                (block $b1
                    global.get $g1
                    {body}
                    global.set $g1
                )
            )
        )"#,
        body = add_one().repeat(10)
    );

    let mut instance = new_instance(&wat, 30);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(10));

    let instructions_used = instr_used(&mut instance);
    assert_eq!(instructions_used, cost_a(10));

    // another one, more complex
    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                global.get $g1
                {p1}
                global.set $g1

                (block $b1
                    global.get $g1
                    {p2a}
                    global.set $g1
                    (block $b2
                        br $b1
                    )
                    global.get $g1
                    {p2b}
                    global.set $g1
                )

                global.get $g1
                {p3}
                global.set $g1
            )
        )"#,
        p1 = add_one().repeat(10),
        p2a = add_one().repeat(100),
        p2b = add_one().repeat(50),
        p3 = add_one().repeat(10),
    );

    let mut instance = new_instance(&wat, 1_000);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(120));

    let instructions_used = instr_used(&mut instance);
    let cbr = instruction_to_cost(&wasmparser::Operator::Br { relative_depth: 1 });
    assert_eq!(instructions_used, cost_a(100) + cost_a(10) * 2 + cbr);

    // another one, with return
    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                global.get $g1
                {p1}
                global.set $g1

                (block $b1
                    global.get $g1
                    {p2a}
                    global.set $g1
                    (block $b2
                        return
                    )
                    global.get $g1
                    {p2b}
                    global.set $g1
                )

                global.get $g1
                {p3}
                global.set $g1
            )
        )"#,
        p1 = add_one().repeat(10),
        p2a = add_one().repeat(100),
        p2b = add_one().repeat(50),
        p3 = add_one().repeat(10),
    );

    let mut instance = new_instance(&wat, 1_000);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(110));

    let instructions_used = instr_used(&mut instance);
    let cret = instruction_to_cost(&wasmparser::Operator::Return);
    assert_eq!(instructions_used, cost_a(100) + cost_a(10) + cret);
}

#[test]
fn metering_if() {
    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                global.get $g1
                {p1}
                global.set $g1
                (i32.const 0)
                (if
                    (then
                        global.get $g1
                        {p2}
                        global.set $g1
                    )
                    (else
                        global.get $g1
                        {p3}
                        global.set $g1
                    )
                )
                global.get $g1
                {p4}
                global.set $g1
            )
        )"#,
        p1 = add_one().repeat(5),
        p2 = add_one().repeat(10),
        p3 = add_one().repeat(20),
        p4 = add_one().repeat(30)
    );

    let mut instance = new_instance(&wat, 100);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(55));

    let cc = instruction_to_cost(&wasmparser::Operator::I64Const { value: 1 });
    let cif = instruction_to_cost(&wasmparser::Operator::If {
        blockty: wasmparser::BlockType::Empty,
    });

    let instructions_used = instr_used(&mut instance);
    assert_eq!(
        instructions_used,
        cost_a(5) + cost_a(20) + cost_a(30) + cc + cif
    );

    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                global.get $g1
                {p1}
                global.set $g1
                (i32.const 1)
                (if
                    (then
                        global.get $g1
                        {p2}
                        global.set $g1
                        return
                    )
                    (else
                        global.get $g1
                        {p3}
                        global.set $g1
                    )
                )
                global.get $g1
                {p4}
                global.set $g1
            )
        )"#,
        p1 = add_one().repeat(5),
        p2 = add_one().repeat(10),
        p3 = add_one().repeat(20),
        p4 = add_one().repeat(30),
    );

    let mut instance = new_instance(&wat, 1000);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(15));

    let cret = instruction_to_cost(&wasmparser::Operator::Return);

    let instructions_used = instr_used(&mut instance);
    assert_eq!(instructions_used, cost_a(5) + cost_a(10) + cc + cif + cret);
}

#[test]
fn metering_loop() {
    let wat = format!(
        r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                (local $i i32)

                global.get $g1
                {p1}
                global.set $g1
                (loop $loop_a
                    global.get $g1
                    {p2}
                    global.set $g1

                    local.get $i
                    (i32.add (i32.const 1))
                    local.set $i

                    local.get $i
                    i32.const 5
                    i32.lt_s
                    br_if $loop_a

                    global.get $g1
                    {p3}
                    global.set $g1
                )
                global.get $g1
                {p4}
                global.set $g1
            )
        )"#,
        p1 = add_one().repeat(5),
        p2 = add_one().repeat(10),
        p3 = add_one().repeat(20),
        p4 = add_one().repeat(30)
    );

    let mut instance = new_instance(&wat, 1000);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(105));

    let cc = instruction_to_cost(&wasmparser::Operator::I32Const { value: 1 });
    let cbrif = instruction_to_cost(&wasmparser::Operator::BrIf { relative_depth: 0 });

    let ca = instruction_to_cost(&wasmparser::Operator::I32Add);
    let clts = instruction_to_cost(&wasmparser::Operator::I32LtS);
    let cset = instruction_to_cost(&wasmparser::Operator::LocalSet { local_index: 0 });
    let cget = instruction_to_cost(&wasmparser::Operator::LocalGet { local_index: 0 });

    let c_loop = cost_a(10) + cc * 2 + ca + cget + cset * 2 + clts + cbrif;

    let instructions_used = instr_used(&mut instance);
    assert_eq!(
        instructions_used,
        cost_a(5) + (c_loop) * 5 + cost_a(20) + cost_a(30)
    );
}

#[test]
fn test_metering_for_table_fill() {
    let wat = r#"
    (module
        (table $table 101 funcref)
        (elem func 0)
        (func $test (export "canister_update test")
          (table.fill 0 (i32.const 0) (ref.func 0) (i32.const 50))
        )
      )"#;

    let mut instance = new_instance(wat, 1000000);
    let _res = instance.run(func_ref("test")).unwrap();

    let param1 = instruction_to_cost(&wasmparser::Operator::I32Const { value: 0 });
    let param2 = instruction_to_cost(&wasmparser::Operator::RefFunc { function_index: 0 });
    let param3 = instruction_to_cost(&wasmparser::Operator::I32Const { value: 50 });
    let table_fill = instruction_to_cost(&wasmparser::Operator::TableFill { table: 0 });
    // The third parameter of table.fill is the number of elements to fill
    // and we charge dynamically 1 for each byte written.
    let dynamic_cost_table_fill = 50;

    let instructions_used = instr_used(&mut instance);
    assert_eq!(
        instructions_used,
        param1 + param2 + param3 + table_fill + dynamic_cost_table_fill
    );

    let mut instance = new_instance(wat, instructions_used);
    instance.run(func_ref("test")).unwrap();
}
