use ic_config::embedders::{Config as EmbeddersConfig, MeteringType};
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SchedulerConfig;
use ic_embedders::{
    wasm_utils::{validate_and_instrument_for_testing, validation::RESERVED_SYMBOLS, Segments},
    WasmtimeEmbedder,
};
use ic_logger::replica_logger::no_op_logger;
use ic_sys::{PageIndex, PAGE_SIZE};
use ic_wasm_transform::Module;
use ic_wasm_types::BinaryEncodedWasm;
use insta::assert_snapshot;
use pretty_assertions::assert_eq;

use ic_embedders::wasm_utils::instrumentation::instruction_to_cost;
use ic_embedders::wasmtime_embedder::{system_api_complexity, WasmtimeInstance};
use ic_interfaces::execution_environment::HypervisorError;
use ic_interfaces::execution_environment::SystemApi;
use ic_replicated_state::Global;
use ic_test_utilities_embedders::WasmtimeInstanceBuilder;
use ic_types::{
    methods::{FuncRef, WasmMethod},
    NumBytes, NumInstructions,
};

/// Assert what the output of wasm instrumentation should be using the [`insta`]
/// crate.
///
/// Expected output is stored in `.snap` files in the `snapshots` folder.
///
/// When tests fail, you can get the new files with `bazel` as follows:
/// - `mkdir /ic/insta`
/// - modify `INSTA_WORKSPACE_ROOT` in BUILD.bazel to `/ic/insta`
/// - `bazel test //rs/embedders:instrumentation --spawn_strategy=local`
/// - the new files will be in `ic/insta`
/// - `cd rs/embedders/tests/snapshots/`
/// - `for x in *.snap; do cp /ic/insta/rs/embedders/tests/snapshots/$x.new $x; done`
/// - the for-loop above overwrites the existing snap files with the new ones.
/// - restore `INSTA_WORKSPACE_ROOT` to `.`
/// - `bazel test //rs/embedders:instrumentation` should pass now.
///
/// If you find a simpler way to get the new snap files, please update the steps.
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
fn test_mixed_data_segments() {
    let config = EmbeddersConfig::default();
    let embedder = WasmtimeEmbedder::new(config, no_op_logger());
    let output = validate_and_instrument_for_testing(
        &embedder,
        &BinaryEncodedWasm::new(
            wat::parse_str(
                r#"(module
                (memory 1)
                (data "passive 0")
                (data (i32.const 0)  "active 1")
                (data (i32.const 16) "active 2")
                (data "passive 3")
                (data (i32.const 32) "active 4")
                (data "passive 5")
                (data (i32.const 48) "active 6")
                (data (i32.const 64) "active 7")
            )"#,
            )
            .unwrap(),
        ),
    )
    .unwrap()
    .1;
    let data = output.data.into_slice();
    assert_eq!((0, b"active 1".to_vec()), data[0]);
    assert_eq!((16, b"active 2".to_vec()), data[1]);
    assert_eq!((32, b"active 4".to_vec()), data[2]);
    assert_eq!((48, b"active 6".to_vec()), data[3]);
    assert_eq!((64, b"active 7".to_vec()), data[4]);
    let module = Module::parse(output.binary.as_slice(), false).unwrap();
    assert_eq!(module.data.len(), 6);
    assert_eq!(&module.data[0].data, &b"passive 0");
    assert_eq!(module.data[1].data.len(), 0);
    assert_eq!(module.data[2].data.len(), 0);
    assert_eq!(&module.data[3].data, &b"passive 3");
    assert_eq!(module.data[4].data.len(), 0);
    assert_eq!(&module.data[5].data, &b"passive 5");
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

fn instr_used(instance: &mut WasmtimeInstance) -> u64 {
    let instruction_counter = instance.instruction_counter();
    let system_api = instance.store_data().system_api().unwrap();
    system_api
        .slice_instructions_executed(instruction_counter)
        .get()
}

#[allow(clippy::field_reassign_with_default)]
fn new_instance(wat: &str, instruction_limit: u64) -> WasmtimeInstance {
    let mut config = EmbeddersConfig::default();
    config.metering_type = MeteringType::New;
    config.dirty_page_overhead = SchedulerConfig::application_subnet().dirty_page_overhead;
    WasmtimeInstanceBuilder::new()
        .with_config(config)
        .with_wat(wat)
        .with_num_instructions(NumInstructions::new(instruction_limit))
        .build()
}

#[allow(clippy::field_reassign_with_default)]
fn new_instance_for_stable_write(
    wat: &str,
    instruction_limit: u64,
    native_stable: FlagStatus,
) -> WasmtimeInstance {
    let mut config = EmbeddersConfig::default();
    config.metering_type = MeteringType::New;
    config.dirty_page_overhead = SchedulerConfig::application_subnet().dirty_page_overhead;
    config.feature_flags.wasm_native_stable_memory = native_stable;
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
    // Function is 1 instruction.
    assert_eq!(instructions_used, 1 + cost_a(10));

    // Now run the same with insufficient instructions
    let mut instance = new_instance(&wat, instructions_used - 1);
    let err = instance.run(func_ref("test")).unwrap_err();
    assert_eq!(
        err,
        HypervisorError::InstructionLimitExceeded(NumInstructions::from(instructions_used - 1))
    );

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
    // Function is 1 instruction.
    assert_eq!(instructions_used, 1 + cost_a(10) + cret);

    // Now run the same with insufficient instructions
    let mut instance = new_instance(&wat, instructions_used - 1);
    let err = instance.run(func_ref("test")).unwrap_err();
    assert_eq!(
        err,
        HypervisorError::InstructionLimitExceeded(NumInstructions::from(instructions_used - 1))
    );

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
    // Function is 1 instruction.
    assert_eq!(instructions_used, 1 + cost_a(10) + ctrap);
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
    // Function is 1 instruction.
    assert_eq!(instructions_used, 1 + cost_a(10));

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
    // Function is 1 instruction.
    assert_eq!(instructions_used, 1 + cost_a(100) + cost_a(10) * 2 + cbr);

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
    // Function is 1 instruction.
    assert_eq!(instructions_used, 1 + cost_a(100) + cost_a(10) + cret);
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
        // Function is 1 instruction.
        1 + cost_a(5) + cost_a(20) + cost_a(30) + cc + cif
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
    // Function is 1 instruction.
    assert_eq!(
        instructions_used,
        1 + cost_a(5) + cost_a(10) + cc + cif + cret
    );
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
        // Function is 1 instruction.
        1 + cost_a(5) + (c_loop) * 5 + cost_a(20) + cost_a(30)
    );
}

#[test]
fn charge_for_dirty_heap() {
    let wat = r#"
        (module
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                (i64.store (i32.const 0) (i64.const 17))
                (i64.store (i32.const 4096) (i64.const 117))
                (i64.load (i32.const 0))
                global.set $g1
            )
            (memory (export "memory") 10)
        )"#;
    let mut instance = new_instance(wat, 10000);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(17));

    let cc = instruction_to_cost(&wasmparser::Operator::I64Const { value: 1 });
    let cg = instruction_to_cost(&wasmparser::Operator::GlobalSet { global_index: 0 });
    let cs = instruction_to_cost(&wasmparser::Operator::I64Store {
        memarg: wasmparser::MemArg {
            align: 0,
            max_align: 0,
            offset: 0,
            memory: 0,
        },
    });
    let cl = instruction_to_cost(&wasmparser::Operator::I64Load {
        memarg: wasmparser::MemArg {
            align: 0,
            max_align: 0,
            offset: 0,
            memory: 0,
        },
    });
    let cd = SchedulerConfig::application_subnet()
        .dirty_page_overhead
        .get();

    let instructions_used = instr_used(&mut instance);
    // Function is 1 instruction.
    assert_eq!(instructions_used, 1 + 5 * cc + cg + 2 * cs + cl + 2 * cd);

    // Now run the same with insufficient instructions
    // We should still succeed (to avoid potentially failing pre-upgrades
    // of canisters that did not adjust their code to new metering)
    let mut instance = new_instance(wat, 100);
    instance.run(func_ref("test")).unwrap();
}

fn run_charge_for_dirty_stable64_test(native_stable: FlagStatus) {
    let wat = r#"
        (module
            (import "ic0" "stable64_grow"
                (func $ic0_stable64_grow (param $pages i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $ic0_stable64_read (param $dst i64) (param $offset i64) (param $size i64)))
            (import "ic0" "stable64_write"
                (func $ic0_stable64_write (param $offset i64) (param $src i64) (param $size i64)))
            (global $g1 (export "g1") (mut i64) (i64.const 0))
            (func $test (export "canister_update test")
                (drop (call $ic0_stable64_grow (i64.const 1)))
                (i64.store (i32.const 0) (i64.const 117))
                (i64.store (i32.const 1) (i64.const 17))
                (call $ic0_stable64_write (i64.const 0) (i64.const 0) (i64.const 1))
                (call $ic0_stable64_write (i64.const 4096) (i64.const 1) (i64.const 1))
                (call $ic0_stable64_read (i64.const 7) (i64.const 4096) (i64.const 1))
                (i64.load (i32.const 7))
                global.set $g1
            )
            (memory (export "memory") 10)
        )"#;

    let mut instance = new_instance_for_stable_write(wat, 10000, native_stable);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I64(17));

    let cc = instruction_to_cost(&wasmparser::Operator::I64Const { value: 1 });
    let cg = instruction_to_cost(&wasmparser::Operator::GlobalSet { global_index: 0 });
    let ccall = instruction_to_cost(&wasmparser::Operator::Call { function_index: 0 });
    let cdrop = instruction_to_cost(&wasmparser::Operator::Drop);

    let cs = instruction_to_cost(&wasmparser::Operator::I64Store {
        memarg: wasmparser::MemArg {
            align: 0,
            max_align: 0,
            offset: 0,
            memory: 0,
        },
    });
    let cl = instruction_to_cost(&wasmparser::Operator::I64Load {
        memarg: wasmparser::MemArg {
            align: 0,
            max_align: 0,
            offset: 0,
            memory: 0,
        },
    });

    let system_api = instance.store_data().system_api().unwrap();

    let cd = SchedulerConfig::application_subnet()
        .dirty_page_overhead
        .get();
    let csg;
    let csw;
    let csr;

    match native_stable {
        FlagStatus::Enabled => {
            csg = system_api_complexity::overhead_native::STABLE_GROW.get();
            csw = system_api_complexity::overhead_native::STABLE64_WRITE.get()
                + system_api
                    .get_num_instructions_from_bytes(NumBytes::from(1))
                    .get();
            csr = system_api_complexity::overhead_native::STABLE64_READ.get()
                + system_api
                    .get_num_instructions_from_bytes(NumBytes::from(1))
                    .get();
        }
        FlagStatus::Disabled => {
            csg = system_api_complexity::overhead::STABLE_GROW.get();
            csw = system_api_complexity::overhead::STABLE64_WRITE.get()
                + system_api
                    .get_num_instructions_from_bytes(NumBytes::from(1))
                    .get();
            csr = system_api_complexity::overhead::STABLE64_READ.get()
                + system_api
                    .get_num_instructions_from_bytes(NumBytes::from(1))
                    .get();
        }
    }

    let instructions_used = instr_used(&mut instance);
    // 2 dirty stable pages and one heap
    assert_eq!(
        instructions_used,
        // Function is 1 instruction.
        1 + cdrop + ccall * 4 + csg + cc * 15 + cs * 2 + cd * 3 + csw * 2 + csr + cl + cg
    );

    // Now run the same with insufficient instructions
    // We should still succeed (to avoid potentially failing pre-upgrades
    // of canisters that did not adjust their code to new metering)
    let mut instance = new_instance_for_stable_write(wat, instructions_used - 1, native_stable);

    instance.run(func_ref("test")).unwrap();
}

#[test]
fn charge_for_dirty_stable64_native() {
    run_charge_for_dirty_stable64_test(FlagStatus::Enabled);
}

#[test]
fn charge_for_dirty_stable64() {
    run_charge_for_dirty_stable64_test(FlagStatus::Disabled);
}

fn run_charge_for_dirty_stable_test(native_stable: FlagStatus) {
    let wat = r#"
        (module
            (import "ic0" "stable_grow"
                (func $ic0_stable_grow (param $pages i32) (result i32)))
            (import "ic0" "stable_read"
                (func $ic0_stable_read (param $dst i32) (param $offset i32) (param $size i32)))
            (import "ic0" "stable_write"
                (func $ic0_stable_write (param $offset i32) (param $src i32) (param $size i32)))
            (global $g1 (export "g1") (mut i32) (i32.const 0))
            (func $test (export "canister_update test")
                (drop (call $ic0_stable_grow (i32.const 1)))
                (i32.store (i32.const 0) (i32.const 117))
                (i32.store (i32.const 1) (i32.const 17))
                (call $ic0_stable_write (i32.const 0) (i32.const 0) (i32.const 1))
                (call $ic0_stable_write (i32.const 4096) (i32.const 1) (i32.const 1))
                (call $ic0_stable_read (i32.const 7) (i32.const 4096) (i32.const 1))
                (i32.load (i32.const 7))
                global.set $g1
            )
            (memory (export "memory") 10)
        )"#;

    let mut instance = new_instance_for_stable_write(wat, 10000, native_stable);
    let res = instance.run(func_ref("test")).unwrap();

    let g = &res.exported_globals;
    assert_eq!(g[0], Global::I32(17));

    let cc = instruction_to_cost(&wasmparser::Operator::I32Const { value: 1 });
    let cg = instruction_to_cost(&wasmparser::Operator::GlobalSet { global_index: 0 });
    let ccall = instruction_to_cost(&wasmparser::Operator::Call { function_index: 0 });
    let cdrop = instruction_to_cost(&wasmparser::Operator::Drop);

    let cs = instruction_to_cost(&wasmparser::Operator::I32Store {
        memarg: wasmparser::MemArg {
            align: 0,
            max_align: 0,
            offset: 0,
            memory: 0,
        },
    });
    let cl = instruction_to_cost(&wasmparser::Operator::I32Load {
        memarg: wasmparser::MemArg {
            align: 0,
            max_align: 0,
            offset: 0,
            memory: 0,
        },
    });

    let system_api = instance.store_data().system_api().unwrap();

    let cd = SchedulerConfig::application_subnet()
        .dirty_page_overhead
        .get();
    let csg;
    let csw;
    let csr;

    match native_stable {
        FlagStatus::Enabled => {
            csg = system_api_complexity::overhead_native::STABLE_GROW.get();
            csw = system_api_complexity::overhead_native::STABLE_WRITE.get()
                + system_api
                    .get_num_instructions_from_bytes(NumBytes::from(1))
                    .get();
            csr = system_api_complexity::overhead_native::STABLE_READ.get()
                + system_api
                    .get_num_instructions_from_bytes(NumBytes::from(1))
                    .get();
        }
        FlagStatus::Disabled => {
            csg = system_api_complexity::overhead::STABLE_GROW.get();
            csw = system_api_complexity::overhead::STABLE_WRITE.get()
                + system_api
                    .get_num_instructions_from_bytes(NumBytes::from(1))
                    .get();
            csr = system_api_complexity::overhead::STABLE_READ.get()
                + system_api
                    .get_num_instructions_from_bytes(NumBytes::from(1))
                    .get();
        }
    }

    let instructions_used = instr_used(&mut instance);
    // 2 dirty stable pages and one heap
    assert_eq!(
        instructions_used,
        // Function is 1 instruction.
        1 + cdrop + ccall * 4 + csg + cc * 15 + cs * 2 + cd * 3 + csw * 2 + csr + cl + cg
    );

    // Now run the same with insufficient instructions
    // We should still succeed (to avoid potentially failing pre-upgrades
    // of canisters that did not adjust their code to new metering)
    let mut instance = new_instance_for_stable_write(wat, instructions_used - 1, native_stable);

    instance.run(func_ref("test")).unwrap();
}

#[test]
fn charge_for_dirty_stable_native() {
    run_charge_for_dirty_stable_test(FlagStatus::Enabled);
}

#[test]
fn charge_for_dirty_stable() {
    run_charge_for_dirty_stable_test(FlagStatus::Disabled);
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
        // Function is 1 instruction.
        1 + param1 + param2 + param3 + table_fill + dynamic_cost_table_fill
    );

    let mut instance = new_instance(wat, instructions_used);
    instance.run(func_ref("test")).unwrap();
}
