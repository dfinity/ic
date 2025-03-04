use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    wasm_utils::{compile, validate_and_instrument_for_testing},
    WasmtimeEmbedder,
};
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::BinaryEncodedWasm;

/// Enable using the same number of rayon threads that we have in production.
fn set_production_rayon_threads() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(EmbeddersConfig::default().num_rayon_compilation_threads)
        .build_global()
        .unwrap_or_else(|err| {
            eprintln!("error in ThreadPoolBuildError (it's fine if the threadpool has already been initialized): {}", err);
        });
}

/// Tuples of (benchmark_name, compilation_cost, wasm) to run compilation benchmarks on.
fn generate_binaries() -> Vec<(String, BinaryEncodedWasm)> {
    let mut result = vec![
        (
            "simple".to_string(),
            BinaryEncodedWasm::new(
                wat::parse_str(
                    r#"
			        (module
				        (import "ic0" "msg_arg_data_copy"
				        (func $ic0_msg_arg_data_copy (param i32 i32 i32)))
				        (func (export "canister_update should_fail_with_contract_violation")
				        (call $ic0_msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 0))
				        )
			        )
			        "#,
                )
                .expect("Failed to convert wat to wasm"),
            ),
        ),
        (
            "empty".to_string(),
            BinaryEncodedWasm::new(
                wat::parse_str(
                    r#"
                    (module)
			        "#,
                )
                .expect("Failed to convert wat to wasm"),
            ),
        ),
    ];

    let mut many_adds = "(module (func (export \"go\") (result i64) (i64.const 1)".to_string();
    for _ in 0..100_000 {
        many_adds.push_str("(i64.add (i64.const 1))");
    }
    many_adds.push_str("))");
    result.push((
        "many_adds".to_string(),
        BinaryEncodedWasm::new(wat::parse_str(many_adds).expect("Failed to convert wat to wasm")),
    ));

    let mut many_funcs = "(module".to_string();
    for _ in 0..EmbeddersConfig::default().max_functions {
        many_funcs.push_str("(func)");
    }
    many_funcs.push(')');
    result.push((
        "many_funcs".to_string(),
        BinaryEncodedWasm::new(wat::parse_str(many_funcs).expect("Failed to convert wat to wasm")),
    ));

    // This benchmark uses a real-world wasm which is stored as a binary file in this repo.
    let real_world_wasm =
        BinaryEncodedWasm::new(include_bytes!("test-data/user_canister_impl.wasm").to_vec());

    result.push(("real_world_wasm".to_string(), real_world_wasm));

    result
}

/// Print a table of benchmark name, compilation cost, and expected compilation
/// time.
fn print_table(data: Vec<Vec<String>>) {
    let header = vec![
        "Benchmark".to_string(),
        "Compilation Cost".to_string(),
        "Expected Compilation Time".to_string(),
    ];
    let mut full = vec![header];
    full.extend(data);
    let mut widths = vec![];
    for i in 0..3 {
        let mut width = 0;
        for row in &full {
            width = std::cmp::max(width, row[i].len())
        }
        widths.push(width);
    }

    print!("\n");
    for row in full {
        print!("| ");
        for i in 0..3 {
            let width = widths[i];
            print!("{:>width$} | ", row[i]);
        }
        print!("\n");
    }
    print!("\n");
}

/// Not really a benchmark, but this will display the compilation cost of each
/// Wasm and what it corresponds to in terms of expected compilation time (based
/// on 2B instructions per second).
fn compilation_cost(c: &mut Criterion) {
    let binaries = generate_binaries();
    let group = c.benchmark_group("compilation-cost");
    let config = EmbeddersConfig::default();

    let mut table = vec![];
    for (name, wasm) in binaries {
        let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());
        let (_, r) = compile(&embedder, &wasm);
        let r = r.expect("Failed to compile canister wasm");
        let cost = r.1.compilation_cost.get() as f64;
        let mill_instructions = cost / 1_000_000.0;
        // 2B inst/second == 2000 inst/microsecond
        let expected_comp_time = std::time::Duration::from_micros((cost / 2_000.0) as u64);

        table.push(vec![
            name,
            format!("{mill_instructions:?}M"),
            format!("{expected_comp_time:?}"),
        ]);
    }

    print_table(table);
    group.finish();
}

fn wasm_compilation(c: &mut Criterion) {
    set_production_rayon_threads();

    let binaries = generate_binaries();
    let mut group = c.benchmark_group("compilation");
    let config = EmbeddersConfig::default();
    for (name, wasm) in binaries {
        let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());

        group.bench_with_input(
            BenchmarkId::from_parameter(name.clone()),
            &(embedder, wasm),
            |b, (embedder, wasm)| {
                b.iter_with_large_drop(|| {
                    let (c, r) = compile(embedder, wasm);
                    let r = r.expect("Failed to compile canister wasm");
                    (c, r)
                })
            },
        );
    }
    group.finish();
}

fn wasm_deserialization(c: &mut Criterion) {
    set_production_rayon_threads();

    let binaries = generate_binaries();
    let mut group = c.benchmark_group("deserialization");
    for (name, wasm) in binaries {
        let config = EmbeddersConfig::default();
        let embedder = WasmtimeEmbedder::new(config, no_op_logger());
        let (_, serialized_module) = compile(&embedder, &wasm)
            .1
            .expect("Failed to compile canister wasm");
        let serialized_module_bytes = serialized_module.bytes;

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(embedder, serialized_module_bytes),
            |b, (embedder, serialized_module_bytes)| {
                b.iter_with_large_drop(|| {
                    embedder
                        .deserialize_module(serialized_module_bytes)
                        .expect("Failed to deserialize module")
                })
            },
        );
    }
    group.finish();
}

fn wasm_validation_instrumentation(c: &mut Criterion) {
    set_production_rayon_threads();

    let binaries = generate_binaries();
    let mut group = c.benchmark_group("validation-instrumentation");
    let config = EmbeddersConfig::default();
    for (name, wasm) in binaries {
        let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());

        group.bench_with_input(
            BenchmarkId::from_parameter(&name),
            &(embedder, wasm),
            |b, (embedder, wasm)| {
                b.iter_with_large_drop(|| {
                    let _ = validate_and_instrument_for_testing(embedder, wasm)
                        .expect("Failed to validate and instrument canister wasm");
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benchmarks,
    compilation_cost,
    wasm_compilation,
    wasm_deserialization,
    wasm_validation_instrumentation
);
criterion_main!(benchmarks);
