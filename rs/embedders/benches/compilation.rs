use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    wasm_utils::{compile, validate_and_instrument_for_testing},
    WasmtimeEmbedder,
};
use ic_logger::replica_logger::no_op_logger;
use ic_types::NumInstructions;
use ic_wasm_types::BinaryEncodedWasm;

/// Tuples of (benchmark_name, compilation_cost, wasm) to run compilation benchmarks on.
fn generate_binaries() -> Vec<(String, NumInstructions, BinaryEncodedWasm)> {
    let mut result = vec![
        (
            "simple".to_string(),
            NumInstructions::from(180_000),
            BinaryEncodedWasm::new(
                wabt::wat2wasm(
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
            NumInstructions::from(90_000),
            BinaryEncodedWasm::new(
                wabt::wat2wasm(
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
        NumInstructions::from(1_200_162_000),
        BinaryEncodedWasm::new(wabt::wat2wasm(many_adds).expect("Failed to convert wat to wasm")),
    ));

    let mut many_funcs = "(module".to_string();
    for _ in 0..EmbeddersConfig::default().max_functions {
        many_funcs.push_str("(func)");
    }
    many_funcs.push(')');
    result.push((
        "many_funcs".to_string(),
        NumInstructions::from(3_300_090_000),
        BinaryEncodedWasm::new(wabt::wat2wasm(many_funcs).expect("Failed to convert wat to wasm")),
    ));

    // This benchmark uses a real-world wasm which is stored as a binary file in this repo.
    let real_world_wasm =
        BinaryEncodedWasm::new(include_bytes!("test-data/user_canister_impl.wasm").to_vec());

    result.push((
        "real_world_wasm".to_string(),
        NumInstructions::from(12_187_254_000),
        real_world_wasm,
    ));

    result
}

fn wasm_compilation(c: &mut Criterion) {
    // Enable using less threads for the rayon wasm compilation.
    rayon::ThreadPoolBuilder::new()
        .num_threads(EmbeddersConfig::default().num_rayon_compilation_threads)
        .build_global()
        .unwrap();

    let binaries = generate_binaries();
    let mut group = c.benchmark_group("compilation");
    let mut config = EmbeddersConfig::default();
    config.feature_flags.new_wasm_transform_lib = ic_config::flag_status::FlagStatus::Disabled;
    for (name, comp_cost, wasm) in binaries {
        let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(embedder, comp_cost, wasm),
            |b, (embedder, comp_cost, wasm)| {
                b.iter_with_large_drop(|| {
                    let (c, r) = compile(embedder, wasm);
                    let r = r.expect("Failed to compile canister wasm");
                    assert_eq!(*comp_cost, r.1.compilation_cost);
                    (c, r)
                })
            },
        );
    }
    group.finish();
}

fn wasm_deserialization(c: &mut Criterion) {
    // Enable using less threads for the rayon wasm compilation.
    let _result = rayon::ThreadPoolBuilder::new()
        .num_threads(EmbeddersConfig::default().num_rayon_compilation_threads)
        .build_global()
        .unwrap_or_else(|err| {
            eprintln!("error in ThreadPoolBuildError: {}", err);
        });

    let binaries = generate_binaries();
    let mut group = c.benchmark_group("deserialization");
    for (name, comp_cost, wasm) in binaries {
        let config = EmbeddersConfig::default();
        let embedder = WasmtimeEmbedder::new(config, no_op_logger());
        let (_, serialized_module) = compile(&embedder, &wasm)
            .1
            .expect("Failed to compile canister wasm");
        assert_eq!(comp_cost, serialized_module.compilation_cost);
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
    // Enable using less threads for the rayon wasm compilation.
    let _result = rayon::ThreadPoolBuilder::new()
        .num_threads(EmbeddersConfig::default().num_rayon_compilation_threads)
        .build_global()
        .unwrap_or_else(|err| {
            eprintln!("error in ThreadPoolBuildError: {}", err);
        });

    let binaries = generate_binaries();
    let mut group = c.benchmark_group("validation-instrumentation");
    let mut config = EmbeddersConfig::default();
    config.feature_flags.new_wasm_transform_lib = ic_config::flag_status::FlagStatus::Disabled;
    for (name, comp_cost, wasm) in binaries {
        let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(embedder, comp_cost, wasm),
            |b, (embedder, comp_cost, wasm)| {
                b.iter_with_large_drop(|| {
                    let (_, instrumentation_output) =
                        validate_and_instrument_for_testing(embedder, wasm)
                            .expect("Failed to validate and instrument canister wasm");
                    assert_eq!(*comp_cost, instrumentation_output.compilation_cost);
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benchmarks,
    wasm_compilation,
    wasm_deserialization,
    wasm_validation_instrumentation
);
criterion_main!(benchmarks);
