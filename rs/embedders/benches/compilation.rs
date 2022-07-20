use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ic_config::{embedders::Config as EmbeddersConfig, flag_status::FlagStatus};
use ic_embedders::{
    wasm_utils::{compile, validate_and_instrument_for_testing},
    WasmtimeEmbedder,
};
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::BinaryEncodedWasm;

/// Pairs of (benchmark_name, wasm) to run compilation benchmarks on.
fn generate_binaries() -> Vec<(String, BinaryEncodedWasm)> {
    let mut result = vec![
        (
            "simple".to_string(),
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
        BinaryEncodedWasm::new(wabt::wat2wasm(many_adds).expect("Failed to convert wat to wasm")),
    ));

    // This benchmark uses a real-world wasm which is stored as a binary file in this repo.
    let real_world_wasm =
        BinaryEncodedWasm::new(include_bytes!("test-data/user_canister_impl.wasm").to_vec());

    result.push(("real_world_wasm".to_string(), real_world_wasm));

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
    for (name, wasm) in binaries {
        let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(embedder, wasm),
            |b, (embedder, wasm)| {
                b.iter_with_large_drop(|| {
                    compile(embedder, wasm).expect("Failed to compile canister wasm")
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
    for (name, wasm) in binaries {
        let mut config = EmbeddersConfig::default();
        config.feature_flags.module_sharing = FlagStatus::Enabled;
        let embedder = WasmtimeEmbedder::new(config, no_op_logger());
        let (_, _, serialized_module) =
            compile(&embedder, &wasm).expect("Failed to compile canister wasm");
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
    for (name, wasm) in binaries {
        let embedder = WasmtimeEmbedder::new(EmbeddersConfig::default(), no_op_logger());

        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(embedder, wasm),
            |b, (embedder, wasm)| {
                b.iter_with_large_drop(|| {
                    validate_and_instrument_for_testing(embedder, wasm)
                        .expect("Failed to validate and instrument canister wasm")
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
