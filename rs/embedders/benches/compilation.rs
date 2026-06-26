//! This benchmark runs nightly in CI, and the results are available in Grafana.
//! See: `schedule-rust-bench.yml`
//!
//! To run the benchmark locally:
//!
//! ```shell
//! bazel run //rs/embedders:compilation_bench
//! ```

use candid::Encode;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use embedders_bench::SetupAction;
use ic_config::embedders::Config as EmbeddersConfig;
use ic_embedders::{
    CompilationResult, SerializedModule, WasmtimeEmbedder,
    wasm_utils::{compile, validate_and_instrument_for_testing},
};
use ic_logger::replica_logger::no_op_logger;
use ic_wasm_types::BinaryEncodedWasm;
use std::io::Read;
use std::sync::OnceLock;

lazy_static::lazy_static! {
    static ref GOVERNANCE_BENCH_CANISTER: Vec<u8> =
        canister_test::Project::cargo_bin_maybe_from_env("governance-bench-canister", &[]).bytes();
}

/// Enable using the same number of rayon threads that we have in production.
fn set_production_rayon_threads() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(EmbeddersConfig::default().num_rayon_compilation_threads)
        .build_global()
        .unwrap_or_else(|err| {
            eprintln!("error in ThreadPoolBuildError (it's fine if the threadpool has already been initialized): {err}");
        });
}

/// Unzip a the bytes before converting to a binary encoded Wasm.
fn unzip_wasm(bytes: &[u8]) -> BinaryEncodedWasm {
    let mut decoder = libflate::gzip::Decoder::new(bytes).unwrap();
    let mut buf = vec![];
    decoder.read_to_end(&mut buf).unwrap();
    BinaryEncodedWasm::new(buf)
}

/// A Wasm binary used by the compilation benchmarks, together with a slot for
/// lazily caching its compilation output so that benchmarks that only need the
/// result of compilation (but don't measure compilation itself) can avoid
/// recompiling.
struct Binary {
    name: String,
    wasm: BinaryEncodedWasm,
    compiled: OnceLock<(CompilationResult, SerializedModule)>,
}

impl Binary {
    fn new(name: &str, wasm: BinaryEncodedWasm) -> Self {
        Self {
            name: name.to_string(),
            wasm,
            compiled: OnceLock::new(),
        }
    }

    /// Returns the compiled artifact for this binary, compiling it on first
    /// access and caching the result for subsequent calls. Benchmarks that are
    /// measuring compilation time must not call this — they should compile
    /// `&self.wasm` directly inside the benchmark loop.
    fn compiled(&self) -> &(CompilationResult, SerializedModule) {
        self.compiled.get_or_init(|| {
            let config = EmbeddersConfig::default();
            let embedder = WasmtimeEmbedder::new(config, no_op_logger());
            compile(&embedder, &self.wasm)
                .1
                .expect("Failed to compile canister wasm")
        })
    }
}

/// Tuples of (benchmark_name, compilation_cost, wasm) to run compilation benchmarks on.
fn generate_binaries() -> Vec<Binary> {
    let mut result = vec![Binary::new(
        "minimal",
        BinaryEncodedWasm::new(
            wat::parse_str(
                r#"
			        (module
				        (import "ic0" "msg_reply" (func $ic0_msg_reply))
                        (func (export "canister_update update_empty")
                            (call $ic0_msg_reply)
                        )
                        (func (export "canister_query go")
                            (call $ic0_msg_reply)
                        )
			        )
			        "#,
            )
            .expect("Failed to convert wat to wasm"),
        ),
    )];

    let mut many_adds = r#"
        (module
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (func (export "canister_update update_empty")
                (call $ic0_msg_reply)
            )
            (func (export "canister_query go") (i64.const 1)"#
        .to_string();
    for _ in 0..100_000 {
        many_adds.push_str("(i64.add (i64.const 1))");
    }
    many_adds.push_str("(drop) (call $ic0_msg_reply)))");
    result.push(Binary::new(
        "many_adds",
        BinaryEncodedWasm::new(wat::parse_str(many_adds).expect("Failed to convert wat to wasm")),
    ));

    let mut many_funcs = r#"
        (module
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (func (export "canister_update update_empty")
                (call $ic0_msg_reply)
            )
            (func (export "canister_query go")
                (call $ic0_msg_reply)
            )
        "#
    .to_string();
    for _ in 0..EmbeddersConfig::default().max_functions - 2 {
        many_funcs.push_str("(func)");
    }
    many_funcs.push(')');
    result.push(Binary::new(
        "many_funcs",
        BinaryEncodedWasm::new(wat::parse_str(many_funcs).expect("Failed to convert wat to wasm")),
    ));

    // This benchmark uses the open chat user canister which is stored as a
    // binary file in this repo.  It is generated from
    // https://github.com/dfinity/open-chat/tree/abk/for-replica-benchmarking
    let open_chat_wasm = unzip_wasm(&include_bytes!("test-data/user.wasm.gz")[..]);
    result.push(Binary::new("open_chat", open_chat_wasm));

    // This benchmark uses the QR code generator canister which is stored as a
    // binary file in this repo.  It is generated from the directory
    // `rust/qrcode` in
    // https://github.com/dfinity/examples/tree/abk/for-replica-benchmarking
    let qrcode_wasm = unzip_wasm(&include_bytes!("test-data/qrcode_backend.wasm.gz")[..]);
    result.push(Binary::new("qrcode", qrcode_wasm));

    // This benchmark uses a canister from the motoko playground which is stored
    // as a binary file in this repo.  It is generated from
    // https://github.com/dfinity/motoko-playground/tree/abk/for-replica-benchmarking
    let motoko_wasm = BinaryEncodedWasm::new(include_bytes!("test-data/pool.wasm").to_vec());
    result.push(Binary::new("motoko", motoko_wasm));

    let governance_wasm = unzip_wasm(&GOVERNANCE_BENCH_CANISTER[..]);
    result.push(Binary::new("governance", governance_wasm));

    result
}

/// Returns the generated binaries, producing them on first access and caching
/// the result so that subsequent benchmarks reuse the same Wasm artifacts.
/// The raw Wasm bytes are always shared; the compiled artifact is cached
/// lazily per binary via `Binary::compiled` and only used by benchmarks that
/// don't measure compilation themselves.
fn get_binaries() -> &'static [Binary] {
    static BINARIES: OnceLock<Vec<Binary>> = OnceLock::new();
    BINARIES.get_or_init(generate_binaries)
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

    println!();
    for row in full {
        print!("| ");
        for i in 0..3 {
            let width = widths[i];
            print!("{:>width$} | ", row[i]);
        }
        println!();
    }
    println!();
}

/// Not really a benchmark, but this will display the compilation cost of each
/// Wasm and what it corresponds to in terms of expected compilation time (based
/// on 2B instructions per second).
fn compilation_cost(c: &mut Criterion) {
    let binaries = get_binaries();
    let group = c.benchmark_group("embedders:compilation/compilation-cost");

    let mut table = vec![];
    for binary in binaries {
        let (_, serialized) = binary.compiled();
        let cost = serialized.compilation_cost.get() as f64;
        let mill_instructions = cost / 1_000_000.0;
        // 2B inst/second == 2000 inst/microsecond
        let expected_comp_time = std::time::Duration::from_micros((cost / 2_000.0) as u64);

        table.push(vec![
            binary.name.clone(),
            format!("{mill_instructions:?}M"),
            format!("{expected_comp_time:?}"),
        ]);
    }

    print_table(table);
    group.finish();
}

fn wasm_compilation(c: &mut Criterion) {
    set_production_rayon_threads();

    let binaries = get_binaries();
    let mut group = c.benchmark_group("embedders:compilation/compilation");
    let config = EmbeddersConfig::default();
    for binary in binaries {
        let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());

        // Intentionally compile `binary.wasm` directly (not `binary.compiled()`)
        // so that this benchmark measures compilation from scratch. As a side
        // effect, the first compile populates the shared compilation cache so
        // later benchmarks in this binary can reuse it.
        group.bench_with_input(
            BenchmarkId::from_parameter(&binary.name),
            &(embedder, &binary.wasm),
            |b, (embedder, wasm)| {
                b.iter_with_large_drop(|| {
                    let (c, r) = compile(embedder, wasm);
                    let r = r.expect("Failed to compile canister wasm");
                    if binary.compiled.get().is_none() {
                        let _ = binary.compiled.set(r.clone());
                    }
                    (c, r)
                })
            },
        );
    }
    group.finish();
}

fn wasm_deserialization(c: &mut Criterion) {
    set_production_rayon_threads();

    let binaries = get_binaries();
    let mut group = c.benchmark_group("embedders:compilation/deserialization");
    for binary in binaries {
        let config = EmbeddersConfig::default();
        let embedder = WasmtimeEmbedder::new(config, no_op_logger());
        let serialized_module_bytes = &binary.compiled().1.bytes;

        group.bench_with_input(
            BenchmarkId::from_parameter(&binary.name),
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

    let binaries = get_binaries();
    let mut group = c.benchmark_group("embedders:compilation/validation-instrumentation");
    let config = EmbeddersConfig::default();
    for binary in binaries {
        let embedder = WasmtimeEmbedder::new(config.clone(), no_op_logger());

        group.bench_with_input(
            BenchmarkId::from_parameter(&binary.name),
            &(embedder, &binary.wasm),
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

fn execution(c: &mut Criterion) {
    set_production_rayon_threads();

    let binaries = get_binaries();
    for binary in binaries {
        let (_, serialized_module) = binary.compiled();
        embedders_bench::query_bench_with_precompiled_module(
            c,
            "embedders:compilation/query",
            &binary.name,
            binary.wasm.as_slice(),
            &Encode!(&()).unwrap(),
            "go",
            &Encode!(&()).unwrap(),
            None,
            SetupAction::None,
            serialized_module,
        );
    }
}

criterion_group! {
    name = benchmarks;
    config = Criterion::default().sample_size(10);
    // `wasm_compilation` is listed first so that its bench body can populate
    // `Binary::compiled`, letting the remaining benchmarks reuse it instead
    // of recompiling.
    targets = wasm_compilation, compilation_cost, wasm_deserialization,
        wasm_validation_instrumentation, execution
}
criterion_main!(benchmarks);
