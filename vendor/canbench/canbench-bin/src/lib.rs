//! A module for running benchmarks.
mod csv_file;
mod data;
mod fmt;
mod instruction_tracing;
mod print_benchmark;
mod results_file;
mod summary;
mod table;

use canbench_rs::{BenchResult, Measurement};
use candid::{Encode, Principal};
use flate2::read::GzDecoder;
use instruction_tracing::{prepare_instruction_tracing, write_traces_to_file};
use pocket_ic::common::rest::BlobCompression;
use pocket_ic::{PocketIc, PocketIcBuilder};
use print_benchmark::print_benchmark;
use results_file::VersionError;
use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};
use wasmparser::Parser as WasmParser;

// The prefix benchmarks are expected to have in their name.
// Other queries exposed by the canister are ignored.
const BENCH_PREFIX: &str = "__canbench__";

const POCKET_IC_SERVER_VERSION: &str = "10.0.0";
const POCKET_IC_LINUX_SHA: &str =
    "bfc17d1acad243841121eee5347dd7453e0d8a8f8f6e090c261fae17523c3144";
const POCKET_IC_MAC_SHA: &str = "fb4a30d3d076411ea9b40f5219d75014ffa05465807c1d32fe86cda481133c65";

/// The maximum number of rows to display in the summary table.
const MAX_DISPLAYED_ROWS: usize = 50;

/// Runs the benchmarks on the canister available in the provided `canister_wasm_path`.
#[allow(clippy::too_many_arguments)]
pub fn run_benchmarks(
    canister_wasm_path: &PathBuf,
    pattern: Option<String>,
    init_args: Vec<u8>,
    persist: bool,
    csv: bool,
    results_file: &PathBuf,
    csv_results_file: &PathBuf,
    verbose: bool,
    show_results: bool,
    show_summary: bool,
    show_canister_output: bool,
    integrity_check: bool,
    instruction_tracing: bool,
    runtime_path: &PathBuf,
    stable_memory_path: Option<PathBuf>,
    noise_threshold: f64,
) {
    maybe_download_pocket_ic(runtime_path, verbose, integrity_check);

    let old_results = match results_file::read(results_file) {
        Ok(old_results) => old_results,
        Err(VersionError {
            our_version,
            their_version,
        }) => {
            eprintln!("canbench is at version {our_version} while the results were generated with version {their_version}. Please upgrade canbench.");
            std::process::exit(1);
        }
    };

    let benchmark_wasm = read_wasm(canister_wasm_path);

    // Extract the benchmark functions in the Wasm.
    let benchmark_fns = extract_benchmark_fns(&benchmark_wasm);

    let (instruction_tracing_wasm, function_names_mapping) = if instruction_tracing {
        let (instruction_tracing_wasm, function_names_mapping) =
            prepare_instruction_tracing(&benchmark_wasm);
        (Some(instruction_tracing_wasm), Some(function_names_mapping))
    } else {
        (None, None)
    };

    // Initialize PocketIC
    let (pocket_ic, benchmark_canister_id, instruction_tracing_canister_id) = init_pocket_ic(
        runtime_path,
        benchmark_wasm,
        instruction_tracing_wasm,
        stable_memory_path,
        init_args,
        show_canister_output,
    );

    // Run the benchmarks
    let mut new_results = BTreeMap::new();
    for bench_fn in &benchmark_fns {
        if let Some(pattern) = &pattern {
            if !bench_fn.contains(pattern) {
                continue;
            }
        }

        let result = run_benchmark(&pocket_ic, benchmark_canister_id, bench_fn);

        if show_results {
            println!("---------------------------------------------------");
            println!();
            print_benchmark(
                bench_fn,
                &result,
                old_results.get(bench_fn),
                noise_threshold,
            );
        }

        if let Some(instruction_tracing_canister_id) = instruction_tracing_canister_id {
            run_instruction_tracing(
                &pocket_ic,
                instruction_tracing_canister_id,
                bench_fn,
                function_names_mapping.as_ref().unwrap(),
                results_file,
                result.total.instructions,
            );
        }

        new_results.insert(bench_fn.to_string(), result);

        if show_results {
            println!();
        }
    }

    println!("---------------------------------------------------");

    let data = data::extract(&new_results, &old_results);
    if verbose || show_summary {
        println!();
        summary::print_summary(&data, noise_threshold);
        println!();
        println!("---------------------------------------------------");

        let filtered = table::filter_entries(&data, noise_threshold);
        if !filtered.is_empty() {
            println!();
            println!("Only significant changes:");
            table::print_table(&mut std::io::stdout(), &filtered, MAX_DISPLAYED_ROWS).unwrap();
            println!();
            println!("---------------------------------------------------");
        }
    }

    // Save benchmark results in CSV format if requested.
    if csv {
        let mut file = std::fs::File::create(csv_results_file).unwrap_or_else(|_| {
            panic!(
                "Failed to create results file: {}",
                csv_results_file.display()
            )
        });
        csv_file::write(&mut file, &data).unwrap_or_else(|_| {
            panic!(
                "Failed to write CSV results to: {}",
                csv_results_file.display()
            )
        });
        println!("CSV results saved to {}", csv_results_file.display());
    }

    // Persist the result if requested.
    if persist {
        results_file::write(results_file, new_results);
        println!(
            "Successfully persisted results to {}",
            results_file.display()
        );
    }
}

// Downloads PocketIC if it's not already downloaded.
fn maybe_download_pocket_ic(path: &PathBuf, verbose: bool, integrity_check: bool) {
    match (path.exists(), integrity_check) {
        (true, true) => {
            // Verify that it's the version we expect it to be.

            let pocket_ic_sha = sha256::try_digest(path).unwrap();
            let expected_sha = expected_runtime_digest();

            if pocket_ic_sha != expected_sha {
                eprintln!(
                    "Runtime has incorrect digest. Expected: {}, actual: {}",
                    expected_sha, pocket_ic_sha
                );
                eprintln!("Runtime will be redownloaded...");
                download_pocket_ic(path, verbose);
            }
        }
        (true, false) => {} // Nothing to do
        (false, _) => {
            // Pocket IC not present. Download it.
            download_pocket_ic(path, verbose);
        }
    }
}

fn download_pocket_ic(path: &PathBuf, verbose: bool) {
    let pocket_ic_url_prefix: &str = &format!(
        "https://github.com/dfinity/pocketic/releases/download/{}/pocket-ic-x86_64-",
        POCKET_IC_SERVER_VERSION
    );
    if verbose {
        println!("Downloading runtime (will be cached for future uses)...");
    }

    // Create the canbench directory if it doesn't exist.
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        panic!("Unsupported operating system");
    };

    let url = format!("{}{}.gz", pocket_ic_url_prefix, os);
    let pocket_ic_compressed = reqwest::blocking::get(url)
        .unwrap()
        .bytes()
        .expect("Failed to download PocketIC");

    let mut decoder = GzDecoder::new(&pocket_ic_compressed[..]);
    let mut file = File::create(path).expect("Failed to create PocketIC file");

    std::io::copy(&mut decoder, &mut file).expect("Failed to write PocketIC file");
    // Make the file executable.
    Command::new("chmod").arg("+x").arg(path).status().unwrap();
}

// Runs the given benchmark.
fn run_benchmark(pocket_ic: &PocketIc, canister_id: Principal, bench_fn: &str) -> BenchResult {
    match pocket_ic.query_call(
        canister_id,
        Principal::anonymous(),
        &format!("{}{}", BENCH_PREFIX, bench_fn),
        Encode!(&()).unwrap(),
    ) {
        Ok(reply) => {
            let res: BenchResult =
                candid::decode_one(&reply).expect("error decoding benchmark result");
            res
        }
        Err(reject_response) => {
            eprintln!(
                "Error executing benchmark {}. Error:\n{}: {}",
                bench_fn, reject_response.error_code, reject_response.reject_message
            );
            std::process::exit(1);
        }
    }
}

fn run_instruction_tracing(
    pocket_ic: &PocketIc,
    canister_id: Principal,
    bench_fn: &str,
    names_mapping: &BTreeMap<i32, String>,
    results_file: &Path,
    bench_instructions: u64,
) {
    let traces: Result<Vec<(i32, i64)>, String> = match pocket_ic.query_call(
        canister_id,
        Principal::anonymous(),
        &format!("__tracing__{bench_fn}"),
        Encode!(&bench_instructions).unwrap(),
    ) {
        Ok(reply) => {
            let res: Result<Vec<(i32, i64)>, String> =
                candid::decode_one(&reply).expect("error decoding tracing result");
            res
        }
        Err(reject_response) => {
            eprintln!(
                "Error tracing benchmark {}. Error:\n{}: {}",
                bench_fn, reject_response.error_code, reject_response.reject_message
            );
            std::process::exit(1);
        }
    };
    match traces {
        Ok(traces) => write_traces_to_file(
            traces,
            names_mapping,
            bench_fn,
            results_file.with_file_name(format!("{bench_fn}.svg")),
        )
        .expect("failed to write tracing results"),
        Err(e) => {
            eprint!("Error tracing benchmark {}. Error:\n{}", bench_fn, e);
        }
    }
}

fn read_wasm(canister_wasm_path: &PathBuf) -> Vec<u8> {
    // Parse the canister's wasm.
    let wasm = std::fs::read(canister_wasm_path).unwrap_or_else(|_| {
        eprintln!(
            "Couldn't read file at {}. Are you sure the file exists?",
            canister_wasm_path.display()
        );
        std::process::exit(1);
    });

    // Decompress the wasm if it's gzipped.
    match canister_wasm_path.extension().unwrap().to_str() {
        Some("gz") => {
            // Decompress the wasm if it's gzipped.
            let mut decoder = GzDecoder::new(&wasm[..]);
            let mut decompressed_wasm = vec![];
            decoder.read_to_end(&mut decompressed_wasm).unwrap();
            decompressed_wasm
        }
        _ => wasm,
    }
}

// Extract the benchmarks that need to be run.
fn extract_benchmark_fns(wasm: &[u8]) -> Vec<String> {
    let prefix = format!("canister_query {BENCH_PREFIX}");

    WasmParser::new(0)
        .parse_all(wasm)
        .filter_map(|section| match section {
            Ok(wasmparser::Payload::ExportSection(export_section)) => {
                let queries: Vec<_> = export_section
                    .into_iter()
                    .filter_map(|export| {
                        if let Ok(export) = export {
                            if export.name.starts_with(&prefix) {
                                return Some(
                                    export
                                        .name
                                        .split(&prefix)
                                        .last()
                                        .expect("query must have a name.")
                                        .to_string(),
                                );
                            }
                        }

                        None
                    })
                    .collect();

                Some(queries)
            }
            _ => None,
        })
        .flatten()
        .collect()
}

// Sets the environment variable to the target value if it's not already set.
fn set_env_var_if_unset(key: &str, target_value: &str) {
    if std::env::var(key).is_err() {
        std::env::set_var(key, target_value);
    }
}

// Initializes PocketIC and installs the canister to benchmark.
fn init_pocket_ic(
    path: &PathBuf,
    benchmark_wasm: Vec<u8>,
    instruction_tracing_wasm: Option<Vec<u8>>,
    stable_memory_path: Option<PathBuf>,
    init_args: Vec<u8>,
    show_canister_output: bool,
) -> (PocketIc, Principal, Option<Principal>) {
    // PocketIC is used for running the benchmark.
    // Set the appropriate ENV variables
    std::env::set_var("POCKET_IC_BIN", path);
    if !show_canister_output {
        set_env_var_if_unset("POCKET_IC_MUTE_SERVER", "1");
    }
    let pocket_ic = PocketIcBuilder::new()
        .with_max_request_time_ms(None)
        .with_benchmarking_application_subnet()
        .build();

    let stable_memory = stable_memory_path.map(|path| match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("Error reading stable memory file {}", path.display());
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
    });

    let instruction_tracing_canister_id = instruction_tracing_wasm
        .map(|wasm| init_canister(&pocket_ic, wasm, init_args.clone(), stable_memory.clone()));
    let benchmark_canister_id = init_canister(&pocket_ic, benchmark_wasm, init_args, stable_memory);

    (
        pocket_ic,
        benchmark_canister_id,
        instruction_tracing_canister_id,
    )
}

fn init_canister(
    pocket_ic: &PocketIc,
    wasm: Vec<u8>,
    init_args: Vec<u8>,
    stable_memory: Option<Vec<u8>>,
) -> Principal {
    let canister_id = pocket_ic.create_canister();
    pocket_ic.add_cycles(canister_id, 1_000_000_000_000_000);
    pocket_ic.install_canister(canister_id, wasm, init_args, None);
    // Load the canister's stable memory if stable memory is specified.
    if let Some(stable_memory) = stable_memory {
        pocket_ic.set_stable_memory(canister_id, stable_memory, BlobCompression::NoCompression);
    }
    canister_id
}

// Public only for tests.
#[doc(hidden)]
pub fn expected_runtime_digest() -> &'static str {
    match env::consts::OS {
        "linux" => POCKET_IC_LINUX_SHA,
        "macos" => POCKET_IC_MAC_SHA,
        _ => panic!("only linux and macos are currently supported."),
    }
}
