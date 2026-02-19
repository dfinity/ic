mod utils;

use std::{fs, path::PathBuf, process::Output};
use tempfile::NamedTempFile;
use utils::BenchTest;

/// Returns the name of the current function, intended to be used in tests.
#[macro_export]
macro_rules! current_test_name {
    () => {{
        fn f() {}
        let full = std::any::type_name_of_val(&f);
        full.strip_suffix("::f")
            .and_then(|s| s.rsplit("::").next())
            .unwrap_or(full)
    }};
}

#[test]
fn overwrite_feature_must_be_disabled() {
    // Fails if the "overwrite" feature is accidentally enabled (e.g. via `--all-features` in CI).
    assert!(
        !cfg!(feature = "overwrite"),
        "'overwrite' feature must be disabled"
    );
}

/// Loads the expected output for a given test case.
/// Overwrites the expected output if the "overwrite" feature is enabled.
///
/// $ cargo test --features overwrite
fn load_expected(test_name: &str, output: &Output) -> String {
    let result = String::from_utf8_lossy(&output.stdout).to_string();
    let path = PathBuf::from(format!("./tests/expected/{test_name}.txt"));

    if cfg!(feature = "overwrite") {
        fs::write(&path, &result).unwrap_or_else(|err| {
            panic!(
                "Failed to write expected result to {}: {}",
                path.display(),
                err
            );
        });
        println!("Updated expected result: {}", path.display());
    }

    fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "Failed to read expected result from {}: {}",
            path.display(),
            err
        );
    })
}

#[test]
fn no_config_prints_error() {
    BenchTest::no_config().run(|output| {
        assert_err!(output, "canbench.yml not found in current directory.\n");
    });
}

#[test]
fn wasm_path_incorrect_prints_error() {
    BenchTest::with_config(
        "
wasm_path:
  ./wasm.wasm",
    )
    .run(|output| {
        assert_err!(
            output,
            "Couldn't read file at ./wasm.wasm. Are you sure the file exists?\n"
        );
    });
}

#[test]
fn benchmark_reports_no_changes() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("no_changes_test")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn benchmark_reports_no_changes_with_hide_results() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("no_changes_test")
        .with_hide_results()
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn broken_benchmark_returns_full_error() {
    BenchTest::canister("measurements_output")
        .with_bench("broken_benchmark")
        .run(|output| {
            assert_err!(
                output,
                "Error executing benchmark broken_benchmark. Error:
IC0506: Canister lxzze-o7777-77777-aaaaa-cai did not produce a response
"
            );
        });
}

#[test]
fn benchmark_reports_noisy_change() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("noisy_change_test")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn benchmark_reports_noisy_change_above_default_noise_threshold() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("noisy_change_above_default_threshold_test")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn benchmark_reports_noisy_change_within_custom_noise_threshold() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("noisy_change_above_default_threshold_test")
        .with_noise_threshold(5.0)
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn benchmark_reports_regression() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("regression_test")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn benchmark_reports_improvement() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("improvement_test")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn benchmark_reports_regression_from_zero() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("stable_memory_increase_from_zero")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

// Tests that only the stable memory increase is reported (as opposed to the entire
// stable memory usage.
#[test]
fn benchmark_stable_memory_increase() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("stable_memory_only_increase")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn benchmark_heap_increase() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("increase_heap_increase")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn supports_gzipped_wasm() {
    let name = current_test_name!();
    BenchTest::canister("gzipped_wasm").run(|output| {
        let expected = load_expected(name, &output);
        assert_success!(output, expected.as_str());
    });
}

#[test]
fn reports_scopes_in_new_benchmark() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("bench_scope_new")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn specifying_a_bogus_runtime_triggers_a_redownload() {
    // Create an empty file and pass it as the runtime.
    // Given that this file's digest doesn't match what canbench expects, it should fail.
    let runtime_file = NamedTempFile::new().unwrap();
    let runtime_path = runtime_file.path().to_path_buf();

    BenchTest::with_config(
        "
wasm_path:
  ./wasm.wasm",
    )
    .with_runtime_path(runtime_path.clone())
    .run(|output| {
        assert_err!(output.clone(), "Runtime has incorrect digest");
        assert_err!(output, "Runtime will be redownloaded");

        // Verify that the runtime has been redownloaded and now has the correct digest.
        let digest = sha256::try_digest(runtime_path).unwrap();

        assert_eq!(digest, canbench::expected_runtime_digest());
    });
}

#[test]
fn specifying_a_bogus_runtime_without_integrity_check() {
    // Create an empty file and pass it as the runtime.
    let runtime_file = NamedTempFile::new().unwrap();
    let runtime_path = runtime_file.path().to_path_buf();

    // Since the runtime integrity check is skipped, canbench won't report
    // a bad digest for the runtime, but will instead report that it can't
    // find the wasm.
    BenchTest::with_config(
        "
wasm_path:
  ./wasm.wasm",
    )
    .with_runtime_path(runtime_path)
    .with_no_runtime_integrity_check()
    .run(|output| {
        assert_err!(output, "Couldn't read file at ./wasm.wasm.");
    });
}

#[test]
fn reports_scopes_in_existing_benchmark() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("bench_scope_exist")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn newer_version() {
    BenchTest::canister("newer_version")
        .run(|output| {
        assert_err!(
                output,
                "canbench is at version 0.4.0 while the results were generated with version 99.0.0. Please upgrade canbench.
"
            );
        });
}

#[test]
fn benchmark_works_with_init_args() {
    let name = current_test_name!();
    BenchTest::canister("init_arg")
        .with_bench("state_check")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

// Ensures writes to stable memory are accounted for in the same way as application subnets.
#[test]
fn benchmark_stable_writes() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("write_stable_memory")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn loads_stable_memory_file() {
    BenchTest::canister("stable_memory").run(|output| {
        // There are assertions in the code of that canister itself, so
        // all is needed is to assert that the run succeeded.
        assert_eq!(output.status.code(), Some(0), "output: {:?}", output);
    });
}

#[test]
fn stable_memory_file_not_exit_prints_error() {
    BenchTest::canister("stable_memory_invalid").run(|output| {
        assert_err!(
            output,
            "
Error reading stable memory file stable_memory_does_not_exist.bin
Error: No such file or directory"
        );
    });
}

#[test]
fn shows_canister_output() {
    BenchTest::canister("debug_print")
        .with_canister_output()
        .run(|output| {
            let err_output = String::from_utf8_lossy(&output.stderr);
            assert!(err_output.contains("Hello from tests!"));
        });
}

#[test]
fn benchmark_instruction_tracing() {
    // TODO: better end-to-end testing, since this test only makes sure there is no error in
    // tracing.
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("write_stable_memory")
        .with_instruction_tracing()
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn reports_repeated_scope_in_new_benchmark() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("bench_repeated_scope_new")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn reports_repeated_scope_in_existing_benchmark() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("bench_repeated_scope_exists")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}

#[test]
fn reports_recursive_scopes_benchmark() {
    let name = current_test_name!();
    BenchTest::canister("measurements_output")
        .with_bench("bench_recursive_scopes")
        .run(|output| {
            let expected = load_expected(name, &output);
            assert_success!(output, expected.as_str());
        });
}
