use assert_cmd::Command;
use predicates::prelude::*;
use regex::Regex;
use std::fs::read_to_string;
use tempfile::tempdir;

fn new_fstrim_tool_command() -> Command {
    match Command::cargo_bin("fstrim_tool") {
        // When in Cargo environment.
        Ok(cmd) => cmd,
        // When in Bazel environment
        Err(_) => Command::new("rs/ic_os/fstrim_tool/fstrim_tool_bin"),
    }
}

/// Replaces lines that contain:
/// - `fstrim_last_run_duration_milliseconds X`
/// - `fstrim_datadir_last_run_duration_milliseconds X`
///
/// with a placeholder:
/// - `fstrim_last_run_duration_milliseconds <DURATION>`
/// - `fstrim_datadir_last_run_duration_milliseconds <DURATION>`
///
/// This ensures that the duration numeric values do not cause test flakiness.
fn normalize_duration_line(input: &str) -> String {
    let re =
        Regex::new(r"(?m)^(fstrim(?:_datadir)?_last_run_duration_milliseconds)\s+\d+(\.\d+)?$")
            .unwrap();
    re.replace_all(input, "$1 <DURATION>").into_owned()
}

#[test]
fn initialize_metrics() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    new_fstrim_tool_command()
        .args([
            "--metrics",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid"),
            "--target",
            tmp_dir
                .path()
                .to_str()
                .expect("tmp_dir path should be valid"),
            "--initialize_metrics_only",
        ])
        .assert()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty())
        .success();

    let actual = read_to_string(&metrics_file).expect("reading metrics file should succeed");
    let expected = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 0
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 1
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total 0
# HELP fstrim_datadir_last_run_duration_milliseconds Duration of last run of fstrim on datadir in milliseconds
# TYPE fstrim_datadir_last_run_duration_milliseconds gauge
fstrim_datadir_last_run_duration_milliseconds 0
# HELP fstrim_datadir_last_run_success Success status of last run of fstrim on datadir (success: 1, failure: 0)
# TYPE fstrim_datadir_last_run_success gauge
fstrim_datadir_last_run_success 1
# HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir
# TYPE fstrim_datadir_runs_total counter
fstrim_datadir_runs_total 0
"#;
    assert_eq!(actual, expected);
}

#[test]
fn should_fail_but_write_metrics_if_target_not_a_directory() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    new_fstrim_tool_command()
        .args([
            "--metrics",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid"),
            "--target",
            "/not/a/directory",
        ])
        .assert()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("not a directory"))
        .failure();

    let actual = read_to_string(&metrics_file).expect("reading metrics file should succeed");
    // The command fails, so success=0, runs=1. Datadir not updated => datadir success=1, runs=0
    let expected = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 0
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 0
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total 1
# HELP fstrim_datadir_last_run_duration_milliseconds Duration of last run of fstrim on datadir in milliseconds
# TYPE fstrim_datadir_last_run_duration_milliseconds gauge
fstrim_datadir_last_run_duration_milliseconds 0
# HELP fstrim_datadir_last_run_success Success status of last run of fstrim on datadir (success: 1, failure: 0)
# TYPE fstrim_datadir_last_run_success gauge
fstrim_datadir_last_run_success 1
# HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir
# TYPE fstrim_datadir_runs_total counter
fstrim_datadir_runs_total 0
"#;

    assert_eq!(actual, expected);
}

#[test]
fn should_fail_but_writes_metrics_when_discard_not_supported() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    new_fstrim_tool_command()
        .args([
            "--metrics",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid"),
            "--target",
            tmp_dir
                .path()
                .to_str()
                .expect("tmp_dir path should be valid"),
        ])
        .assert()
        .stdout(predicate::str::is_empty())
        .stderr(
            predicate::str::contains("the discard operation is not supported")
                .or(predicate::str::contains("Operation not permitted")),
        )
        .failure();

    let actual_raw = read_to_string(&metrics_file).expect("reading metrics file should succeed");
    let actual = normalize_duration_line(&actual_raw);
    // The tool fails => success=0, runs=1. Datadir not updated => success=1, runs=0
    let expected_raw = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 2
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 0
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total 1
# HELP fstrim_datadir_last_run_duration_milliseconds Duration of last run of fstrim on datadir in milliseconds
# TYPE fstrim_datadir_last_run_duration_milliseconds gauge
fstrim_datadir_last_run_duration_milliseconds 0
# HELP fstrim_datadir_last_run_success Success status of last run of fstrim on datadir (success: 1, failure: 0)
# TYPE fstrim_datadir_last_run_success gauge
fstrim_datadir_last_run_success 1
# HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir
# TYPE fstrim_datadir_runs_total counter
fstrim_datadir_runs_total 0
"#;
    let expected = normalize_duration_line(expected_raw);

    assert_eq!(actual, expected);
}

#[test]
fn should_fail_if_arguments_missing() {
    new_fstrim_tool_command()
        .assert()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "the following required arguments were not provided",
        ))
        .failure();
}
