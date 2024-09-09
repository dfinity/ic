use assert_cmd::Command;
use predicates::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use tempfile::tempdir;

fn new_fstrim_tool_command() -> Command {
    match Command::cargo_bin("fstrim_tool") {
        // When in Cargo environment.
        Ok(v) => v,
        // When in Bazel environment
        Err(_) => Command::new("rs/ic_os//fstrim_tool/fstrim_tool_bin"),
    }
}

fn assert_metrics_file_content(metrics_filename: &PathBuf, is_success: bool, total_runs: u32) {
    let file = File::open(metrics_filename).expect("should succeed in opening metrics file");
    let reader = BufReader::new(file);
    let lines = reader.lines();
    for (i, line) in lines.enumerate() {
        match i {
            0 => assert_eq!(
                line.unwrap(),
                "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds"
            ),
            1 => assert_eq!(
                line.unwrap(),
                "# TYPE fstrim_last_run_duration_milliseconds gauge"
            ),
            2 => assert!(line.unwrap().starts_with("fstrim_last_run_duration_milliseconds")),
            3 => assert_eq!(
                line.unwrap(), "# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)"
            ),
            4 => assert_eq!(
                line.unwrap(), "# TYPE fstrim_last_run_success gauge"
            ),
            5 => {
                let line_str = line.unwrap();
                let mut tokens = line_str.split(' ');
                assert_eq!(tokens.next().unwrap(), "fstrim_last_run_success", "{}", line_str);
                let success_str = if is_success { "1" } else { "0" };
                assert_eq!(tokens.next().unwrap(), success_str, "{}", line_str);
            },
            6 => assert_eq!(
                line.unwrap(), "# HELP fstrim_runs_total Total number of runs of fstrim"
            ),
            7 => assert_eq!(
                line.unwrap(), "# TYPE fstrim_runs_total counter"
            ),
            8 => {
                let line_str = line.unwrap();
                let mut tokens = line_str.split(' ');
                assert_eq!(tokens.next().unwrap(), "fstrim_runs_total", "{}", line_str);
                assert_eq!(tokens.next().unwrap().parse::<u32>().unwrap(), total_runs, "{}", line_str);
            },
            _ => panic!("unexpected line: {}", line.unwrap()),
        }
    }
}

#[test]
fn should_successfully_initialize_metrics_if_flag_is_set() {
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

    assert_metrics_file_content(&metrics_file, true, 0);
}

#[test]
fn should_fail_but_write_metrics_if_target_is_not_a_directory() {
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

    assert_metrics_file_content(&metrics_file, false, 1);
}

#[test]
fn should_fail_but_write_metrics_with_discard_not_supported_with_correct_parameters() {
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
        .stderr(predicate::str::contains(
            "the discard operation is not supported",
        ))
        .failure();

    assert_metrics_file_content(&metrics_file, false, 1);
}

#[test]
fn should_fail_if_arguments_missing() {
    new_fstrim_tool_command()
        .assert()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "error: the following required arguments were not provided",
        ))
        .failure();
}
