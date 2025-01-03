use assert_cmd::Command;
use predicates::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use tempfile::tempdir;

fn new_fstrim_tool_command() -> Command {
    match Command::cargo_bin("fstrim_tool") {
        // When in Cargo environment.
        Ok(cmd) => cmd,
        // When in Bazel environment
        Err(_) => Command::new("rs/ic_os/fstrim_tool/fstrim_tool_bin"),
    }
}

fn assert_metrics_file_content(
    metrics_filename: &PathBuf,
    is_success: bool,
    total_runs: u32,
    datadir_is_success: bool,
    datadir_total_runs: u32,
) {
    let file = File::open(metrics_filename).expect("should succeed in opening metrics file");
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader
        .lines()
        .collect::<Result<Vec<_>, _>>()
        .expect("failed to read lines from metrics file");

    // We expect 18 lines total:
    //   0..2:   last_run_duration (HELP/TYPE/value)
    //   3..5:   last_run_success (HELP/TYPE/value)
    //   6..8:   runs_total       (HELP/TYPE/value)
    //   9..11:  datadir_last_run_duration (HELP/TYPE/value)
    //   12..14: datadir_last_run_success  (HELP/TYPE/value)
    //   15..17: datadir_runs_total        (HELP/TYPE/value)

    // Lines 0..2: fstrim_last_run_duration_milliseconds
    assert_eq!(
        lines[0],
        "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds"
    );
    assert_eq!(
        lines[1],
        "# TYPE fstrim_last_run_duration_milliseconds gauge"
    );
    assert!(lines[2].starts_with("fstrim_last_run_duration_milliseconds"));

    // Lines 3..5: fstrim_last_run_success
    assert_eq!(
        lines[3],
        "# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)"
    );
    assert_eq!(lines[4], "# TYPE fstrim_last_run_success gauge");
    let success_line = &lines[5];
    {
        let mut tokens = success_line.split(' ');
        assert_eq!(
            tokens.next().unwrap(),
            "fstrim_last_run_success",
            "{}",
            success_line
        );
        let success_str = if is_success { "1" } else { "0" };
        assert_eq!(
            tokens.next().unwrap(),
            success_str,
            "line[5]: {}",
            success_line
        );
    }

    // Lines 6..8: fstrim_runs_total
    assert_eq!(
        lines[6],
        "# HELP fstrim_runs_total Total number of runs of fstrim"
    );
    assert_eq!(lines[7], "# TYPE fstrim_runs_total counter");
    let runs_line = &lines[8];
    {
        let mut tokens = runs_line.split(' ');
        assert_eq!(tokens.next().unwrap(), "fstrim_runs_total");
        let found_total = tokens.next().unwrap().parse::<u32>().unwrap();
        assert_eq!(
            found_total, total_runs,
            "mismatch on normal runs_total in line[8]: {}",
            runs_line
        );
    }

    // Lines 9..11: fstrim_datadir_last_run_duration_milliseconds
    assert_eq!(
        lines[9],
        "# HELP fstrim_datadir_last_run_duration_milliseconds Duration of last run of fstrim on datadir in milliseconds"
    );
    assert_eq!(
        lines[10],
        "# TYPE fstrim_datadir_last_run_duration_milliseconds gauge"
    );
    assert!(lines[11].starts_with("fstrim_datadir_last_run_duration_milliseconds"));

    // Lines 12..14: fstrim_datadir_last_run_success
    assert_eq!(
        lines[12],
        "# HELP fstrim_datadir_last_run_success Success status of last run of fstrim on datadir (success: 1, failure: 0)"
    );
    assert_eq!(lines[13], "# TYPE fstrim_datadir_last_run_success gauge");
    let datadir_success_line = &lines[14];
    {
        let mut tokens = datadir_success_line.split(' ');
        assert_eq!(
            tokens.next().unwrap(),
            "fstrim_datadir_last_run_success",
            "{}",
            datadir_success_line
        );
        let success_str = if datadir_is_success { "1" } else { "0" };
        assert_eq!(
            tokens.next().unwrap(),
            success_str,
            "line[14]: {}",
            datadir_success_line
        );
    }

    // Lines 15..17: fstrim_datadir_runs_total
    assert_eq!(
        lines[15],
        "# HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir"
    );
    assert_eq!(lines[16], "# TYPE fstrim_datadir_runs_total counter");
    let datadir_runs_line = &lines[17];
    {
        let mut tokens = datadir_runs_line.split(' ');
        assert_eq!(tokens.next().unwrap(), "fstrim_datadir_runs_total");
        let found_total = tokens.next().unwrap().parse::<u32>().unwrap();
        assert_eq!(
            found_total, datadir_total_runs,
            "mismatch on datadir runs_total in line[17]: {}",
            datadir_runs_line
        );
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

    assert_metrics_file_content(&metrics_file, true, 0, true, 0);
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

    // The command fails, so success=0, runs=1. Datadir not updated => datadir success=1, runs=0 by default
    assert_metrics_file_content(&metrics_file, false, 1, true, 0);
}

// This fails if not tested under root user as the successful execution of the 1st target calls fstrim
// #[test]
// fn should_fail_but_write_metrics_if_data_target_is_not_a_directory() {
//     let tmp_dir = tempdir().expect("temp dir creation should succeed");
//     let metrics_file = tmp_dir.path().join("fstrim.prom");
//     new_fstrim_tool_command()
//         .args([
//             "--metrics",
//             metrics_file
//                 .to_str()
//                 .expect("metrics file path should be valid"),
//             "--target",
//             tmp_dir
//                 .path()
//                 .to_str()
//                 .expect("tmp_dir path should be valid"),
//             "--datadir_target",
//             "/not/a/directory",
//         ])
//         .assert()
//         .stdout(predicate::str::is_empty())
//         .stderr(predicate::str::contains("not a directory"))
//         .failure();
//
//     // The first target is valid, so normal metrics are updated as success => success=1, runs=1
//     // The datadir target fails => datadir success=0, runs=1
//     assert_metrics_file_content(&metrics_file, true, 1, false, 1);
// }

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
        .stderr(
            predicate::str::contains("the discard operation is not supported")
                .or(predicate::str::contains("Operation not permitted")),
        )
        .failure();

    // The tool fails => success=0, runs=1. Datadir not updated => success=1, runs=0
    assert_metrics_file_content(&metrics_file, false, 1, true, 0);
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
