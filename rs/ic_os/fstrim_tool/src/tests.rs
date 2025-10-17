use super::*;
use assert_matches::assert_matches;
use std::fs::{read_to_string, write};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;

const EXISTING_METRICS_CONTENT: &str = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 0
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 1
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total 1
"#;

const EXISTING_METRICS_CONTENT_WITH_SPECIAL_VALUES: &str = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 0
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 1
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total +Inf
"#;

#[test]
fn parse_metrics_without_datadir_fields() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");
    write(&metrics_file, EXISTING_METRICS_CONTENT).expect("error writing to file");

    let parsed_metrics = parse_existing_metrics_from_file(
        metrics_file
            .to_str()
            .expect("should convert metrics_file path buf to str"),
    )
    .expect("parsing metrics should succeed")
    .expect("parsed metrics should be some");

    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: 0.0,
        last_run_success: true,
        total_runs: 1.0,
        last_duration_milliseconds_datadir: 0.0,
        last_run_success_datadir: true,
        total_runs_datadir: 0.0,
    };

    assert_eq!(parsed_metrics, expected_metrics);
}

#[test]
fn parse_metrics_with_datadir_fields() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    let initial_metrics = FsTrimMetrics {
        last_duration_milliseconds: 42.0,
        last_run_success: false,
        total_runs: 7.0,
        last_duration_milliseconds_datadir: 999.0,
        last_run_success_datadir: true,
        total_runs_datadir: 12.0,
    };
    write_metrics_using_tmp_file(
        &initial_metrics,
        metrics_file
            .to_str()
            .expect("metrics file path should be valid"),
    )
    .unwrap();

    let parsed_metrics = parse_existing_metrics_from_file(metrics_file.to_str().unwrap())
        .expect("parsing metrics should succeed")
        .expect("parsed metrics should be some");

    assert_eq!(parsed_metrics, initial_metrics);
}

#[test]
fn should_error_if_metrics_in_file_has_special_values() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");
    write(&metrics_file, EXISTING_METRICS_CONTENT_WITH_SPECIAL_VALUES)
        .expect("error writing to file");

    let res = parse_existing_metrics_from_file(
        metrics_file
            .to_str()
            .expect("should convert metrics_file path buf to str"),
    );
    assert_matches!(res, Err(err) if err.to_string().contains("parsed metrics are invalid"));
}

#[test]
fn write_metrics_to_file() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    let metrics = FsTrimMetrics {
        last_duration_milliseconds: 64.0,
        last_run_success: false,
        total_runs: 60.0,
        last_duration_milliseconds_datadir: 3.0,
        last_run_success_datadir: true,
        total_runs_datadir: 16.0,
    };

    write_metrics_using_tmp_file(
        &metrics,
        metrics_file
            .to_str()
            .expect("metrics file path should be valid"),
    )
    .expect("writing metrics should succeed");

    let parsed_metrics = parse_existing_metrics_from_file(
        metrics_file
            .to_str()
            .expect("should convert metrics_file path buf to str"),
    )
    .expect("parsing metrics should succeed")
    .expect("parsed metrics should be some");

    assert_eq!(parsed_metrics, metrics);
}

#[test]
fn test_update_metrics() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    let initial_metrics = FsTrimMetrics {
        last_duration_milliseconds: 0.0,
        last_run_success: true,
        total_runs: 1.0,
        last_duration_milliseconds_datadir: 0.0,
        last_run_success_datadir: true,
        total_runs_datadir: 0.0,
    };
    write_metrics_using_tmp_file(
        &initial_metrics,
        metrics_file
            .to_str()
            .expect("metrics file path should be valid"),
    )
    .unwrap();

    update_metrics(
        Duration::from_millis(151),
        true,
        metrics_file
            .to_str()
            .expect("metrics file path should be valid"),
        false,
    )
    .expect("updating metrics should succeed");

    let parsed_metrics = parse_existing_metrics_from_file(
        metrics_file
            .to_str()
            .expect("should convert metrics_file path buf to str"),
    )
    .expect("parsing metrics should succeed")
    .expect("parsed metrics should be some");

    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: 151.0,
        last_run_success: true,
        total_runs: 2.0,
        last_duration_milliseconds_datadir: 0.0,
        last_run_success_datadir: true,
        total_runs_datadir: 0.0,
    };
    assert_eq!(parsed_metrics, expected_metrics);
}

#[test]
fn update_datadir_metrics() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    let initial_metrics = FsTrimMetrics {
        last_duration_milliseconds: 0.0,
        last_run_success: true,
        total_runs: 1.0,
        last_duration_milliseconds_datadir: 0.0,
        last_run_success_datadir: true,
        total_runs_datadir: 0.0,
    };
    write_metrics_using_tmp_file(
        &initial_metrics,
        metrics_file
            .to_str()
            .expect("metrics file path should be valid"),
    )
    .unwrap();

    update_metrics(
        Duration::from_millis(501),
        false,
        metrics_file
            .to_str()
            .expect("metrics file path should be valid"),
        true,
    )
    .expect("updating datadir metrics should succeed");

    let parsed_metrics = parse_existing_metrics_from_file(
        metrics_file.to_str().expect("should convert path to str"),
    )
    .expect("parsing metrics should succeed")
    .expect("parsed metrics should be some");

    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: 0.0,
        last_run_success: true,
        total_runs: 1.0,
        last_duration_milliseconds_datadir: 501.0,
        last_run_success_datadir: false,
        total_runs_datadir: 1.0,
    };
    assert_eq!(parsed_metrics, expected_metrics);
}

#[test]
fn start_from_empty_metrics_when_file_has_special_values() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");
    write(&metrics_file, EXISTING_METRICS_CONTENT_WITH_SPECIAL_VALUES)
        .expect("error writing to file");

    update_metrics(
        Duration::from_millis(151),
        true,
        metrics_file
            .to_str()
            .expect("metrics file path should be valid"),
        false,
    )
    .expect("updating metrics should succeed");

    let parsed_metrics = parse_existing_metrics_from_file(
        metrics_file
            .to_str()
            .expect("should convert metrics_file path buf to str"),
    )
    .expect("parsing metrics should succeed")
    .expect("parsed metrics should be some");

    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: 151.0,
        last_run_success: true,
        total_runs: 1.0,
        last_duration_milliseconds_datadir: 0.0,
        last_run_success_datadir: true,
        total_runs_datadir: 0.0,
    };
    assert_eq!(parsed_metrics, expected_metrics);
}

#[test]
fn successfully_run_command() {
    run_command("true", "/").expect("running command should succeed");
}

#[test]
fn unsuccessfully_run_command() {
    let res = run_command("false", "/");
    assert_matches!(res, Err(err) if err.to_string().contains("Failed to run command"));
}

#[test]
fn command_fails_but_writes_metrics() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let tmp_dir2 = tempdir().expect("temp dir creation should succeed");

    let metrics_file = tmp_dir.path().join("fstrim.prom");

    // This should fail to run the command, but still write updated metrics
    assert_matches!(
        fstrim_tool(
            "/non/existent/command",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid")
                .to_string(),
            tmp_dir
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
            false,
            tmp_dir2
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
        ),
        Err(err)
        if err.to_string().contains("Failed to run command")
    );

    // Verify that the metrics were written with success=0, total_runs=1, etc.
    let parsed_metrics =
        parse_existing_metrics_from_file(metrics_file.to_str().expect("valid path"))
            .expect("parsing metrics should succeed")
            .expect("parsed metrics should be some");

    assert!(!parsed_metrics.last_run_success);
    assert_eq!(parsed_metrics.total_runs, 1.0);
    assert!(!parsed_metrics.last_run_success_datadir);
    assert_eq!(parsed_metrics.total_runs_datadir, 1.0);
}

#[test]
fn fails_if_command_cannot_be_run() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let tmp_dir2 = tempdir().expect("temp dir creation should succeed");

    let metrics_file = tmp_dir.path().join("fstrim.prom");
    assert_matches!(
        fstrim_tool(
            "/non/existent/command",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid")
                .to_string(),
            tmp_dir
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
            false,
            tmp_dir2
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
        ),
        Err(err)
        if err.to_string().contains("Failed to run command")
    );
}

#[test]
fn init_flag() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let tmp_dir2 = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    assert!(
        fstrim_tool(
            "/non/existent/command",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid")
                .to_string(),
            tmp_dir
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
            true, //init should write out default metrics even though the command fails
            tmp_dir2
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
        )
        .is_ok()
    );

    let parsed_metrics =
        parse_existing_metrics_from_file(metrics_file.to_str().expect("valid path"))
            .expect("parsing metrics should succeed")
            .expect("parsed metrics should be some");

    assert_eq!(parsed_metrics, FsTrimMetrics::default());
}

#[test]
fn init_flag_does_not_overwrite_existing_metrics() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let tmp_dir2 = tempdir().expect("temp dir creation should succeed");

    let metrics_file = tmp_dir.path().join("fstrim.prom");
    assert!(
        fstrim_tool(
            "true",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid")
                .to_string(),
            tmp_dir
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
            false,
            tmp_dir2
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
        )
        .is_ok()
    );

    assert!(
        fstrim_tool(
            "true",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid")
                .to_string(),
            tmp_dir
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
            true,
            tmp_dir2
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
        )
        .is_ok()
    );

    let content = read_to_string(&metrics_file).expect("reading metrics should succeed");
    assert!(content.contains("fstrim_runs_total 1"));
}

#[test]
fn should_fail_if_metrics_file_cannot_be_written() {
    let metrics_file = PathBuf::from("/non/existent/directory/fstrim.prom");
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let tmp_dir2 = tempdir().expect("temp dir creation should succeed");

    assert_matches!(
        fstrim_tool(
            "true",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid")
                .to_string(),
            tmp_dir
                .path()
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
            false,
            tmp_dir2
            .path()
            .to_str()
            .expect("tmp_dir path should be valid")
            .to_string(),
        ),
        Err(err)
        if err.to_string().contains("Failed to write metrics to file")
    );
}

#[test]
fn should_fail_if_target_is_not_a_directory() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let tmp_dir2 = tempdir().expect("temp dir creation should succeed");

    let metrics_file = tmp_dir.path().join("fstrim.prom");
    let target = PathBuf::from("/non/existent/target/directory");
    let expected_error = format!("Target {} is not a directory", target.to_str().unwrap());

    assert_matches!(
        fstrim_tool(
            "true",
            metrics_file
                .to_str()
                .expect("metrics file path should be valid")
                .to_string(),
            target
                .to_str()
                .expect("tmp_dir path should be valid")
                .to_string(),
            false,
            tmp_dir2
            .path()
            .to_str()
            .expect("tmp_dir path should be valid")
            .to_string(),
        ),
        Err(err)
        if err.to_string() == expected_error
    );
}
