use super::*;
use assert_matches::assert_matches;
use regex::Regex;
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

const EXISTING_METRICS_WITH_DATADIR: &str = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 42
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 0
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total 7
# HELP fstrim_datadir_last_run_duration_milliseconds Duration of last run of fstrim on datadir in milliseconds
# TYPE fstrim_datadir_last_run_duration_milliseconds gauge
fstrim_datadir_last_run_duration_milliseconds 999
# HELP fstrim_datadir_last_run_success Success status of last run of fstrim on datadir (success: 1, failure: 0)
# TYPE fstrim_datadir_last_run_success gauge
fstrim_datadir_last_run_success 1
# HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir
# TYPE fstrim_datadir_runs_total counter
fstrim_datadir_runs_total 12
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

/// Replaces lines that contain:
/// - `fstrim_last_run_duration_milliseconds X`
/// - `fstrim_datadir_last_run_duration_milliseconds X`
///
/// with a placeholder:
/// - `fstrim_last_run_duration_milliseconds <DURATION>`
/// - `fstrim_datadir_last_run_duration_milliseconds <DURATION>`
///
/// This ensures that numeric values (e.g., durations) do not cause test flakiness.
fn normalize_duration_line(input: &str) -> String {
    let re =
        Regex::new(r"(?m)^(fstrim(?:_datadir)?_last_run_duration_milliseconds)\s+\d+(\.\d+)?$")
            .unwrap();
    re.replace_all(input, "$1 <DURATION>").into_owned()
}

#[test]
fn should_parse_metrics_without_datadir_fields() {
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

    let actual_str = parsed_metrics.to_p8s_metrics_string();
    let expected_str = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 0
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 1
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
    assert_eq!(actual_str, expected_str);
}

#[test]
fn should_parse_metrics_with_datadir_fields() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");
    write(&metrics_file, EXISTING_METRICS_WITH_DATADIR).expect("error writing to file");

    let parsed_metrics = parse_existing_metrics_from_file(
        metrics_file
            .to_str()
            .expect("should convert path buf to str"),
    )
    .expect("parsing metrics should succeed")
    .expect("parsed metrics should be some");

    let actual_str = parsed_metrics.to_p8s_metrics_string();
    assert_eq!(actual_str, EXISTING_METRICS_WITH_DATADIR);
}

#[test]
fn should_return_error_if_metrics_in_file_contain_special_values() {
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
fn should_write_metrics_to_file() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");
    let default_metrics = FsTrimMetrics::default();

    write_metrics_using_tmp_file(
        &default_metrics,
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
    let parsed_metrics_str = parsed_metrics.to_p8s_metrics_string();
    let default_str = FsTrimMetrics::default().to_p8s_metrics_string();

    assert_eq!(parsed_metrics_str, default_str);
}

#[test]
fn should_update_metrics() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");
    write(&metrics_file, EXISTING_METRICS_CONTENT).expect("error writing to file");

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

    let expected_str = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 151
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 1
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total 2
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

    assert_eq!(parsed_metrics.to_p8s_metrics_string(), expected_str);
}

#[test]
fn should_update_datadir_metrics() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");
    write(&metrics_file, EXISTING_METRICS_CONTENT).expect("error writing to file");

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

    let expected_str = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 0
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 1
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total 1
# HELP fstrim_datadir_last_run_duration_milliseconds Duration of last run of fstrim on datadir in milliseconds
# TYPE fstrim_datadir_last_run_duration_milliseconds gauge
fstrim_datadir_last_run_duration_milliseconds 501
# HELP fstrim_datadir_last_run_success Success status of last run of fstrim on datadir (success: 1, failure: 0)
# TYPE fstrim_datadir_last_run_success gauge
fstrim_datadir_last_run_success 0
# HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir
# TYPE fstrim_datadir_runs_total counter
fstrim_datadir_runs_total 1
"#;

    assert_eq!(parsed_metrics.to_p8s_metrics_string(), expected_str);
}

#[test]
fn should_start_from_empty_metrics_for_update_if_metrics_in_file_contain_special_values() {
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

    let expected_str = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 151
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 1
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
    assert_eq!(parsed_metrics.to_p8s_metrics_string(), expected_str);
}

#[test]
fn should_return_ok_from_successfully_run_command() {
    run_command("true", "/").expect("running command should succeed");
}

#[test]
fn should_return_error_from_unsuccessfully_run_command() {
    let res = run_command("false", "/");
    assert_matches!(res, Err(err) if err.to_string().contains("Failed to run command"));
}

#[test]
fn should_fail_but_write_metrics_if_command_fails() {
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

    let actual_raw = read_to_string(&metrics_file).expect("should read metrics");
    let actual = normalize_duration_line(&actual_raw);
    // Even though it fails, it should write updated metrics with success=0, total_runs=1
    let expected_after_fail_raw = r#"# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
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
fstrim_datadir_last_run_success 0
# HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir
# TYPE fstrim_datadir_runs_total counter
fstrim_datadir_runs_total 1
"#;
    let expected_after_fail = normalize_duration_line(expected_after_fail_raw);
    assert_eq!(actual, expected_after_fail);
}

#[test]
fn should_fail_if_command_cannot_be_run() {
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
fn should_not_run_command_but_initialize_metrics_if_flag_set() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let tmp_dir2 = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");

    assert!(fstrim_tool(
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
        true,
        tmp_dir2
            .path()
            .to_str()
            .expect("tmp_dir path should be valid")
            .to_string(),
    )
    .is_ok());

    let actual = read_to_string(&metrics_file).expect("should read file");
    let expected = FsTrimMetrics::default().to_p8s_metrics_string();
    assert_eq!(actual, expected);
}

#[test]
fn should_not_overwrite_existing_metrics_if_metrics_init_flag_set() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let tmp_dir2 = tempdir().expect("temp dir creation should succeed");

    let metrics_file = tmp_dir.path().join("fstrim.prom");
    assert!(fstrim_tool(
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
    .is_ok());

    assert!(fstrim_tool(
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
    .is_ok());

    let content = read_to_string(&metrics_file).expect("reading metrics should succeed");
    assert!(content.contains("fstrim_runs_total 1"));
}

#[test]
fn should_fail_if_metrics_file_cannot_be_written_to() {
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
