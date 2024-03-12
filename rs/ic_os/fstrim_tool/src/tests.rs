use super::*;
use assert_matches::assert_matches;
use std::fs::write;
use tempfile::tempdir;

const EXISTING_METRICS_CONTENT: &str =
    "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds\n\
     # TYPE fstrim_last_run_duration_milliseconds gauge\n\
     fstrim_last_run_duration_milliseconds 0\n\
     # HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)\n\
     # TYPE fstrim_last_run_success gauge\n\
     fstrim_last_run_success 1\n\
     # HELP fstrim_runs_total Total number of runs of fstrim\n\
     # TYPE fstrim_runs_total counter\n\
     fstrim_runs_total 1\n";

const EXISTING_METRICS_CONTENT_WITH_SPECIAL_VALUES: &str =
    "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds\n\
     # TYPE fstrim_last_run_duration_milliseconds gauge\n\
     fstrim_last_run_duration_milliseconds 0\n\
     # HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)\n\
     # TYPE fstrim_last_run_success gauge\n\
     fstrim_last_run_success 1\n\
     # HELP fstrim_runs_total Total number of runs of fstrim\n\
     # TYPE fstrim_runs_total counter\n\
     fstrim_runs_total +Inf\n";

#[test]
fn should_parse_metrics_from_file() {
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
    let parsed_metrics_string = parsed_metrics.to_p8s_metrics_string();
    assert_eq!(parsed_metrics_string, EXISTING_METRICS_CONTENT);
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
    let default_metrics_string = default_metrics.to_p8s_metrics_string();

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
    let parsed_metrics_string = parsed_metrics.to_p8s_metrics_string();
    assert_eq!(
        parsed_metrics, default_metrics,
        "{}\n{}",
        parsed_metrics_string, default_metrics_string
    );
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
    )
    .expect("updating metrics should succeed");
    let parsed_metrics = parse_existing_metrics_from_file(
        metrics_file
            .to_str()
            .expect("should convert metrics_file path buf to str"),
    )
    .expect("parsing metrics should succeed")
    .expect("parsed metrics should be some");
    let expected_metrics =
        "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds\n\
         # TYPE fstrim_last_run_duration_milliseconds gauge\n\
         fstrim_last_run_duration_milliseconds 151\n\
         # HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)\n\
         # TYPE fstrim_last_run_success gauge\n\
         fstrim_last_run_success 1\n\
         # HELP fstrim_runs_total Total number of runs of fstrim\n\
         # TYPE fstrim_runs_total counter\n\
         fstrim_runs_total 2\n";
    let parsed_metrics_string = parsed_metrics.to_p8s_metrics_string();
    assert_eq!(parsed_metrics_string, expected_metrics);
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
    )
    .expect("updating metrics should succeed");
    let parsed_metrics = parse_existing_metrics_from_file(
        metrics_file
            .to_str()
            .expect("should convert metrics_file path buf to str"),
    )
    .expect("parsing metrics should succeed")
    .expect("parsed metrics should be some");
    let expected_metrics =
        "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds\n\
         # TYPE fstrim_last_run_duration_milliseconds gauge\n\
         fstrim_last_run_duration_milliseconds 151\n\
         # HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)\n\
         # TYPE fstrim_last_run_success gauge\n\
         fstrim_last_run_success 1\n\
         # HELP fstrim_runs_total Total number of runs of fstrim\n\
         # TYPE fstrim_runs_total counter\n\
         fstrim_runs_total 1\n";
    let parsed_metrics_string = parsed_metrics.to_p8s_metrics_string();
    assert_eq!(parsed_metrics_string, expected_metrics);
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
        ),
        Err(err)
        if err.to_string().contains("Failed to run command")
    );

    assert_metrics_file_content(&metrics_file, false, 1);
}

#[test]
fn should_fail_if_command_cannot_be_run() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
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
        ),
        Err(err)
        if err.to_string().contains("Failed to run command")
    );
}

#[test]
fn should_not_run_command_but_initialize_metrics_if_flag_set() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
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
    )
    .is_ok());

    assert_metrics_file_content(&metrics_file, true, 0);
}

#[test]
fn should_not_overwrite_existing_metrics_if_metrics_init_flag_set() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
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
    )
    .is_ok());

    assert_metrics_file_content(&metrics_file, true, 1);
}

#[test]
fn should_fail_if_metrics_file_cannot_be_written_to() {
    let metrics_file = PathBuf::from("/non/existent/directory/fstrim.prom");
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
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
        ),
        Err(err)
        if err.to_string().contains("Failed to write metrics to file")
    );
}

#[test]
fn should_fail_if_target_is_not_a_directory() {
    let tmp_dir = tempdir().expect("temp dir creation should succeed");
    let metrics_file = tmp_dir.path().join("fstrim.prom");
    let target = PathBuf::from("/non/existent/target/directory");
    let expected_error = format!(
        "Target {} is not a directory",
        target.to_str().expect("target path should be valid")
    );
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
        ),
        Err(err)
        if err.to_string() == expected_error
    );
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
