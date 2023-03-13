use ic_tests::driver::{report::SystemTestGroupReportSummary, test_env_api::FarmBaseUrl};
use std::{
    env,
    path::PathBuf,
    process::{Command, Output},
};
use tempfile::Builder;

const BINARY_PATH: &str = "rs/tests/test-driver-e2e-scenarios";

// It is important that each #[test] creates a unique tmp directory.
fn create_unique_working_dir() -> PathBuf {
    let prefix_path = PathBuf::from(env::var("TEST_TMPDIR").unwrap());
    let path = Builder::new()
        .prefix(prefix_path.as_os_str())
        .tempdir()
        .unwrap()
        .into_path();
    // Test driver assumes that "root_env" dir already exists prior to starting execution.
    std::fs::create_dir(path.join("root_env")).unwrap();
    path
}

fn execute_test_scenario_with_default_cmd(scenario_name: &str) -> Output {
    let working_dir = create_unique_working_dir();
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "run",
    ]);
    cmd.output().expect("failed to execute process")
}

// Use by calling cmd.output() instead of cmd.result()
fn extract_report(out: Vec<u8>) -> Option<SystemTestGroupReportSummary> {
    let log = String::from_utf8(out).unwrap();
    let group_report = log
        .split('\n')
        .skip_while(|line| !line.contains("JSON Report:"))
        .nth(1)
        .map(|r| serde_json::from_str(r).ok())
        .expect("Failed to find json summary in test logs.");
    group_report
}

#[test]
fn test_scenario_without_errors_succeeds() {
    let result = execute_test_scenario_with_default_cmd("test_without_errors");
    assert!(result.status.success(), "{:?}", result)
}

#[test]
fn test_scenario_with_test_panic_fails() {
    let result = execute_test_scenario_with_default_cmd("test_with_panic");
    assert!(!result.status.success(), "{:?}", result)
}

#[test]
fn test_scenario_with_default_farm_url_succeeds() {
    let working_dir = create_unique_working_dir();
    let scenario_name = "test_without_errors";
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "run",
    ]);
    let result = cmd.output().expect("failed to execute process");
    assert!(result.status.success(), "{:?}", result);
    // Check that Farm url stored in test env matches the default one.
    let farm_url: FarmBaseUrl = {
        let file_path = working_dir.join("root_env/farm_url.json");
        let content = std::fs::read_to_string(file_path).unwrap();
        serde_json::from_str::<FarmBaseUrl>(&content).unwrap()
    };
    assert_eq!(farm_url.to_string(), "https://farm.dfinity.systems/");
}

#[test]
fn test_scenario_with_custom_farm_url_succeeds() {
    let working_dir = create_unique_working_dir();
    let scenario_name = "test_without_errors";
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "--farm-base-url",
        "https://my_custom_url.com/",
        "run",
    ]);
    let result = cmd.output().expect("failed to execute process");
    assert!(result.status.success(), "{:?}", result);
    // Check that Farm url stored in test env matches the given url.
    let farm_url: FarmBaseUrl = {
        let file_path = working_dir.join("root_env/farm_url.json");
        let content = std::fs::read_to_string(file_path).unwrap();
        serde_json::from_str::<FarmBaseUrl>(&content).unwrap()
    };
    assert_eq!(farm_url.to_string(), "https://my_custom_url.com/");
}

#[test]
fn test_scenario_with_skipped_panic_test_succeeds() {
    let working_dir = create_unique_working_dir();
    let scenario_name = "test_with_panic";
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "--include-tests",
        "non_existing_test_function", // execute test functions containing this substring (and skip all the others)
        "run",
    ]);
    let result = cmd.output().expect("failed to execute process");
    assert!(result.status.success(), "{:?}", result);
}

#[test]
fn test_scenario_with_non_skipped_panic_test_fails() {
    let working_dir = create_unique_working_dir();
    let scenario_name = "test_with_panic";
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "--include-tests",
        "test_to_fail", // execute test functions containing this substring (and skip all the others)
        "run",
    ]);
    let result = cmd.output().expect("failed to execute process");
    assert!(!result.status.success(), "{:?}", result);
}

#[test]
fn test_scenario_with_two_skipped_panic_tests_succeeds() {
    let working_dir = create_unique_working_dir();
    let scenario_name = "test_with_two_panics";
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "--include-tests",
        "test_to_succeed", // execute test functions containing this substring (and skip all the others)
        "run",
    ]);
    let result = cmd.output().expect("failed to execute process");
    assert!(result.status.success(), "{:?}", result);
}

#[test]
fn test_scenario_with_setup_panic_fails() {
    let result = execute_test_scenario_with_default_cmd("test_with_setup_panic");
    assert!(!result.status.success(), "{:?}", result)
}

#[test]
fn test_that_runs_out_of_time() {
    let result = execute_test_scenario_with_default_cmd("test_that_runs_out_of_time");
    assert!(!result.status.success(), "{:?}", result)
}

#[test]
fn test_duplicate_tasks() {
    let result = execute_test_scenario_with_default_cmd("test_duplicate_tasks");
    assert!(!result.status.success(), "{:?}", result)
}

#[test]
fn test_that_runs_1_parallel_task() {
    let result = execute_test_scenario_with_default_cmd("test_that_runs_1_parallel_task");
    assert!(result.status.success(), "{:?}", result)
}

#[test]
fn test_that_runs_2_parallel_tasks() {
    let result = execute_test_scenario_with_default_cmd("test_that_runs_2_parallel_tasks");
    assert!(result.status.success(), "{:?}", result)
}

#[test]
fn test_that_runs_3_parallel_tasks() {
    let result = execute_test_scenario_with_default_cmd("test_that_runs_3_parallel_tasks");
    assert!(result.status.success(), "{:?}", result)
}

#[test]
fn test_that_runs_3_parallel_tasks_one_of_which_fails() {
    let result = execute_test_scenario_with_default_cmd(
        "test_that_runs_3_parallel_tasks_one_of_which_fails",
    );
    assert!(!result.status.success(), "{:?}", result)
}

#[test]
fn test_that_runs_2_parallel_tasks_then_one_task_then_2_parallel_tasks() {
    let result = execute_test_scenario_with_default_cmd(
        "test_that_runs_2_parallel_tasks_then_one_task_then_2_parallel_tasks",
    );
    assert!(result.status.success(), "{:?}", result)
}

#[test]
fn test_that_runs_2_parallel_tasks_then_one_failing_task_then_2_parallel_tasks() {
    let result = execute_test_scenario_with_default_cmd(
        "test_that_runs_2_parallel_tasks_then_one_failing_task_then_2_parallel_tasks",
    );
    assert!(!result.status.success(), "{:?}", result)
}

#[test]
fn test_overall_group_timeout() {
    let result = execute_test_scenario_with_default_cmd("test_overall_group_timeout");
    assert!(!result.status.success(), "{:?}", result)
}

#[test]
fn test_setup_failure_file_written() {
    let working_dir = create_unique_working_dir();
    let scenario_name = "test_without_errors";
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "run",
    ]);
    let result = cmd.output().expect("failed to execute process");
    assert!(result.status.success(), "{:?}", result);
    assert!(working_dir
        .join("setup")
        .join("setup_succeeded.json")
        .exists());
}

#[test]
fn test_setup_failure_file_not_written() {
    let working_dir = create_unique_working_dir();
    let scenario_name = "test_with_setup_panic";
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "run",
    ]);
    let result = cmd.output().expect("failed to execute process");
    assert!(!result.status.success(), "{:?}", result);
    assert!(!working_dir
        .join("setup")
        .join("setup_succeeded.json")
        .exists());
    let summary = extract_report(result.stderr).expect("Failed to extract report from logs.");
    assert!(summary.failure.len() == 2);
}
