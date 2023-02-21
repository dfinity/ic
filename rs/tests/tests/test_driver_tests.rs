use anyhow::{bail, Result};
use std::{env, path::PathBuf, process::Command};
use tempfile::Builder;

const BINARY_PATH: &str = "rs/tests/test-driver-e2e-scenarios";

// It is important that each #[test] creates a unique tmp directory.
fn create_unique_working_dir() -> PathBuf {
    let prefix_path = PathBuf::from(env::var("TEST_TMPDIR").unwrap());
    Builder::new()
        .prefix(prefix_path.as_os_str())
        .tempdir()
        .unwrap()
        .into_path()
}

fn execute_cmd(mut cmd: Command) -> Result<()> {
    let status = cmd.status().expect("failed to execute process");
    if status.success() {
        Ok(())
    } else {
        bail!("execution of test scenario failed.")
    }
}

fn execute_test_scenario_with_default_cmd(scenario_name: &str) -> Result<()> {
    let working_dir = create_unique_working_dir();
    let binary_path = env::current_dir().unwrap().join(BINARY_PATH);
    let mut cmd = Command::new(binary_path);
    cmd.env("TEST_SCENARIO_NAME", scenario_name).args([
        "--working-dir",
        working_dir.to_str().unwrap(),
        "run",
    ]);
    execute_cmd(cmd)
}

// these tests don't work in the cargo case

#[test]
fn test_scenario_without_errors_succeeds() {
    let result = execute_test_scenario_with_default_cmd("test_without_errors");
    assert!(result.is_ok())
}

#[test]
fn test_scenario_with_test_panic_fails() {
    let result = execute_test_scenario_with_default_cmd("test_with_panic");
    assert!(result.is_err())
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
        "--filter-tests",
        "non_existing_test_function", // execute test functions containing this substring (and skip all the others)
        "run",
    ]);
    let result = execute_cmd(cmd);
    assert!(result.is_ok())
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
        "--filter-tests",
        "test_to_fail", // execute test functions containing this substring (and skip all the others)
        "run",
    ]);
    let result = execute_cmd(cmd);
    assert!(result.is_err())
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
        "--filter-tests",
        "test_to_succeed", // execute test functions containing this substring (and skip all the others)
        "run",
    ]);
    let result = execute_cmd(cmd);
    assert!(result.is_ok())
}

#[test]
fn test_scenario_with_setup_panic_fails() {
    let result = execute_test_scenario_with_default_cmd("test_with_setup_panic");
    assert!(result.is_err())
}

#[test]
fn test_that_runs_out_of_time() {
    let result = execute_test_scenario_with_default_cmd("test_that_runs_out_of_time");
    assert!(result.is_err())
}

#[test]
fn test_duplicate_tasks() {
    let result = execute_test_scenario_with_default_cmd("test_duplicate_tasks");
    assert!(result.is_err())
}

#[test]
fn test_that_runs_1_parallel_task() {
    let result = execute_test_scenario_with_default_cmd("test_that_runs_1_parallel_task");
    assert!(result.is_ok())
}

#[test]
fn test_that_runs_2_parallel_tasks() {
    let result = execute_test_scenario_with_default_cmd("test_that_runs_2_parallel_tasks");
    assert!(result.is_ok())
}

#[test]
fn test_that_runs_3_parallel_tasks() {
    let result = execute_test_scenario_with_default_cmd("test_that_runs_3_parallel_tasks");
    assert!(result.is_ok())
}

#[test]
fn test_that_runs_3_parallel_tasks_one_of_which_fails() {
    let result = execute_test_scenario_with_default_cmd(
        "test_that_runs_3_parallel_tasks_one_of_which_fails",
    );
    assert!(result.is_err())
}

#[test]
fn test_that_runs_2_parallel_tasks_then_one_task_then_2_parallel_tasks() {
    let result = execute_test_scenario_with_default_cmd(
        "test_that_runs_2_parallel_tasks_then_one_task_then_2_parallel_tasks",
    );
    assert!(result.is_ok())
}

#[test]
fn test_that_runs_2_parallel_tasks_then_one_failing_task_then_2_parallel_tasks() {
    let result = execute_test_scenario_with_default_cmd(
        "test_that_runs_2_parallel_tasks_then_one_failing_task_then_2_parallel_tasks",
    );
    assert!(result.is_err())
}

#[test]
fn test_overall_group_timeout() {
    let result = execute_test_scenario_with_default_cmd("test_overall_group_timeout");
    assert!(result.is_err())
}
