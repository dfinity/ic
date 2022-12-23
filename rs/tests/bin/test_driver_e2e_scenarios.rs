use anyhow::Result;
use ic_tests::driver::new::group::{SystemTestGroup, SystemTestSubGroup};
use ic_tests::driver::test_env::TestEnv;
use ic_tests::systest;
use slog::info;
use std::collections::HashMap;
use std::process;
use std::time::Duration;

const TEST_SCENARIO_ENV_VAR: &str = "TEST_SCENARIO_NAME";

// This is a single binary linking all e2e scenarios for the testing framework.
// Specific scenario is selected based on the environment variable.
fn main() -> Result<()> {
    let scenario_name = std::env::var(TEST_SCENARIO_ENV_VAR).unwrap_or_else(|_| {
        eprintln!("environment variable {TEST_SCENARIO_ENV_VAR} is not set");
        process::exit(1);
    });
    let mut test_scenarios = get_all_e2e_test_scenarios();
    test_scenarios
        .remove(scenario_name.as_str())
        .unwrap_or_else(|| {
            eprintln!("test scenario with name={scenario_name} is not defined in the suite");
            process::exit(1);
        })
        .execute_from_args()
}

fn get_all_e2e_test_scenarios() -> HashMap<String, SystemTestGroup> {
    HashMap::from([
        (
            "test_without_errors".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_test(systest!(test_to_succeed)),
        ),
        (
            "test_with_panic".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_test(systest!(test_to_fail)),
        ),
        (
            "test_with_setup_panic".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_panic)
                .add_test(systest!(test_to_fail)),
        ),
        (
            "test_that_runs_out_of_time".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_test(systest!(never_ending_task))
                .with_timeout_per_test(Duration::from_secs(10)),
        ),
        (
            "test_duplicate_tasks".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_parallel(SystemTestSubGroup::new().add_test(systest!(test_to_succeed)))
                .add_test(systest!(test_to_succeed)),
        ),
        (
            "test_that_runs_1_parallel_task".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_parallel(SystemTestSubGroup::new().add_test(systest!(test_to_succeed_3sec))),
        ),
        (
            "test_that_runs_2_parallel_tasks".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_parallel(
                    SystemTestSubGroup::new()
                        .add_test(systest!(test_to_succeed_5sec))
                        .add_test(systest!(test_to_succeed_3sec)),
                ),
        ),
        (
            "test_that_runs_3_parallel_tasks".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_parallel(
                    SystemTestSubGroup::new()
                        .add_test(systest!(test_to_succeed_3sec))
                        .add_test(systest!(test_to_succeed_5sec))
                        .add_test(systest!(test_to_succeed_7sec)),
                ),
        ),
        (
            "test_that_runs_3_parallel_tasks_one_of_which_fails".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_parallel(
                    SystemTestSubGroup::new()
                        .add_test(systest!(test_to_succeed_3sec))
                        .add_test(systest!(test_to_fail_5sec))
                        .add_test(systest!(test_to_succeed_7sec)),
                ),
        ),
        (
            "test_that_runs_2_parallel_tasks_then_one_task_then_2_parallel_tasks".to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_parallel(
                    SystemTestSubGroup::new()
                        .add_test(systest!(test_to_succeed_3sec))
                        .add_test(systest!(test_to_succeed_2sec)),
                )
                .add_test(systest!(test_to_succeed_1sec))
                .add_parallel(
                    SystemTestSubGroup::new()
                        .add_test(systest!(test_to_succeed_5sec))
                        .add_test(systest!(test_to_succeed_7sec)),
                ),
        ),
        (
            "test_that_runs_2_parallel_tasks_then_one_failing_task_then_2_parallel_tasks"
                .to_string(),
            SystemTestGroup::new()
                .with_setup(setup_to_succeed)
                .add_parallel(
                    SystemTestSubGroup::new()
                        .add_test(systest!(test_to_succeed_3sec))
                        .add_test(systest!(test_to_succeed_2sec)),
                )
                .add_test(systest!(test_to_fail_1sec))
                .add_parallel(
                    SystemTestSubGroup::new()
                        .add_test(systest!(test_to_succeed_5sec))
                        .add_test(systest!(test_to_succeed_7sec)),
                ),
        ),
        (
            "test_overall_group_timeout".to_string(),
            SystemTestGroup::new()
                .with_overall_timeout(Duration::from_secs(5))
                .with_setup(setup_to_succeed)
                .add_test(systest!(test_to_succeed_7sec)),
        ),
    ])
}

fn setup_to_succeed(_: TestEnv) {}

fn setup_to_panic(_: TestEnv) {
    panic!("this setup panics");
}

fn test_to_succeed(_: TestEnv) {}

fn test_to_succeed_7sec(_: TestEnv) {
    std::thread::sleep(Duration::from_secs(7));
}

fn test_to_succeed_5sec(_: TestEnv) {
    std::thread::sleep(Duration::from_secs(5));
}

fn test_to_fail_5sec(_: TestEnv) {
    std::thread::sleep(Duration::from_secs(5));
    panic!("this test panics after 5 seconds");
}

fn test_to_succeed_3sec(_: TestEnv) {
    std::thread::sleep(Duration::from_secs(3));
}

fn test_to_succeed_2sec(_: TestEnv) {
    std::thread::sleep(Duration::from_secs(2));
}

fn test_to_succeed_1sec(_: TestEnv) {
    std::thread::sleep(Duration::from_secs(1));
}

fn test_to_fail_1sec(_: TestEnv) {
    std::thread::sleep(Duration::from_secs(1));
    panic!("this test panics after 1 seconds");
}

fn test_to_fail(_: TestEnv) {
    panic!("this test panics");
}

fn never_ending_task(env: TestEnv) {
    info!(
        env.logger(),
        "Running (infinite) task `never_ending_task` ..."
    );

    loop {
        info!(env.logger(), "Ping from `never_ending_task`");
        std::thread::sleep(Duration::from_secs(1));
    }
}
