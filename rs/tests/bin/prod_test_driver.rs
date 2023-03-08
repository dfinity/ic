use clap::Parser;
use ic_tests::driver::driver_setup::initialize_env;
use ic_tests::{
    driver::{
        cli::{CliArgs, DriverSubCommand, ValidatedCliProcessTestsArgs, ValidatedCliRunTestsArgs},
        config,
        driver_setup::{create_driver_context_from_cli, mk_stdout_logger},
        evaluation::{evaluate, generate_suite_execution_contract},
        pot_dsl::*,
        test_env::TestEnv,
    },
    test_suites::test_suite::get_e2e_suites,
};
use regex::Regex;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

fn run_tests(validated_args: ValidatedCliRunTestsArgs) -> anyhow::Result<()> {
    let mut suite = match get_test_suites().remove(&validated_args.suite) {
        Some(s) => s,
        None => anyhow::bail!(format!("Test suite {} is undefined", &validated_args.suite)),
    };
    apply_filters(
        &mut suite,
        &validated_args.include_pattern,
        &validated_args.skip_pattern,
    );
    // system_env dir is expected to be created by run-system-tests.py script
    let system_env = validated_args.working_dir.join(config::SYSTEM_ENV_DIR);

    let logger = mk_stdout_logger();
    let env = TestEnv::new(system_env, logger.clone())?;
    initialize_env(&env, validated_args.clone())?;
    let context = create_driver_context_from_cli(validated_args, env, get_hostname());
    // Contract file is used in the processing stage of the test results.
    // It is necessary to infer if tests/pots/suite were executed successfully according to the plan.
    let suite_contract = generate_suite_execution_contract(&suite);
    context
        .env
        .write_json_object(config::TEST_SUITE_CONTRACT_FILE, &suite_contract)
        .expect("Couldn't save test suite execution contract file.");
    // Run all tests. Each test dumps an execution result file, which indicates whether this test has succeeded or failed (with an error message).
    evaluate(&context, suite);
    Ok(())
}

fn process_test_results(validated_args: ValidatedCliProcessTestsArgs) -> anyhow::Result<()> {
    let working_dir: PathBuf = validated_args.working_dir.clone();
    // Final result object to be populated/updated with individual test results and saved.
    let mut suite_result: TestResultNode = {
        let suite_contract_file = working_dir
            .join(Path::new(config::SYSTEM_ENV_DIR).join(config::TEST_SUITE_CONTRACT_FILE));
        let file = fs::File::open(&suite_contract_file)
            .unwrap_or_else(|_| panic!("Could not open: {:?}", suite_contract_file));
        let suite_contract = serde_json::from_reader(&file)
            .unwrap_or_else(|_| panic!("Could not read json. {:?}", &file));
        TestResultNode::from(&suite_contract)
    };

    for pot in suite_result.children.iter_mut() {
        let pot_path = working_dir.join(&pot.name);
        for test in pot.children.iter_mut() {
            let test_name = test.name.clone();
            // Pot setup result file should be always present, otherwise we panic.
            let pot_result: TestResult = {
                let file_path = pot_path
                    .join(config::POT_SETUP_DIR)
                    .join(config::POT_SETUP_RESULT_FILE);
                let file = fs::File::open(&file_path)
                    .unwrap_or_else(|_| panic!("Could not open: {:?}", file_path));
                serde_json::from_reader(&file)
                    .unwrap_or_else(|_| panic!("Could not read json. {:?}", &file))
            };
            let test_result_path = pot_path
                .join(config::TESTS_DIR)
                .join(&test_name)
                .join(config::TEST_RESULT_FILE);
            // On the contrary, test result file might be absent, e.g., if test timed out, or pot setup failed.
            // In case test result file is absent, pot_result is used to propagate error message of the pot setup to the test.
            let test_result_file = fs::File::open(test_result_path);
            let test_result: TestResultNode = {
                match test_result_file {
                    Ok(file) => serde_json::from_reader(&file)
                        .unwrap_or_else(|_| panic!("Could not read json. {:?}", &file)),
                    Err(_) => {
                        let err_msg = if let TestResult::Failed(err) = pot_result {
                            format!("Pot setup failed: {}", err)
                        } else {
                            // In this case we have no additional info about the reason of test failure.
                            String::from("Test execution has not finished.")
                        };
                        TestResultNode {
                            name: test_name.clone(),
                            result: TestResult::Failed(err_msg),
                            ..Default::default()
                        }
                    }
                }
            };
            *test = test_result;
        }
    }
    // Recursively infer suite and pot level results from individual tests results.
    propagate_children_results_to_parents(&mut suite_result);
    // Save the final result file of the test suite.
    let suite_result_file = working_dir.join(config::TEST_SUITE_RESULT_FILE);
    let content = serde_json::to_string_pretty(&suite_result)
        .unwrap_or_else(|e| panic!("Could not serialize suite result to string. error={:?}", e));
    fs::write(suite_result_file, content)
        .unwrap_or_else(|e| panic!("Could not save test suite result to a file. error={:?}", e));
    // Generate and save slack alerts for failed pots.
    let alerts = generate_alerts(&suite_result, &validated_args);
    let alerts_serialized = serde_json::to_string_pretty(&alerts)
        .unwrap_or_else(|e| panic!("Could not serialize slack alerts to string: {:?}", e));
    let slack_alert_file = working_dir.join(config::SLACK_FAILURE_ALERTS_FILE);
    fs::write(&slack_alert_file, alerts_serialized)
        .unwrap_or_else(|e| panic!("Could not save {:?} file: {:?}", &slack_alert_file, e));
    if suite_result.result != TestResult::Passed {
        anyhow::bail!(format!("Test suite {} failed", suite_result.name))
    } else {
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let cli_args = CliArgs::parse();
    match cli_args.action {
        DriverSubCommand::RunTests(args) => {
            let validated_args = args.validate()?;
            run_tests(validated_args)
        }
        DriverSubCommand::ProcessTestResults(args) => {
            let validated_args = args.validate()?;
            process_test_results(validated_args)
        }
    }
}

fn get_hostname() -> Option<String> {
    std::env::var("HOSTNAME").ok()
}

fn apply_filters(suite: &mut Suite, include: &Option<Regex>, skip: &Option<Regex>) {
    for p in suite.pots.iter_mut() {
        for t in p.testset.iter_mut() {
            let path = TestPath::new()
                .join(suite.name.clone())
                .join(p.name.clone())
                .join(t.name.clone());
            t.execution_mode = resolve_execution_mode(&format!("{}", path), include, skip);
        }
        // At least one test is qualified for running. A corresponding pot needs to be
        // set up.
        if p.testset
            .iter()
            .any(|t| t.execution_mode == ExecutionMode::Run)
        {
            continue;
        }
        // At least one test is skipped. The pot needs to be included in a summary.
        if p.testset
            .iter()
            .any(|t| t.execution_mode == ExecutionMode::Skip)
        {
            p.execution_mode = ExecutionMode::Skip;
            continue;
        }
        p.execution_mode = ExecutionMode::Ignore;
    }
}

fn resolve_execution_mode(
    name: &str,
    include: &Option<Regex>,
    skip: &Option<Regex>,
) -> ExecutionMode {
    if let Some(i) = include {
        if i.is_match(name) {
            return ExecutionMode::Run;
        }
        return ExecutionMode::Ignore;
    }
    if let Some(s) = skip {
        if s.is_match(name) {
            return ExecutionMode::Skip;
        }
    }
    ExecutionMode::Run
}

fn get_test_suites() -> HashMap<String, Suite> {
    let mut m = HashMap::new();
    // Suites used for testing `prod-test-driver` itself.
    get_e2e_suites().into_iter().for_each(|s| m.add_suite(s));
    m
}

trait TestCatalog {
    fn add_suite(&mut self, suite: Suite);
}

impl TestCatalog for HashMap<String, Suite> {
    fn add_suite(&mut self, suite: Suite) {
        use std::collections::hash_map::Entry;
        if let Entry::Vacant(e) = self.entry(suite.name.clone()) {
            e.insert(suite);
        } else {
            panic!("Redefinition of suite {:?}", suite.name)
        }
    }
}

fn generate_alerts(
    suite_result: &TestResultNode,
    validated_args: &ValidatedCliProcessTestsArgs,
) -> HashMap<usize, SlackAlert> {
    let mut alerts: HashMap<usize, SlackAlert> = HashMap::new();
    let mut alert_id: usize = 0;
    let ic_version_id_datetime_msg = (validated_args.ic_version_id != validated_args.ci_commit_sha)
        .then_some(format!("; {}.", {
            validated_args.ic_version_id_date.clone()
        }))
        .unwrap_or_else(|| ".".to_string());
    for failed_pot in suite_result
        .children
        .iter()
        .filter(|p| matches!(p.result, TestResult::Failed(_)))
    {
        let message = format!(
            r#"Pot `{pot_name}` *failed*. <{ci_job_url}|log>.
Commit: <{ci_project_url}/-/commit/{ci_commit_sha}|{ci_commit_short_sha}>; {ci_commit_date}.
IC_VERSION_ID: `{ic_version_id}`{ic_version_id_datetime_msg}"#,
            pot_name = failed_pot.name,
            ci_job_url = validated_args.ci_job_url,
            ci_project_url = validated_args.ci_project_url,
            ci_commit_sha = validated_args.ci_commit_sha,
            ci_commit_short_sha = validated_args.ci_commit_short_sha,
            ci_commit_date = validated_args.ci_commit_date,
            ic_version_id = validated_args.ic_version_id,
        );
        failed_pot.alert_channels.iter().for_each(|channel| {
            alerts.insert(alert_id, SlackAlert::new(channel.clone(), message.clone()));
            alert_id += 1;
        });
    }
    alerts
}
