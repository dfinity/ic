use fondue::pot::execution::TestResult;
use ic_fondue::prod_tests::cli::CliArgs;
use ic_fondue::prod_tests::driver_setup::create_driver_context_from_cli;
use ic_fondue::prod_tests::evaluation::evaluate;
use ic_fondue::prod_tests::pot_dsl::*;
use ic_tests::create_subnet::{self, create_subnet_test};
use ic_tests::nns_fault_tolerance_test;
use ic_tests::nns_follow_test::{self, test as follow_test};
use ic_tests::nns_voting_test::{self, test as voting_test};
use ic_tests::node_assign_test::{self, test as node_assign_test};
use ic_tests::node_restart_test::{self, test as node_restart_test};
use ic_tests::rosetta_test;
use ic_tests::security::nns_voting_fuzzing_poc_test;
use ic_tests::token_balance_test::{self, test as token_balance_test};
use ic_tests::upgrade_reject::{self, upgrade_reject};
use ic_tests::{
    basic_health_test::{self, basic_health_test},
    execution,
};
use ic_tests::{
    cycles_minting_test, feature_flags, nns_canister_upgrade_test, registry_authentication_test,
    ssh_access_to_nodes, subnet_creation, transaction_ledger_correctness_test, wasm_generator_test,
};
use regex::Regex;
use std::collections::HashMap;
use std::time::Duration;
use structopt::StructOpt;

fn main() -> anyhow::Result<()> {
    let cli_args = CliArgs::from_args();
    let validated_args = cli_args.validate()?;

    let mut writer = None;
    if let Some(ref p) = validated_args.result_file {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(p)?;
        writer = Some(std::io::BufWriter::new(Box::new(f)));
    }

    let mut suite = match get_test_suites().remove(&validated_args.suite) {
        Some(s) => s,
        None => anyhow::bail!(format!("Test suite {} is undefined", &validated_args.suite)),
    };
    apply_filters(
        &mut suite,
        &validated_args.include_pattern,
        &validated_args.ignore_pattern,
        &validated_args.skip_pattern,
    );

    let context = create_driver_context_from_cli(validated_args, get_hostname());
    let result = evaluate(&context, suite);

    if let Some(mut w) = writer {
        serde_json::to_writer_pretty(&mut w, &result)?;
    }

    if result.result == TestResult::Failed {
        anyhow::bail!(format!("Test suite {} failed", result.name))
    } else {
        Ok(())
    }
}

fn get_hostname() -> Option<String> {
    std::env::var("HOSTNAME").ok()
}

fn apply_filters(
    suite: &mut Suite,
    include: &Option<Regex>,
    ignore: &Option<Regex>,
    skip: &Option<Regex>,
) {
    for p in suite.pots.iter_mut() {
        let tests = match &mut p.testset {
            TestSet::Parallel(tests) => tests,
            TestSet::Sequence(tests) => tests,
        };
        for t in tests.iter_mut() {
            let path = TestPath::new()
                .join(suite.name.clone())
                .join(p.name.clone())
                .join(t.name.clone());
            t.execution_mode = resolve_execution_mode(&format!("{}", path), include, ignore, skip);
        }
        // At least one test is qualified for running. A corresponding pot needs to be
        // set up.
        if tests.iter().any(|t| t.execution_mode == ExecutionMode::Run) {
            continue;
        }
        // At least one test is skipped. The pot needs to be included in a summary.
        if tests
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
    ignore: &Option<Regex>,
    skip: &Option<Regex>,
) -> ExecutionMode {
    if let Some(i) = include {
        if i.is_match(name) {
            return ExecutionMode::Run;
        }
        return ExecutionMode::Ignore;
    }
    if let Some(i) = ignore {
        if i.is_match(name) {
            return ExecutionMode::Ignore;
        }
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
    m.insert(
        "pre_master".to_string(),
        suite(
            "pre_master",
            vec![
                pot(
                    "create_subnet", 
                    create_subnet::config(),
                    par(vec![
                        t("create_subnet", create_subnet_test),
                    ]),
                ),
                execution::upgraded_pots::general_execution_pot(),
                execution::upgraded_pots::cycles_restrictions_pot(),
                execution::upgraded_pots::inter_canister_queries(),
                execution::upgraded_pots::compute_allocation_pot(),
                pot(
                    "node_assign_pot",
                    node_assign_test::config(),
                    par(vec![t("node_assign_test", node_assign_test)]),
                ),
                pot(
                    "nns_follow_pot",
                    nns_follow_test::config(),
                    par(vec![t("follow_test", follow_test)]),
                ),
                pot(
                    "nns_voting_pot",
                    nns_voting_test::config(),
                    par(vec![t("voting_test", voting_test)]),
                ),
                pot(
                    "nns_token_balance_pot",
                    token_balance_test::config(),
                    par(vec![t("token_balance_test", token_balance_test)]),
                ),
                pot(
                    "node_restart_pot",
                    node_restart_test::config(),
                    par(vec![t("node_restart_test", node_restart_test)]),
                ),
                pot(
                    "cycles_minting_pot",
                    cycles_minting_test::config(),
                    par(vec![t("cycles_minting_test", cycles_minting_test::test)]),
                ),
                pot(
                    "nns_subnet_creation_pot",
                    subnet_creation::config(),
                    par(vec![t(
                        "create_subnet_with_assigned_nodes_fails",
                        subnet_creation::create_subnet_with_assigned_nodes_fails,
                    )]),
                ),
                pot(
                    "nns_voting_fuzzing_poc_pot",
                    nns_voting_fuzzing_poc_test::config(),
                    par(vec![t(
                        "nns_voting_fuzzing_poc_test",
                        nns_voting_fuzzing_poc_test::test,
                    )]),
                ),
                pot(
                    "nns_canister_upgrade_pot",
                    nns_canister_upgrade_test::config(),
                    par(vec![t(
                        "nns_canister_upgrade_test",
                        nns_canister_upgrade_test::test,
                    )]),
                ),
                pot(
                    "certified_registry_pot",
                    registry_authentication_test::config(),
                    par(vec![t(
                        "registry_authentication_test",
                        registry_authentication_test::test,
                    )]),
                ),
                pot(
                    "transaction_ledger_correctness_pot",
                    transaction_ledger_correctness_test::config(),
                    par(vec![t(
                        "transaction_ledger_correctness_test",
                        transaction_ledger_correctness_test::test,
                    )]),
                ),
                pot(
                    "ssh_access_to_nodes_pot",
                    ssh_access_to_nodes::config(),
                    seq(vec![
                        t(
                            "root_cannot_authenticate",
                            ssh_access_to_nodes::root_cannot_authenticate,
                        ),
                        t(
                            "readonly_cannot_authenticate_without_a_key",
                            ssh_access_to_nodes::readonly_cannot_authenticate_without_a_key,
                        ),
                        t(
                            "readonly_cannot_authenticate_with_random_key",
                            ssh_access_to_nodes::readonly_cannot_authenticate_with_random_key,
                        ),
                        t(
                            "keys_in_the_subnet_record_can_be_updated",
                            ssh_access_to_nodes::keys_in_the_subnet_record_can_be_updated,
                        ),
                        t(
                            "keys_for_unassigned_nodes_can_be_updated",
                            ssh_access_to_nodes::keys_for_unassigned_nodes_can_be_updated,
                        ),
                        t(
                            "multiple_keys_can_access_one_account",
                            ssh_access_to_nodes::multiple_keys_can_access_one_account,
                        ),
                        t(
                            "multiple_keys_can_access_one_account_on_unassigned_nodes",
                            ssh_access_to_nodes::multiple_keys_can_access_one_account_on_unassigned_nodes,
                        ),
                        t(
                            "updating_readonly_does_not_remove_backup_keys",
                            ssh_access_to_nodes::updating_readonly_does_not_remove_backup_keys,
                        ),
                        t(
                            "can_add_50_readonly_and_backup_keys",
                            ssh_access_to_nodes::can_add_100_readonly_and_backup_keys,
                        ),
                        t(
                            "cannot_add_51_readonly_or_backup_keys",
                            ssh_access_to_nodes::cannot_add_101_readonly_or_backup_keys,
                        ),
                    ]),
                ),
            ],
        ),
    );

    m.insert(
        "hourly".to_string(),
        suite(
            "hourly",
            vec![
                pot(
                    "basic_health_pot",
                    basic_health_test::config(),
                    par(vec![
                        t("basic_health_test", basic_health_test),
                        t("basic_health_test2", basic_health_test),
                    ]),
                ),
                pot(
                    "nns_fault_tolerance_pot",
                    nns_fault_tolerance_test::config(),
                    par(vec![t(
                        "nns_fault_tolerance_test",
                        nns_fault_tolerance_test::test,
                    )]),
                ),
                pot(
                    "create_subnet",
                    create_subnet::config(),
                    par(vec![t("create_subnet", create_subnet_test)]),
                ),
                pot(
                    "upgrade_reject",
                    upgrade_reject::config(),
                    par(vec![t("upgrade_reject", upgrade_reject)]),
                ),
                pot(
                    "basic_pot_with_all_features_enabled",
                    feature_flags::basic_config_with_all_features_enabled(),
                    par(vec![t(
                        "mock_ecdsa_signatures_are_supported",
                        feature_flags::mock_ecdsa_signatures_are_supported,
                    )]),
                ),
            ],
        ),
    );

    // The tests in this suite require canisters to be build prior to
    // running the tests which is why we separate it out.
    m.insert(
        "wasm_generator".to_string(),
        suite(
            "wasm_generator",
            vec![pot_with_time_limit(
                "wasm_generator_pot",
                wasm_generator_test::config(),
                par(vec![t("wasm_generator_test", wasm_generator_test::test)]),
                Duration::from_secs(7200),
            )],
        ),
    );

    m.insert(
        "rosetta".to_string(),
        suite(
            "rosetta",
            vec![pot(
                "rosetta_pot",
                rosetta_test::config(),
                par(vec![t(
                    "rosetta_test_everything",
                    rosetta_test::test_everything,
                )]),
            )],
        ),
    );

    m
}
