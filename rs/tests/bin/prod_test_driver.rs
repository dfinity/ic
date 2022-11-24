use clap::Parser;
use ic_fondue::{
    pot::execution::TestResult,
    result::{propagate_children_results_to_parents, TestResultNode},
    slack::{Alertable, SlackAlert},
};
use ic_tests::{
    api_test, basic_health_test, boundary_nodes_integration, boundary_nodes_snp_tests,
    btc_integration, canister_http, ckbtc, consensus, driver::driver_setup::initialize_env,
    execution, icrc1_agent_test, ledger_tests, message_routing, networking, nns_tests,
    orchestrator, rosetta_test, tecdsa, wasm_generator_test, workload_counter_canister_test,
};
use ic_tests::{
    driver::{
        cli::{CliArgs, DriverSubCommand, ValidatedCliProcessTestsArgs, ValidatedCliRunTestsArgs},
        config::{self, *},
        driver_setup::{create_driver_context_from_cli, mk_stdout_logger},
        evaluation::{evaluate, generate_suite_execution_contract},
        ic::{AmountOfMemoryKiB, ImageSizeGiB, NrOfVCPUs, VmAllocationStrategy, VmResources},
        pot_dsl::*,
        test_env::TestEnv,
    },
    par, seq,
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
            let test_result_file = fs::File::open(&test_result_path);
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

    m.add_suite(
        suite(
            "create_subnet_pre_master",
            vec![pot_with_setup(
                "create_subnet",
                nns_tests::create_subnet::pre_master_config,
                par(vec![sys_t("create_subnet", nns_tests::create_subnet::test)]),
            )],
        )
        .with_alert(TEST_FAILURE_CHANNEL),
    );

    m.add_suite(
        suite(
            "boundary_nodes_pre_master",
            vec![pot_with_setup(
                "boundary_nodes_pot",
                boundary_nodes_integration::boundary_nodes::config,
                seq!(
                    par!(
                        sys_t(
                            "boundary_nodes_canister_test",
                            boundary_nodes_integration::boundary_nodes::canister_test,
                        ),
                        sys_t(
                            "boundary_nodes_http_canister_test",
                            boundary_nodes_integration::boundary_nodes::http_canister_test,
                        ),
                        sys_t(
                            "boundary_nodes_nginx_valid_config_test",
                            boundary_nodes_integration::boundary_nodes::nginx_valid_config_test,
                        ),
                        sys_t(
                            "boundary_nodes_redirect_http_to_https_test",
                            boundary_nodes_integration::boundary_nodes::redirect_http_to_https_test,
                        ),
                        sys_t(
                            "boundary_nodes_redirect_to_dashboard_test",
                            boundary_nodes_integration::boundary_nodes::redirect_to_dashboard_test,
                        ),
                        sys_t(
                            "boundary_nodes_redirect_to_non_raw_test",
                            boundary_nodes_integration::boundary_nodes::redirect_to_non_raw_test,
                        ),
                        sys_t(
                            "boundary_nodes_sw_test",
                            boundary_nodes_integration::boundary_nodes::sw_test,
                        ),
                        sys_t(
                            "boundary_nodes_icx_proxy_test",
                            boundary_nodes_integration::boundary_nodes::icx_proxy_test,
                        ),
                        sys_t(
                            "boundary_nodes_direct_to_replica_test",
                            boundary_nodes_integration::boundary_nodes::direct_to_replica_test,
                        ),
                        sys_t(
                            "boundary_nodes_direct_to_replica_rosetta_test",
                            boundary_nodes_integration::boundary_nodes::direct_to_replica_rosetta_test,
                        ),
                        sys_t(
                            "boundary_nodes_direct_to_replica_options_test",
                            boundary_nodes_integration::boundary_nodes::direct_to_replica_options_test,
                        ),
                        sys_t(
                            "boundary_nodes_seo_test",
                            boundary_nodes_integration::boundary_nodes::seo_test,
                        ),
                    ),
                    sys_t(
                        "boundary_nodes_denylist_test",
                        boundary_nodes_integration::boundary_nodes::denylist_test,
                    ),
                    sys_t(
                        "boundary_nodes_canister_allowlist_test",
                        boundary_nodes_integration::boundary_nodes::canister_allowlist_test,
                    ),
                    sys_t(
                        "boundary_nodes_reboot_test",
                        boundary_nodes_integration::boundary_nodes::reboot_test,
                    )
                ),
            )],
        )
        .with_alert(TEST_FAILURE_CHANNEL),
    );

    m.add_suite(
        suite(
            "boundary_nodes_sev_snp_pre_master",
            vec![pot_with_setup(
                "boundary_nodes_sev_snp_pot",
                boundary_nodes_snp_tests::boundary_nodes_snp::config,
                par(vec![
                    sys_t(
                        "boundary_nodes_sev_snp_kernel_test",
                        boundary_nodes_snp_tests::boundary_nodes_snp::snp_kernel_test,
                    ),
                    sys_t(
                        "boundary_nodes_sev_snp_basic_test",
                        boundary_nodes_snp_tests::boundary_nodes_snp::snp_basic_test,
                    ),
                ]),
            )
            .with_alert(ENG_NODE_CHANNEL)],
        )
        .with_alert(TEST_FAILURE_CHANNEL),
    );

    m.add_suite(
        suite(
            "tecdsa_pre_master",
            vec![
                pot_with_setup(
                    "tecdsa_add_nodes_pot",
                    tecdsa::tecdsa_add_nodes_test::config,
                    par(vec![sys_t(
                        "test_tecdsa_add_nodes",
                        tecdsa::tecdsa_add_nodes_test::test,
                    )]),
                ),
                pot_with_setup(
                    "tecdsa_remove_nodes_pot",
                    tecdsa::tecdsa_remove_nodes_test::config,
                    par(vec![sys_t(
                        "test_tecdsa_remove_nodes",
                        tecdsa::tecdsa_remove_nodes_test::test,
                    )]),
                ),
                pot_with_setup(
                    "tecdsa_signature_life_cycle",
                    tecdsa::tecdsa_signature_test::config_without_ecdsa_on_nns,
                    seq(vec![sys_t(
                        "test_threshold_ecdsa_life_cycle",
                        tecdsa::tecdsa_signature_test::test_threshold_ecdsa_life_cycle,
                    )]),
                ),
                pot_with_setup(
                    "tecdsa_signature_timeout",
                    tecdsa::tecdsa_signature_test::config_without_ecdsa_on_nns,
                    seq(vec![t(
                        "test_threshold_ecdsa_signature_timeout",
                        tecdsa::tecdsa_signature_test::test_threshold_ecdsa_signature_timeout,
                    )]),
                ),
            ],
        )
        .with_alert(ENG_CONSENSUS_CHANNEL),
    );

    m.add_suite(
        suite(
            "ckbtc_pre_master",
            vec![
                pot_with_setup(
                    "minter_pot_basics",
                    ckbtc::lib::config,
                    seq!(
                        par(vec![
                            sys_t(
                                "minter_get_btc_address",
                                ckbtc::minter::test_get_btc_address::test_get_btc_address
                            ),
                            sys_t(
                                "minter_get_withdrawal_account",
                                ckbtc::minter::test_get_withdrawal_account::test_get_withdrawal_account
                            ),
                        ]),
                        sys_t("ckbtc_minter_agent", ckbtc::agent::test_ckbtc_minter_agent),
                    ),
                ),
                pot_with_setup(
                    "minter_pot_update_balance",
                    ckbtc::lib::config,
                    seq!(sys_t(
                        "minter_update_balance",
                        ckbtc::minter::test_update_balance::test_update_balance
                    ),),
                ),
                pot_with_setup(
                    "minter_pot_retrieve_btc",
                    ckbtc::lib::config,
                    seq!(sys_t(
                        "minter_retrieve_btc",
                        ckbtc::minter::test_retrieve_btc::test_retrieve_btc
                    ),),
                ),
                pot_with_setup(
                    "minter_pot_heartbeat",
                    ckbtc::lib::config,
                    seq!(sys_t(
                        "minter_heartbeat_btc",
                        ckbtc::minter::test_heartbeat::test_heartbeat
                    ),),
                ),
            ],
        )
        .with_alert(ENG_FINANCIAL_INTEGRATION),
    );

    m.add_suite(suite(
        "pre_master",
        vec![
            pot_with_setup(
                "api_test",
                api_test::setup_two_ics,
                par(vec![
                    sys_t(
                        "ics_have_correct_subnet_count",
                        api_test::ics_have_correct_subnet_count,
                    ),
                    // sys_t("vm_control", api_test::vm_control), disabled due to flakiness
                    sys_t(
                        "install_counter_canister",
                        api_test::install_counter_canister,
                    ),
                ]),
            ),
            pot_with_setup(
                "btc_pot",
                btc_integration::btc::config,
                par(vec![
                    sys_t("btc_get_balance", btc_integration::btc::get_balance),
                ]),
            ),
            /*
            pot_with_setup(
                "boundary_nodes_pot",
                boundary_nodes_integration::boundary_nodes::config,
                par(vec![
                    sys_t(
                        "boundary_nodes_test",
                        boundary_nodes_integration::boundary_nodes::test,
                    ),
                    sys_t(
                        "boundary_nodes_nginx_valid_config_test",
                        boundary_nodes_integration::boundary_nodes::nginx_valid_config_test,
                    ),
                ]),
            ),
             */
            pot_with_setup(
                "canister_http",
                canister_http::lib::config,
                par(vec![sys_t("http_basic", canister_http::http_basic::test)]),
            ),
            pot_with_setup(
                "firewall_priority_pot",
                networking::firewall_priority::config,
                par(vec![
                    sys_t("firewall_priority", networking::firewall_priority::override_firewall_rules_with_priority),
                ]),
            ),
            execution::upgraded_pots::general_execution_pot(),
            execution::upgraded_pots::cycles_restrictions_pot(),
            execution::upgraded_pots::inter_canister_queries(),
            execution::upgraded_pots::compute_allocation_pot(),
            execution::upgraded_pots::max_number_of_canisters_pot(),
            pot_with_setup(
                "global_reboot_pot",
                message_routing::global_reboot_test::config,
                par(vec![sys_t(
                    "global_reboot_test",
                    message_routing::global_reboot_test::test,
                )]),
            ),
            icrc1_agent_test::icrc1_agent_test_pot(),
            pot_with_setup(
                "node_removal_from_registry_pot",
                nns_tests::node_removal_from_registry::config,
                par(vec![sys_t(
                    "node_removal_from_registry_test",
                    nns_tests::node_removal_from_registry::test,
                )]),
            ),
            pot_with_setup(
                "node_assign_pot",
                orchestrator::node_assign_test::config,
                par(vec![sys_t(
                    "node_assign_test",
                    orchestrator::node_assign_test::test,
                )]),
            ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
            pot_with_setup(
                "node_graceful_leaving_pot",
                consensus::node_graceful_leaving_test::config,
                par(vec![sys_t(
                    "node_graceful_leaving_test",
                    consensus::node_graceful_leaving_test::test,
                )]),
            ),
            pot_with_setup(
                "nns_follow_pot",
                nns_tests::nns_follow::config,
                par(vec![sys_t("follow_test", nns_tests::nns_follow::test)]),
            ),
            pot_with_setup(
                "nns_voting_pot",
                nns_tests::nns_voting::config,
                par(vec![sys_t("voting_test", nns_tests::nns_voting::test)]),
            ),
            pot_with_setup(
                "nns_token_balance_pot",
                ledger_tests::token_balance::config,
                par(vec![sys_t(
                    "token_balance_test",
                    ledger_tests::token_balance::test,
                )]),
            ),
            pot_with_setup(
                "cycles_minting_pot",
                nns_tests::cycles_minting::config,
                par(vec![sys_t(
                    "cycles_minting_test",
                    nns_tests::cycles_minting::test,
                )]),
            ),
            pot_with_setup(
                "cycles_minting_pot_with_multiple_app_subnets",
                nns_tests::cycles_minting::config_with_multiple_app_subnets,
                par(vec![sys_t(
                    "cycles_minting_with_subnet_types_test",
                    nns_tests::cycles_minting::create_canister_on_specific_subnet_type,
                )]),
            ),
            pot_with_setup(
                "nns_voting_fuzzing_poc_pot",
                nns_tests::nns_voting_fuzzing_poc_test::config,
                par(vec![sys_t(
                    "nns_voting_fuzzing_poc_test",
                    nns_tests::nns_voting_fuzzing_poc_test::test,
                )]),
            ),
            pot_with_setup(
                "nns_canister_uninstall_pot",
                nns_tests::nns_uninstall_canister_by_proposal::config,
                par(vec![sys_t(
                    "nns_uninstall_canister_by_proposal_test",
                    nns_tests::nns_uninstall_canister_by_proposal::test,
                )]),
            ),
            pot_with_setup(
                "nns_canister_upgrade_pot",
                nns_tests::nns_canister_upgrade::config,
                par(vec![sys_t(
                    "nns_canister_upgrade_test",
                    nns_tests::nns_canister_upgrade::test,
                )]),
            ),
            pot_with_setup(
                "certified_registry_pot",
                execution::registry_authentication_test::config,
                par(vec![sys_t(
                    "registry_authentication_test",
                    execution::registry_authentication_test::test,
                )]),
            ),
            pot_with_setup(
                "rotate_ecdsa_idkg_key_pot",
                orchestrator::rotate_ecdsa_idkg_key::setup,
                par(vec![sys_t(
                    "rotate_ecdsa_idkg_key_test",
                    orchestrator::rotate_ecdsa_idkg_key::test,
                )]),
            ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
            pot_with_setup(
                "transaction_ledger_correctness_pot",
                ledger_tests::transaction_ledger_correctness::config,
                par(vec![sys_t(
                    "transaction_ledger_correctness_test",
                    ledger_tests::transaction_ledger_correctness::test,
                )]),
            ),
            pot_with_setup(
                "ssh_access_to_nodes_pot",
                orchestrator::ssh_access_to_nodes::config,
                seq(vec![
                    sys_t(
                        "root_cannot_authenticate",
                        orchestrator::ssh_access_to_nodes::root_cannot_authenticate,
                    ),
                    sys_t(
                        "readonly_cannot_authenticate_without_a_key",
                        orchestrator::ssh_access_to_nodes::readonly_cannot_authenticate_without_a_key,
                    ),
                    sys_t(
                        "readonly_cannot_authenticate_with_random_key",
                        orchestrator::ssh_access_to_nodes::readonly_cannot_authenticate_with_random_key,
                    ),
                    sys_t(
                        "keys_in_the_subnet_record_can_be_updated",
                        orchestrator::ssh_access_to_nodes::keys_in_the_subnet_record_can_be_updated,
                    ),
                    sys_t(
                        "keys_for_unassigned_nodes_can_be_updated",
                        orchestrator::ssh_access_to_nodes::keys_for_unassigned_nodes_can_be_updated,
                    ),
                    sys_t(
                        "multiple_keys_can_access_one_account",
                        orchestrator::ssh_access_to_nodes::multiple_keys_can_access_one_account,
                    ),
                    sys_t(
                        "multiple_keys_can_access_one_account_on_unassigned_nodes",
                        orchestrator::ssh_access_to_nodes::multiple_keys_can_access_one_account_on_unassigned_nodes,
                    ),
                    sys_t(
                        "updating_readonly_does_not_remove_backup_keys",
                        orchestrator::ssh_access_to_nodes::updating_readonly_does_not_remove_backup_keys,
                    ),
                    sys_t(
                        "can_add_max_number_of_readonly_and_backup_keys",
                        orchestrator::ssh_access_to_nodes::can_add_max_number_of_readonly_and_backup_keys,
                    ),
                    sys_t(
                        "cannot_add_more_than_max_number_of_readonly_or_backup_keys",
                        orchestrator::ssh_access_to_nodes::cannot_add_more_than_max_number_of_readonly_or_backup_keys,
                    ),
                ]),
            ),
        ],
    ).with_alert(TEST_FAILURE_CHANNEL));

    let xnet_slo_3_subnets = message_routing::xnet_slo_test::config_hotfix_slo_3_subnets();
    m.add_suite(suite(
        "hotfix",
        vec![pot_with_setup(
            "xnet_slo_3_subnets_pot",
            xnet_slo_3_subnets.clone().build(),
            par(vec![sys_t(
                "xnet_slo_3_subnets_test",
                xnet_slo_3_subnets.test(),
            )]),
        )],
    ));

    let xnet_slo_3_subnets = message_routing::xnet_slo_test::config_prod_slo_3_subnets();
    m.add_suite(suite(
        "prod_slo",
        vec![pot_with_setup(
            "xnet_slo_3_subnets_pot",
            xnet_slo_3_subnets.clone().build(),
            par(vec![sys_t(
                "xnet_slo_3_subnets_test",
                xnet_slo_3_subnets.test(),
            )]),
        )],
    ));

    let xnet_nightly_120_subnets = message_routing::xnet_slo_test::config_nightly_120_subnets();
    m.add_suite(
        suite(
            "staging", //runs nightly, allowed to fail
            vec![
                pot_with_setup(
                    "xnet_120_subnets_pot",
                    xnet_nightly_120_subnets.clone().build(),
                    par(vec![sys_t(
                        "xnet_slo_120_subnets_test",
                        xnet_nightly_120_subnets.test(),
                    )]),
                ),
                pot_with_setup(
                    "canister_http_fault_tolerance",
                    canister_http::lib::config,
                    par(vec![sys_t(
                        "http_fault_tolerance",
                        canister_http::http_fault_tolerance::test,
                    )]),
                ),
                // pot_with_setup(
                //     "large_subnet_workload_pot",
                //     networking::subnet_update_workload::large_config,
                //     seq(vec![
                //         sys_t(
                //             "large_subnet_update_workload_test",
                //             networking::subnet_update_workload::large_subnet_test,
                //         ),
                //         sys_t(
                //             "large_subnet_query_workload_test",
                //             networking::subnet_query_workload::large_subnet_test,
                //         ),
                //     ]),
                // )
                // .with_default_vm_resources(Some(VmResources {
                //     vcpus: Some(NrOfVCPUs::new(16)),
                //     memory_kibibytes: Some(AmountOfMemoryKiB::new(67108864)), // 64GiB
                //     boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                // })),
                //.with_vm_allocation(VmAllocationStrategy::DistributeAcrossDcs),
            ],
        )
        .with_alert(TEST_FAILURE_CHANNEL),
    );

    m.add_suite(suite(
        "nightly_default_subnet_query_workload_long_duration_test",
        vec![pot_with_setup(
            "nightly_default_subnet_query_workload_long_duration_test",
            networking::subnet_update_workload::default_config,
            par(vec![sys_t(
                "default_subnet_query_workload_long_duration_test",
                networking::subnet_query_workload::long_duration_test,
            )]),
        )
        .with_default_vm_resources(Some(VmResources {
            vcpus: None,
            memory_kibibytes: None,
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
        }))],
    ));
    m.add_suite(suite(
        "nightly_default_subnet_update_workload_long_duration_test",
        vec![pot_with_setup(
            "nightly_default_subnet_update_workload_long_duration_test",
            networking::subnet_update_workload::default_config,
            par(vec![sys_t(
                "default_subnet_update_workload_long_duration_test",
                networking::subnet_update_workload::long_duration_test,
            )]),
        )],
    ));
    m.add_suite(suite(
        "nightly_default_subnet_update_workload_large_payload",
        vec![pot_with_setup(
            "nightly_default_subnet_update_workload_large_payload",
            networking::subnet_update_workload::default_config,
            par(vec![sys_t(
                "default_subnet_update_workload_large_payload",
                networking::subnet_update_workload::large_payload_test,
            )]),
        )],
    ));

    let network_reliability = networking::network_reliability::config_sys_4_nodes_app_4_nodes();
    let xnet_nightly_3_subnets = message_routing::xnet_slo_test::config_nightly_3_subnets();
    let xnet_nightly_29_subnets = message_routing::xnet_slo_test::config_nightly_29_subnets();
    m.add_suite(suite(
        "nightly_short_duration",
        vec![
            pot_with_setup(
                "xnet_slo_3_subnets_pot",
                xnet_nightly_3_subnets.clone().build(),
                par(vec![sys_t(
                    "xnet_slo_3_subnets_test",
                    xnet_nightly_3_subnets.test(),
                )]),
            ),
            pot_with_setup(
                "xnet_slo_29_subnets_pot",
                xnet_nightly_29_subnets.clone().build(),
                par(vec![sys_t(
                    "xnet_slo_29_subnets_test",
                    xnet_nightly_29_subnets.test(),
                )]),
            ),
            pot_with_setup(
                "canister_http_remote",
                canister_http::lib::config,
                par(vec![sys_t(
                    "http_basic_remote",
                    canister_http::http_basic_remote::test,
                )]),
            ),
            pot_with_setup(
                "canister_http_time_out",
                canister_http::lib::config,
                seq(vec![sys_t(
                    "http_time_out",
                    canister_http::http_time_out::test,
                )]),
            ),
            pot_with_setup(
                "two_third_latency_pot",
                workload_counter_canister_test::two_third_latency_config,
                par(vec![sys_t(
                    "workload_counter_canister_test",
                    workload_counter_canister_test::two_third_latency_test,
                )]),
            )
            .with_vm_allocation(VmAllocationStrategy::DistributeAcrossDcs),
            pot_with_setup(
                "network_reliability_pot",
                network_reliability.build(),
                par(vec![sys_t(
                    "network_reliability_test",
                    network_reliability.test(),
                )]),
            )
            .with_default_vm_resources(Some(VmResources {
                vcpus: Some(NrOfVCPUs::new(8)),
                memory_kibibytes: Some(AmountOfMemoryKiB::new(50331648)), // 48GiB
                boot_image_minimal_size_gibibytes: None,
            })),
        ],
    ));

    m.add_suite(
        suite(
            "hourly",
            vec![
                pot_with_setup(
                    "boundary_subnet_workload_pot",
                    networking::subnet_update_workload::boundary_config,
                    seq(vec![
                        sys_t(
                            "boundary_subnet_update_workload_test",
                            networking::subnet_update_workload::boundary_test,
                        ),
                    ]),
                ),
                pot_with_setup(
                    "basic_health_pot_single_host",
                    basic_health_test::config_single_host,
                    par(vec![sys_t("basic_health_test", basic_health_test::test)]),
                )
                .with_alert(TEST_FAILURE_CHANNEL)
                .with_alert(ENG_TESTING_CHANNEL),
                pot_with_setup(
                    "node_reassignment_pot",
                    orchestrator::node_reassignment_test::config,
                    par(vec![sys_t(
                        "node_reassignment_test",
                        orchestrator::node_reassignment_test::test,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "token_fault_tolerance_pot",
                    ledger_tests::token_fault_tolerance::config,
                    par(vec![sys_t(
                        "token_fault_tolerance_test",
                        ledger_tests::token_fault_tolerance::test,
                    )]),
                ),
                pot_with_setup(
                    "create_subnet",
                    nns_tests::create_subnet::hourly_config,
                    par(vec![sys_t("create_subnet", nns_tests::create_subnet::test)]),
                ),
                pot_with_setup(
                    "canister_http_correctness",
                    canister_http::lib::config,
                    par(vec![sys_t(
                        "http_correctness",
                        canister_http::http_correctness::test,
                    )]),
                ),
                pot_with_setup(
                    "rejoin",
                    message_routing::rejoin_test::config,
                    par(vec![sys_t("rejoin", message_routing::rejoin_test::test)]),
                ),
                pot_with_setup(
                    "workload_counter_canister_pot",
                    workload_counter_canister_test::config,
                    par(vec![sys_t(
                        "workload_counter_canister_test",
                        workload_counter_canister_test::short_test,
                    )]),
                )
                .with_alert(TEST_FAILURE_CHANNEL)
                .with_alert(ENG_TESTING_CHANNEL),
                pot_with_setup(
                    "nns_backup_pot",
                    orchestrator::nns_backup::config,
                    par(vec![sys_t(
                        "nns_backup_test",
                        orchestrator::nns_backup::test,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "tecdsa_signature_same_subnet_pot",
                    tecdsa::tecdsa_signature_test::config,
                    seq(vec![t(
                        "test_threshold_ecdsa_signature_same_subnet",
                        tecdsa::tecdsa_signature_test::test_threshold_ecdsa_signature_same_subnet,
                    )])
                ).with_alert(ENG_CONSENSUS_CHANNEL),
                pot_with_setup(
                    "tecdsa_signature_from_other_subnet_pot",
                    tecdsa::tecdsa_signature_test::config,
                    seq(vec![t(
                        "test_threshold_ecdsa_signature_from_other_subnet",
                        tecdsa::tecdsa_signature_test::test_threshold_ecdsa_signature_from_other_subnet,
                    )])
                ).with_alert(ENG_CONSENSUS_CHANNEL),
                pot_with_setup(
                    "tecdsa_signature_fails_without_cycles_pot",
                    tecdsa::tecdsa_signature_test::config,
                    seq(vec![t(
                        "test_threshold_ecdsa_signature_fails_without_cycles",
                        tecdsa::tecdsa_signature_test::test_threshold_ecdsa_signature_fails_without_cycles,
                    )])
                ).with_alert(ENG_CONSENSUS_CHANNEL),
                pot_with_setup(
                    "tecdsa_signature_from_nns_without_cycles_pot",
                    tecdsa::tecdsa_signature_test::config,
                    seq(vec![t(
                        "test_threshold_ecdsa_signature_from_nns_without_cycles",
                        tecdsa::tecdsa_signature_test::test_threshold_ecdsa_signature_from_nns_without_cycles,
                    )])
                ).with_alert(ENG_CONSENSUS_CHANNEL),
                pot_with_setup(
                    "unassigned_node_upgrade_test_pot",
                    orchestrator::unassigned_node_upgrade_test::config,
                    par(vec![sys_t(
                        "unassigned_node_upgrade_test",
                        orchestrator::unassigned_node_upgrade_test::test,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "unstuck_subnet_test_pot",
                    orchestrator::unstuck_subnet_test::config,
                    par(vec![sys_t(
                        "unstuck_subnet_test",
                        orchestrator::unstuck_subnet_test::test,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "upgrade_with_alternative_urls_pot",
                    orchestrator::upgrade_with_alternative_urls::config,
                    par(vec![sys_t(
                        "upgrade_with_alternative_urls",
                        orchestrator::upgrade_with_alternative_urls::test,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "subnet_recovery_app_no_upgrade_with_tecdsa",
                    orchestrator::subnet_recovery_app_subnet::setup_same_nodes_tecdsa,
                    par(vec![sys_t(
                        "subnet_recovery_app_no_upgrade_with_tecdsa",
                        orchestrator::subnet_recovery_app_subnet::test_no_upgrade_with_tecdsa,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "subnet_recovery_app_same_nodes_with_tecdsa",
                    orchestrator::subnet_recovery_app_subnet::setup_same_nodes_tecdsa,
                    par(vec![sys_t(
                        "subnet_recovery_app_same_nodes_with_tecdsa",
                        orchestrator::subnet_recovery_app_subnet::test_with_tecdsa,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "subnet_recovery_app_failover_nodes_with_tecdsa",
                    orchestrator::subnet_recovery_app_subnet::setup_failover_nodes_tecdsa,
                    par(vec![sys_t(
                        "subnet_recovery_app_failover_nodes_with_tecdsa",
                        orchestrator::subnet_recovery_app_subnet::test_with_tecdsa,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "subnet_recovery_app_no_upgrade_enable_tecdsa",
                    orchestrator::subnet_recovery_app_subnet::setup_same_nodes,
                    par(vec![sys_t(
                        "subnet_recovery_app_no_upgrade_enable_tecdsa",
                        orchestrator::subnet_recovery_app_subnet::test_no_upgrade_with_tecdsa,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "subnet_recovery_app_same_nodes_enable_tecdsa",
                    orchestrator::subnet_recovery_app_subnet::setup_same_nodes,
                    par(vec![sys_t(
                        "subnet_recovery_app_same_nodes_enable_tecdsa",
                        orchestrator::subnet_recovery_app_subnet::test_with_tecdsa,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
                pot_with_setup(
                    "subnet_recovery_app_failover_nodes_enable_tecdsa",
                    orchestrator::subnet_recovery_app_subnet::setup_failover_nodes,
                    par(vec![sys_t(
                        "subnet_recovery_app_failover_nodes_enable_tecdsa",
                        orchestrator::subnet_recovery_app_subnet::test_with_tecdsa,
                    )]),
                ).with_alert(ENG_ORCHESTRATOR_CHANNEL),
            ],
        )
        .with_alert(TEST_FAILURE_CHANNEL),
    );

    // The tests in this suite require canisters to be build prior to
    // running the tests which is why we separate it out.
    m.add_suite(
        suite(
            "wasm_generator",
            vec![pot_with_setup(
                "wasm_generator_pot",
                wasm_generator_test::config,
                par(vec![sys_t(
                    "wasm_generator_test",
                    wasm_generator_test::test,
                )]),
            )],
        )
        .with_alert(TEST_FAILURE_CHANNEL),
    );

    m.add_suite(
        suite(
            "subnet_recovery",
            vec![
                pot_with_setup(
                    "subnet_recovery_app_same_nodes",
                    orchestrator::subnet_recovery_app_subnet::setup_same_nodes,
                    par(vec![sys_t(
                        "subnet_recovery_app_same_nodes",
                        orchestrator::subnet_recovery_app_subnet::test_without_tecdsa,
                    )]),
                ),
                pot_with_setup(
                    "subnet_recovery_app_no_upgrade",
                    orchestrator::subnet_recovery_app_subnet::setup_same_nodes,
                    par(vec![sys_t(
                        "subnet_recovery_app_no_upgrade",
                        orchestrator::subnet_recovery_app_subnet::test_no_upgrade_without_tecdsa,
                    )]),
                ),
                pot_with_setup(
                    "subnet_recovery_app_failover_nodes",
                    orchestrator::subnet_recovery_app_subnet::setup_failover_nodes,
                    par(vec![sys_t(
                        "subnet_recovery_app_failover_nodes",
                        orchestrator::subnet_recovery_app_subnet::test_without_tecdsa,
                    )]),
                ),
                pot_with_setup(
                    "subnet_recovery_nns_same_nodes",
                    orchestrator::subnet_recovery_nns_subnet::setup,
                    par(vec![sys_t(
                        "subnet_recovery_nns_same_nodes",
                        orchestrator::subnet_recovery_nns_subnet::test,
                    )]),
                ),
                pot_with_setup(
                    "subnet_recovery_nns_failover_nodes",
                    orchestrator::subnet_recovery_nns_failover::setup,
                    par(vec![sys_t(
                        "subnet_recovery_nns_failover_nodes",
                        orchestrator::subnet_recovery_nns_failover::test,
                    )]),
                ),
            ],
        )
        .with_alert(ENG_ORCHESTRATOR_CHANNEL)
        .with_alert(TEST_FAILURE_CHANNEL),
    );

    m.add_suite(
        suite(
            "upgrade_compatibility",
            vec![
                pot_with_setup(
                    "downgrade_app_subnet_with_ecdsa",
                    orchestrator::downgrade_with_ecdsa::config,
                    par(vec![sys_t(
                        "downgrade_app_subnet_with_ecdsa",
                        orchestrator::downgrade_with_ecdsa::downgrade_app_subnet,
                    )]),
                ),
                pot_with_setup(
                    "upgrade_downgrade_app_subnet",
                    orchestrator::upgrade_downgrade::config,
                    par(vec![sys_t(
                        "upgrade_downgrade_app_subnet",
                        orchestrator::upgrade_downgrade::upgrade_downgrade_app_subnet,
                    )]),
                ),
                pot_with_setup(
                    "upgrade_downgrade_nns_subnet",
                    orchestrator::upgrade_downgrade::config,
                    par(vec![sys_t(
                        "upgrade_downgrade_nns_subnet",
                        orchestrator::upgrade_downgrade::upgrade_downgrade_nns_subnet,
                    )]),
                ),
                pot_with_setup(
                    "backup_manager_pot",
                    orchestrator::backup_manager::config,
                    par(vec![sys_t(
                        "backup_manager_test",
                        orchestrator::backup_manager::test,
                    )]),
                ),
            ],
        )
        .with_alert(ENG_ORCHESTRATOR_CHANNEL),
    );

    m.add_suite(
        suite(
            "rosetta",
            vec![pot_with_setup(
                "rosetta_pot",
                rosetta_test::config,
                par(vec![sys_t(
                    "rosetta_test_everything",
                    rosetta_test::test_everything,
                )]),
            )],
        )
        .with_alert(ENG_FINANCIAL_INTEGRATION)
        .with_alert(TEST_FAILURE_CHANNEL),
    );

    let network_robustness_loss = networking::network_robustness::loss_config();
    let network_robustness_delay = networking::network_robustness::delay_config();
    let network_robustness_bandwidth = networking::network_robustness::bandwidth_config();
    m.add_suite(suite(
        "network_robustness",
        vec![
            pot_with_setup(
                "network_robustness_loss_pot",
                network_robustness_loss.build(),
                par(vec![sys_t(
                    "network_robustness_loss_test",
                    network_robustness_loss.test(),
                )]),
            ),
            pot_with_setup(
                "network_robustness_delay_pot",
                network_robustness_delay.build(),
                par(vec![sys_t(
                    "network_robustness_delay_test",
                    network_robustness_delay.test(),
                )]),
            ),
            pot_with_setup(
                "network_robustness_bandwidth_pot",
                network_robustness_bandwidth.build(),
                par(vec![sys_t(
                    "network_robustness_bandwidth_test",
                    network_robustness_bandwidth.test(),
                )]),
            ),
        ],
    ));
    m.add_suite(suite(
        "manual",
        vec![pot_with_setup(
            "canister_http_correctness",
            canister_http::lib::config,
            par(vec![sys_t(
                "http_correctness",
                canister_http::http_correctness::test,
            )]),
        )],
    ));
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
    for failed_pot in suite_result
        .children
        .iter()
        .filter(|p| matches!(p.result, TestResult::Failed(_)))
    {
        let message = format!(
            r#"Pot `{pot_name}` *failed*. <{ci_job_url}|log>.
Commit: <{ci_project_url}/-/commit/{ci_commit_sha}|{ci_commit_short_sha}>.
IC_VERSION_ID: `{ic_version_id}`."#,
            pot_name = failed_pot.name,
            ci_job_url = validated_args.ci_job_url,
            ci_project_url = validated_args.ci_project_url,
            ci_commit_sha = validated_args.ci_commit_sha,
            ci_commit_short_sha = validated_args.ci_commit_short_sha,
            ic_version_id = validated_args.ic_version_id
        );
        failed_pot.alert_channels.iter().for_each(|channel| {
            alerts.insert(alert_id, SlackAlert::new(channel.clone(), message.clone()));
            alert_id += 1;
        });
    }
    alerts
}
