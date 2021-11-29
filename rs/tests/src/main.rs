//! # System Tests
//!
//! ## Tackling Flakiness & Disabling Tests
//!
//! name and github-handle of the principal author of test. If you think you
//! have identified a flaky test and therefore want to disable it, at least
//! include the principal author on the corresponding PR.
#![allow(unused_imports)]
use ic_tests::consensus;
use ic_tests::execution::pot1_config;
use std::ffi::OsString;
use std::fs;
use std::panic;
use structopt::StructOpt;

use fondue::*; // Import the macros for easier pot declaration
use fondue::{
    log::Logger,
    manager::{HasHandle, Manager},
    pot,
};
use ic_fondue::{
    ic_manager::IcManager,
    internet_computer::{InternetComputer, Subnet},
};
use ic_registry_subnet_type::SubnetType;

use ic_tests::basic_health_test;
use ic_tests::cow_safety_test;
use ic_tests::cycles_minting_test;
use ic_tests::execution;
use ic_tests::feature_flags;
use ic_tests::malicious_input_test;
use ic_tests::nns_canister_upgrade_test;
use ic_tests::nns_follow_test;
use ic_tests::nns_uninstall_code_proposal_test;
use ic_tests::nns_voting_test;
use ic_tests::node_removal_test;
use ic_tests::registry_authentication_test;
use ic_tests::replica_determinism_test;
use ic_tests::request_auth_malicious_replica_test;
use ic_tests::request_signature_test;
use ic_tests::rosetta_test;
use ic_tests::security::nns_voting_fuzzing_poc_test;
use ic_tests::security::system_api_security_test;
use ic_tests::subnet_creation;
use ic_tests::token_balance_test;
use ic_tests::transaction_ledger_correctness_test;
use ic_tests::util::CYCLES_LIMIT_PER_CANISTER;

mod cli;
use cli::Options;

use std::time::Instant;

/// Defines the test suite of system tests. If you want to add more tests in
/// here, just add another entry to the vector with the corresponding pot.
/// The [basic_health_pot] have a tutorial nature to them and are good
/// places to look for simple test examples.
fn all_pots() -> Vec<fondue::pot::Pot<IcManager>> {
    // HAVE YOU READ THE README AT THE TOP?
    vec![
        pot1(),
        pot1_2(),
        basic_pot_with_all_features_enabled(),
        inter_canister_queries_pot(),
        canister_lifecycle_memory_capacity_pot(),
        cycles_restrictions_pot(),
        canister_lifecycle_memory_size_pot(),
        compute_allocation_pot(),
        max_number_of_canisters_pot(),
        node_removal_pot(),
        basic_health_pot(),
        consensus_liveness_with_equivocation_pot(),
        consensus_safety_pot(),
        certified_registry_pot(),
        cow_safety_pot(),
        rosetta_pot(),
        cycles_minting_pot(),
        token_balance_pot(),
        execution_config_is_none_pot(),
        nns_follow_pot(),
        nns_uninstall_pot(),
        nns_voting_pot(),
        nns_voting_fuzzing_poc_pot(),
        nns_canister_upgrade_pot(),
        nns_subnet_creation_pot(),
        replica_determinism_pot(),
        max_payload_pot(),
        dual_workload_pot(),
        subnet_capacity_pot(),
        system_subnets_pot(),
        transaction_ledger_correctness_pot(),
        request_auth_malicious_replica_pot(),
        system_api_security_pot(),
    ]
}

/// If its your first time looking at or writing tests, the basic_health_test is
/// the ideal place to start. Because this test does /not/ change its
/// environment--e.g., adding or removing replicas--it is declared as a
/// composable test and consists in a setup phase. The setup is responsible for
/// installing a number of passive health monitoring devices in the network.
/// After the setup runs, the actual test is ran.
fn basic_health_pot() -> pot::Pot<IcManager> {
    composable!(
        "basic_health_pot",
        basic_health_test::config(),
        steps! {
            basic_health_test::basic_health_test,
            feature_flags::ecdsa_signatures_disabled_by_default
        }
    )
}

/// In contrast to a composable test, we also have isolated tests, which
/// are allowed to manipulate their environment. In this case,
/// [node_removal_test::test] removes a node. Isolated tests consists of a
/// single [node_removal_test::config] and a single [node_removal_test::test]
/// function, which must exist in the module passed to the macro below.
fn node_removal_pot() -> pot::Pot<IcManager> {
    isolated_test!(node_removal_test)
}

fn cow_safety_pot() -> pot::Pot<IcManager> {
    isolated_test!(cow_safety_test)
}

// Defines a composable pot with a given configuration and a number of steps.
//
// WARNING: The order in which the steps are declared does NOT correspond to
// the order they are executed.
//
// Given that this pot contains tests from various components, it's labeled
// pot1, for lack of a better name.
fn pot1() -> pot::Pot<IcManager> {
    composable!(
        "pot1",
        pot1_config(),
        steps! {
            request_signature_test::test,
            malicious_input_test::test,
            execution::api_tests::test_raw_rand_api,
            execution::big_stable_memory::can_access_big_heap_and_big_stable_memory,
            execution::big_stable_memory::can_access_big_stable_memory,
            execution::big_stable_memory::can_handle_overflows_when_indexing_stable_memory,
            execution::big_stable_memory::can_handle_out_of_bounds_access,
            execution::big_stable_memory::canister_traps_if_32_bit_api_used_on_big_memory,
            execution::canister_lifecycle::create_canister_via_ingress_fails,
            execution::canister_lifecycle::create_canister_via_canister_succeeds,
            execution::canister_lifecycle::create_canister_with_controller_and_controllers_fails,
            execution::canister_lifecycle::create_canister_with_one_controller,
            execution::canister_lifecycle::create_canister_with_no_controllers,
            execution::canister_lifecycle::create_canister_with_multiple_controllers,
            execution::canister_lifecycle::create_canister_with_too_many_controllers_fails,
            execution::canister_lifecycle::create_canister_with_empty_settings,
            execution::canister_lifecycle::create_canister_with_none_settings_field,
            execution::canister_lifecycle::create_canister_with_empty_settings,
            execution::canister_lifecycle::create_canister_with_settings,
            execution::canister_lifecycle::create_canister_with_freezing_threshold,
            execution::canister_lifecycle::create_canister_with_invalid_freezing_threshold_fails,
            execution::canister_lifecycle::managing_a_canister_with_wrong_controller_fails,
            execution::canister_lifecycle::delete_stopped_canister_succeeds,
            execution::canister_lifecycle::delete_running_canister_fails,
            execution::canister_lifecycle::canister_can_manage_other_canister,
            execution::canister_lifecycle::canister_can_manage_other_canister_batched,
            execution::canister_lifecycle::canister_large_wasm_small_memory_allocation,
            execution::canister_lifecycle::canister_large_initial_memory_small_memory_allocation,
            execution::canister_lifecycle::refunds_after_uninstall_are_refunded,
            execution::canister_lifecycle::update_settings_with_controller_and_controllers_fails,
            execution::canister_lifecycle::update_settings_multiple_controllers,
            execution::cycles_transfer::can_transfer_cycles_from_a_canister_to_another,
            execution::ingress_rate_limiting::canister_accepts_ingress_by_default,
            execution::ingress_rate_limiting::empty_canister_inspect_rejects_all_messages,
            execution::ingress_rate_limiting::canister_can_accept_ingress,
            execution::ingress_rate_limiting::canister_only_accepts_ingress_with_payload,
            execution::ingress_rate_limiting::canister_rejects_ingress_only_from_one_caller
        }
    )
}

/// In order to parallelize execution of the large number of execution related
/// system tests, we declare a second pot with the same configuration.
fn pot1_2() -> pot::Pot<IcManager> {
    composable!(
        "pot2",
        pot1_config(),
        steps! {
            execution::queries::query_reply_sizes,
            execution::nns_shielding::mint_cycles_supported_on_system_subnet,
            execution::nns_shielding::mint_cycles_not_supported_on_application_subnet,
            execution::nns_shielding::no_cycle_balance_limit_on_nns_subnet,
            execution::nns_shielding::max_cycles_per_canister_system_subnet,
            execution::nns_shielding::max_cycles_per_canister_application_subnet,
            execution::nns_shielding::app_canister_attempt_initiating_dkg_fails,
            execution::canister_heartbeat::canister_heartbeat_is_called_at_regular_intervals,
            execution::canister_heartbeat::stopping_a_canister_with_a_heartbeat_succeeds,
            execution::canister_heartbeat::canister_heartbeat_can_call_another_canister,
            execution::canister_heartbeat::canister_heartbeat_can_call_multiple_canisters_xnet,
            execution::canister_heartbeat::canister_heartbeat_can_stop,
            execution::canister_heartbeat::canister_heartbeat_cannot_reply
        }
    )
}

fn compute_allocation_pot() -> pot::Pot<IcManager> {
    composable!(
        "compute_allocation_pot",
        execution::canister_lifecycle::config_compute_allocation(),
        steps! {execution::canister_lifecycle::total_compute_allocation_cannot_be_exceeded}
    )
}

fn request_auth_malicious_replica_pot() -> pot::Pot<IcManager> {
    composable!(
        "request_auth_malicious_replica_pot",
        request_auth_malicious_replica_test::config(),
        steps! {request_auth_malicious_replica_test::test => "request_auth_malicious_replica_test"}
    )
}

fn canister_lifecycle_memory_capacity_pot() -> pot::Pot<IcManager> {
    composable!(
        "canister_lifecycle_memory_capacity_pot",
        execution::config_memory_capacity(),
        steps! { execution::canister_lifecycle::exceeding_memory_capacity_fails_when_memory_allocation_changes }
    )
}

fn subnet_capacity_pot() -> pot::Pot<IcManager> {
    composable!(
        "subnet_capacity_pot",
        execution::config_memory_capacity(),
        steps! {
            execution::subnet_capacity::exceeding_memory_capacity_fails_during_message_execution
        }
    )
}

fn cycles_restrictions_pot() -> pot::Pot<IcManager> {
    composable!(
        "cycles_restrictions_pot",
        execution::config_system_verified_application_subnets(),
        steps! {
            execution::cycles_transfer::cannot_send_cycles_from_application_to_verified_subnets,
            execution::canister_lifecycle::controller_and_controllee_on_different_subnets,
            execution::instructions_limit::can_use_more_instructions_during_install_code
        }
    )
}

fn max_number_of_canisters_pot() -> pot::Pot<IcManager> {
    composable!(
        "max_number_of_canisters_pot",
        execution::canister_lifecycle::config_max_number_of_canisters(),
        steps! {
            execution::canister_lifecycle::creating_canisters_fails_if_limit_of_allowed_canisters_is_reached
        }
    )
}

fn inter_canister_queries_pot() -> pot::Pot<IcManager> {
    composable!(
        "inter_canister_queries_pot",
        execution::config_system_verified_subnets(),
        steps! {
            execution::inter_canister_queries::intermediate_canister_does_not_reply,
            execution::inter_canister_queries::cannot_query_xnet_canister,
            execution::inter_canister_queries::simple_query,
            execution::inter_canister_queries::self_loop_fails,
            execution::inter_canister_queries::canisters_loop_fails,
            execution::inter_canister_queries::query_two_canisters,
            execution::inter_canister_queries::query_three_canisters,
            execution::inter_canister_queries::canister_queries_non_existent,
            execution::inter_canister_queries::canister_queries_does_not_reply,
            execution::inter_canister_queries::inter_canister_query_first_canister_multiple_request,
            execution::call_on_cleanup::is_called_if_reply_traps,
            execution::call_on_cleanup::is_called_if_reject_traps,
            execution::call_on_cleanup::changes_are_discarded_if_trapped,
            execution::call_on_cleanup::changes_are_discarded_in_query,
            execution::call_on_cleanup::is_called_in_query
        }
    )
}

fn canister_lifecycle_memory_size_pot() -> pot::Pot<IcManager> {
    composable!(
        "canister_lifecycle_memory_size_pot",
        execution::canister_lifecycle::config_canister_memory_size(),
        steps! { execution::canister_lifecycle::memory_allocation_not_set }
    )
}

fn system_subnets_pot() -> pot::Pot<IcManager> {
    composable!(
        "system_subnets_pot",
        execution::config_many_system_subnets(),
        steps! {
            execution::nns_shielding::non_nns_canister_attempt_to_create_canister_on_another_subnet_fails,
            execution::nns_shielding::nns_canister_attempt_to_create_canister_on_another_subnet_succeeds
        }
    )
}

/// Basic pot where all features are enabled.
fn basic_pot_with_all_features_enabled() -> pot::Pot<IcManager> {
    composable!(
        "basic_pot_with_all_features_enabled",
        feature_flags::basic_config_with_all_features_enabled(),
        steps! {
            feature_flags::mock_ecdsa_signatures_are_supported
        }
    )
}

/// In case you want to choose the name of each composable step explicitely,
/// you can use the more manual form by defining each step individually.
fn consensus_liveness_with_equivocation_pot() -> pot::Pot<IcManager> {
    composable!(
        "consensus_liveness_with_equivocation_pot",
        consensus::liveness_with_equivocation_test::config(),
        steps! {consensus::liveness_with_equivocation_test::test => "consensus_liveness_with_equivocation_test"}
    )
}

fn consensus_safety_pot() -> pot::Pot<IcManager> {
    composable!(
        "consensus_safety_pot",
        consensus::safety_test::config(),
        steps! {consensus::safety_test::test => "consensus_safety_test"}
    )
}

fn certified_registry_pot() -> pot::Pot<IcManager> {
    composable!(
        "certified_registry_pot",
        registry_authentication_test::config(),
        steps! {registry_authentication_test::test => "registry_authentication_test"}
    )
}

fn nns_canister_upgrade_pot() -> pot::Pot<IcManager> {
    composable!(
        "nns_canister_upgrade_pot",
        nns_canister_upgrade_test::config(),
        steps! {nns_canister_upgrade_test::test => "nns_canister_upgrade_test"}
    )
}

fn nns_follow_pot() -> pot::Pot<IcManager> {
    composable!(
        "nns_follow_pot",
        nns_follow_test::config(),
        steps! {nns_follow_test::test => "nns_follow_test"}
    )
}

fn nns_voting_pot() -> pot::Pot<IcManager> {
    composable!(
        "nns_voting_pot",
        nns_voting_test::config(),
        steps! {nns_voting_test::test => "nns_voting_test"}
    )
}

fn nns_voting_fuzzing_poc_pot() -> pot::Pot<IcManager> {
    composable!(
        "nns_voting_fuzzing_poc_pot",
        nns_voting_fuzzing_poc_test::config(),
        steps! {nns_voting_fuzzing_poc_test::test => "nns_voting_fuzzing_poc_test"}
    )
}

fn nns_uninstall_pot() -> pot::Pot<IcManager> {
    composable!(
        "nns_uninstall_pot",
        nns_uninstall_code_proposal_test::config(),
        steps! {nns_uninstall_code_proposal_test::test => "nns_uninstall_code_proposal_test"}
    )
}

fn nns_subnet_creation_pot() -> pot::Pot<IcManager> {
    composable!(
        "nns_subnet_creation_pot",
        subnet_creation::config(),
        steps! {subnet_creation::create_subnet_with_assigned_nodes_fails}
    )
}

fn rosetta_pot() -> pot::Pot<IcManager> {
    composable!(
        "rosetta_pot",
        rosetta_test::config(),
        steps! {
            rosetta_test::test_everything
        }
    )
}

fn cycles_minting_pot() -> pot::Pot<IcManager> {
    composable!(
        "cycles_minting_pot",
        cycles_minting_test::config(),
        steps! {
            cycles_minting_test::test
        }
    )
}

fn token_balance_pot() -> pot::Pot<IcManager> {
    composable!(
        "token_balance_pot",
        token_balance_test::config(),
        steps! {token_balance_test::test => "token_balance_test"}
    )
}

fn execution_config_is_none_pot() -> pot::Pot<IcManager> {
    composable!(
        "execution_config_is_none_pot",
        execution::nns_shielding::config(),
        steps! {
            execution::nns_shielding::max_cycles_per_canister_system_subnet,
            execution::nns_shielding::max_cycles_per_canister_is_none_application_subnet
        }
    )
}

fn replica_determinism_pot() -> pot::Pot<IcManager> {
    composable!(
        "replica_determinism_pot",
        replica_determinism_test::config(),
        steps! {replica_determinism_test::test => "replica_determinism_test"}
    )
}

fn dual_workload_pot() -> pot::Pot<IcManager> {
    composable!(
        "dual_workload_pot",
        consensus::payload_builder_test::dual_workload_config(),
        steps! {consensus::payload_builder_test::dual_workload_test}
    )
}

fn max_payload_pot() -> pot::Pot<IcManager> {
    composable!(
        "max_payload_pod",
        consensus::payload_builder_test::max_payload_size_config(),
        steps! {
            consensus::payload_builder_test::max_ingress_payload_size_test,
            consensus::payload_builder_test::max_xnet_payload_size_test
        }
    )
}

fn transaction_ledger_correctness_pot() -> pot::Pot<IcManager> {
    composable!(
        "transaction_ledger_correctness_pot",
        transaction_ledger_correctness_test::config(),
        steps! {transaction_ledger_correctness_test::test => "transaction_ledger_correctness_test"}
    )
}

fn system_api_security_pot() -> pot::Pot<IcManager> {
    composable!(
        "system_security_tests",
        system_api_security_test::config(),
        steps! {
            system_api_security_test::malicious_inputs => "malicious input - security",
            system_api_security_test::malicious_intercanister_calls => "malicious inter canister calls - security"
        }
    )
}

fn main() {
    let started_at = Instant::now();
    let opt = cli::Options::from_args();
    // Here we create a default fondue config but then randomize the rng_seed.
    // If the user specified their own seed 's', then 's' will be used when we
    // `modify_fondue_exec_config`.
    let fondue_default_config = fondue::pot::execution::Config::default().random_pot_rng_seed();
    let fondue_config = opt.modify_fondue_exec_config(fondue_default_config);

    // Select the pots that match the filter, if any.
    let scheduled_pots = if let Some(ref pot_filter) = opt.pot_filter {
        all_pots()
            .into_iter()
            .filter(|p| p.derived_name.contains(pot_filter))
            .collect()
    } else {
        all_pots()
    };

    // filter for experimental pots if necessary
    let scheduled_pots = scheduled_pots
        .into_iter()
        .filter(|p| opt.experimental || !p.experimental)
        .collect();

    let runtime_stats_writer = opt.runtime_stats_file.map(|p| {
        std::io::BufWriter::new(Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .expect("couldn't open runtime_stats file"),
        ))
    });

    if let Some(res) = fondue::pot::execution::execute(&fondue_config, scheduled_pots) {
        res.print_summary();
        print_rng_seed(&fondue_config);

        if let Some(mut w) = runtime_stats_writer {
            serde_json::to_writer_pretty(
                &mut w,
                &res.extract_runtime_summary("system_tests".to_string(), started_at),
            )
            .expect("failed to write runtime statistics to file");
        }
        if !res.was_successful() {
            // propagate error in case of any failures
            std::process::exit(1);
        }
    } else {
        print_rng_seed(&fondue_config);
        std::process::exit(1);
    }
}

fn print_rng_seed<ManCfg>(fondue_config: &fondue::pot::execution::Config<ManCfg>) {
    println!(
        "(To reproduce this exact run, make sure to use '--seed {}')",
        fondue_config.pot_config.rng_seed
    );
}
