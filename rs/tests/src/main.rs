//! # Legacy System Tests
//!
//! Please do not add new tests here but learn from the README how write
//! system tests these days.
//!
//! ## Tackling Flakiness & Disabling Tests
//!
//! name and github-handle of the principal author of test. If you think you
//! have identified a flaky test and therefore want to disable it, at least
//! include the principal author on the corresponding PR.
#![allow(unused_imports)]
use clap::Parser;
use ic_tests::consensus;
use std::ffi::OsString;
use std::fs;
use std::panic;

use ic_fondue::pot;
use ic_fondue::*; // Import the macros for easier pot declaration
use ic_fondue::{
    ic_instance::{LegacyInternetComputer, Subnet},
    ic_manager::IcManager,
};
use ic_registry_subnet_type::SubnetType;
use slog::Logger;

use ic_tests::cli::Options;
use ic_tests::consensus::cow_safety_test;
use ic_tests::execution;
use ic_tests::execution::system_api_security_test;
use ic_tests::nns_tests::nns_voting_fuzzing_poc_test;
use ic_tests::tecdsa;
use ic_tests::util::CYCLES_LIMIT_PER_CANISTER;

use std::time::Instant;

/// Defines the test suite of system tests. If you want to add more tests in
/// here, just add another entry to the vector with the corresponding pot.
fn all_pots() -> Vec<ic_fondue::pot::Pot> {
    // HAVE YOU READ THE README AT THE TOP?
    vec![
        max_payload_pot(),
        dual_workload_pot(),
        system_subnets_pot(),
        request_auth_malicious_replica_pot(),
        system_api_security_pot(),
        tecdsa_complaint_test_pot(),
    ]
}

fn request_auth_malicious_replica_pot() -> pot::Pot {
    composable!(
        "request_auth_malicious_replica_pot",
        consensus::request_auth_malicious_replica_test::config(),
        steps! {consensus::request_auth_malicious_replica_test::test => "request_auth_malicious_replica_test"}
    )
}

fn system_subnets_pot() -> pot::Pot {
    composable!(
        "system_subnets_pot",
        execution::legacy_config_many_system_subnets(),
        steps! {
            execution::nns_shielding::non_nns_canister_attempt_to_create_canister_on_another_subnet_fails,
            execution::nns_shielding::nns_canister_attempt_to_create_canister_on_another_subnet_succeeds
        }
    )
}

fn dual_workload_pot() -> pot::Pot {
    composable!(
        "dual_workload_pot",
        consensus::payload_builder_test::dual_workload_config(),
        steps! {consensus::payload_builder_test::dual_workload_test}
    )
}

fn max_payload_pot() -> pot::Pot {
    composable!(
        "max_payload_pod",
        consensus::payload_builder_test::max_payload_size_config(),
        steps! {
            consensus::payload_builder_test::max_ingress_payload_size_test,
            consensus::payload_builder_test::max_xnet_payload_size_test
        }
    )
}

fn system_api_security_pot() -> pot::Pot {
    composable!(
        "system_security_tests",
        system_api_security_test::config(),
        steps! {
            system_api_security_test::malicious_inputs => "malicious input - security",
            system_api_security_test::malicious_intercanister_calls => "malicious inter canister calls - security"
        }
    )
}

fn tecdsa_complaint_test_pot() -> pot::Pot {
    composable!(
        "tecdsa_complaint_test",
        tecdsa::tecdsa_complaint_test::config(),
        steps! {
            tecdsa::tecdsa_complaint_test::test_threshold_ecdsa_complaint => "tECDSA complaints test"
        }
    )
}

fn main() {
    let started_at = Instant::now();
    let opt = Options::parse();
    // Here we create a default fondue config but then randomize the rng_seed.
    // If the user specified their own seed 's', then 's' will be used when we
    // `modify_fondue_exec_config`.
    let fondue_default_config = ic_fondue::pot::execution::Config::default().random_pot_rng_seed();
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

    let results_writer = opt.result_file.map(|p| {
        std::io::BufWriter::new(Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
                .expect("couldn't open result-file"),
        ))
    });

    print_rng_seed(&fondue_config);
    if let Some(res) = ic_fondue::pot::execution::execute(&fondue_config, scheduled_pots) {
        if let Some(mut w) = results_writer {
            serde_json::to_writer_pretty(
                &mut w,
                &res.treeify("system_tests".to_string(), started_at),
            )
            .expect("failed to write results to file");
        }
        if !res.was_successful() {
            // propagate error in case of any failures
            std::process::exit(1);
        }
    } else {
        std::process::exit(1);
    }
}

fn print_rng_seed(fondue_config: &ic_fondue::pot::execution::Config) {
    println!(
        "(To reproduce this exact run, make sure to use '--seed {}')",
        fondue_config.pot_config.rng_seed
    );
}
