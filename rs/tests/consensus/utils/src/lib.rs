use std::path::PathBuf;

use ic_system_test_driver::{
    driver::{test_env::TestEnv, test_env_api::{set_var_to_path, HasTopologySnapshot, IcNodeContainer}},
    util::{block_on, MetricsFetcher},
};
use slog::{info, warn};

pub mod node;
pub mod performance;
pub mod rw_message;
pub mod ssh_access;
pub mod subnet;
pub mod upgrade;

pub fn set_sandbox_env_vars(dir: PathBuf) {
    set_var_to_path("SANDBOX_BINARY", dir.join("canister_sandbox"));
    set_var_to_path("LAUNCHER_BINARY", dir.join("sandbox_launcher"));
    set_var_to_path("COMPILER_BINARY", dir.join("compiler_sandbox"));
}

/// Fetches metrics from the given nodes and checks whether some error counters have increased.
/// Note: this shouldn't be used in system tests where we have malicious nodes as some of the
/// counters could increase due to malicious behavior.
pub async fn assert_no_consensus_error_counters_increased(env: &TestEnv) {
    let nodes = env.topology_snapshot().subnets().flat_map(|subnet| subnet.nodes());

    const ERROR_COUNTERS: &[&str; 8] = &[
        "consensus_invalidated_artifacts",
        "certification_invalidated_artifacts",
        "dkg_invalidated_artifacts",
        "idkg_invalidated_artifacts",
        "canister_http_invalidated_artifacts",
        "orchestrator_cup_deserialization_failed_total",
        "orchestrator_master_public_key_changed_errors_total",
        "orchestrator_state_removal_failed_total",
    ];

    info!(env.logger(), "Fetching metrics: {:?}", ERROR_COUNTERS);

    let fetcher = MetricsFetcher::new(
        nodes,
        ERROR_COUNTERS.iter().map(ToString::to_string).collect(),
    );

    let metrics = match fetcher.fetch::<u64>().await {
        Ok(metrics) => metrics,
        Err(err) => {
            warn!(env.logger(), "Failed to fetch the metrics: {}", err);

            return;
        }
    };

    for (metric_name, metric_values) in metrics {
        if metric_values.iter().any(|value| *value > 0) {
            panic!("{metric_name} has a non zero value!");
        }
    }

    info!(env.logger(), "No error counter increased!");
}

pub async fn assert_no_consensus_error_counters_increased_blocking(env: &TestEnv) {
    block_on(assert_no_consensus_error_counters_increased(env))
}
