//! Integration tests for the NNS canisters.
//!
//! These tests instantiate a local replica, install the NNS canisters and then
//! proceed to perform operations and verify they completed successfully, and
//! that the state is the expected one.
//!
//! This is not a library at all. However, if this was under `tests/`, then each
//! file would become its own crate, and the tests would run sequentially. By
//! pretending it's a library with several modules inside, `cargo test` is
//! supposed to run all tests in parallel, because they are all in the same
//! crate.
#[cfg(test)]
mod add_or_remove_data_centers;

#[cfg(test)]
mod autonomy;

#[cfg(test)]
mod bad_input;

#[cfg(test)]
mod canister_playground;

#[cfg(test)]
mod cycles_minting_canister;

#[cfg(test)]
mod cycles_minting_canister_with_exchange_rate_canister;

#[cfg(test)]
mod node_provider_remuneration;

#[cfg(test)]
mod node_provider_remuneration_performance_based_with_golden_nns_state;

#[cfg(test)]
mod governance_get_build_metadata_test;

#[cfg(test)]
mod gtc;

#[cfg(test)]
mod http_request;

#[cfg(test)]
mod ledger;

#[cfg(test)]
mod lifeline;

#[cfg(test)]
mod node_assignment;

#[cfg(test)]
mod reinstall_and_upgrade;

#[cfg(test)]
mod reset_root;

#[cfg(test)]
mod root;

#[cfg(test)]
mod rewards;

#[cfg(test)]
mod add_canister;

#[cfg(test)]
mod stable_mem;

#[cfg(test)]
mod subnet_handler;

#[cfg(test)]
mod upgrades_handler;

#[cfg(test)]
mod node_operator_handler;

#[cfg(test)]
mod clear_provisional_whitelist;

#[cfg(test)]
mod voting_rewards;

#[cfg(test)]
mod governance_upgrade;

#[cfg(test)]
mod update_node_rewards_table;

#[cfg(test)]
mod root_proposals;

#[cfg(test)]
mod update_unassigned_nodes_config;

#[cfg(test)]
mod wait_for_quiet;

#[cfg(test)]
mod governance_neurons;

#[cfg(test)]
mod governance_time_warp;

#[cfg(test)]
mod governance_proposals;

#[cfg(test)]
mod known_neurons;

#[cfg(test)]
mod update_node_provider;

#[cfg(test)]
mod list_node_providers;

#[cfg(test)]
mod network_economics;

#[cfg(test)]
mod neuron_following;

#[cfg(test)]
mod neuron_voting;

#[cfg(test)]
mod uninstall_canister_by_proposal;

#[cfg(test)]
mod canister_upgrade;

#[cfg(test)]
mod subnet_rental_canister;

#[cfg(test)]
mod stop_or_start_canister;

#[cfg(test)]
mod api_boundary_node_queries;

#[cfg(test)]
mod upgrade_canisters_with_golden_nns_state;

#[cfg(test)]
mod create_service_nervous_system;

#[cfg(test)]
mod registry_get_chunk;
