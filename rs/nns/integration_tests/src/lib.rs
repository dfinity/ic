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
mod cycles_minting_canister;

#[cfg(test)]
mod fuzz;

#[cfg(test)]
mod get_monthly_node_provider_rewards;

#[cfg(test)]
mod governance_mem_test;

#[cfg(test)]
mod gtc;

#[cfg(test)]
mod ledger;

#[cfg(test)]
mod lifeline;

#[cfg(test)]
mod node_assignment;

#[cfg(test)]
mod reinstall_and_upgrade;

#[cfg(test)]
mod root;

#[cfg(test)]
mod add_canister;

#[cfg(test)]
mod stable_mem;

#[cfg(test)]
mod subnet_handler;

#[cfg(test)]
mod upgrades_handler;

#[cfg(test)]
mod rewards;

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
mod known_neurons;
