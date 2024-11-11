//! Integration tests for the SNS canisters.
//!
//! These tests instantiate a local replica, install the SNS canisters and then
//! proceed to perform operations and verify they completed successfully, and
//! that the state is the expected one.
//!
//! This is not a library at all. However, if this was under `tests/`, then each
//! file would become its own crate, and the tests would run sequentially. By
//! pretending it's a library with several modules inside, `cargo test` is
//! supposed to run all tests in parallel, because they are all in the same
//! crate.

#[cfg(test)]
mod ledger;

#[cfg(test)]
mod nervous_system_parameters;

#[cfg(test)]
mod nervous_system_functions;

#[cfg(test)]
mod neuron;

#[cfg(test)]
mod proposals;

#[cfg(test)]
mod root;

#[cfg(test)]
mod swap;

#[cfg(test)]
mod upgrade_canister;

#[cfg(test)]
mod governance;

#[cfg(test)]
mod sns_treasury;

#[cfg(test)]
mod payment_flow;

#[cfg(test)]
mod initialization_flow;

#[cfg(test)]
mod manage_ledger_parameters;

#[cfg(test)]
mod manage_dapp_canister_settings;

#[cfg(test)]
mod http_request;
