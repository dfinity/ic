//! An implementation of RegistryClient intended to be used in canister
//! where polling in the background is not required because handed over to a timer.
//! The code is entirely copied from `ic-registry-client-fake` and more tests added.
pub mod client;
pub mod data_provider;
pub mod stable_memory;
