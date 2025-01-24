#![cfg_attr(not(test), deny(missing_docs))]
//! The consensus crate provides implementations of the consensus algorithm of
//! the internet computer block chain, a component responsible for executing
//! distributed key generation using said block chain to hold the state of the
//! algorithm, and a component responsible for certifying state hashes produced
//! by the upper layers of the internet computer.

pub mod certification;
pub mod consensus;
pub mod cup_utils;
pub mod idkg;

pub use cup_utils::{make_registry_cup, make_registry_cup_from_cup_contents};
