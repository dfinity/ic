#![deny(missing_docs)]
//! The consensus crate provides implementations of the consensus algorithm of
//! the internet computer block chain, a component responsible for executing
//! distributed key generation using said block chain to hold the state of the
//! algorithm, and a component responsible for certifying state hashes produced
//! by the upper layers of the internet computer.

pub mod certification;
pub mod consensus;
pub mod dkg;
pub mod ecdsa;
