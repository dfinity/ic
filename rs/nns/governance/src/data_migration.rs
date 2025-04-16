//! This module is the home of code that you call from post_upgrade and/or init,
//! and only has an effect once.
//!
//! Ideally, once such code is released, it gets deleted. At the same time,
//! ideally, it is safe for the same code to be in multiple releases.
//!
//! A typical use case is that you add some field, and you want to give it some
//! initial value, but thereafter, it can be changed as the result of requests
//! (e.g. create a proposal followed by many votes in favor).

#[path = "data_migration_tests.rs"]
#[cfg(test)]
mod tests;
