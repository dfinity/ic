//! Tests that rely on interleaving two method calls on the governance canister
//! (in particular, when one method is suspended when it calls out to the ledger
//! canister).

extern crate core;

// TODO - remove macro when used in tests - NNS1-1260
#[allow(dead_code)]
mod interleaving;

// TODO - remove macro when used in tests - NNS1-1260
#[allow(dead_code)]
mod fixtures;
