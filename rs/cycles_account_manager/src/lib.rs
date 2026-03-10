//! This module contains the `CyclesAccountManager` which is responsible for
//! updating the cycles account of canisters.
//!
//! A canister has an associated cycles balance, and may `send` a part of
//! this cycles balance to another canister
//! In addition to sending cycles to another canister, a canister `spend`s
//! cycles in the following three ways:
//! a) executing messages,
//! b) sending messages to other canisters,
//! c) storing data over time/rounds
//! Each of the above spending is done in three phases:
//! 1. reserving maximum cycles the operation can require
//! 2. executing the operation and return `cycles_spent`
//! 3. reimburse the canister with `cycles_reserved` - `cycles_spent`

pub const CRITICAL_ERROR_RESPONSE_CYCLES_REFUND: &str =
    "cycles_account_manager_response_cycles_refund_error";

pub const CRITICAL_ERROR_EXECUTION_CYCLES_REFUND: &str =
    "cycles_account_manager_execution_cycles_refund_error";

mod cycles_account_manager;
pub use cycles_account_manager::{
    CyclesAccountManager, CyclesAccountManagerError, IngressInductionCost, ResourceSaturation,
};
