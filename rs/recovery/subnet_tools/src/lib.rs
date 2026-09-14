//! Helpers shared by the tools that reshape the canister id ranges of a
//! subnet -- `subnet_splitting` and `subnet_merging`.
//!
//! Both tools halt a subnet at a CUP, work on the state it halted at, validate
//! what they produced against the CUP and the NNS signed state tree, and let an
//! operator confirm a dashboard before the next proposal. This crate holds the
//! parts of that which are the same for either operation, as well as the
//! `ic-admin` command builders and small utilities that only one of them
//! happens to use so far; what carries the logic of splitting or of merging
//! stays in the respective tool.

pub mod admin_helper;
pub mod agent_helper;
pub mod state_tool_helper;
pub mod steps;
pub mod utils;
pub mod validation;
