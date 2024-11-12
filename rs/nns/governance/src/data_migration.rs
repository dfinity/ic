//! This module is the home of code that you call from post_upgrade and/or init,
//! and only has an effect once.
//!
//! Ideally, once such code is released, it gets deleted. At the same time,
//! ideally, it is safe for the same code to be in multiple releases.
//!
//! A typical use case is that you add some field, and you want to give it some
//! initial value, but thereafter, it can be changed as the result of requests
//! (e.g. create a proposal followed by many votes in favor).

use crate::pb::v1::{Governance, VotingPowerEconomics};

#[path = "data_migration_tests.rs"]
#[cfg(test)]
mod tests;

/// This ensures that the fields in voting_power_economics are set.
///
/// If they already have Some value, the existing values are left alone.
///
/// Whereas, if values are missing (or voting_power_economics itself is None),
/// they get set according to DEFAULT_VOTING_POWER_ECONOMICS.
///
/// What we expect in production is that when governance is upgraded,
/// voting_power_economics will default to None, and during post_ugprade, this
/// gets called, causing voting_power_economics to be set to
/// DEFAULT_VOTING_POWER_ECONOMICS.
///
/// In testing, when a new governance canister is created,
/// voting_power_economics gets set in init, which also calls this.
pub fn set_initial_voting_power_economics(governance: &mut Governance) {
    let economics = governance.economics.as_mut();

    let Some(economics) = economics else {
        // DO NOT MERGE - Log.
        return;
    };

    let voting_power_economics = economics.voting_power_economics.as_mut();
    let default = VotingPowerEconomics::with_default_values();

    let Some(voting_power_economics) = voting_power_economics else {
        // DO NOT MERGE - Log.
        economics.voting_power_economics = Some(default);
        return;
    };

    // This is weird, but we handle it anyway instead of freaking out.
    // DO NOT MERGE - Log.

    let VotingPowerEconomics {
        start_reducing_voting_power_after_seconds,
        clear_following_after_seconds,
    } = voting_power_economics;

    if start_reducing_voting_power_after_seconds.is_none() {
        // DO NOT MERGE - Log.
        *start_reducing_voting_power_after_seconds =
            default.start_reducing_voting_power_after_seconds;
    }

    if clear_following_after_seconds.is_none() {
        // DO NOT MERGE - Log.
        *clear_following_after_seconds = default.clear_following_after_seconds;
    }
}
