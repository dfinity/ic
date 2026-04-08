use crate::{
    governance::{MAX_NEURON_AGE_FOR_AGE_BONUS, max_dissolve_delay_seconds},
    is_mission_70_voting_rewards_enabled,
};
use rust_decimal::Decimal;

/// Currently, only used by an integration test.
pub fn dissolve_delay_bonus_multiplier(dissolve_delay_seconds: u64) -> Decimal {
    let max_dissolve_delay_seconds = max_dissolve_delay_seconds();

    let dissolve_delay_seconds = dissolve_delay_seconds.clamp(0, max_dissolve_delay_seconds);

    // t is (clamped) dissolve delay in units of max dissolve delay, so 0.0 <= t <= 1.0.
    let t = Decimal::from(dissolve_delay_seconds) / Decimal::from(max_dissolve_delay_seconds);

    (if is_mission_70_voting_rewards_enabled() {
        Decimal::from(2) * t * t
    } else {
        t
    }) + Decimal::from(1)
}

pub(crate) fn age_bonus_multiplier(age_seconds: u64) -> Decimal {
    let age_seconds = Decimal::from(age_seconds.clamp(0, MAX_NEURON_AGE_FOR_AGE_BONUS));

    // t is (clamped) age in units of max age, so its value is from 0.0 to 1.0
    let t = age_seconds / Decimal::from(MAX_NEURON_AGE_FOR_AGE_BONUS);

    // 0.25 * t + 1
    t / Decimal::from(4) + Decimal::from(1)
}

#[cfg(test)]
#[path = "voting_power_tests.rs"]
mod tests;
