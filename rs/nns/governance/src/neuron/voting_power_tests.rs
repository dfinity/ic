use super::*;
use crate::{
    temporarily_disable_mission_70_voting_rewards, temporarily_enable_mission_70_voting_rewards,
};
use ic_nervous_system_common::{ONE_MONTH_SECONDS, ONE_YEAR_SECONDS};

#[test]
fn test_dissolve_delay_bonus_multiplier_pre_mission_70() {
    let _restore_on_drop = temporarily_disable_mission_70_voting_rewards();

    // Test the endpoints.
    assert_eq!(dissolve_delay_bonus_multiplier(0), Decimal::from(1));
    assert_eq!(
        dissolve_delay_bonus_multiplier(8 * ONE_YEAR_SECONDS),
        Decimal::from(2)
    );

    // Test intermediate points.
    assert_eq!(
        dissolve_delay_bonus_multiplier(ONE_YEAR_SECONDS),
        Decimal::from(1) + Decimal::from(1) / Decimal::from(8)
    );
    assert_eq!(
        dissolve_delay_bonus_multiplier(2 * ONE_YEAR_SECONDS),
        Decimal::from(1) + Decimal::from(2) / Decimal::from(8)
    );
    assert_eq!(
        dissolve_delay_bonus_multiplier(3 * ONE_YEAR_SECONDS),
        Decimal::from(1) + Decimal::from(3) / Decimal::from(8)
    );
    assert_eq!(
        dissolve_delay_bonus_multiplier(4 * ONE_YEAR_SECONDS),
        Decimal::from(1) + Decimal::from(4) / Decimal::from(8)
    );
    assert_eq!(
        dissolve_delay_bonus_multiplier(5 * ONE_YEAR_SECONDS),
        Decimal::from(1) + Decimal::from(5) / Decimal::from(8)
    );
    assert_eq!(
        dissolve_delay_bonus_multiplier(6 * ONE_YEAR_SECONDS),
        Decimal::from(1) + Decimal::from(6) / Decimal::from(8)
    );
    assert_eq!(
        dissolve_delay_bonus_multiplier(7 * ONE_YEAR_SECONDS),
        Decimal::from(1) + Decimal::from(7) / Decimal::from(8)
    );

    // Test beyond max dissolve delay. (No neuron should have this, but we can
    // and do defend against it by clamping.)
    assert_eq!(
        dissolve_delay_bonus_multiplier(15 * ONE_YEAR_SECONDS),
        Decimal::from(2)
    );
}

#[test]
fn test_dissolve_delay_bonus_multiplier_while_mission_70_is_engaged() {
    let _restore_on_drop = temporarily_enable_mission_70_voting_rewards();

    // Test the endpoints.
    assert_eq!(dissolve_delay_bonus_multiplier(0), Decimal::from(1));
    assert_eq!(
        dissolve_delay_bonus_multiplier(2 * ONE_YEAR_SECONDS),
        Decimal::from(3)
    );

    // Test intermediate points.
    for t_months in 3..24 {
        let previous = dissolve_delay_bonus_multiplier((t_months - 2) * ONE_MONTH_SECONDS);
        let current = dissolve_delay_bonus_multiplier((t_months - 1) * ONE_MONTH_SECONDS);
        let next = dissolve_delay_bonus_multiplier((t_months) * ONE_MONTH_SECONDS);

        let d1 = current - previous;
        let d2 = next - current;

        // Dissolve delay bonus increases with greater dissolve delay.
        assert!(
            d1 > Decimal::from(0),
            "{t_months}: {previous} vs. {current} vs. {next}"
        );
        assert!(
            d2 > Decimal::from(0),
            "{t_months}: {previous} vs. {current} vs. {next}"
        );

        // Dissolve delay bonus skews towards those with greater dissolve delay, i.e. is convex.
        assert!(
            d2 > d1,
            "{t_months}: {previous} vs. {current} vs. {next} ({d1} vs. {d2})"
        );
    }
}

#[test]
fn test_age_bonus_multiplier() {
    // Test endpoints.
    assert_eq!(age_bonus_multiplier(0), Decimal::from(1));
    assert_eq!(
        age_bonus_multiplier(4 * ONE_YEAR_SECONDS),
        Decimal::from_f64_retain(1.25).unwrap()
    );

    // Test intermediate points.
    assert_eq!(
        age_bonus_multiplier(ONE_YEAR_SECONDS),
        Decimal::from_f64_retain(1.0625).unwrap()
    );
    assert_eq!(
        age_bonus_multiplier(2 * ONE_YEAR_SECONDS),
        Decimal::from_f64_retain(1.1250).unwrap()
    );
    assert_eq!(
        age_bonus_multiplier(3 * ONE_YEAR_SECONDS),
        Decimal::from_f64_retain(1.1875).unwrap()
    );
}
