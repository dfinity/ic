use crate::numeric::Wei;
use crate::state::sweeper_funding::{
    InvalidSweeperFundingConfig, SweeperFundingAccounting, SweeperFundingConfig,
};

const BURN: u128 = 100_000_000_000_000_000; // 0.1 ETH
const FEE: u128 = 1_000_000_000_000_000; // 0.001 ETH

mod accounting {
    use super::*;

    #[test]
    fn should_start_empty() {
        let accounting = SweeperFundingAccounting::default();

        assert_eq!(accounting.cumulative_burned(), Wei::ZERO);
        assert_eq!(accounting.cumulative_spent(), Wei::ZERO);
        assert_eq!(accounting.burned_not_yet_spent(), Wei::ZERO);
    }

    #[test]
    fn should_leave_no_surplus_after_a_successful_funding() {
        let mut accounting = SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(BURN));
        accounting.record_finalized_funding(Wei::new(BURN - FEE), Wei::new(FEE));

        assert_eq!(accounting.cumulative_spent(), Wei::new(BURN));
        assert_eq!(
            accounting.burned_not_yet_spent(),
            Wei::ZERO,
            "burn and spend must balance exactly on success"
        );
    }

    #[test]
    fn should_keep_the_unspent_fee_as_surplus_after_a_successful_funding() {
        let mut accounting = SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(BURN));
        // The burn covers the fee the transaction may pay; the block charges half of it.
        accounting.record_finalized_funding(Wei::new(BURN - FEE), Wei::new(FEE / 2));

        assert_eq!(
            accounting.burned_not_yet_spent(),
            Wei::new(FEE - FEE / 2),
            "the fee provisioned but never paid stays as backing"
        );
    }

    #[test]
    fn should_keep_the_burn_as_surplus_after_a_failed_funding() {
        let mut accounting = SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(BURN));
        accounting.record_finalized_funding(Wei::ZERO, Wei::new(FEE));

        assert_eq!(accounting.cumulative_spent(), Wei::new(FEE));
        assert_eq!(
            accounting.burned_not_yet_spent(),
            Wei::new(BURN - FEE),
            "everything except the gas actually paid stays as backing"
        );
        assert!(
            accounting.cumulative_burned() > accounting.cumulative_spent(),
            "burned must exceed spent, i.e. ckETH is over-backed rather than under-backed"
        );
    }

    #[test]
    fn should_accumulate_across_fundings() {
        let mut accounting = SweeperFundingAccounting::default();
        for _ in 0..3 {
            accounting.record_burn(Wei::new(BURN));
            accounting.record_finalized_funding(Wei::new(BURN - FEE), Wei::new(FEE));
        }

        assert_eq!(accounting.cumulative_burned(), Wei::new(3 * BURN));
        assert_eq!(accounting.cumulative_spent(), Wei::new(3 * BURN));
        assert_eq!(accounting.burned_not_yet_spent(), Wei::ZERO);
    }

    #[test]
    #[should_panic(expected = "more ETH spent on sweeping than ckETH burned")]
    fn should_panic_when_spending_more_than_was_burned() {
        let mut accounting = SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(FEE));

        accounting.record_finalized_funding(Wei::new(BURN), Wei::new(FEE));
    }
}

mod config {
    use super::*;

    /// ckETH's mainnet minimum withdrawal amount, i.e. the floor a funding's burn is held to.
    const MINIMUM_BURN: u128 = 30_000_000_000_000_000;

    #[test]
    fn should_accept_the_defaults() {
        let config = SweeperFundingConfig::default();

        assert_eq!(config.validate(Wei::new(MINIMUM_BURN)), Ok(()));
        assert!(
            config.target > config.low_water_mark,
            "the default target must leave refill headroom"
        );
    }

    #[test]
    fn should_reject_a_target_at_or_below_the_low_water_mark() {
        for target in [Wei::new(BURN), Wei::new(BURN - 1), Wei::ZERO] {
            let config = SweeperFundingConfig {
                low_water_mark: Wei::new(BURN),
                target,
            };

            assert_eq!(
                config.validate(Wei::new(MINIMUM_BURN)),
                Err(InvalidSweeperFundingConfig::TargetNotAboveLowWaterMark {
                    low_water_mark: Wei::new(BURN),
                    target,
                }),
                "a target of {target} must be rejected: funding would loop"
            );
        }
    }

    #[test]
    fn should_reject_headroom_below_the_minimum_burn() {
        let config = SweeperFundingConfig {
            low_water_mark: Wei::new(20_000_000_000_000_000), // 0.02 ETH
            target: Wei::new(30_000_000_000_000_000),         // 0.03 ETH -> only 0.01 of headroom
        };

        assert_eq!(
            config.validate(Wei::new(MINIMUM_BURN)),
            Err(InvalidSweeperFundingConfig::HeadroomBelowMinimumBurn {
                headroom: Wei::new(10_000_000_000_000_000),
                minimum_burn: Wei::new(MINIMUM_BURN),
            }),
            "0.03 ckETH burned to move 0.01 ETH is a 3x over-burn on every cycle"
        );
    }

    #[test]
    fn should_accept_headroom_exactly_at_the_minimum_burn() {
        let config = SweeperFundingConfig {
            low_water_mark: Wei::new(20_000_000_000_000_000),
            target: Wei::new(20_000_000_000_000_000 + MINIMUM_BURN),
        };

        assert_eq!(config.validate(Wei::new(MINIMUM_BURN)), Ok(()));
    }

    #[test]
    fn should_not_fund_above_the_low_water_mark() {
        let config = SweeperFundingConfig {
            low_water_mark: Wei::new(BURN),
            target: Wei::new(2 * BURN),
        };

        assert_eq!(config.amount_due(Wei::new(2 * BURN)), None);
        assert_eq!(
            config.amount_due(Wei::new(BURN)),
            None,
            "at the mark, not below"
        );
    }

    #[test]
    fn should_fund_up_to_the_target() {
        let config = SweeperFundingConfig {
            low_water_mark: Wei::new(BURN),
            target: Wei::new(2 * BURN),
        };

        assert_eq!(
            config.amount_due(Wei::new(BURN - 1)),
            Some(Wei::new(BURN + 1)),
            "top up the shortfall to the target, not a fixed amount"
        );
        assert_eq!(config.amount_due(Wei::ZERO), Some(Wei::new(2 * BURN)));
    }
}
