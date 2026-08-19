use crate::numeric::Wei;
use crate::state::sweeper_funding::{SweeperFundingAccounting, SweeperFundingConfig};

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
    use crate::state::sweeper_funding::SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS;

    /// ckETH's mainnet minimum withdrawal amount, i.e. the floor a funding's burn is held to.
    const MINIMUM_BURN: u128 = 30_000_000_000_000_000;

    fn config_for(minimum_withdrawal_amount: u128) -> SweeperFundingConfig {
        SweeperFundingConfig::for_minimum_withdrawal_amount(Wei::new(minimum_withdrawal_amount))
            .expect("test setup: the bounds must fit")
    }

    #[test]
    fn should_derive_the_bounds_from_the_minimum_withdrawal_amount() {
        let config = config_for(MINIMUM_BURN);

        assert_eq!(
            config.target,
            Wei::new(MINIMUM_BURN * SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS as u128)
        );
        assert_eq!(
            config.low_water_mark,
            config.target.checked_div_floor(2_u8).unwrap()
        );
    }

    /// The relation the two bounds exist for: the smallest amount a funding moves is the gap between
    /// them, and it has to clear the minimum the burn is held to. Derived, it holds for any input
    /// rather than for the pairs a proposal happens to set.
    #[test]
    fn should_leave_headroom_above_the_minimum_withdrawal_amount() {
        for minimum in [
            1,
            1_000,
            10_000_000_000, // Sepolia's ledger transfer fee
            MINIMUM_BURN,
            1_000 * MINIMUM_BURN,
        ] {
            let config = config_for(minimum);
            let headroom = config
                .target
                .checked_sub(config.low_water_mark)
                .expect("the target must exceed the low-water mark");

            assert!(
                headroom >= Wei::new(minimum),
                "a funding of a minter with minimum {minimum} moves at least {headroom}, \
                 which must cover the minimum itself"
            );
        }
    }

    #[test]
    fn should_report_no_bounds_when_the_target_would_not_fit() {
        let too_large = Wei::MAX
            .checked_div_floor(SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS)
            .unwrap()
            .checked_add(Wei::ONE)
            .unwrap();

        assert_eq!(
            SweeperFundingConfig::for_minimum_withdrawal_amount(too_large),
            None,
            "the caller must find out rather than the derivation trapping"
        );
    }

    #[test]
    fn should_not_fund_above_the_low_water_mark() {
        let config = config_for(MINIMUM_BURN);

        assert_eq!(config.amount_due(config.target), None);
        assert_eq!(
            config.amount_due(config.low_water_mark),
            None,
            "at the mark, not below"
        );
    }

    #[test]
    fn should_fund_up_to_the_target() {
        let config = config_for(MINIMUM_BURN);
        let just_below = config.low_water_mark.checked_sub(Wei::ONE).unwrap();

        assert_eq!(
            config.amount_due(just_below),
            Some(config.target.checked_sub(just_below).unwrap()),
            "top up the shortfall to the target, not a fixed amount"
        );
        assert_eq!(config.amount_due(Wei::ZERO), Some(config.target));
    }
}
