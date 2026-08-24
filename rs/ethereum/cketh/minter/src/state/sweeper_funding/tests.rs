use crate::numeric::Wei;
use crate::state::sweeper_funding::{SweeperFundingAccounting, SweeperFundingConfig};

const BURN: u128 = 100_000_000_000_000_000; // 0.1 ETH
const FEE: u128 = 1_000_000_000_000_000; // 0.001 ETH

/// The two sides of the invariant, in isolation from the pipeline that decides when a funding is
/// accepted and when its transaction settles — that sequencing is covered where it lives, by the
/// event-driven tests in [`crate::state::tests`] and [`crate::sweeper::tests`].
mod accounting {
    use super::*;

    #[test]
    fn should_count_only_failed_fundings() {
        let mut accounting = SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(BURN));
        accounting.record_finalized_funding(Wei::new(BURN - FEE), Wei::new(FEE));

        assert_eq!(
            accounting.failed_fundings(),
            0,
            "a funding that delivered its ETH is not a failure"
        );

        // What the caller does on a failure receipt: no ETH transferred, and the count bumped.
        accounting.record_burn(Wei::new(BURN));
        accounting.record_failed_funding();
        accounting.record_finalized_funding(Wei::ZERO, Wei::new(FEE));

        assert_eq!(accounting.failed_fundings(), 1);
    }

    #[test]
    fn should_start_empty() {
        let accounting = SweeperFundingAccounting::default();

        assert_eq!(accounting.cumulative_burned(), Wei::ZERO);
        assert_eq!(accounting.cumulative_spent(), Wei::ZERO);
        assert_eq!(accounting.burned_not_yet_spent(), Wei::ZERO);
        assert_eq!(accounting.sweeper_balance_lower_bound(), Wei::ZERO);
    }

    #[test]
    fn should_not_credit_the_sweeper_balance_bound_before_the_funding_finalizes() {
        let mut accounting = SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(BURN));

        assert_eq!(
            accounting.sweeper_balance_lower_bound(),
            Wei::ZERO,
            "a burn alone has moved no ETH, so it bounds nothing"
        );
    }

    #[test]
    fn should_bound_the_sweeper_balance_by_what_fundings_delivered() {
        let mut accounting = SweeperFundingAccounting::default();
        for _ in 1..=3 {
            accounting.record_burn(Wei::new(BURN));
            accounting.record_finalized_funding(Wei::new(BURN - FEE), Wei::new(FEE));
        }

        assert_eq!(
            accounting.sweeper_balance_lower_bound(),
            Wei::new(3 * (BURN - FEE)),
            "the bound counts the transfers, not the burns that paid for them"
        );
    }

    #[test]
    fn should_not_credit_the_sweeper_balance_bound_for_a_failed_funding() {
        let mut accounting = SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(BURN));
        accounting.record_finalized_funding(Wei::ZERO, Wei::new(FEE));

        assert_eq!(
            accounting.sweeper_balance_lower_bound(),
            Wei::ZERO,
            "a failed funding delivered nothing, however much it burned"
        );
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
        accounting.record_finalized_funding(Wei::new(BURN - FEE), Wei::new(FEE / 2));

        assert_eq!(
            accounting.burned_not_yet_spent(),
            Wei::new(FEE / 2),
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
        for _ in 1..=3 {
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
    use proptest::prelude::*;

    const MINIMUM_BURN: u128 = 30_000_000_000_000_000; // ckETH's mainnet minimum withdrawal amount

    fn config_for(minimum_withdrawal_amount: u128) -> SweeperFundingConfig {
        SweeperFundingConfig::for_minimum_withdrawal_amount(Wei::new(minimum_withdrawal_amount))
            .expect("test setup: the bounds must fit")
    }

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

    proptest! {
        #[test]
        fn should_fund_up_to_the_target(
            balance in 0..MINIMUM_BURN * SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS as u128
        ) {
            let config = config_for(MINIMUM_BURN);
            let balance = Wei::new(balance);
            prop_assume!(balance < config.low_water_mark);

            let amount_due = config
                .amount_due(balance)
                .expect("a balance below the low-water mark is due a funding");

            prop_assert_eq!(balance.checked_add(amount_due), Some(config.target));
        }
    }
}

mod gate {
    use crate::numeric::Wei;
    use crate::state::sweeper_funding::{PrepaidGasUnavailable, check_prepaid_sweep_gas};

    const GAS: u128 = 1_000_000_000_000_000; // 0.001 ETH

    #[test]
    fn should_allow_spending_covered_by_the_bound() {
        assert_eq!(
            check_prepaid_sweep_gas(Wei::new(10 * GAS), Wei::new(GAS)),
            Ok(Wei::new(10 * GAS))
        );
    }

    #[test]
    fn should_allow_spending_exactly_the_bound() {
        assert_eq!(
            check_prepaid_sweep_gas(Wei::new(GAS), Wei::new(GAS)),
            Ok(Wei::new(GAS)),
            "the whole prepaid balance is spendable; it was all burned for"
        );
    }

    #[test]
    fn should_refuse_when_the_bound_is_one_wei_short() {
        assert_eq!(
            check_prepaid_sweep_gas(Wei::new(GAS), Wei::new(GAS + 1)),
            Err(PrepaidGasUnavailable::Insufficient {
                available: Wei::new(GAS),
                required: Wei::new(GAS + 1),
            })
        );
    }

    #[test]
    fn should_refuse_everything_before_the_first_funding_lands() {
        assert_eq!(
            check_prepaid_sweep_gas(Wei::ZERO, Wei::new(1)),
            Err(PrepaidGasUnavailable::Insufficient {
                available: Wei::ZERO,
                required: Wei::new(1),
            }),
            "an empty bound authorises nothing, whatever the address really holds"
        );
    }
}
