use crate::numeric::{LedgerBurnIndex, Wei};
use crate::state::sweeper_funding::SweeperFundingAccounting;
use crate::sweeper::burn_for;

const MINIMUM_BURN: u128 = 30_000_000_000_000_000; // ckETH's mainnet minimum withdrawal amount
const AMOUNT: u128 = 100_000_000_000_000_000; // 0.1 ETH
const CREATED_AT: u64 = 1_700_000_000_000_000_000;

fn accept(
    accounting: &mut SweeperFundingAccounting,
    index: u64,
    amount: Wei,
    burn: Wei,
) -> LedgerBurnIndex {
    let index = LedgerBurnIndex::new(index);
    accounting.record_burn(burn);
    accounting.mark_funding_in_flight(index, amount, CREATED_AT);
    index
}

#[test]
fn should_burn_the_whole_amount_when_nothing_is_prepaid() {
    let accounting = SweeperFundingAccounting::default();

    assert_eq!(
        burn_for(&accounting, Wei::new(AMOUNT), Wei::new(MINIMUM_BURN)),
        Wei::new(AMOUNT)
    );
}

#[test]
fn should_offset_the_burn_by_earlier_unspent_burns() {
    let unspent_fee_allowance = 42_000_u128;
    let mut accounting = SweeperFundingAccounting::default();
    let index = accept(&mut accounting, 1, Wei::new(AMOUNT), Wei::new(AMOUNT));
    accounting.record_finalized_funding(
        index,
        Wei::new(AMOUNT - unspent_fee_allowance - 1_000),
        Wei::new(1_000),
    );
    assert_eq!(
        accounting.burned_not_yet_spent(),
        Wei::new(unspent_fee_allowance)
    );

    assert_eq!(
        burn_for(&accounting, Wei::new(AMOUNT), Wei::new(MINIMUM_BURN)),
        Wei::new(AMOUNT - unspent_fee_allowance),
        "the credit reduces the burn while the ETH still moves in full"
    );
}

#[test]
fn should_floor_the_burn_at_the_minimum_even_when_fully_covered() {
    let mut accounting = SweeperFundingAccounting::default();
    let index = accept(
        &mut accounting,
        1,
        Wei::new(10 * AMOUNT),
        Wei::new(10 * AMOUNT),
    );
    accounting.record_finalized_funding(index, Wei::ZERO, Wei::new(1_000));
    assert!(accounting.burned_not_yet_spent() > Wei::new(AMOUNT));

    assert_eq!(
        burn_for(&accounting, Wei::new(AMOUNT), Wei::new(MINIMUM_BURN)),
        Wei::new(MINIMUM_BURN),
        "a fully covered funding still burns the ledger minimum so it has an index"
    );
}

#[test]
fn should_floor_a_small_residual_burn_at_the_minimum() {
    let mut accounting = SweeperFundingAccounting::default();
    let index = accept(&mut accounting, 1, Wei::new(AMOUNT), Wei::new(AMOUNT));
    accounting.record_finalized_funding(index, Wei::new(1_000), Wei::new(1_000));

    let burn = burn_for(&accounting, Wei::new(AMOUNT), Wei::new(MINIMUM_BURN));

    assert_eq!(burn, Wei::new(MINIMUM_BURN));
    assert!(
        burn >= accounting.burn_required_for(Wei::new(AMOUNT)),
        "flooring must only ever burn more than strictly required, never less"
    );
}

#[test]
fn should_preserve_the_invariant_across_an_offset_funding() {
    let mut accounting = SweeperFundingAccounting::default();
    let index = accept(&mut accounting, 1, Wei::new(AMOUNT), Wei::new(AMOUNT));
    accounting.record_finalized_funding(index, Wei::new(AMOUNT - 43_000), Wei::new(1_000));

    let amount = Wei::new(AMOUNT);
    let burn = burn_for(&accounting, amount, Wei::new(MINIMUM_BURN));

    let index = accept(&mut accounting, 2, amount, burn);
    accounting.record_finalized_funding(
        index,
        amount.checked_sub(Wei::new(1_500)).unwrap(),
        Wei::new(1_000),
    );

    assert!(accounting.cumulative_burned() >= accounting.cumulative_spent());
    assert!(accounting.burned_not_yet_spent() <= accounting.cumulative_burned());
}

/// Regression tests for two fundings decided before the first one's transfer finalizes. They drive
/// [`plan_funding`] itself rather than a copy of its logic, which would keep passing if the guard
/// were deleted or reordered.
mod concurrent_fundings {
    use crate::numeric::{LedgerBurnIndex, Wei};
    use crate::state::State;
    use crate::state::sweeper_funding::SweeperFundingConfig;
    use crate::sweeper::{FundingDecision, plan_funding};
    use crate::test_fixtures::initial_state;

    const CREATED_AT: u64 = 1_700_000_000_000_000_000;
    const LOW_WATER_MARK: u128 = 20_000_000_000_000_000; // 0.02 ETH
    const TARGET: u128 = 100_000_000_000_000_000; // 0.1 ETH
    const MINIMUM_BURN: u128 = 30_000_000_000_000_000; // 0.03 ETH

    fn state() -> State {
        let mut state = initial_state();
        state.sweeper_funding_config = SweeperFundingConfig {
            low_water_mark: Wei::new(LOW_WATER_MARK),
            target: Wei::new(TARGET),
        };
        state.cketh_minimum_withdrawal_amount = Wei::new(MINIMUM_BURN);
        // Funding is capped by the ETH the minter received through deposits, so a fixture with none
        // could never fund at all.
        state.eth_balance = crate::state::EthBalance::with_eth_balance(Wei::new(10 * TARGET));
        state
    }

    #[test]
    fn should_refuse_to_fund_more_than_the_deposit_backed_balance() {
        let mut state = state();
        state.eth_balance = crate::state::EthBalance::with_eth_balance(Wei::new(TARGET - 1));

        assert_eq!(
            plan_funding(&state, Wei::ZERO),
            FundingDecision::InsufficientBalance {
                available: Wei::new(TARGET - 1),
                required: Wei::new(TARGET),
            },
            "funding beyond the backed balance would underflow the debit at finalization and trap"
        );
    }

    #[test]
    fn should_fund_when_the_backed_balance_exactly_covers_it() {
        let mut state = state();
        state.eth_balance = crate::state::EthBalance::with_eth_balance(Wei::new(TARGET));

        match plan_funding(&state, Wei::ZERO) {
            FundingDecision::Fund(plan) => assert_eq!(plan.amount, Wei::new(TARGET)),
            other => panic!("a fully covered funding must be due, got {other:?}"),
        }
    }

    #[test]
    fn should_refuse_a_second_funding_while_the_first_is_in_flight() {
        let mut state = state();

        let first = match plan_funding(&state, Wei::ZERO) {
            FundingDecision::Fund(plan) => plan,
            other => panic!("the first funding must be due, got {other:?}"),
        };
        assert_eq!(first.amount, Wei::new(TARGET));
        assert_eq!(first.burn, Wei::new(TARGET));
        state.sweeper_funding.record_burn(first.burn);
        state.sweeper_funding.mark_funding_in_flight(
            LedgerBurnIndex::new(1),
            first.amount,
            CREATED_AT,
        );

        // F2: the transfer has not landed, so the balance is still zero and a naive planner would
        // fund again — offsetting against F1's earmarked burn.
        assert_eq!(
            plan_funding(&state, Wei::ZERO),
            FundingDecision::AlreadyInFlight(
                state
                    .sweeper_funding
                    .in_flight_funding()
                    .expect("BUG: F1 must be in flight")
            ),
            "a second funding must be refused while the first has not settled"
        );
    }

    /// The guard must not deadlock funding: once the first transfer settles, planning resumes.
    #[test]
    fn should_resume_funding_once_the_first_has_settled() {
        let mut state = state();
        let first = match plan_funding(&state, Wei::ZERO) {
            FundingDecision::Fund(plan) => plan,
            other => panic!("unexpected {other:?}"),
        };
        state.sweeper_funding.record_burn(first.burn);
        state.sweeper_funding.mark_funding_in_flight(
            LedgerBurnIndex::new(1),
            first.amount,
            CREATED_AT,
        );
        let fee = Wei::new(1_000_000_000_000_000);
        state.sweeper_funding.record_finalized_funding(
            LedgerBurnIndex::new(1),
            first.amount.checked_sub(fee).unwrap(),
            fee,
        );

        // The sweeper now holds roughly the target, so nothing is due — but the reason is
        // "not due", not "still in flight".
        assert_eq!(
            plan_funding(&state, Wei::new(TARGET - 1_000_000_000_000_000)),
            FundingDecision::NotDue
        );
        // Once it drains again, funding resumes.
        assert!(matches!(
            plan_funding(&state, Wei::ZERO),
            FundingDecision::Fund(_)
        ));
    }

    /// Whatever sequence the guard permits, the invariant must survive it. This is the assertion the
    /// buggy sequence failed: `record_finalized_funding` traps when spend exceeds burn.
    #[test]
    fn should_preserve_the_invariant_across_repeated_fundings() {
        let mut state = state();
        let fee = Wei::new(1_000_000_000_000_000);

        for index in 1..=5_u64 {
            let plan = match plan_funding(&state, Wei::ZERO) {
                FundingDecision::Fund(plan) => plan,
                other => panic!("funding {index} should be due, got {other:?}"),
            };
            state.sweeper_funding.record_burn(plan.burn);
            state.sweeper_funding.mark_funding_in_flight(
                LedgerBurnIndex::new(index),
                plan.amount,
                CREATED_AT,
            );
            // Reaching here without a trap is the assertion: spend never exceeds burn.
            state.sweeper_funding.record_finalized_funding(
                LedgerBurnIndex::new(index),
                plan.amount.checked_sub(fee).unwrap(),
                fee,
            );
            assert!(
                state.sweeper_funding.cumulative_burned()
                    >= state.sweeper_funding.cumulative_spent()
            );
        }
    }

    /// The guard is what upholds the invariant, so bypassing it must be loud rather than silently
    /// producing an under-backed state.
    #[test]
    #[should_panic(expected = "a second sweeper funding was accepted while one is still in flight")]
    fn should_panic_when_a_second_funding_is_accepted_anyway() {
        let mut accounting = crate::state::sweeper_funding::SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(TARGET));
        accounting.mark_funding_in_flight(LedgerBurnIndex::new(1), Wei::new(TARGET), CREATED_AT);

        // The first funding has not settled, so earmarking a second must be loud rather than
        // silently overwriting and letting the two transfers outspend the burns.
        accounting.mark_funding_in_flight(LedgerBurnIndex::new(2), Wei::new(TARGET), CREATED_AT);
    }
}
