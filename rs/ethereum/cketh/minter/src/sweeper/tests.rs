use crate::numeric::{LedgerBurnIndex, Wei};
use crate::state::sweeper_funding::SweeperFundingAccounting;

const AMOUNT: u128 = 100_000_000_000_000_000; // 0.1 ETH
/// Fixed acceptance time; these tests are about the accounting, not about ageing.
const CREATED_AT: Option<u64> = Some(1_700_000_000_000_000_000);

#[test]
fn should_preserve_the_invariant_across_consecutive_fundings() {
    let mut accounting = SweeperFundingAccounting::default();

    for index in 1..=3_u64 {
        let index = LedgerBurnIndex::new(index);
        accounting.record_burn(Wei::new(AMOUNT));
        accounting.mark_funding_in_flight(index, Wei::new(AMOUNT), CREATED_AT);
        accounting.record_finalized_funding(index, Wei::new(AMOUNT - 43_000), Wei::new(1_000));

        assert!(accounting.cumulative_burned() >= accounting.cumulative_spent());
        assert!(accounting.burned_not_yet_spent() <= accounting.cumulative_burned());
    }

    assert_eq!(
        accounting.burned_not_yet_spent(),
        Wei::new(3 * 42_000),
        "each funding leaves the fee it provisioned but did not pay"
    );
}

/// Regression tests for two fundings decided before the first one's transfer finalizes. They drive
/// [`plan_funding`] itself rather than a copy of its logic, which would keep passing if the guard
/// were deleted or reordered.
mod concurrent_fundings {
    use crate::numeric::{LedgerBurnIndex, Wei};
    use crate::state::State;
    use crate::sweeper::{FundingDecision, plan_funding};
    use crate::test_fixtures::initial_state;

    const CREATED_AT: Option<u64> = Some(1_700_000_000_000_000_000);
    const MINIMUM_BURN: u128 = 30_000_000_000_000_000; // 0.03 ETH, ckETH's mainnet minimum
    /// The bounds the fixture's minimum implies, rather than a pair of its own: the target is ten
    /// times the minimum withdrawal amount, and refilling starts at half of that.
    const TARGET: u128 = 10 * MINIMUM_BURN;

    fn state() -> State {
        let mut state = initial_state();
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
            FundingDecision::Fund(amount) => assert_eq!(amount, Wei::new(TARGET)),
            other => panic!("a fully covered funding must be due, got {other:?}"),
        }
    }

    #[test]
    fn should_refuse_a_second_funding_while_the_first_is_in_flight() {
        let mut state = state();

        let first = match plan_funding(&state, Wei::ZERO) {
            FundingDecision::Fund(amount) => amount,
            other => panic!("the first funding must be due, got {other:?}"),
        };
        assert_eq!(first, Wei::new(TARGET));
        state.sweeper_funding.record_burn(first);
        state
            .sweeper_funding
            .mark_funding_in_flight(LedgerBurnIndex::new(1), first, CREATED_AT);

        // F2: the transfer has not landed, so the balance is still zero and a planner without the
        // earmark would put a second funding on the same nonce lane.
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
            FundingDecision::Fund(amount) => amount,
            other => panic!("unexpected {other:?}"),
        };
        state.sweeper_funding.record_burn(first);
        state
            .sweeper_funding
            .mark_funding_in_flight(LedgerBurnIndex::new(1), first, CREATED_AT);
        let fee = Wei::new(1_000_000_000_000_000);
        state.sweeper_funding.record_finalized_funding(
            LedgerBurnIndex::new(1),
            first.checked_sub(fee).unwrap(),
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
            let amount = match plan_funding(&state, Wei::ZERO) {
                FundingDecision::Fund(amount) => amount,
                other => panic!("funding {index} should be due, got {other:?}"),
            };
            state.sweeper_funding.record_burn(amount);
            state.sweeper_funding.mark_funding_in_flight(
                LedgerBurnIndex::new(index),
                amount,
                CREATED_AT,
            );
            // Reaching here without a trap is the assertion: spend never exceeds burn.
            state.sweeper_funding.record_finalized_funding(
                LedgerBurnIndex::new(index),
                amount.checked_sub(fee).unwrap(),
                fee,
            );
            assert!(
                state.sweeper_funding.cumulative_burned()
                    >= state.sweeper_funding.cumulative_spent()
            );
        }
    }

    /// Bypassing the guard is a prudence violation, not a solvency one: each funding burns for its
    /// own transfer, so the invariant survives two of them in flight.
    #[test]
    fn should_survive_a_second_funding_accepted_anyway() {
        let mut accounting = crate::state::sweeper_funding::SweeperFundingAccounting::default();
        let fee = Wei::new(1_000_000_000_000_000);
        accounting.record_burn(Wei::new(TARGET));
        accounting.mark_funding_in_flight(LedgerBurnIndex::new(1), Wei::new(TARGET), CREATED_AT);

        accounting.record_burn(Wei::new(TARGET));
        accounting.mark_funding_in_flight(LedgerBurnIndex::new(2), Wei::new(TARGET), CREATED_AT);

        assert_eq!(
            accounting
                .in_flight_funding()
                .map(|funding| funding.ledger_burn_index),
            Some(LedgerBurnIndex::new(2)),
            "the newer funding takes over the earmark"
        );
        // Both transfers settle; both were covered by their own burn, so the invariant holds.
        accounting.record_finalized_funding(
            LedgerBurnIndex::new(2),
            Wei::new(TARGET).checked_sub(fee).unwrap(),
            fee,
        );
        accounting.record_finalized_funding(
            LedgerBurnIndex::new(1),
            Wei::new(TARGET).checked_sub(fee).unwrap(),
            fee,
        );
        assert!(accounting.cumulative_burned() >= accounting.cumulative_spent());
    }
}
