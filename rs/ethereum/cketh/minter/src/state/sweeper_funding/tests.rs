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

/// The sweeper's own spending, driven through the state transitions the sweep pipeline records, so
/// that the wiring is covered and not only the arithmetic. The funding that delivers the ETH is a
/// precondition here rather than the subject, so it is arranged directly.
mod sweep_events {
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::{BlockNumber, GasAmount, Wei, WeiPerGas};
    use crate::state::State;
    use crate::state::audit::{EventType, apply_state_transition};
    use crate::state::transactions::{PipelineRequest, SweepRequest};
    use crate::sweep::SWEEP_TRANSACTION_GAS_LIMIT;
    use crate::test_fixtures::{initial_state, sweep_request};
    use crate::tx::{GasFeeEstimate, SignedSweepTransaction, TransactionSignature};

    /// The gas the receipt below charges: the sweep's whole gas limit at one wei per gas.
    const SWEEP_GAS: u64 = 100_000;
    /// Comfortably above [`SWEEP_GAS`], so a sweep leaves an unspent part to hand back.
    const FEE_CEILING: u64 = 10 * SWEEP_GAS;
    /// What a funding is taken to have delivered to the sweeper, arranged directly.
    const DELIVERED: u128 = 1_000_000 * SWEEP_GAS as u128;

    /// A state whose sweeper address holds `DELIVERED`, as a finalized funding would have left it.
    fn state_with_a_funded_sweeper() -> State {
        let mut state = initial_state();
        state.sweeper_funding.record_burn(Wei::new(DELIVERED));
        state
            .sweeper_funding
            .record_finalized_funding(Wei::new(DELIVERED), Wei::ZERO);
        state
    }

    fn bound(state: &State) -> Wei {
        state.sweeper_funding.sweeper_balance_lower_bound()
    }

    fn accept(state: &mut State, amount: Wei) -> SweepRequest {
        let request = SweepRequest {
            amount,
            max_transaction_fee: Wei::from(FEE_CEILING),
            ..sweep_request(1)
        };
        apply_state_transition(state, &EventType::AcceptedSweepRequest(request.clone()));
        request
    }

    fn finalize(state: &mut State, request: &SweepRequest, status: TransactionStatus) {
        let sweep_id = request.id;
        let transaction = request
            .clone()
            .create_transaction(
                state.sweeper_transactions.next_transaction_nonce(),
                GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::ONE,
                    max_priority_fee_per_gas: WeiPerGas::ONE,
                },
                SWEEP_TRANSACTION_GAS_LIMIT,
                EthereumNetwork::Mainnet,
            )
            .expect("test setup: the fee ceiling covers the fixture's fee");
        apply_state_transition(
            state,
            &EventType::CreatedSweeperTransaction {
                sweep_id,
                transaction: transaction.clone(),
            },
        );
        let signed = SignedSweepTransaction::from((
            transaction,
            TransactionSignature {
                signature_y_parity: false,
                r: Default::default(),
                s: Default::default(),
            },
        ));
        apply_state_transition(
            state,
            &EventType::SignedSweeperTransaction {
                sweep_id,
                transaction: signed.clone(),
            },
        );
        apply_state_transition(
            state,
            &EventType::FinalizedSweeperTransaction {
                sweep_id,
                transaction_receipt: TransactionReceipt {
                    block_hash:
                        "0xce67a85c9fb8bc50213815c32814c159fd75160acf7cb8631e8e7b7cf7f1d472"
                            .parse()
                            .unwrap(),
                    block_number: BlockNumber::new(4190269),
                    effective_gas_price: WeiPerGas::ONE,
                    gas_used: GasAmount::from(SWEEP_GAS),
                    status,
                    transaction_hash: signed.hash(),
                },
            },
        );
    }

    #[test]
    fn should_provision_an_accepted_sweep_before_it_has_spent_anything() {
        let mut state = state_with_a_funded_sweeper();
        let value = Wei::from(7 * SWEEP_GAS);

        accept(&mut state, value);

        assert_eq!(
            bound(&state),
            Wei::new(DELIVERED)
                .checked_sub(value.checked_add(Wei::from(FEE_CEILING)).unwrap())
                .unwrap(),
            "the whole of what the sweep may cost stops counting as available gas"
        );
    }

    /// What each outcome leaves subtracted, which is the refund rule in full: gas is paid either
    /// way, the value only leaves if the transaction succeeded, and the unused fee always returns.
    #[test]
    fn should_settle_the_bound_on_what_a_finalized_sweep_actually_cost() {
        let value = Wei::from(7 * SWEEP_GAS);
        for (status, amount, cost) in [
            (TransactionStatus::Success, Wei::ZERO, Wei::from(SWEEP_GAS)),
            (
                TransactionStatus::Success,
                value,
                value.checked_add(Wei::from(SWEEP_GAS)).unwrap(),
            ),
            (TransactionStatus::Failure, value, Wei::from(SWEEP_GAS)),
        ] {
            let mut state = state_with_a_funded_sweeper();
            let request = accept(&mut state, amount);

            finalize(&mut state, &request, status);

            assert_eq!(
                bound(&state),
                Wei::new(DELIVERED).checked_sub(cost).unwrap(),
                "a {status:?} sweep moving {amount} must cost the sweeper {cost}"
            );
        }
    }

    /// Sweep spending is the sweeper's ETH, already counted as spent when the funding delivered it.
    /// Counting it again here would make spend overtake burn and trip the invariant.
    #[test]
    fn should_leave_the_burn_first_accounting_alone() {
        let mut state = state_with_a_funded_sweeper();
        let burned = state.sweeper_funding.cumulative_burned();
        let spent = state.sweeper_funding.cumulative_spent();
        let request = accept(&mut state, Wei::ZERO);

        finalize(&mut state, &request, TransactionStatus::Success);

        assert_eq!(state.sweeper_funding.cumulative_burned(), burned);
        assert_eq!(state.sweeper_funding.cumulative_spent(), spent);
    }

    /// Provisioning beyond what the minter has recorded as delivered — an upgrade that starts the
    /// counters from zero, or a sweeper funded before it was tracked — floors the bound rather than
    /// trapping, which would take the replay of every later event with it.
    #[test]
    fn should_floor_the_bound_at_zero_rather_than_trap() {
        let mut state = initial_state();

        accept(&mut state, Wei::from(SWEEP_GAS));

        assert_eq!(bound(&state), Wei::ZERO);
    }
}
