use crate::numeric::Wei;
use crate::state::sweeper_funding::{SweeperFundingAccounting, SweeperFundingConfig};

const BURN: u128 = 100_000_000_000_000_000; // 0.1 ETH
const FEE: u128 = 1_000_000_000_000_000; // 0.001 ETH

/// The two sides of the invariant, in isolation from the pipeline that decides when a funding is
/// accepted and when its transaction settles — that sequencing is covered where it lives, by the
/// event-driven tests in [`crate::state::tests`] and [`crate::sweeper::tests`].
mod accounting {
    use super::*;
    use crate::eth_rpc::Hash;
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::numeric::{BlockNumber, GasAmount, TransactionNonce};
    use crate::test_fixtures::{gas_fee_estimate, transaction_signature};
    use crate::tx::{AccessList, Eip1559TransactionRequest, Finalized, Signed, SweepTransaction};
    use ic_ethereum_types::Address;

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

    #[test]
    fn should_hold_every_accepted_sweep() {
        let mut accounting = funded_accounting();

        accounting.record_accepted_sweep(Wei::new(FEE));
        accounting.record_accepted_sweep(Wei::new(2 * FEE));

        assert_eq!(
            accounting.sweeper_balance_lower_bound(),
            Wei::new(BURN - 3 * FEE),
            "every accepted sweep adds its own hold"
        );
    }

    #[test]
    #[should_panic(expected = "a sweep must not send ETH")]
    fn should_panic_when_a_finalized_sweep_sent_eth() {
        let mut accounting = funded_accounting();
        let (sweep, fee_paid) = finalized_sweep(Wei::new(12_345), TransactionStatus::Success);
        let fee_ceiling = fee_paid.checked_add(Wei::new(FEE)).unwrap();
        accounting.record_accepted_sweep(fee_ceiling);

        accounting.record_finalized_sweep(fee_ceiling, &sweep);
    }

    #[test]
    fn should_record_the_fees_sweeps_paid() {
        let mut accounting = funded_accounting();
        let (sweep, fee_paid) = finalized_sweep(Wei::ZERO, TransactionStatus::Success);
        let fee_ceiling = fee_paid.checked_add(Wei::new(FEE)).unwrap();
        accounting.record_accepted_sweep(fee_ceiling);

        accounting.record_finalized_sweep(fee_ceiling, &sweep);

        assert_eq!(accounting.total_effective_sweep_fees(), fee_paid);
        assert_eq!(
            accounting.sweeper_balance_lower_bound(),
            Wei::new(BURN).checked_sub(fee_paid).unwrap(),
            "the unspent fee must stay available to the sweeper"
        );
    }

    fn funded_accounting() -> SweeperFundingAccounting {
        let mut accounting = SweeperFundingAccounting::default();
        accounting.record_burn(Wei::new(BURN));
        accounting.record_finalized_funding(Wei::new(BURN), Wei::ZERO);
        accounting
    }

    fn finalized_sweep(
        amount: Wei,
        status: TransactionStatus,
    ) -> (Finalized<SweepTransaction>, Wei) {
        let estimate = gas_fee_estimate();
        let max_fee_per_gas = estimate
            .base_fee_per_gas
            .checked_mul(2_u8)
            .unwrap()
            .checked_add(estimate.max_priority_fee_per_gas)
            .unwrap();
        let gas_limit = GasAmount::new(100_000);
        let signed = Signed::from((
            SweepTransaction::Eip1559(Eip1559TransactionRequest {
                chain_id: 1,
                nonce: TransactionNonce::ZERO,
                max_priority_fee_per_gas: estimate.max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                destination: Address::new([0x5e; 20]),
                amount,
                data: Vec::new(),
                access_list: AccessList::new(),
            }),
            transaction_signature(),
        ));
        let receipt = TransactionReceipt {
            block_hash: Hash([0x11; 32]),
            block_number: BlockNumber::new(4_190_269),
            effective_gas_price: estimate
                .base_fee_per_gas
                .checked_add(estimate.max_priority_fee_per_gas)
                .unwrap(),
            gas_used: gas_limit,
            status,
            transaction_hash: signed.hash(),
        };
        let fee_paid = receipt.effective_transaction_fee();
        let finalized = signed
            .try_finalize(receipt)
            .expect("test setup: the receipt matches the signed transaction");
        (finalized, fee_paid)
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

mod sweep_events {
    use crate::eth_rpc::Hash;
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::numeric::{BlockNumber, Wei, WeiPerGas};
    use crate::state::State;
    use crate::state::audit::{EventType, apply_state_transition};
    use crate::state::sweeper_funding::SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS;
    use crate::state::tests::eth_balance_of;
    use crate::state::transactions::{PipelineRequest, SweepRequest};
    use crate::sweeper::{FundingDecision, plan_funding};
    use crate::test_fixtures::{
        PREPAID_SWEEP_GAS, account, gas_fee_estimate, state_with_enqueued_sweep, usdc,
    };
    use crate::tx::{
        GasFeeEstimate, SignableTransaction, Signed, SweepTransaction, TransactionSignature,
    };

    #[tokio::test]
    async fn should_provision_an_accepted_sweep_before_it_has_spent_anything() {
        let (state, request) = state_with_enqueued_sweep(&[(account(), usdc())]).await;

        assert_eq!(
            sweeper_balance(&state),
            PREPAID_SWEEP_GAS
                .checked_sub(request.max_transaction_fee)
                .unwrap(),
            "the whole of what the sweep may cost stops counting as available gas"
        );
    }

    /// The refund rule in full: gas is paid whether the sweep succeeded or reverted, and the part
    /// of the ceiling it did not pay always returns. An ERC-20 sweep moves no ETH value, so there
    /// is nothing else either outcome can leave behind.
    #[tokio::test]
    async fn should_settle_the_bound_on_what_a_finalized_sweep_actually_cost() {
        for status in [TransactionStatus::Success, TransactionStatus::Failure] {
            let (mut state, request) = state_with_enqueued_sweep(&[(account(), usdc())]).await;

            let fee_paid = finalize(&mut state, &request, status);

            assert!(
                fee_paid < request.max_transaction_fee,
                "the fixture must leave an unspent part to hand back"
            );
            assert_eq!(
                sweeper_balance(&state),
                PREPAID_SWEEP_GAS.checked_sub(fee_paid).unwrap(),
                "a {status:?} sweep must cost the sweeper exactly the {fee_paid} of gas it paid"
            );
        }
    }

    #[tokio::test]
    async fn should_settle_on_the_receipt_of_the_resubmission_that_finalized() {
        let (mut state, request) = state_with_enqueued_sweep(&[(account(), usdc())]).await;
        let repriced = GasFeeEstimate {
            max_priority_fee_per_gas: WeiPerGas::ZERO,
            ..gas_fee_estimate()
        };

        let fee_paid = settle(
            &mut state,
            &request,
            TransactionStatus::Success,
            Some(repriced),
        );

        let original_price = gas_fee_estimate()
            .base_fee_per_gas
            .checked_add(gas_fee_estimate().max_priority_fee_per_gas)
            .unwrap();
        assert_ne!(
            Some(fee_paid),
            original_price.transaction_cost(request.gas_limit()),
            "the replacement must pay a different fee, or this shows nothing"
        );
        assert_eq!(
            sweeper_balance(&state),
            PREPAID_SWEEP_GAS.checked_sub(fee_paid).unwrap(),
            "one refund, measured against the request's ceiling, settled off the receipt of \
             whichever resubmission finalized"
        );
    }

    #[tokio::test]
    async fn should_fund_again_once_accepted_sweeps_consume_the_prepaid_gas() {
        let (mut state, request) = state_with_enqueued_sweep(&[(account(), usdc())]).await;
        state.cketh_minimum_withdrawal_amount = sweeper_balance(&state)
            .checked_div_floor(SWEEPER_FUNDING_TARGET_IN_MINIMUM_WITHDRAWAL_AMOUNTS / 2)
            .expect("test setup: dividing by a non-zero constant");
        state.eth_balance = eth_balance_of(state.sweeper_funding_config().target);
        assert_eq!(
            plan_funding(&state),
            FundingDecision::NotDue,
            "the gas already delivered must hold the sweeper at its low-water mark"
        );

        state.update_sweeper_balance_upon_accepted_sweep(&request);

        let target = state.sweeper_funding_config().target;
        match plan_funding(&state) {
            FundingDecision::Fund(amount) => assert_eq!(
                amount.checked_add(sweeper_balance(&state)),
                Some(target),
                "the funding must top the sweeper back up to the target"
            ),
            other => panic!(
                "gas a committed sweep will spend must bring a funding forward, got {other:?}"
            ),
        }
    }

    /// Sweep spending is the sweeper's ETH, already counted as spent when the funding delivered it.
    /// Counting it again here would make spend overtake burn and trip the invariant.
    #[tokio::test]
    async fn should_leave_the_burn_first_accounting_alone() {
        let (mut state, request) = state_with_enqueued_sweep(&[(account(), usdc())]).await;
        let burned = state.sweeper_funding.cumulative_burned();
        let spent = state.sweeper_funding.cumulative_spent();

        finalize(&mut state, &request, TransactionStatus::Success);

        assert_eq!(state.sweeper_funding.cumulative_burned(), burned);
        assert_eq!(state.sweeper_funding.cumulative_spent(), spent);
    }

    #[tokio::test]
    #[should_panic(expected = "cannot cover a debit")]
    async fn should_panic_when_provisioning_more_than_was_delivered() {
        let (mut state, _request) = state_with_enqueued_sweep(&[(account(), usdc())]).await;

        state
            .sweeper_funding
            .record_accepted_sweep(PREPAID_SWEEP_GAS);
    }

    fn sweeper_balance(state: &State) -> Wei {
        state.sweeper_funding.sweeper_balance_lower_bound()
    }

    fn finalize(state: &mut State, request: &SweepRequest, status: TransactionStatus) -> Wei {
        settle(state, request, status, None)
    }

    fn settle(
        state: &mut State,
        request: &SweepRequest,
        status: TransactionStatus,
        replacement_estimate: Option<GasFeeEstimate>,
    ) -> Wei {
        let sweep_id = request.id;
        let nonce = state.automatic_deposits.next_sweeper_transaction_nonce();
        let ethereum_network = state.ethereum_network;
        let priced_with = |estimate: GasFeeEstimate| {
            request
                .create_transaction(nonce, estimate, request.gas_limit(), ethereum_network)
                .expect("BUG: the fixture prices the request with the estimate it creates with")
        };
        let transaction = priced_with(gas_fee_estimate());
        apply_state_transition(
            state,
            &EventType::CreatedSweeperTransaction {
                sweep_id,
                transaction: transaction.clone(),
            },
        );
        let sign = |transaction: SweepTransaction| {
            Signed::from((
                transaction,
                TransactionSignature {
                    signature_y_parity: false,
                    r: Default::default(),
                    s: Default::default(),
                },
            ))
        };
        apply_state_transition(
            state,
            &EventType::SignedSweeperTransaction {
                sweep_id,
                transaction: sign(transaction.clone()),
            },
        );
        let mut effective_estimate = gas_fee_estimate();
        let mut signed = sign(transaction);
        if let Some(estimate) = replacement_estimate {
            let replacement = priced_with(estimate.clone());
            apply_state_transition(
                state,
                &EventType::ReplacedSweeperTransaction {
                    sweep_id,
                    transaction: replacement.clone(),
                },
            );
            signed = sign(replacement);
            apply_state_transition(
                state,
                &EventType::SignedSweeperTransaction {
                    sweep_id,
                    transaction: signed.clone(),
                },
            );
            effective_estimate = estimate;
        }
        let receipt = TransactionReceipt {
            block_hash: Hash([0x11; 32]),
            block_number: BlockNumber::new(4_190_269),
            effective_gas_price: effective_estimate
                .base_fee_per_gas
                .checked_add(effective_estimate.max_priority_fee_per_gas)
                .unwrap(),
            gas_used: signed.transaction().gas_limit(),
            status,
            transaction_hash: signed.hash(),
        };
        apply_state_transition(
            state,
            &EventType::FinalizedSweeperTransaction {
                sweep_id,
                transaction_receipt: receipt.clone(),
            },
        );
        receipt.effective_transaction_fee()
    }
}
