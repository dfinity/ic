/// Regression tests for two fundings decided before the first one's transfer finalizes. They drive
/// [`plan_funding`] itself rather than a copy of its logic, which would keep passing if the guard
/// were deleted or reordered, and they move the funding through the pipeline by applying the same
/// events the minter records.
mod concurrent_fundings {
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::numeric::{BlockNumber, GasAmount, LedgerBurnIndex, Wei, WeiPerGas};
    use crate::state::State;
    use crate::state::audit::{EventType, apply_state_transition};
    use crate::state::tests::eth_balance_of;
    use crate::state::transactions::{EthWithdrawalRequest, PipelineRequest, WithdrawalRequest};
    use crate::sweeper::{FundingDecision, plan_funding};
    use crate::test_fixtures::{initial_state, sweeper_funding_request};
    use crate::tx::{
        Eip1559TransactionRequest, GasFeeEstimate, SignedEip1559TransactionRequest,
        TransactionSignature,
    };

    const MINIMUM_BURN: u128 = 30_000_000_000_000_000; // 0.03 ETH, ckETH's mainnet minimum
    /// The bounds the fixture's minimum implies, rather than a pair of its own: the target is ten
    /// times the minimum withdrawal amount, and refilling starts at half of that.
    const TARGET: u128 = 10 * MINIMUM_BURN;
    /// A funding that lands the sweeper below the low-water mark rather than at the target, so that
    /// a test can tell a lifted guard from a sweeper that simply needs nothing.
    const PARTIAL_FUNDING: u128 = TARGET / 4;

    fn state() -> State {
        let mut state = initial_state();
        state.cketh_minimum_withdrawal_amount = Wei::new(MINIMUM_BURN);
        // Funding is capped by the ETH the minter received through deposits, so a fixture with none
        // could never fund at all.
        state.eth_balance = eth_balance_of(Wei::new(10 * TARGET));
        state
    }

    /// A funding request as the funding task builds one, under a burn index of its own.
    fn funding_request(ledger_burn_index: u64, amount: Wei) -> EthWithdrawalRequest {
        EthWithdrawalRequest {
            ledger_burn_index: LedgerBurnIndex::new(ledger_burn_index),
            ..sweeper_funding_request(amount)
        }
    }

    fn accept(state: &mut State, request: &EthWithdrawalRequest) {
        apply_state_transition(
            state,
            &EventType::AcceptedSweeperFundingRequest(request.clone()),
        );
    }

    fn create(state: &mut State, request: &EthWithdrawalRequest) -> Eip1559TransactionRequest {
        let transaction = WithdrawalRequest::SweeperFunding(request.clone())
            .create_transaction(
                state.withdrawal_transactions.next_transaction_nonce(),
                GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::ONE,
                    max_priority_fee_per_gas: WeiPerGas::ONE,
                },
                GasAmount::from(21_000_u32),
                state.ethereum_network,
            )
            .expect("test setup: the funding must cover its transaction fee");
        apply_state_transition(
            state,
            &EventType::CreatedTransaction {
                withdrawal_id: request.ledger_burn_index,
                transaction: transaction.clone(),
            },
        );
        transaction
    }

    fn sign(
        state: &mut State,
        request: &EthWithdrawalRequest,
        transaction: Eip1559TransactionRequest,
    ) -> SignedEip1559TransactionRequest {
        let signed = SignedEip1559TransactionRequest::from((
            transaction,
            TransactionSignature {
                signature_y_parity: false,
                r: Default::default(),
                s: Default::default(),
            },
        ));
        apply_state_transition(
            state,
            &EventType::SignedTransaction {
                withdrawal_id: request.ledger_burn_index,
                transaction: signed.clone(),
            },
        );
        signed
    }

    fn finalize(
        state: &mut State,
        request: &EthWithdrawalRequest,
        transaction: &SignedEip1559TransactionRequest,
    ) {
        apply_state_transition(
            state,
            &EventType::FinalizedTransaction {
                withdrawal_id: request.ledger_burn_index,
                transaction_receipt: TransactionReceipt {
                    block_hash:
                        "0xce67a85c9fb8bc50213815c32814c159fd75160acf7cb8631e8e7b7cf7f1d472"
                            .parse()
                            .unwrap(),
                    block_number: BlockNumber::new(4190269),
                    effective_gas_price: WeiPerGas::ONE,
                    gas_used: GasAmount::from(21_000_u32),
                    status: TransactionStatus::Success,
                    transaction_hash: transaction.hash(),
                },
            },
        );
    }

    /// Accepts a funding and runs it to a finalized transfer.
    pub(super) fn fund(state: &mut State, request: &EthWithdrawalRequest) {
        accept(state, request);
        let transaction = create(state, request);
        let signed = sign(state, request, transaction);
        finalize(state, request, &signed);
    }

    fn assert_refuses_while(state: &State, request: &EthWithdrawalRequest, stage: &str) {
        assert_eq!(
            plan_funding(state),
            FundingDecision::AlreadyInFlight {
                ledger_burn_index: request.ledger_burn_index,
                amount: request.withdrawal_amount,
            },
            "a second funding must be refused while the first is {stage}"
        );
    }

    #[test]
    fn should_refuse_to_fund_more_than_the_deposit_backed_balance() {
        let mut state = state();
        state.eth_balance = eth_balance_of(Wei::new(TARGET - 1));

        assert_eq!(
            plan_funding(&state),
            FundingDecision::InsufficientBalance {
                available: Wei::new(TARGET - 1),
                required: Wei::new(TARGET),
            },
            "a fresh deployment may hold ETH it has credited no deposit for, and funding must not \
             reach for it"
        );
    }

    #[test]
    fn should_fund_when_the_backed_balance_exactly_covers_it() {
        let mut state = state();
        state.eth_balance = eth_balance_of(Wei::new(TARGET));

        match plan_funding(&state) {
            FundingDecision::Fund(amount) => assert_eq!(amount, Wei::new(TARGET)),
            other => panic!("a fully covered funding must be due, got {other:?}"),
        }
    }

    /// The transfer has not landed at any of these stages, so the balance is still zero and a
    /// planner without the guard would put a second funding on the same nonce lane.
    #[test]
    fn should_refuse_a_second_funding_at_every_stage_before_finalization() {
        let mut state = state();

        // Deliberately less than the target: with the bound read from the state, a funding that
        // topped the sweeper up would make the last assertion below hold for the wrong reason.
        let request = funding_request(1, Wei::new(PARTIAL_FUNDING));

        accept(&mut state, &request);
        assert_refuses_while(&state, &request, "still queued");

        let transaction = create(&mut state, &request);
        assert_refuses_while(&state, &request, "waiting to be signed");

        let signed = sign(&mut state, &request, transaction);
        assert_refuses_while(&state, &request, "sent but not finalized");

        finalize(&mut state, &request, &signed);
        assert!(
            matches!(plan_funding(&state), FundingDecision::Fund(_)),
            "the guard must lift once the transfer has finalized"
        );
    }

    /// The guard must not deadlock funding: once the first transfer settles, planning resumes — and
    /// asks for the shortfall the first one left, since the bound now carries what it delivered.
    #[test]
    fn should_resume_funding_once_the_first_has_settled() {
        let mut state = state();
        fund(&mut state, &funding_request(1, Wei::new(PARTIAL_FUNDING)));

        let bound = state.sweeper_funding.sweeper_balance_lower_bound();
        assert!(
            bound > Wei::ZERO && bound < Wei::new(TARGET / 2),
            "test setup: the first funding must leave the sweeper below the low-water mark, got \
             {bound}"
        );
        match plan_funding(&state) {
            FundingDecision::Fund(second) => assert_eq!(
                second.checked_add(bound),
                Some(Wei::new(TARGET)),
                "the second funding must ask for exactly what the first left short"
            ),
            other => panic!("funding must resume once the first has settled, got {other:?}"),
        }
    }

    /// The other side of the same coin: a funding that reached the target leaves nothing to do, and
    /// the state says so on its own — nothing tells the planner what the balance is.
    #[test]
    fn should_not_fund_a_sweeper_the_last_funding_topped_up() {
        let mut state = state();
        fund(&mut state, &funding_request(1, Wei::new(TARGET)));

        assert_eq!(plan_funding(&state), FundingDecision::NotDue);
    }

    /// Whatever sequence the guard permits, the invariant must survive it. This is the assertion the
    /// buggy sequence failed: `record_finalized_funding` traps when spend exceeds burn.
    #[test]
    fn should_preserve_the_invariant_across_repeated_fundings() {
        let mut state = state();

        for index in 1..=5_u64 {
            // Arranged rather than planned: nothing draws the bound down until sweeping spends the
            // gas, so the planner would decline every funding after the first.
            // Reaching here without a trap is the assertion: spend never exceeds burn.
            fund(&mut state, &funding_request(index, Wei::new(TARGET)));
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
        let mut state = state();
        // Partial fundings, so that finalizing the first leaves the sweeper short and the guard is
        // still the reason the second is refused.
        let first = funding_request(1, Wei::new(PARTIAL_FUNDING));
        let second = funding_request(2, Wei::new(PARTIAL_FUNDING));

        accept(&mut state, &first);
        accept(&mut state, &second);
        assert_refuses_while(
            &state,
            &first,
            "the oldest of two outstanding fundings, which is the one reported",
        );

        let first_tx = create(&mut state, &first);
        let first_signed = sign(&mut state, &first, first_tx);
        assert_refuses_while(
            &state,
            &first,
            "the one furthest along the pipeline, reported ahead of the newer one still pending",
        );

        let second_tx = create(&mut state, &second);
        let second_signed = sign(&mut state, &second, second_tx);

        finalize(&mut state, &first, &first_signed);
        assert_refuses_while(&state, &second, "the second, now the only one outstanding");

        finalize(&mut state, &second, &second_signed);
        assert!(
            state.sweeper_funding.cumulative_burned() >= state.sweeper_funding.cumulative_spent()
        );
        assert!(
            state
                .withdrawal_transactions
                .outstanding_sweeper_funding()
                .is_none(),
            "with both settled, nothing is outstanding and the guard holds nothing back"
        );
    }
}

/// The other side of the balance bound: sweeping spends the gas a funding provisioned, and the bound
/// has to come back down as it does, or the minter believes a drained sweeper is still topped up and
/// never funds it again.
mod sweep_spending {
    use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
    use crate::lifecycle::EthereumNetwork;
    use crate::numeric::{BlockNumber, GasAmount, LedgerBurnIndex, Wei, WeiPerGas};
    use crate::state::State;
    use crate::state::audit::{EventType, apply_state_transition};
    use crate::state::tests::eth_balance_of;
    use crate::state::transactions::{PipelineRequest, SweepId, SweepRequest};
    use crate::sweep::SWEEP_TRANSACTION_GAS_LIMIT;
    use crate::test_fixtures::{initial_state, sweeper_funding_request};
    use crate::tx::{GasFeeEstimate, SignedSweepTransaction, TransactionSignature};
    use ic_ethereum_types::Address;

    const MINIMUM_BURN: u128 = 30_000_000_000_000_000; // 0.03 ETH, ckETH's mainnet minimum
    const TARGET: u128 = 10 * MINIMUM_BURN;
    /// What the receipt below charges: the sweep's gas limit at one wei per gas.
    const SWEEP_GAS: u64 = 100_000;

    fn state() -> State {
        let mut state = initial_state();
        state.cketh_minimum_withdrawal_amount = Wei::new(MINIMUM_BURN);
        state.eth_balance = eth_balance_of(Wei::new(10 * TARGET));
        state
    }

    /// Puts ETH at the sweeper address the way production does: a funding, run to a finalized
    /// transfer, which is what credits the bound in the first place.
    fn deliver_to_sweeper(state: &mut State) -> Wei {
        let request = crate::state::transactions::EthWithdrawalRequest {
            ledger_burn_index: LedgerBurnIndex::new(1),
            ..sweeper_funding_request(Wei::new(TARGET))
        };
        super::concurrent_fundings::fund(state, &request);
        state.sweeper_funding.sweeper_balance_lower_bound()
    }

    /// `amount` is the ETH the transaction itself moves: zero for an ERC-20 sweep, which moves
    /// tokens through the calldata, and non-zero only where the call needs value.
    fn sweep_request(amount: Wei) -> SweepRequest {
        SweepRequest {
            id: SweepId(1),
            destination: Address::new([0x77; 20]),
            amount,
            data: vec![0xaa],
            max_transaction_fee: Wei::from(SWEEP_FEE_CEILING),
            created_at: 1_620_328_630_000_000_000,
            authorizations: vec![],
        }
    }

    /// Accepts a sweep moving `amount` of ETH, which is where its provision is taken.
    fn accept_sweep(state: &mut State, amount: Wei) -> SweepRequest {
        let request = sweep_request(amount);
        apply_state_transition(state, &EventType::AcceptedSweepRequest(request.clone()));
        request
    }

    /// Runs an accepted sweep through the pipeline to a finalized receipt with `status`.
    fn finalize_sweep(state: &mut State, request: &SweepRequest, status: TransactionStatus) {
        let request = request.clone();
        let sweep_id = request.id;

        let transaction = request
            .create_transaction(
                state.sweeper_transactions.next_transaction_nonce(),
                GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::ONE,
                    max_priority_fee_per_gas: WeiPerGas::ONE,
                },
                SWEEP_TRANSACTION_GAS_LIMIT,
                EthereumNetwork::Mainnet,
            )
            .expect("test setup: the sweep must cover its transaction fee");
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

    /// The fee ceiling the fixture's sweep provisions against.
    const SWEEP_FEE_CEILING: u64 = 10 * SWEEP_GAS;

    #[test]
    fn should_provision_an_accepted_sweep_out_of_the_bound() {
        let mut state = state();
        let delivered = deliver_to_sweeper(&mut state);

        accept_sweep(&mut state, Wei::ZERO);

        assert_eq!(
            state.sweeper_funding.sweeper_balance_lower_bound(),
            delivered.checked_sub(Wei::from(SWEEP_FEE_CEILING)).unwrap(),
            "the bound must fall by the most the sweep can cost, before it has cost anything"
        );
    }

    #[test]
    fn should_settle_the_bound_on_what_a_sweep_actually_paid() {
        let mut state = state();
        let delivered = deliver_to_sweeper(&mut state);
        let request = accept_sweep(&mut state, Wei::ZERO);

        finalize_sweep(&mut state, &request, TransactionStatus::Success);

        assert_eq!(
            state.sweeper_funding.sweeper_balance_lower_bound(),
            delivered.checked_sub(Wei::from(SWEEP_GAS)).unwrap(),
            "the unspent part of the fee ceiling comes back"
        );
    }

    #[test]
    fn should_hand_back_the_value_a_failed_sweep_did_not_move() {
        let mut state = state();
        let delivered = deliver_to_sweeper(&mut state);
        // A sweep whose call carries ETH, so that the value is a separate thing to hand back.
        let value = Wei::from(7 * SWEEP_GAS);
        let request = accept_sweep(&mut state, value);
        assert_eq!(
            state.sweeper_funding.sweeper_balance_lower_bound(),
            delivered
                .checked_sub(value.checked_add(Wei::from(SWEEP_FEE_CEILING)).unwrap())
                .unwrap(),
            "test setup: the provision covers the value as well as the fee ceiling"
        );

        finalize_sweep(&mut state, &request, TransactionStatus::Failure);

        assert_eq!(
            state.sweeper_funding.sweeper_balance_lower_bound(),
            delivered.checked_sub(Wei::from(SWEEP_GAS)).unwrap(),
            "a failed sweep paid its gas and moved nothing, so the value comes back"
        );
    }

    #[test]
    fn should_keep_the_value_a_successful_sweep_moved() {
        let mut state = state();
        let delivered = deliver_to_sweeper(&mut state);
        let value = Wei::from(7 * SWEEP_GAS);
        let request = accept_sweep(&mut state, value);

        finalize_sweep(&mut state, &request, TransactionStatus::Success);

        assert_eq!(
            state.sweeper_funding.sweeper_balance_lower_bound(),
            delivered
                .checked_sub(value.checked_add(Wei::from(SWEEP_GAS)).unwrap())
                .unwrap(),
            "the value left the sweeper along with the gas it paid"
        );
    }

    /// Sweeping must not disturb the burn-first invariant: this ETH was counted as spent once
    /// already, when the funding that delivered it finalized.
    #[test]
    fn should_leave_the_burn_first_accounting_alone() {
        let mut state = state();
        deliver_to_sweeper(&mut state);
        let burned = state.sweeper_funding.cumulative_burned();
        let spent = state.sweeper_funding.cumulative_spent();
        let request = accept_sweep(&mut state, Wei::ZERO);

        finalize_sweep(&mut state, &request, TransactionStatus::Success);

        assert_eq!(state.sweeper_funding.cumulative_burned(), burned);
        assert_eq!(state.sweeper_funding.cumulative_spent(), spent);
    }
}
