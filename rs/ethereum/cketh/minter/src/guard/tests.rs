use crate::test_fixtures::initial_state;

mod retrieve_eth_guard {
    use crate::guard::tests::init_state;
    use crate::guard::{GuardError, MAX_CONCURRENT, MAX_PENDING, retrieve_withdraw_guard};
    use crate::numeric::{LedgerBurnIndex, Wei};
    use crate::state::mutate_state;
    use crate::state::transactions::EthWithdrawalRequest;
    use candid::Principal;
    use ic_ethereum_types::Address;

    #[test]
    fn should_error_on_reentrant_principal() {
        init_state();
        let principal = principal_with_id(1);
        let _guard = retrieve_withdraw_guard(principal).unwrap();

        assert_eq!(
            retrieve_withdraw_guard(principal),
            Err(GuardError::AlreadyProcessing)
        )
    }

    #[test]
    fn should_allow_reentrant_principal_after_drop() {
        init_state();
        let principal = principal_with_id(1);
        {
            let _guard = retrieve_withdraw_guard(principal).unwrap();
        }

        assert!(retrieve_withdraw_guard(principal).is_ok());
    }

    #[test]
    fn should_allow_limited_number_of_principals() {
        init_state();
        let mut guards: Vec<_> = (0..MAX_CONCURRENT)
            .map(|i| retrieve_withdraw_guard(principal_with_id(i as u64)).unwrap())
            .collect();

        for additional_principal in MAX_CONCURRENT..2 * MAX_CONCURRENT {
            assert_eq!(
                retrieve_withdraw_guard(principal_with_id(additional_principal as u64)),
                Err(GuardError::TooManyConcurrentRequests)
            );
        }

        {
            let _guard = guards.pop().expect("should have at least one guard");
        }
        assert!(retrieve_withdraw_guard(principal_with_id(MAX_CONCURRENT as u64)).is_ok());
    }

    #[test]
    fn should_allow_limited_number_of_pending_requests() {
        init_state();
        for i in 0..MAX_PENDING {
            let _guard = retrieve_withdraw_guard(principal_with_id(i as u64)).unwrap();
            record_withdrawal_request(LedgerBurnIndex::new(i as u64));
        }

        for additional_principal in MAX_PENDING..2 * MAX_PENDING {
            assert_eq!(
                retrieve_withdraw_guard(principal_with_id(additional_principal as u64)),
                Err(GuardError::TooManyPendingRequests)
            );
        }

        fn record_withdrawal_request(ledger_burn_index: LedgerBurnIndex) {
            mutate_state(|s| {
                s.eth_transactions
                    .record_withdrawal_request(EthWithdrawalRequest {
                        withdrawal_amount: Wei::ONE,
                        destination: Address::ZERO,
                        ledger_burn_index,
                        from: Principal::anonymous(),
                        from_subaccount: None,
                        created_at: None,
                    })
            })
        }
    }

    fn principal_with_id(id: u64) -> Principal {
        Principal::try_from_slice(&id.to_le_bytes()).unwrap()
    }
}

mod timer_guard {
    use crate::guard::tests::init_state;
    use crate::guard::{TimerGuard, TimerGuardError};
    use crate::state::TaskType;
    use strum::IntoEnumIterator;

    #[test]
    fn should_prevent_concurrent_access() {
        for task_type in TaskType::iter() {
            init_state();
            let _guard = TimerGuard::new(task_type).expect("can retrieve timer guard");

            assert_eq!(
                TimerGuard::new(task_type),
                Err(TimerGuardError::AlreadyProcessing)
            );
        }
    }

    #[test]
    fn should_allow_access_when_guard_dropped() {
        for task_type in TaskType::iter() {
            init_state();
            let _guard = TimerGuard::new(task_type).expect("can retrieve timer guard");

            drop(_guard);

            assert!(TimerGuard::new(task_type).is_ok());
        }
    }

    #[test]
    fn should_be_able_to_get_all_timer_guards() {
        init_state();
        let mut guards = Vec::new();

        for task_type in TaskType::iter() {
            guards.push(TimerGuard::new(task_type).expect("can retrieve timer guard"));
        }
    }
}

fn init_state() {
    crate::state::STATE.with(|s| {
        *s.borrow_mut() = Some(initial_state());
    });
}
