use crate::numeric::wei_from_milli_ether;

mod retrieve_eth_guard {
    use crate::guard::tests::init_state;
    use crate::guard::{retrieve_eth_guard, GuardError, MAX_CONCURRENT};
    use candid::Principal;

    #[test]
    fn should_error_on_reentrant_principal() {
        init_state();
        let principal = principal_with_id(1);
        let _guard = retrieve_eth_guard(principal).unwrap();

        assert_eq!(
            retrieve_eth_guard(principal),
            Err(GuardError::AlreadyProcessing)
        )
    }

    #[test]
    fn should_allow_reentrant_principal_after_drop() {
        init_state();
        let principal = principal_with_id(1);
        {
            let _guard = retrieve_eth_guard(principal).unwrap();
        }

        assert!(retrieve_eth_guard(principal).is_ok());
    }

    #[test]
    fn should_allow_limited_number_of_principals() {
        init_state();
        let mut guards: Vec<_> = (0..MAX_CONCURRENT)
            .map(|i| retrieve_eth_guard(principal_with_id(i as u64)).unwrap())
            .collect();

        for additional_principal in MAX_CONCURRENT..2 * MAX_CONCURRENT {
            assert_eq!(
                retrieve_eth_guard(principal_with_id(additional_principal as u64)),
                Err(GuardError::TooManyConcurrentRequests)
            );
        }

        {
            let _guard = guards.pop().expect("should have at least one guard");
        }
        assert!(retrieve_eth_guard(principal_with_id(MAX_CONCURRENT as u64)).is_ok());
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
    use crate::lifecycle::init::InitArg;
    use crate::state::State;
    use candid::Principal;
    crate::state::STATE.with(|s| {
        *s.borrow_mut() = Some(
            State::try_from(InitArg {
                ethereum_network: Default::default(),
                ecdsa_key_name: "test_key_1".to_string(),
                ethereum_contract_address: None,
                ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
                    .expect("BUG: invalid principal"),
                ethereum_block_height: Default::default(),
                minimum_withdrawal_amount: wei_from_milli_ether(10).into(),
                next_transaction_nonce: Default::default(),
            })
            .expect("init args should be valid"),
        );
    });
}
