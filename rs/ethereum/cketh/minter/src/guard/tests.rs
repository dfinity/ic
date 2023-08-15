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

mod retrieve_eth_timer_guard {
    use crate::guard::tests::init_state;
    use crate::guard::{retrieve_eth_timer_guard, TimerGuardError};

    #[test]
    fn should_prevent_concurrent_access() {
        init_state();
        let _guard = retrieve_eth_timer_guard().expect("can retrieve timer guard");

        assert_eq!(
            retrieve_eth_timer_guard(),
            Err(TimerGuardError::AlreadyProcessing)
        );
    }

    #[test]
    fn should_allow_access_when_guard_dropped() {
        init_state();
        let _guard = retrieve_eth_timer_guard().expect("can retrieve timer guard");

        drop(_guard);

        assert!(retrieve_eth_timer_guard().is_ok());
    }
}

fn init_state() {
    use crate::state::State;
    crate::state::STATE.with(|s| {
        *s.borrow_mut() = Some(State::default());
    });
}
