use crate::candid::InitArg;
use crate::scheduler::Erc20Contract;
use crate::state::State;

mod manage_canister {
    use crate::state::tests::{expect_panic_with_message, init_state, usdc, usdt};
    use crate::state::{
        Canisters, Index, Ledger, ManageSingleCanister, ManagedCanisterStatus, WasmHash,
    };
    use candid::Principal;
    use std::fmt::Debug;

    #[test]
    fn should_record_created_canister_in_any_order() {
        let mut state = init_state();
        let usdc_index_canister_id = Principal::from_slice(&[1_u8; 29]);
        state.record_created_canister::<Index>(&usdc(), usdc_index_canister_id);
        assert_eq!(
            state.managed_status::<Index>(&usdc()),
            Some(&ManagedCanisterStatus::Created {
                canister_id: usdc_index_canister_id
            })
        );
        let usdc_ledger_canister_id = Principal::from_slice(&[2_u8; 29]);
        assert_ne!(usdc_index_canister_id, usdc_ledger_canister_id);
        state.record_created_canister::<Ledger>(&usdc(), usdc_ledger_canister_id);
        assert_eq!(
            state.managed_status::<Ledger>(&usdc()),
            Some(&ManagedCanisterStatus::Created {
                canister_id: usdc_ledger_canister_id
            })
        );

        let usdt_ledger_canister_id = Principal::from_slice(&[3_u8; 29]);
        state.record_created_canister::<Ledger>(&usdt(), usdt_ledger_canister_id);
        assert_eq!(
            state.managed_status::<Ledger>(&usdt()),
            Some(&ManagedCanisterStatus::Created {
                canister_id: usdt_ledger_canister_id
            })
        );
        let usdt_index_canister_id = Principal::from_slice(&[4_u8; 29]);
        state.record_created_canister::<Index>(&usdt(), usdt_index_canister_id);
        assert_eq!(
            state.managed_status::<Index>(&usdt()),
            Some(&ManagedCanisterStatus::Created {
                canister_id: usdt_index_canister_id
            })
        );
    }

    #[test]
    fn should_record_installed_canister_and_keep_correct_status() {
        fn test<C: Debug>()
        where
            Canisters: ManageSingleCanister<C>,
        {
            let mut state = init_state();
            let canister_id = Principal::from_slice(&[1_u8; 29]);
            let contract = usdc();

            assert_eq!(state.managed_status::<C>(&contract), None);

            state.record_created_canister::<C>(&contract, canister_id);
            assert_eq!(
                state.managed_status::<C>(&contract),
                Some(&ManagedCanisterStatus::Created { canister_id })
            );

            let wasm_hash = WasmHash::from([1_u8; 32]);
            state.record_installed_canister::<C>(&contract, wasm_hash.clone());
            assert_eq!(
                state.managed_status::<C>(&contract),
                Some(&ManagedCanisterStatus::Installed {
                    canister_id,
                    installed_wasm_hash: wasm_hash
                })
            );
        }

        test::<Index>();
        test::<Ledger>();
    }

    #[test]
    fn should_panic_when_recording_twice_canister_created() {
        fn test<C: Debug>()
        where
            Canisters: ManageSingleCanister<C>,
        {
            let mut state = init_state();
            let canister_id = Principal::from_slice(&[1_u8; 29]);
            state.record_created_canister::<C>(&usdc(), canister_id);

            expect_panic_with_message(
                || state.record_created_canister::<C>(&usdc(), canister_id),
                "already created",
            );
        }

        test::<Index>();
        test::<Ledger>();
    }

    #[test]
    fn should_panic_when_recording_installed_canister_but_canister_was_not_created() {
        fn test<C: Debug>()
        where
            Canisters: ManageSingleCanister<C>,
        {
            let mut state = init_state();

            expect_panic_with_message(
                || state.record_installed_canister::<C>(&usdc(), WasmHash::from([1_u8; 32])),
                "no managed canisters",
            );
        }

        test::<Index>();
        test::<Ledger>();
    }
}

fn expect_panic_with_message<F: FnOnce() -> R, R: std::fmt::Debug>(f: F, expected_message: &str) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let error = result.unwrap_err();
    let panic_message = {
        if let Some(s) = error.downcast_ref::<String>() {
            s.to_string()
        } else if let Some(s) = error.downcast_ref::<&str>() {
            s.to_string()
        } else {
            format!("{:?}", error)
        }
    };
    assert!(
        panic_message.contains(expected_message),
        "Expected panic message to contain: {}, but got: {}",
        expected_message,
        panic_message
    );
}

fn init_state() -> State {
    State::from(InitArg {
        ledger_wasm: vec![],
        index_wasm: vec![],
        archive_wasm: vec![],
    })
}

fn usdc() -> Erc20Contract {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
    }
    .try_into()
    .unwrap()
}

fn usdt() -> Erc20Contract {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
    }
    .try_into()
    .unwrap()
}
