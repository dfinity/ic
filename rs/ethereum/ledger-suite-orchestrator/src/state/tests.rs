mod manage_canister {
    use crate::scheduler::test_fixtures::{usdc, usdc_metadata, usdt, usdt_metadata};
    use crate::state::test_fixtures::{expect_panic_with_message, new_state};
    use crate::state::{
        Canisters, Index, Ledger, ManageSingleCanister, ManagedCanisterStatus, WasmHash,
    };
    use candid::Principal;
    use std::fmt::Debug;

    #[test]
    fn should_record_created_canister_in_any_order() {
        let mut state = new_state();
        state.record_new_erc20_token(usdc(), usdc_metadata());
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

        state.record_new_erc20_token(usdt(), usdt_metadata());
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
            let mut state = new_state();
            let canister_id = Principal::from_slice(&[1_u8; 29]);
            let contract = usdc();

            assert_eq!(state.managed_status::<C>(&contract), None);

            state.record_new_erc20_token(contract.clone(), usdc_metadata());
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
                    installed_wasm_hash: wasm_hash,
                })
            );
        }

        test::<Index>();
        test::<Ledger>();
    }

    #[test]
    fn should_panic_when_recording_created_canister_for_not_managed_erc20_token() {
        fn test<C: Debug>()
        where
            Canisters: ManageSingleCanister<C>,
        {
            let mut state = new_state();

            expect_panic_with_message(
                || state.record_created_canister::<C>(&usdc(), Principal::from_slice(&[1_u8; 29])),
                "not managed",
            );
        }

        test::<Index>();
        test::<Ledger>();
    }

    #[test]
    fn should_panic_when_recording_twice_same_new_erc20_token() {
        let mut state = new_state();
        let erc20 = usdc();
        state.record_new_erc20_token(erc20.clone(), usdc_metadata());

        expect_panic_with_message(
            || state.record_new_erc20_token(erc20, usdc_metadata()),
            "already managed",
        );
    }

    #[test]
    fn should_panic_when_recording_twice_canister_created() {
        fn test<C: Debug>()
        where
            Canisters: ManageSingleCanister<C>,
        {
            let mut state = new_state();
            let erc20 = usdc();
            state.record_new_erc20_token(erc20.clone(), usdc_metadata());
            let canister_id = Principal::from_slice(&[1_u8; 29]);
            state.record_created_canister::<C>(&erc20, canister_id);

            expect_panic_with_message(
                || state.record_created_canister::<C>(&erc20, canister_id),
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
            let mut state = new_state();

            expect_panic_with_message(
                || state.record_installed_canister::<C>(&usdc(), WasmHash::from([1_u8; 32])),
                "no managed canisters",
            );
        }

        test::<Index>();
        test::<Ledger>();
    }
}

mod wasm_hash {
    use crate::state::WasmHash;
    use assert_matches::assert_matches;
    use proptest::arbitrary::any;
    use proptest::array::uniform32;
    use proptest::{prop_assert_eq, proptest};
    use std::str::FromStr;

    proptest! {
        #[test]
        fn should_decode_display_string(hash in uniform32(any::<u8>())) {
            let parsed_hash = WasmHash::from_str(&WasmHash::from(hash).to_string()).unwrap();
            prop_assert_eq!(parsed_hash.as_ref(), &hash);
        }

        #[test]
        fn should_error_on_invalid_hash(invalid_hash in "[0-9a-fA-F]{0,63}|[0-9a-fA-F]{65,}") {
           assert_matches!(WasmHash::from_str(&invalid_hash), Err(_));
        }

         #[test]
        fn should_accept_valid_hash(valid_hash in "[0-9a-fA-F]{64}") {
            let result = WasmHash::from_str(&valid_hash).unwrap();
            prop_assert_eq!(result.as_ref(), &hex::decode(valid_hash).unwrap()[..]);
        }
    }
}

mod git_commit_hash {
    use crate::state::GitCommitHash;
    use assert_matches::assert_matches;
    use proptest::arbitrary::any;
    use proptest::array::uniform20;
    use proptest::{prop_assert_eq, proptest};
    use std::str::FromStr;

    proptest! {
        #[test]
        fn should_decode_display_string(hash in uniform20(any::<u8>())) {
            let parsed_hash = GitCommitHash::from_str(&GitCommitHash::from(hash).to_string()).unwrap();
            prop_assert_eq!(parsed_hash.as_ref(), &hash);
        }

        #[test]
        fn should_error_on_invalid_hash(invalid_hash in "[0-9a-fA-F]{0,39}|[0-9a-fA-F]{41,}") {
           assert_matches!(GitCommitHash::from_str(&invalid_hash), Err(_));
        }

         #[test]
        fn should_accept_valid_hash(valid_hash in "[0-9a-fA-F]{40}") {
            let result = GitCommitHash::from_str(&valid_hash).unwrap();
            prop_assert_eq!(result.as_ref(), &hex::decode(valid_hash).unwrap()[..]);
        }
    }
}

mod validate_config {
    use crate::candid::InitArg;
    use crate::state::test_fixtures::{arb_init_arg, arb_principal};
    use crate::state::{InvalidStateError, State};
    use proptest::collection::vec;
    use proptest::proptest;

    proptest! {
        #[test]
        fn should_accept_valid_config(init_arg in arb_init_arg(0..=9)) {
            let state = State::try_from(init_arg.clone()).expect("valid init arg");

           assert_eq!(state.more_controller_ids, init_arg.more_controller_ids);
        }

        #[test]
        fn should_error_when_too_many_additional_controllers(additional_controllers in vec(arb_principal(), 10..=100)) {
            let init_arg = InitArg {
                more_controller_ids: additional_controllers.clone(),
                minter_id: None,
                cycles_management: None,
            };

            let result = State::try_from(init_arg);

           assert_eq!(result, Err(InvalidStateError::TooManyAdditionalControllers{max: 9, actual: additional_controllers.len()}));
        }
    }
}

mod schema_upgrades {
    use crate::candid::CyclesManagement;
    use crate::scheduler::Task;
    use crate::state::test_fixtures::arb_state;
    use crate::state::{decode, encode, ManagedCanisters, State};
    use candid::{Deserialize, Principal};
    use proptest::proptest;
    use serde::Serialize;
    use std::collections::BTreeSet;

    #[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
    pub struct StatePreviousVersion {
        managed_canisters: ManagedCanisters,
        cycles_management: CyclesManagement,
        more_controller_ids: Vec<Principal>,
        minter_id: Option<Principal>,
        /// Locks preventing concurrent execution timer tasks
        pub active_tasks: BTreeSet<Task>,
    }

    impl From<State> for StatePreviousVersion {
        fn from(
            State {
                managed_canisters,
                cycles_management,
                more_controller_ids,
                minter_id,
                active_tasks,
                ledger_suite_version: _,
            }: State,
        ) -> Self {
            Self {
                managed_canisters,
                cycles_management,
                more_controller_ids,
                minter_id,
                active_tasks,
            }
        }
    }

    proptest! {
        #[test]
        fn should_be_able_to_upgrade_state(state in arb_state()) {
            let state_before_upgrade: StatePreviousVersion = state.into();

            let serialized_state_before_upgrade = encode(&state_before_upgrade);
            let state_after_upgrade: State = decode(serialized_state_before_upgrade.as_slice());

            assert_eq!(state_before_upgrade, state_after_upgrade.clone().into());
            assert_eq!(
                state_after_upgrade.ledger_suite_version,
                None
            );
        }
    }
}
