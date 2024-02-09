use crate::candid::{InitArg, LedgerInitArg};
use crate::management::{CallError, Reason};
use crate::scheduler::test_fixtures::usdc_metadata;
use crate::scheduler::tests::mock::MockCanisterRuntime;
use crate::scheduler::{Erc20Token, InstallLedgerSuiteArgs, Task, TaskError, Tasks};
use crate::state::{
    read_state, Canisters, IndexCanister, LedgerCanister, ManagedCanisterStatus, State, WasmHash,
};
use candid::Principal;

const ORCHESTRATOR_PRINCIPAL: Principal = Principal::from_slice(&[0_u8; 29]);
const LEDGER_PRINCIPAL: Principal = Principal::from_slice(&[1_u8; 29]);
const INDEX_PRINCIPAL: Principal = Principal::from_slice(&[2_u8; 29]);

#[tokio::test]
async fn should_install_ledger_suite() {
    init_state();
    let mut tasks = Tasks::default();
    tasks.add_task(Task::InstallLedgerSuite(usdc_install_args()));
    let mut runtime = MockCanisterRuntime::new();

    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(
        &mut runtime,
        vec![Ok(LEDGER_PRINCIPAL), Ok(INDEX_PRINCIPAL)],
    );
    runtime.expect_install_code().times(2).return_const(Ok(()));

    assert_eq!(tasks.execute(&runtime).await, Ok(()));

    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Installed {
                canister_id: LEDGER_PRINCIPAL,
                installed_wasm_hash: read_ledger_wasm_hash(),
            })),
            index: Some(IndexCanister::new(ManagedCanisterStatus::Installed {
                canister_id: INDEX_PRINCIPAL,
                installed_wasm_hash: read_index_wasm_hash(),
            })),
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );
}

#[tokio::test]
async fn should_not_retry_successful_operation_after_failing_one() {
    init_state();
    let mut tasks = Tasks::default();
    tasks.add_task(Task::InstallLedgerSuite(usdc_install_args()));
    let mut runtime = MockCanisterRuntime::new();

    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(&mut runtime, vec![Ok(LEDGER_PRINCIPAL)]);
    let expected_error = CallError {
        method: "install_code".to_string(),
        reason: Reason::OutOfCycles,
    };
    runtime
        .expect_install_code()
        .times(1)
        .return_const(Err(expected_error.clone()));

    assert_eq!(
        tasks.execute(&runtime).await,
        Err(TaskError::InstallCodeError(expected_error))
    );
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Created {
                canister_id: LEDGER_PRINCIPAL
            })),
            index: None,
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );

    runtime.checkpoint();
    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    let expected_error = CallError {
        method: "create_canister".to_string(),
        reason: Reason::OutOfCycles,
    };
    runtime.expect_install_code().times(1).return_const(Ok(()));
    expect_create_canister_returning(&mut runtime, vec![Err(expected_error.clone())]);

    assert_eq!(
        tasks.execute(&runtime).await,
        Err(TaskError::CanisterCreationError(expected_error))
    );
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Installed {
                canister_id: LEDGER_PRINCIPAL,
                installed_wasm_hash: read_ledger_wasm_hash(),
            })),
            index: None,
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );

    runtime.checkpoint();
    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(&mut runtime, vec![Ok(INDEX_PRINCIPAL)]);
    let expected_error = CallError {
        method: "install_code".to_string(),
        reason: Reason::OutOfCycles,
    };
    runtime
        .expect_install_code()
        .times(1)
        .return_const(Err(expected_error.clone()));

    assert_eq!(
        tasks.execute(&runtime).await,
        Err(TaskError::InstallCodeError(expected_error))
    );
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Installed {
                canister_id: LEDGER_PRINCIPAL,
                installed_wasm_hash: read_ledger_wasm_hash(),
            })),
            index: Some(IndexCanister::new(ManagedCanisterStatus::Created {
                canister_id: INDEX_PRINCIPAL
            })),
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );

    runtime.checkpoint();
    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    runtime.expect_install_code().times(1).return_const(Ok(()));
    assert_eq!(tasks.execute(&runtime).await, Ok(()));
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Installed {
                canister_id: LEDGER_PRINCIPAL,
                installed_wasm_hash: read_ledger_wasm_hash(),
            })),
            index: Some(IndexCanister::new(ManagedCanisterStatus::Installed {
                canister_id: INDEX_PRINCIPAL,
                installed_wasm_hash: read_index_wasm_hash(),
            })),
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );
}

#[tokio::test]
async fn should_discard_add_erc20_task_when_ledger_wasm_not_found() {
    init_state();
    let mut tasks = Tasks::default();
    let mut runtime = MockCanisterRuntime::new();
    let mut install_args = usdc_install_args();
    let unknown_wasm_hash = WasmHash::from([0_u8; 32]);
    install_args.ledger_compressed_wasm_hash = unknown_wasm_hash.clone();
    tasks.add_task(Task::InstallLedgerSuite(install_args));

    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(&mut runtime, vec![Ok(LEDGER_PRINCIPAL)]);

    assert_eq!(
        tasks.execute(&runtime).await,
        Err(TaskError::WasmHashNotFound(unknown_wasm_hash))
    );
    runtime.checkpoint();

    assert_eq!(tasks.execute(&runtime).await, Ok(()));
    assert_eq!(tasks.0.len(), 0);
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Created {
                canister_id: LEDGER_PRINCIPAL
            })),
            index: None,
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );
}

#[tokio::test]
async fn should_discard_add_erc20_task_when_index_wasm_not_found() {
    init_state();
    let mut tasks = Tasks::default();
    let mut runtime = MockCanisterRuntime::new();
    let mut install_args = usdc_install_args();
    let unknown_wasm_hash = WasmHash::from([0_u8; 32]);
    install_args.index_compressed_wasm_hash = unknown_wasm_hash.clone();
    tasks.add_task(Task::InstallLedgerSuite(install_args));

    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(
        &mut runtime,
        vec![Ok(LEDGER_PRINCIPAL), Ok(INDEX_PRINCIPAL)],
    );
    runtime.expect_install_code().times(1).return_const(Ok(()));

    assert_eq!(
        tasks.execute(&runtime).await,
        Err(TaskError::WasmHashNotFound(unknown_wasm_hash))
    );
    runtime.checkpoint();

    assert_eq!(tasks.execute(&runtime).await, Ok(()));
    assert_eq!(tasks.0.len(), 0);
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Installed {
                canister_id: LEDGER_PRINCIPAL,
                installed_wasm_hash: read_ledger_wasm_hash(),
            })),
            index: Some(IndexCanister::new(ManagedCanisterStatus::Created {
                canister_id: INDEX_PRINCIPAL
            })),
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );
}

fn init_state() {
    crate::state::init_state(State::from(InitArg {}));
}

fn usdc_install_args() -> InstallLedgerSuiteArgs {
    InstallLedgerSuiteArgs {
        contract: usdc(),
        ledger_init_arg: ledger_init_arg(),
        ledger_compressed_wasm_hash: read_ledger_wasm_hash(),
        index_compressed_wasm_hash: read_index_wasm_hash(),
    }
}

fn usdc() -> Erc20Token {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
    }
    .try_into()
    .unwrap()
}

fn ledger_init_arg() -> LedgerInitArg {
    use icrc_ledger_types::icrc1::account::Account as LedgerAccount;

    LedgerInitArg {
        minting_account: LedgerAccount {
            owner: Principal::anonymous(),
            subaccount: None,
        },
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: 10_000_u32.into(),
        decimals: None,
        token_name: "Chain Key USDC".to_string(),
        token_symbol: "ckUSDC".to_string(),
        token_logo: "".to_string(),
        max_memo_length: None,
        feature_flags: None,
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    }
}

fn read_index_wasm_hash() -> WasmHash {
    read_state(|s| s.index_wasm().hash().clone())
}

fn read_ledger_wasm_hash() -> WasmHash {
    read_state(|s| s.ledger_wasm().hash().clone())
}

fn expect_create_canister_returning(
    runtime: &mut MockCanisterRuntime,
    results: Vec<Result<Principal, CallError>>,
) {
    assert!(!results.is_empty(), "must return at least one result");
    let mut create_canister_call_counter = 0_usize;
    runtime
        .expect_create_canister()
        .times(results.len())
        .returning(move |_| {
            if create_canister_call_counter >= results.len() {
                panic!("create_canister called too many times!");
            }
            let result = results[create_canister_call_counter].clone();
            create_canister_call_counter += 1;
            result
        });
}
mod mock {
    use crate::management::CanisterRuntime;
    use crate::scheduler::CallError;
    use crate::state::Wasm;
    use async_trait::async_trait;
    use candid::Principal;
    use mockall::mock;

    mock! {
       pub CanisterRuntime{}

        #[async_trait]
        impl CanisterRuntime for CanisterRuntime {

            fn id(&self) -> Principal;

            async fn create_canister(
                &self,
                cycles_for_canister_creation: u64,
            ) -> Result<Principal, CallError>;

            async fn install_code(
                &self,
                canister_id: Principal,
                wasm_module: Wasm,
                arg: Vec<u8>,
            ) -> Result<(), CallError>;
        }
    }
}

mod install_ledger_suite_args {
    use crate::candid::{AddErc20Arg, InitArg, LedgerInitArg};
    use crate::scheduler::tests::usdc_metadata;
    use crate::scheduler::{ChainId, Erc20Token, InstallLedgerSuiteArgs, InvalidAddErc20ArgError};
    use crate::state::{State, Wasm, WasmHash};
    use assert_matches::assert_matches;
    use candid::{Nat, Principal};
    use proptest::array::uniform32;
    use proptest::prelude::any;
    use proptest::{prop_assert_eq, proptest};

    const ERC20_CONTRACT_ADDRESS: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    #[test]
    fn should_error_if_contract_is_already_managed() {
        let mut state = initial_state();
        let arg = valid_add_erc20_arg(&state);
        let contract: Erc20Token = arg.contract.clone().try_into().unwrap();
        state.record_new_erc20_token(contract.clone(), usdc_metadata());

        assert_eq!(
            InstallLedgerSuiteArgs::validate_add_erc20(&state, arg),
            Err(InvalidAddErc20ArgError::Erc20ContractAlreadyManaged(
                contract
            ))
        );
    }

    proptest! {
        #[test]
        fn should_error_on_invalid_ethereum_address(invalid_address in "0x[0-9a-fA-F]{0,39}|[0-9a-fA-F]{41,}") {
            let state = initial_state();
            let mut arg = valid_add_erc20_arg(&state);
            arg.contract.address = invalid_address;
            assert_matches!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, arg),
                Err(InvalidAddErc20ArgError::InvalidErc20Contract(_))
            );
        }

        #[test]
        fn should_error_on_large_chain_id(offset in 0_u128..=u64::MAX as u128) {
            let state = initial_state();
            let mut arg = valid_add_erc20_arg(&state);
            arg.contract.chain_id = Nat::from((u64::MAX as u128) + offset);

            assert_matches!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, arg),
                Err(InvalidAddErc20ArgError::InvalidErc20Contract(_))
            );
        }

        #[test]
        fn should_error_on_invalid_wasm_hash(invalid_hash in "[0-9a-fA-F]{0,63}|[0-9a-fA-F]{65,}") {
            let state = initial_state();
            let mut arg = valid_add_erc20_arg(&state);
            arg.ledger_compressed_wasm_hash = invalid_hash.clone();
            assert_matches!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, arg),
                Err(InvalidAddErc20ArgError::InvalidWasmHash(_))
            );

            let mut arg = valid_add_erc20_arg(&state);
            arg.index_compressed_wasm_hash = invalid_hash;
            assert_matches!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, arg),
                Err(InvalidAddErc20ArgError::InvalidWasmHash(_))
            );
        }

        #[test]
        fn should_error_when_wasm_hash_not_found(hash in uniform32(any::<u8>())) {
            let state = initial_state();
            let mut arg = valid_add_erc20_arg(&state);
            let unknown_hash = WasmHash::from(hash);
            arg.ledger_compressed_wasm_hash = unknown_hash.to_string();
            prop_assert_eq!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, arg),
                Err(InvalidAddErc20ArgError::WasmHashNotFound(unknown_hash.clone()))
            );

            let mut arg = valid_add_erc20_arg(&state);
            arg.index_compressed_wasm_hash = unknown_hash.to_string();
            prop_assert_eq!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, arg),
                Err(InvalidAddErc20ArgError::WasmHashNotFound(unknown_hash.clone()))
            );
        }

        #[test]
        fn should_error_on_wasm_hash_for_ledger_and_index_are_equal(hash in "[0-9a-fA-F]{64}") {
            let state = initial_state();
            let mut arg = valid_add_erc20_arg(&state);
            arg.ledger_compressed_wasm_hash = hash.clone();
            arg.index_compressed_wasm_hash = hash;

            assert_matches!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, arg),
                Err(InvalidAddErc20ArgError::InvalidWasmHash(_))
            );
        }
    }

    #[test]
    fn should_accept_valid_erc20_arg() {
        let state = initial_state();
        let arg = valid_add_erc20_arg(&state);
        let ledger_init_arg = arg.ledger_init_arg.clone();

        let result = InstallLedgerSuiteArgs::validate_add_erc20(&state, arg).unwrap();

        assert_eq!(
            result,
            InstallLedgerSuiteArgs {
                contract: Erc20Token(ChainId(1), ERC20_CONTRACT_ADDRESS.parse().unwrap()),
                ledger_init_arg,
                ledger_compressed_wasm_hash: Wasm::from(crate::state::LEDGER_BYTECODE)
                    .hash()
                    .clone(),
                index_compressed_wasm_hash: Wasm::from(crate::state::INDEX_BYTECODE).hash().clone(),
            }
        );
    }

    fn valid_add_erc20_arg(state: &State) -> AddErc20Arg {
        use icrc_ledger_types::icrc1::account::Account as LedgerAccount;

        let arg = AddErc20Arg {
            contract: crate::candid::Erc20Contract {
                chain_id: Nat::from(1_u8),
                address: ERC20_CONTRACT_ADDRESS.to_string(),
            },
            ledger_init_arg: LedgerInitArg {
                minting_account: LedgerAccount {
                    owner: Principal::anonymous(),
                    subaccount: None,
                },
                fee_collector_account: None,
                initial_balances: vec![],
                transfer_fee: 10_000_u32.into(),
                decimals: None,
                token_name: "USD Coin".to_string(),
                token_symbol: "USDC".to_string(),
                token_logo: "".to_string(),
                max_memo_length: None,
                feature_flags: None,
                maximum_number_of_accounts: None,
                accounts_overflow_trim_quantity: None,
            },
            ledger_compressed_wasm_hash: Wasm::from(crate::state::LEDGER_BYTECODE)
                .hash()
                .to_string(),
            index_compressed_wasm_hash: Wasm::from(crate::state::INDEX_BYTECODE).hash().to_string(),
        };
        assert_matches!(
            InstallLedgerSuiteArgs::validate_add_erc20(state, arg.clone()),
            Ok(_),
            "BUG: invalid add erc20: {:?}",
            arg
        );
        arg
    }

    fn initial_state() -> State {
        State::from(InitArg {})
    }
}
