use crate::candid::{AddCkErc20Token, CyclesManagement, InitArg, LedgerInitArg};
use crate::management::{CallError, CanisterRuntime, Reason};
use crate::scheduler::test_fixtures::{usdc, usdc_metadata, usdc_token_id};
use crate::scheduler::tests::mock::MockCanisterRuntime;
use crate::scheduler::{InstallLedgerSuiteArgs, Task, TaskError, TaskExecution, cycles_to_u128};
use crate::state::test_fixtures::new_state;
use crate::state::{
    ARCHIVE_NODE_BYTECODE, Canisters, GitCommitHash, INDEX_BYTECODE, IndexCanister,
    LEDGER_BYTECODE, LedgerCanister, LedgerSuiteVersion, ManagedCanisterStatus, State, WasmHash,
    read_state,
};
use crate::storage::{TASKS, mutate_wasm_store, record_icrc1_ledger_suite_wasms};
use candid::Principal;
use icrc_ledger_types::icrc3::archive::{GetArchivesArgs, GetArchivesResult};

const ORCHESTRATOR_PRINCIPAL: Principal = Principal::from_slice(&[0_u8; 29]);
const LEDGER_PRINCIPAL: Principal = Principal::from_slice(&[1_u8; 29]);
const INDEX_PRINCIPAL: Principal = Principal::from_slice(&[2_u8; 29]);
const MINTER_PRINCIPAL: Principal = Principal::from_slice(&[3_u8; 29]);

#[tokio::test]
async fn should_install_ledger_suite() {
    init_state();
    let mut runtime = MockCanisterRuntime::new();

    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(
        &mut runtime,
        vec![ORCHESTRATOR_PRINCIPAL],
        vec![Ok(LEDGER_PRINCIPAL), Ok(INDEX_PRINCIPAL)],
    );
    runtime.expect_install_code().times(2).return_const(Ok(()));

    let task = TaskExecution {
        task_type: Task::InstallLedgerSuite(usdc_install_args()),
        execute_at_ns: 0,
    };
    assert_eq!(task.execute(&runtime).await, Ok(()));

    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
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
async fn should_top_up_canister() {
    use mockall::Sequence;
    init_state();
    let cycles_management = CyclesManagement::default();
    let orchestrator_cycles = cycles_to_u128(cycles_management.minimum_orchestrator_cycles()) * 2;
    let low_cycles = cycles_to_u128(cycles_management.minimum_monitored_canister_cycles()) / 2;
    let enough_cycles = cycles_to_u128(cycles_management.minimum_monitored_canister_cycles());
    let mut runtime = MockCanisterRuntime::new();
    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(
        &mut runtime,
        vec![ORCHESTRATOR_PRINCIPAL],
        vec![Ok(LEDGER_PRINCIPAL), Ok(INDEX_PRINCIPAL)],
    );
    runtime.expect_install_code().times(2).return_const(Ok(()));

    let task = TaskExecution {
        task_type: Task::InstallLedgerSuite(usdc_install_args()),
        execute_at_ns: 0,
    };
    assert_eq!(task.execute(&runtime).await, Ok(()));

    let task = TaskExecution {
        task_type: Task::MaybeTopUp,
        execute_at_ns: 0,
    };
    let mut seq = Sequence::new();
    runtime
        .expect_canister_cycles()
        .times(1)
        .in_sequence(&mut seq)
        .return_const(Ok(orchestrator_cycles));
    runtime
        .expect_canister_cycles()
        .times(2)
        .in_sequence(&mut seq)
        .return_const(Ok(low_cycles));

    runtime
        .expect_send_cycles()
        .withf(move |&canister_id, _args: &u128| {
            canister_id == LEDGER_PRINCIPAL || canister_id == INDEX_PRINCIPAL
        })
        .times(2)
        .return_const(Ok(()));
    assert_eq!(task.execute(&runtime).await, Ok(()));

    let mut seq = Sequence::new();
    runtime
        .expect_canister_cycles()
        .times(1)
        .in_sequence(&mut seq)
        .return_const(Ok(orchestrator_cycles));
    runtime
        .expect_canister_cycles()
        .times(2)
        .in_sequence(&mut seq)
        .return_const(Ok(low_cycles));
    runtime
        .expect_send_cycles()
        .times(1)
        .return_const(Err(CallError {
            method: "send_cycles".to_string(),
            reason: Reason::OutOfCycles,
        }));
    runtime.expect_send_cycles().times(1).return_const(Ok(()));
    assert_eq!(task.execute(&runtime).await, Ok(()));

    let mut seq = Sequence::new();
    runtime
        .expect_canister_cycles()
        .times(1)
        .in_sequence(&mut seq)
        .return_const(Ok(orchestrator_cycles));
    runtime
        .expect_canister_cycles()
        .times(2)
        .in_sequence(&mut seq)
        .return_const(Ok(enough_cycles));
    runtime.expect_send_cycles().never();
    assert_eq!(task.execute(&runtime).await, Ok(()));
}

#[tokio::test]
async fn should_install_ledger_suite_with_additional_controllers() {
    const OTHER_PRINCIPAL: Principal = Principal::from_slice(&[3_u8; 29]);
    crate::state::init_state(
        State::try_from(InitArg {
            more_controller_ids: vec![OTHER_PRINCIPAL],
            minter_id: None,
            cycles_management: None,
        })
        .unwrap(),
    );
    let _version = register_embedded_wasms();

    let mut runtime = MockCanisterRuntime::new();

    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(
        &mut runtime,
        vec![ORCHESTRATOR_PRINCIPAL, OTHER_PRINCIPAL],
        vec![Ok(LEDGER_PRINCIPAL), Ok(INDEX_PRINCIPAL)],
    );
    runtime.expect_install_code().times(2).return_const(Ok(()));

    let task = TaskExecution {
        task_type: Task::InstallLedgerSuite(usdc_install_args()),
        execute_at_ns: 0,
    };
    assert_eq!(task.execute(&runtime).await, Ok(()));

    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
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
    let mut runtime = MockCanisterRuntime::new();

    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    let expected_error = CallError {
        method: "create_canister".to_string(),
        reason: Reason::OutOfCycles,
    };
    expect_create_canister_returning(
        &mut runtime,
        vec![ORCHESTRATOR_PRINCIPAL],
        vec![Err(expected_error.clone())],
    );

    let task = TaskExecution {
        task_type: Task::InstallLedgerSuite(usdc_install_args()),
        execute_at_ns: 0,
    };
    assert_eq!(
        task.execute(&runtime).await,
        Err(TaskError::CanisterCreationError(expected_error))
    );
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
        Some(Canisters {
            ledger: None,
            index: None,
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );

    runtime.checkpoint();
    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    let expected_error = CallError {
        method: "create_canister".to_string(),
        reason: Reason::OutOfCycles,
    };
    expect_create_canister_returning(
        &mut runtime,
        vec![ORCHESTRATOR_PRINCIPAL],
        vec![Ok(LEDGER_PRINCIPAL), Err(expected_error.clone())],
    );

    let task = TaskExecution {
        task_type: Task::InstallLedgerSuite(usdc_install_args()),
        execute_at_ns: 0,
    };
    assert_eq!(
        task.execute(&runtime).await,
        Err(TaskError::CanisterCreationError(expected_error))
    );
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
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
    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(
        &mut runtime,
        vec![ORCHESTRATOR_PRINCIPAL],
        vec![Ok(INDEX_PRINCIPAL)],
    );
    let expected_error = CallError {
        method: "install_code".to_string(),
        reason: Reason::OutOfCycles,
    };
    runtime
        .expect_install_code()
        .times(1)
        .return_const(Err(expected_error.clone()));

    let task = TaskExecution {
        task_type: Task::InstallLedgerSuite(usdc_install_args()),
        execute_at_ns: 0,
    };
    assert_eq!(
        task.execute(&runtime).await,
        Err(TaskError::InstallCodeError(expected_error))
    );
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Created {
                canister_id: LEDGER_PRINCIPAL
            })),
            index: Some(IndexCanister::new(ManagedCanisterStatus::Created {
                canister_id: INDEX_PRINCIPAL
            })),
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );

    runtime.checkpoint();
    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    let expected_error = CallError {
        method: "install_code".to_string(),
        reason: Reason::OutOfCycles,
    };
    expect_install_code_returning(&mut runtime, vec![Ok(()), Err(expected_error.clone())]);

    assert_eq!(
        task.execute(&runtime).await,
        Err(TaskError::InstallCodeError(expected_error))
    );
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
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
    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    runtime.expect_install_code().times(1).return_const(Ok(()));
    assert_eq!(task.execute(&runtime).await, Ok(()));
    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
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
    let mut runtime = MockCanisterRuntime::new();
    let mut install_args = usdc_install_args();
    let unknown_wasm_hash = WasmHash::from([0_u8; 32]);
    install_args.ledger_compressed_wasm_hash = unknown_wasm_hash.clone();
    let task = TaskExecution {
        task_type: Task::InstallLedgerSuite(install_args),
        execute_at_ns: 0,
    };

    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(
        &mut runtime,
        vec![ORCHESTRATOR_PRINCIPAL],
        vec![Ok(LEDGER_PRINCIPAL), Ok(INDEX_PRINCIPAL)],
    );

    assert_eq!(
        task.execute(&runtime).await,
        Err(TaskError::WasmHashNotFound(unknown_wasm_hash))
    );
    runtime.checkpoint();

    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
        Some(Canisters {
            ledger: Some(LedgerCanister::new(ManagedCanisterStatus::Created {
                canister_id: LEDGER_PRINCIPAL
            })),
            index: Some(IndexCanister::new(ManagedCanisterStatus::Created {
                canister_id: INDEX_PRINCIPAL
            })),
            archives: vec![],
            metadata: usdc_metadata(),
        })
    );
}

#[tokio::test]
async fn should_discard_add_erc20_task_when_index_wasm_not_found() {
    init_state();
    let mut runtime = MockCanisterRuntime::new();
    let mut install_args = usdc_install_args();
    let unknown_wasm_hash = WasmHash::from([0_u8; 32]);
    install_args.index_compressed_wasm_hash = unknown_wasm_hash.clone();
    let task = TaskExecution {
        task_type: Task::InstallLedgerSuite(install_args),
        execute_at_ns: 0,
    };
    runtime.expect_id().return_const(ORCHESTRATOR_PRINCIPAL);
    expect_create_canister_returning(
        &mut runtime,
        vec![ORCHESTRATOR_PRINCIPAL],
        vec![Ok(LEDGER_PRINCIPAL), Ok(INDEX_PRINCIPAL)],
    );
    runtime.expect_install_code().times(1).return_const(Ok(()));

    assert_eq!(
        task.execute(&runtime).await,
        Err(TaskError::WasmHashNotFound(unknown_wasm_hash))
    );
    runtime.checkpoint();

    assert_eq!(
        read_state(|s| s.managed_canisters(&usdc_token_id()).cloned()),
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

mod notify_erc_20_added {
    use crate::candid::AddCkErc20Token;
    use crate::management::{CallError, Reason};
    use crate::scheduler::test_fixtures::{usdc, usdc_metadata};
    use crate::scheduler::tests::mock::MockCanisterRuntime;
    use crate::scheduler::tests::{
        LEDGER_PRINCIPAL, MINTER_PRINCIPAL, expect_call_canister_add_ckerc20_token, init_state,
    };
    use crate::scheduler::{Task, TaskError, TaskExecution};
    use crate::state::{Ledger, mutate_state};
    use candid::Nat;

    #[tokio::test]
    async fn should_retry_when_ledger_not_yet_created() {
        init_state();
        let usdc = usdc();
        let task = TaskExecution {
            task_type: Task::NotifyErc20Added {
                erc20_token: usdc.clone(),
                minter_id: MINTER_PRINCIPAL,
            },
            execute_at_ns: 0,
        };
        let runtime = MockCanisterRuntime::new();

        assert_eq!(
            task.execute(&runtime).await,
            Err(TaskError::LedgerNotFound(usdc.clone()))
        );

        assert_eq!(
            task.execute(&runtime).await,
            Err(TaskError::LedgerNotFound(usdc.clone()))
        );

        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata());
        });
        assert_eq!(
            task.execute(&runtime).await,
            Err(TaskError::LedgerNotFound(usdc))
        );
    }

    #[tokio::test]
    async fn should_notify_erc20_added() {
        init_state();
        let usdc = usdc();
        let usdc_metadata = usdc_metadata();
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata.clone());
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
        });
        let task = TaskExecution {
            task_type: Task::NotifyErc20Added {
                erc20_token: usdc.clone(),
                minter_id: MINTER_PRINCIPAL,
            },
            execute_at_ns: 0,
        };
        let mut runtime = MockCanisterRuntime::new();
        expect_call_canister_add_ckerc20_token(
            &mut runtime,
            MINTER_PRINCIPAL,
            AddCkErc20Token {
                chain_id: Nat::from(1_u8),
                address: usdc.address().to_string(),
                ckerc20_token_symbol: usdc_metadata.token_symbol,
                ckerc20_ledger_id: LEDGER_PRINCIPAL,
            },
            Ok(()),
        );

        assert_eq!(task.execute(&runtime).await, Ok(()));
    }

    #[tokio::test]
    async fn should_not_retry_when_error_unrecoverable() {
        init_state();
        let usdc = usdc();
        let usdc_metadata = usdc_metadata();
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata.clone());
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
        });

        for unrecoverable_reason in [
            Reason::CanisterError("trap".to_string()),
            Reason::Rejected("rejected".to_string()),
            Reason::InternalError("internal".to_string()),
        ] {
            let task = TaskExecution {
                task_type: Task::NotifyErc20Added {
                    erc20_token: usdc.clone(),
                    minter_id: MINTER_PRINCIPAL,
                },
                execute_at_ns: 0,
            };
            let expected_error = CallError {
                method: "error".to_string(),
                reason: unrecoverable_reason,
            };
            let mut runtime = MockCanisterRuntime::new();
            runtime
                .expect_call_canister::<AddCkErc20Token, ()>()
                .times(1)
                .withf(move |_canister_id, method, _args: &AddCkErc20Token| {
                    method == "add_ckerc20_token"
                })
                .return_const(Err(expected_error.clone()));

            assert_eq!(
                task.execute(&runtime).await,
                Err(TaskError::InterCanisterCallError(expected_error))
            );
        }
    }

    #[tokio::test]
    async fn should_retry_when_error_is_recoverable() {
        init_state();
        let usdc = usdc();
        let usdc_metadata = usdc_metadata();
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata.clone());
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
        });

        for recoverable_reason in [
            Reason::OutOfCycles,
            Reason::TransientInternalError("transient".to_string()),
        ] {
            let task = TaskExecution {
                task_type: Task::NotifyErc20Added {
                    erc20_token: usdc.clone(),
                    minter_id: MINTER_PRINCIPAL,
                },
                execute_at_ns: 0,
            };
            let expected_error = CallError {
                method: "error".to_string(),
                reason: recoverable_reason,
            };
            let mut runtime = MockCanisterRuntime::new();
            runtime
                .expect_call_canister::<AddCkErc20Token, ()>()
                .times(1)
                .withf(move |_canister_id, method, _args: &AddCkErc20Token| {
                    method == "add_ckerc20_token"
                })
                .return_const(Err(expected_error.clone()));

            assert_eq!(
                task.execute(&runtime).await,
                Err(TaskError::InterCanisterCallError(expected_error))
            );
            runtime.checkpoint();

            expect_call_canister_add_ckerc20_token(
                &mut runtime,
                MINTER_PRINCIPAL,
                AddCkErc20Token {
                    chain_id: Nat::from(1_u8),
                    address: usdc.address().to_string(),
                    ckerc20_token_symbol: usdc_metadata.token_symbol.clone(),
                    ckerc20_ledger_id: LEDGER_PRINCIPAL,
                },
                Ok(()),
            );

            assert_eq!(task.execute(&runtime).await, Ok(()));
        }
    }
}
mod discover_archives {
    use crate::management::{CallError, Reason};
    use crate::scheduler::test_fixtures::{
        dai, dai_metadata, usdc, usdc_metadata, usdt, usdt_metadata,
    };
    use crate::scheduler::tests::mock::MockCanisterRuntime;
    use crate::scheduler::tests::{
        LEDGER_PRINCIPAL, expect_call_canister_icrc3_get_archives, init_state,
    };
    use crate::scheduler::{DiscoverArchivesError, Erc20Token, Task, TaskError, TaskExecution};
    use crate::state::{Ledger, TokenId, mutate_state, read_state};
    use candid::Principal;
    use icrc_ledger_types::icrc3::archive::ICRC3ArchiveInfo;

    #[tokio::test]
    async fn should_discover_multiple_archives() {
        init_state();
        let usdc = usdc();
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata());
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
        });

        let first_archive = Principal::from_slice(&[4_u8; 29]);
        let first_archive_info = ICRC3ArchiveInfo {
            canister_id: first_archive,
            start: 0_u8.into(),
            end: 1_u8.into(),
        };
        let mut runtime = MockCanisterRuntime::new();
        expect_call_canister_icrc3_get_archives(
            &mut runtime,
            LEDGER_PRINCIPAL,
            Ok(vec![first_archive_info.clone()]),
        );

        let discover_archives_task = TaskExecution {
            task_type: Task::DiscoverArchives,
            execute_at_ns: 0,
        };
        assert_eq!(discover_archives_task.execute(&runtime).await, Ok(()));
        assert_eq!(archives_from_state(&usdc), vec![first_archive]);

        runtime.checkpoint();

        let second_archive = Principal::from_slice(&[5_u8; 29]);
        let second_archive_info = ICRC3ArchiveInfo {
            canister_id: second_archive,
            start: 2_u8.into(),
            end: 3_u8.into(),
        };
        expect_call_canister_icrc3_get_archives(
            &mut runtime,
            LEDGER_PRINCIPAL,
            Ok(vec![first_archive_info, second_archive_info]),
        );

        assert_eq!(discover_archives_task.execute(&runtime).await, Ok(()));
        assert_eq!(
            archives_from_state(&usdc),
            vec![first_archive, second_archive]
        );
    }

    #[tokio::test]
    async fn should_discover_archive_and_return_first_error() {
        init_state();
        let (dai, dai_ledger) = (dai(), Principal::from_slice(&[4_u8; 29]));
        let (usdc, usdc_ledger) = (usdc(), Principal::from_slice(&[5_u8; 29]));
        let (usdt, usdt_ledger) = (usdt(), Principal::from_slice(&[6_u8; 29]));
        mutate_state(|s| {
            s.record_new_erc20_token(dai.clone(), dai_metadata());
            s.record_created_canister::<Ledger>(&dai, dai_ledger);

            s.record_new_erc20_token(usdc.clone(), usdc_metadata());
            s.record_created_canister::<Ledger>(&usdc, usdc_ledger);

            s.record_new_erc20_token(usdt.clone(), usdt_metadata());
            s.record_created_canister::<Ledger>(&usdt, usdt_ledger);
        });

        let mut runtime = MockCanisterRuntime::new();
        let first_error = CallError {
            method: "dai error".to_string(),
            reason: Reason::OutOfCycles,
        };
        expect_call_canister_icrc3_get_archives(&mut runtime, dai_ledger, Err(first_error.clone()));
        let usdc_archive = Principal::from_slice(&[7_u8; 29]);
        expect_call_canister_icrc3_get_archives(
            &mut runtime,
            usdc_ledger,
            Ok(vec![ICRC3ArchiveInfo {
                canister_id: usdc_archive,
                start: 0_u8.into(),
                end: 1_u8.into(),
            }]),
        );
        expect_call_canister_icrc3_get_archives(
            &mut runtime,
            usdt_ledger,
            Err(CallError {
                method: "usdt error".to_string(),
                reason: Reason::OutOfCycles,
            }),
        );

        let discover_archives_task = TaskExecution {
            task_type: Task::DiscoverArchives,
            execute_at_ns: 0,
        };
        assert_eq!(
            discover_archives_task.execute(&runtime).await,
            Err(TaskError::DiscoverArchivesError(
                DiscoverArchivesError::InterCanisterCallError(first_error)
            ))
        );
        assert_eq!(archives_from_state(&dai), vec![]);
        assert_eq!(archives_from_state(&usdc), vec![usdc_archive]);
        assert_eq!(archives_from_state(&usdt), vec![]);
    }

    fn archives_from_state(contract: &Erc20Token) -> Vec<Principal> {
        read_state(|s| {
            s.managed_canisters(&TokenId::from(contract.clone()))
                .unwrap()
                .archives
                .clone()
        })
    }
}

mod upgrade_ledger_suite {
    use crate::management::CallError;
    use crate::scheduler::UpgradeLedgerSuiteError::{CanisterNotReady, TokenNotFound};
    use crate::scheduler::test_fixtures::{usdc, usdc_metadata, usdc_token_id};
    use crate::scheduler::tests::{
        INDEX_PRINCIPAL, LEDGER_PRINCIPAL, execute_now, expect_call_canister_icrc3_get_archives,
        init_state, mock::MockCanisterRuntime, read_archive_wasm_hash, read_index_wasm_hash,
        read_ledger_wasm_hash, task_queue_from_state,
    };
    use crate::scheduler::{
        Task, TaskError, UpgradeLedgerSuite, UpgradeLedgerSuiteError, UpgradeLedgerSuiteSubtask,
        pop_if_ready,
    };
    use crate::state::{
        ARCHIVE_NODE_BYTECODE, CanisterUpgrade, INDEX_BYTECODE, Index, LEDGER_BYTECODE, Ledger,
        ManagedCanisterStatus, TokenId, WasmHash, mutate_state, read_state,
    };
    use UpgradeLedgerSuiteSubtask::{
        DiscoverArchives, UpgradeArchives, UpgradeIndex, UpgradeLedger,
    };
    use candid::Principal;
    use icrc_ledger_types::icrc3::archive::ICRC3ArchiveInfo;
    use maplit::btreemap;

    #[test]
    fn should_upgrade_in_the_correct_order() {
        let ledger_wasm_hash = WasmHash::from([1_u8; 32]);
        let index_wasm_hash = WasmHash::from([2_u8; 32]);
        let archive_wasm_hash = WasmHash::from([3_u8; 32]);

        let subtasks: Vec<_> = UpgradeLedgerSuite::builder(usdc_token_id())
            .build()
            .collect();
        assert_eq!(subtasks, vec![]);

        let subtasks: Vec<_> = UpgradeLedgerSuite::builder(usdc_token_id())
            .ledger_wasm_hash(ledger_wasm_hash.clone())
            .build()
            .collect();
        assert_eq!(
            subtasks,
            vec![UpgradeLedger {
                token_id: usdc_token_id(),
                compressed_wasm_hash: ledger_wasm_hash.clone()
            },]
        );

        let subtasks: Vec<_> = UpgradeLedgerSuite::builder(usdc_token_id())
            .index_wasm_hash(index_wasm_hash.clone())
            .build()
            .collect();
        assert_eq!(
            subtasks,
            vec![UpgradeIndex {
                token_id: usdc_token_id(),
                compressed_wasm_hash: index_wasm_hash.clone()
            },]
        );

        let subtasks: Vec<_> = UpgradeLedgerSuite::builder(usdc_token_id())
            .ledger_wasm_hash(ledger_wasm_hash.clone())
            .index_wasm_hash(index_wasm_hash.clone())
            .build()
            .collect();
        assert_eq!(
            subtasks,
            vec![
                UpgradeIndex {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: index_wasm_hash.clone()
                },
                UpgradeLedger {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: ledger_wasm_hash.clone()
                },
            ]
        );

        let subtasks: Vec<_> = UpgradeLedgerSuite::builder(usdc_token_id())
            .archive_wasm_hash(archive_wasm_hash.clone())
            .build()
            .collect();
        assert_eq!(
            subtasks,
            vec![
                DiscoverArchives {
                    token_id: usdc_token_id()
                },
                UpgradeArchives {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: archive_wasm_hash.clone()
                }
            ]
        );

        let subtasks: Vec<_> = UpgradeLedgerSuite::builder(usdc_token_id())
            .ledger_wasm_hash(ledger_wasm_hash.clone())
            .archive_wasm_hash(archive_wasm_hash.clone())
            .build()
            .collect();
        assert_eq!(
            subtasks,
            vec![
                UpgradeLedger {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: ledger_wasm_hash.clone()
                },
                DiscoverArchives {
                    token_id: usdc_token_id()
                },
                UpgradeArchives {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: archive_wasm_hash.clone()
                }
            ]
        );

        let subtasks: Vec<_> = UpgradeLedgerSuite::builder(usdc_token_id())
            .index_wasm_hash(index_wasm_hash.clone())
            .archive_wasm_hash(archive_wasm_hash.clone())
            .build()
            .collect();
        assert_eq!(
            subtasks,
            vec![
                UpgradeIndex {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: index_wasm_hash.clone()
                },
                DiscoverArchives {
                    token_id: usdc_token_id()
                },
                UpgradeArchives {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: archive_wasm_hash.clone()
                }
            ]
        );

        let subtasks: Vec<_> = UpgradeLedgerSuite::builder(usdc_token_id())
            .ledger_wasm_hash(ledger_wasm_hash.clone())
            .index_wasm_hash(index_wasm_hash.clone())
            .archive_wasm_hash(archive_wasm_hash.clone())
            .build()
            .collect();
        assert_eq!(
            subtasks,
            vec![
                UpgradeIndex {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: index_wasm_hash.clone()
                },
                UpgradeLedger {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: ledger_wasm_hash.clone()
                },
                DiscoverArchives {
                    token_id: usdc_token_id()
                },
                UpgradeArchives {
                    token_id: usdc_token_id(),
                    compressed_wasm_hash: archive_wasm_hash.clone()
                }
            ]
        );
    }

    #[test]
    fn should_implement_exact_size_iterator() {
        let mut subtasks = UpgradeLedgerSuite::builder(usdc_token_id())
            .ledger_wasm_hash(WasmHash::from([0_u8; 32]))
            .index_wasm_hash(WasmHash::from([1_u8; 32]))
            .archive_wasm_hash(WasmHash::from([2_u8; 32]))
            .build();

        let mut expected_size: usize = 4;
        assert_eq!(subtasks.size_hint(), (expected_size, Some(expected_size)));
        assert_eq!(subtasks.len(), expected_size);

        while subtasks.next().is_some() {
            expected_size -= 1;
            assert_eq!(subtasks.size_hint(), (expected_size, Some(expected_size)));
            assert_eq!(subtasks.len(), expected_size);
        }

        assert_eq!(expected_size, 0);
    }

    #[tokio::test]
    async fn should_be_no_op_when_no_canisters_to_upgrade() {
        init_state();
        let usdc = usdc();
        let usdc_token_id = TokenId::from(usdc.clone());
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata());
        });
        let runtime = MockCanisterRuntime::new();
        let task = Task::UpgradeLedgerSuite(UpgradeLedgerSuite::builder(usdc_token_id).build());

        let result = execute_now(task.clone(), &runtime).await;

        assert_eq!(result, Ok(()));
        assert_eq!(task_queue_from_state(), vec![]);
    }

    #[tokio::test]
    async fn should_fail_when_erc20_token_not_found() {
        init_state();
        let runtime = MockCanisterRuntime::new();
        let task = Task::UpgradeLedgerSuite(
            UpgradeLedgerSuite::builder(usdc_token_id())
                .ledger_wasm_hash(read_ledger_wasm_hash())
                .build(),
        );

        let result = execute_now(task.clone(), &runtime).await;

        assert_eq!(
            result,
            Err(TaskError::UpgradeLedgerSuiteError(TokenNotFound(
                usdc_token_id()
            )))
        );
        assert_eq!(task_queue_from_state(), vec![]);
    }

    #[tokio::test]
    async fn should_fail_when_wasm_hash_not_found() {
        init_state();
        let runtime = MockCanisterRuntime::new();
        let usdc = usdc();
        let usdc_token_id = TokenId::from(usdc.clone());
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata());
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
            s.record_installed_canister::<Ledger>(&usdc, WasmHash::default());
            s.record_created_canister::<Index>(&usdc, INDEX_PRINCIPAL);
            s.record_installed_canister::<Index>(&usdc, WasmHash::default());
        });

        let wrong_ledger_wasm_hash = WasmHash::from([1_u8; 32]);
        let task = Task::UpgradeLedgerSuite(
            UpgradeLedgerSuite::builder(usdc_token_id)
                .ledger_wasm_hash(wrong_ledger_wasm_hash.clone())
                .build(),
        );

        let error = execute_now(task.clone(), &runtime)
            .await
            .expect_err("wasm hash not found");

        assert_eq!(
            error,
            TaskError::UpgradeLedgerSuiteError(UpgradeLedgerSuiteError::WasmHashNotFound(
                wrong_ledger_wasm_hash
            ))
        );
        assert_eq!(task_queue_from_state(), vec![]);
    }

    #[tokio::test]
    async fn should_error_when_canister_to_upgrade_not_installed_yet() {
        init_state();
        let usdc = usdc();
        let usdc_token_id = TokenId::from(usdc.clone());
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata());
        });
        let runtime = MockCanisterRuntime::new();
        let update_index_task = Task::UpgradeLedgerSuite(
            UpgradeLedgerSuite::builder(usdc_token_id.clone())
                .index_wasm_hash(read_index_wasm_hash())
                .build(),
        );
        let update_ledger_task = Task::UpgradeLedgerSuite(
            UpgradeLedgerSuite::builder(usdc_token_id.clone())
                .ledger_wasm_hash(read_ledger_wasm_hash())
                .build(),
        );

        for task in [update_index_task.clone(), update_ledger_task.clone()] {
            let error = execute_now(task.clone(), &runtime)
                .await
                .expect_err("canister not ready for upgrade");

            assert!(error.is_recoverable());
            assert_eq!(
                error,
                TaskError::UpgradeLedgerSuiteError(CanisterNotReady {
                    token_id: usdc_token_id.clone(),
                    status: None,
                    message: "canister not yet created".to_string(),
                })
            );
        }

        mutate_state(|s| {
            s.record_created_canister::<Index>(&usdc, INDEX_PRINCIPAL);
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
        });

        for (task, canister_id) in [
            (update_index_task, INDEX_PRINCIPAL),
            (update_ledger_task, LEDGER_PRINCIPAL),
        ] {
            let error = execute_now(task, &runtime)
                .await
                .expect_err("canister not ready for upgrade");

            assert!(error.is_recoverable());
            assert_eq!(
                error,
                TaskError::UpgradeLedgerSuiteError(CanisterNotReady {
                    token_id: usdc_token_id.clone(),
                    status: Some(ManagedCanisterStatus::Created { canister_id }),
                    message: "canister not yet installed".to_string(),
                })
            );
        }
    }

    #[tokio::test]
    async fn should_upgrade_ledger_suite_without_archives() {
        init_state();
        let usdc = usdc();
        let usdc_token_id = TokenId::from(usdc.clone());
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata());
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
            s.record_installed_canister::<Ledger>(&usdc, WasmHash::default());
            s.record_created_canister::<Index>(&usdc, INDEX_PRINCIPAL);
            s.record_installed_canister::<Index>(&usdc, WasmHash::default());
        });
        let mut runtime = MockCanisterRuntime::new();
        let task = Task::UpgradeLedgerSuite(
            UpgradeLedgerSuite::builder(usdc_token_id)
                .ledger_wasm_hash(read_ledger_wasm_hash())
                .index_wasm_hash(read_index_wasm_hash())
                .build(),
        );

        expect_stop_canister(&mut runtime, INDEX_PRINCIPAL, Ok(()));
        expect_upgrade_canister(
            &mut runtime,
            INDEX_PRINCIPAL,
            INDEX_BYTECODE.to_vec(),
            Ok(()),
        );
        expect_start_canister(&mut runtime, INDEX_PRINCIPAL, Ok(()));

        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());

        let result = execute_now(task.clone(), &runtime).await;
        assert_eq!(result, Ok(()));
        runtime.checkpoint();

        runtime.expect_time().return_const(1_u64);
        let upgrade_ledger_task = pop_if_ready(&runtime).expect("missing upgrade ledger task");

        expect_stop_canister(&mut runtime, LEDGER_PRINCIPAL, Ok(()));
        expect_upgrade_canister(
            &mut runtime,
            LEDGER_PRINCIPAL,
            LEDGER_BYTECODE.to_vec(),
            Ok(()),
        );
        expect_start_canister(&mut runtime, LEDGER_PRINCIPAL, Ok(()));

        let result = upgrade_ledger_task.execute(&runtime).await;

        assert_eq!(result, Ok(()));

        let completed_upgrades = read_state(|s| s.completed_upgrades().clone());
        assert_eq!(
            completed_upgrades,
            btreemap! {
                INDEX_PRINCIPAL => CanisterUpgrade {wasm_hash: read_index_wasm_hash(),timestamp: 0},
                LEDGER_PRINCIPAL => CanisterUpgrade {wasm_hash: read_ledger_wasm_hash(),timestamp: 1},
            }
        )
    }

    #[tokio::test]
    async fn should_upgrade_ledger_suite_with_archives() {
        init_state();
        let usdc = usdc();
        let usdc_token_id = TokenId::from(usdc.clone());
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata());
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
            s.record_installed_canister::<Ledger>(&usdc, WasmHash::default());
            s.record_created_canister::<Index>(&usdc, INDEX_PRINCIPAL);
            s.record_installed_canister::<Index>(&usdc, WasmHash::default());
        });
        let mut runtime = MockCanisterRuntime::new();
        let task = Task::UpgradeLedgerSuite(
            UpgradeLedgerSuite::builder(usdc_token_id)
                .ledger_wasm_hash(read_ledger_wasm_hash())
                .index_wasm_hash(read_index_wasm_hash())
                .archive_wasm_hash(read_archive_wasm_hash())
                .build(),
        );

        expect_stop_canister(&mut runtime, INDEX_PRINCIPAL, Ok(()));
        expect_upgrade_canister(
            &mut runtime,
            INDEX_PRINCIPAL,
            INDEX_BYTECODE.to_vec(),
            Ok(()),
        );
        expect_start_canister(&mut runtime, INDEX_PRINCIPAL, Ok(()));

        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().times(1).return_const(());

        let result = execute_now(task.clone(), &runtime).await;
        assert_eq!(result, Ok(()));
        runtime.checkpoint();

        runtime.expect_time().return_const(1_u64);
        let upgrade_ledger_task = pop_if_ready(&runtime).expect("missing upgrade ledger task");
        runtime.checkpoint();

        expect_stop_canister(&mut runtime, LEDGER_PRINCIPAL, Ok(()));
        expect_upgrade_canister(
            &mut runtime,
            LEDGER_PRINCIPAL,
            LEDGER_BYTECODE.to_vec(),
            Ok(()),
        );
        expect_start_canister(&mut runtime, LEDGER_PRINCIPAL, Ok(()));
        runtime.expect_time().return_const(2_u64);
        runtime.expect_global_timer_set().times(1).return_const(());

        let result = upgrade_ledger_task.execute(&runtime).await;
        assert_eq!(result, Ok(()));
        runtime.checkpoint();

        runtime.expect_time().return_const(2_u64);
        let discover_archive_task = pop_if_ready(&runtime).expect("missing discover archives task");
        runtime.checkpoint();

        let first_archive = Principal::from_slice(&[4_u8; 29]);
        let first_archive_info = ICRC3ArchiveInfo {
            canister_id: first_archive,
            start: 0_u8.into(),
            end: 1_u8.into(),
        };
        let second_archive = Principal::from_slice(&[5_u8; 29]);
        let second_archive_info = ICRC3ArchiveInfo {
            canister_id: second_archive,
            start: 2_u8.into(),
            end: 3_u8.into(),
        };
        expect_call_canister_icrc3_get_archives(
            &mut runtime,
            LEDGER_PRINCIPAL,
            Ok(vec![first_archive_info, second_archive_info]),
        );
        runtime.expect_time().return_const(3_u64);
        runtime.expect_global_timer_set().times(1).return_const(());

        let result = discover_archive_task.execute(&runtime).await;
        assert_eq!(result, Ok(()));
        runtime.checkpoint();

        runtime.expect_time().return_const(3_u64);
        let upgrade_archives_task = pop_if_ready(&runtime).expect("missing upgrade archives task");
        runtime.checkpoint();

        for archive in [first_archive, second_archive] {
            expect_stop_canister(&mut runtime, archive, Ok(()));
            expect_upgrade_canister(
                &mut runtime,
                archive,
                ARCHIVE_NODE_BYTECODE.to_vec(),
                Ok(()),
            );
            expect_start_canister(&mut runtime, archive, Ok(()));
            runtime.expect_time().return_const(4_u64);
        }
        let result = upgrade_archives_task.execute(&runtime).await;
        assert_eq!(result, Ok(()));
        assert_eq!(task_queue_from_state(), vec![]);
        runtime.checkpoint();

        let completed_upgrades = read_state(|s| s.completed_upgrades().clone());
        assert_eq!(
            completed_upgrades,
            btreemap! {
                INDEX_PRINCIPAL => CanisterUpgrade {wasm_hash: read_index_wasm_hash(),timestamp: 0},
                LEDGER_PRINCIPAL => CanisterUpgrade {wasm_hash: read_ledger_wasm_hash(),timestamp: 2},
                first_archive => CanisterUpgrade {wasm_hash: read_archive_wasm_hash(),timestamp: 4},
                second_archive => CanisterUpgrade {wasm_hash: read_archive_wasm_hash(),timestamp: 4},
            }
        )
    }

    fn expect_stop_canister(
        runtime: &mut MockCanisterRuntime,
        canister_id: Principal,
        mocked_result: Result<(), CallError>,
    ) {
        runtime
            .expect_stop_canister()
            .withf(move |&id| id == canister_id)
            .times(1)
            .return_const(mocked_result);
    }

    fn expect_upgrade_canister(
        runtime: &mut MockCanisterRuntime,
        canister_id: Principal,
        wasm_module: Vec<u8>,
        mocked_result: Result<(), CallError>,
    ) {
        runtime
            .expect_upgrade_canister()
            .withf(move |&id, module| id == canister_id && module == &wasm_module)
            .times(1)
            .return_const(mocked_result);
    }

    fn expect_start_canister(
        runtime: &mut MockCanisterRuntime,
        canister_id: Principal,
        mocked_result: Result<(), CallError>,
    ) {
        runtime
            .expect_start_canister()
            .withf(move |&id| id == canister_id)
            .times(1)
            .return_const(mocked_result);
    }
}

mod run_task {
    use crate::candid::AddCkErc20Token;
    use crate::guard::TimerGuard;
    use crate::management::{CallError, Reason};
    use crate::scheduler::test_fixtures::{usdc, usdc_metadata};
    use crate::scheduler::tests::mock::MockCanisterRuntime;
    use crate::scheduler::tests::{
        LEDGER_PRINCIPAL, MINTER_PRINCIPAL, expect_call_canister_add_ckerc20_token, init_state,
        task_deadline_from_state, task_queue_from_state,
    };
    use crate::scheduler::{Task, TaskExecution, run_task};
    use crate::state::{Ledger, mutate_state};
    use candid::Nat;
    use std::time::Duration;

    #[tokio::test]
    async fn should_reschedule_task_when_previous_one_still_running() {
        init_state();
        let task = Task::MaybeTopUp;
        let mut runtime = MockCanisterRuntime::new();
        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());
        let _guard_mocking_already_running_task =
            TimerGuard::new(task.clone()).expect("no previous task running");

        run_task(
            TaskExecution {
                execute_at_ns: 0,
                task_type: task.clone(),
            },
            runtime,
        )
        .await;

        assert_eq!(
            task_deadline_from_state(&task),
            Some(Duration::from_secs(3_600).as_nanos() as u64)
        );
    }

    #[tokio::test]
    async fn should_reschedule_failed_task_with_recoverable_error() {
        init_state();
        record_added_usdc();
        let task = notify_usdc_added_task();
        let mut runtime = MockCanisterRuntime::new();
        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());
        expect_call_canister_add_ckerc20_token(
            &mut runtime,
            MINTER_PRINCIPAL,
            add_ckusdc(),
            Err(CallError {
                method: "error".to_string(),
                reason: Reason::OutOfCycles,
            }),
        );

        run_task(task.clone(), runtime).await;

        assert_eq!(
            task_queue_from_state(),
            vec![TaskExecution {
                execute_at_ns: task.execute_at_ns + (Duration::from_secs(5).as_nanos() as u64),
                ..task
            }]
        );
    }

    #[tokio::test]
    async fn should_not_reschedule_failed_task_with_irrecoverable_error() {
        init_state();
        record_added_usdc();
        let mut runtime = MockCanisterRuntime::new();
        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());
        expect_call_canister_add_ckerc20_token(
            &mut runtime,
            MINTER_PRINCIPAL,
            add_ckusdc(),
            Err(CallError {
                method: "error".to_string(),
                reason: Reason::CanisterError("trap".to_string()),
            }),
        );

        run_task(notify_usdc_added_task(), runtime).await;

        assert_eq!(task_queue_from_state(), vec![]);
    }

    #[tokio::test]
    async fn should_reschedule_failed_task_in_case_of_unexpected_panic() {
        use futures::FutureExt;

        init_state();
        record_added_usdc();
        let task = notify_usdc_added_task();
        let mut runtime = MockCanisterRuntime::new();
        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());
        runtime
            .expect_call_canister::<AddCkErc20Token, ()>()
            .times(1)
            .withf(move |_canister_id, method, _args: &AddCkErc20Token| {
                method == "add_ckerc20_token"
            })
            .return_once(|_, _, _| panic!("unexpected panic"));

        let task_cloned = task.clone();
        let error = async move {
            std::panic::AssertUnwindSafe(run_task(task_cloned, runtime))
                .catch_unwind()
                .await
        }
        .await
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<&str>(),
            Some("unexpected panic").as_ref()
        );

        assert_eq!(
            task_queue_from_state(),
            vec![TaskExecution {
                execute_at_ns: task.execute_at_ns + (Duration::from_secs(5).as_nanos() as u64),
                ..task
            }]
        );
    }

    #[tokio::test]
    async fn should_not_reschedule_successful_task() {
        init_state();
        record_added_usdc();
        let mut runtime = MockCanisterRuntime::new();
        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());
        expect_call_canister_add_ckerc20_token(
            &mut runtime,
            MINTER_PRINCIPAL,
            add_ckusdc(),
            Ok(()),
        );

        run_task(notify_usdc_added_task(), runtime).await;

        assert_eq!(task_queue_from_state(), vec![]);
    }

    fn record_added_usdc() {
        let usdc = usdc();
        let usdc_metadata = usdc_metadata();
        mutate_state(|s| {
            s.record_new_erc20_token(usdc.clone(), usdc_metadata.clone());
            s.record_created_canister::<Ledger>(&usdc, LEDGER_PRINCIPAL);
        });
    }

    fn notify_usdc_added_task() -> TaskExecution {
        TaskExecution {
            task_type: Task::NotifyErc20Added {
                erc20_token: usdc(),
                minter_id: MINTER_PRINCIPAL,
            },
            execute_at_ns: 0,
        }
    }

    fn add_ckusdc() -> AddCkErc20Token {
        AddCkErc20Token {
            chain_id: Nat::from(1_u8),
            address: usdc().address().to_string(),
            ckerc20_token_symbol: usdc_metadata().token_symbol.clone(),
            ckerc20_ledger_id: LEDGER_PRINCIPAL,
        }
    }
}

fn task_deadline_from_state(task: &Task) -> Option<u64> {
    TASKS.with(|t| t.borrow().deadline_by_task.get(task))
}

fn task_queue_from_state() -> Vec<TaskExecution> {
    TASKS.with(|t| {
        t.borrow()
            .queue
            .iter()
            .map(|(task, _)| task.clone())
            .collect()
    })
}

fn init_state() {
    crate::state::init_state(new_state());
    let _version = register_embedded_wasms();
}

fn register_embedded_wasms() -> LedgerSuiteVersion {
    mutate_wasm_store(|s| {
        record_icrc1_ledger_suite_wasms(s, 1_620_328_630_000_000_000, GitCommitHash::default())
    })
    .unwrap()
}

fn usdc_install_args() -> InstallLedgerSuiteArgs {
    InstallLedgerSuiteArgs {
        contract: usdc(),
        minter_id: MINTER_PRINCIPAL,
        ledger_init_arg: ledger_init_arg(),
        ledger_compressed_wasm_hash: read_ledger_wasm_hash(),
        index_compressed_wasm_hash: read_index_wasm_hash(),
    }
}

fn ledger_init_arg() -> LedgerInitArg {
    LedgerInitArg {
        transfer_fee: 10_000_u32.into(),
        decimals: 6,
        token_name: "Chain Key USDC".to_string(),
        token_symbol: "ckUSDC".to_string(),
        token_logo: "".to_string(),
    }
}

fn read_index_wasm_hash() -> WasmHash {
    WasmHash::from(ic_crypto_sha2::Sha256::hash(INDEX_BYTECODE))
}

fn read_ledger_wasm_hash() -> WasmHash {
    WasmHash::from(ic_crypto_sha2::Sha256::hash(LEDGER_BYTECODE))
}

fn read_archive_wasm_hash() -> WasmHash {
    WasmHash::from(ic_crypto_sha2::Sha256::hash(ARCHIVE_NODE_BYTECODE))
}

fn expect_create_canister_returning(
    runtime: &mut MockCanisterRuntime,
    expected_controllers: Vec<Principal>,
    results: Vec<Result<Principal, CallError>>,
) {
    assert!(!results.is_empty(), "must return at least one result");
    let mut create_canister_call_counter = 0_usize;
    runtime
        .expect_create_canister()
        .withf(move |controllers, _cycles| controllers == &expected_controllers)
        .times(results.len())
        .returning(move |_controllers, _cycles| {
            if create_canister_call_counter >= results.len() {
                panic!("create_canister called too many times!");
            }
            let result = results[create_canister_call_counter].clone();
            create_canister_call_counter += 1;
            result
        });
}

fn expect_install_code_returning(
    runtime: &mut MockCanisterRuntime,
    results: Vec<Result<(), CallError>>,
) {
    assert!(!results.is_empty(), "must return at least one result");
    let mut install_code_call_counter = 0_usize;
    runtime
        .expect_install_code()
        .times(results.len())
        .returning(move |_canister_id, _wasm, _args| {
            if install_code_call_counter >= results.len() {
                panic!("install_code called too many times!");
            }
            let result = results[install_code_call_counter].clone();
            install_code_call_counter += 1;
            result
        });
}

fn expect_call_canister_add_ckerc20_token(
    runtime: &mut MockCanisterRuntime,
    expected_canister_id: Principal,
    expected_args: AddCkErc20Token,
    mocked_result: Result<(), CallError>,
) {
    runtime
        .expect_call_canister()
        .times(1)
        .withf(move |&canister_id, method, args: &AddCkErc20Token| {
            canister_id == expected_canister_id
                && method == "add_ckerc20_token"
                && args == &expected_args
        })
        .return_const(mocked_result);
}

fn expect_call_canister_icrc3_get_archives(
    runtime: &mut MockCanisterRuntime,
    expected_canister_id: Principal,
    mocked_result: Result<GetArchivesResult, CallError>,
) {
    runtime
        .expect_call_canister()
        .withf(move |&canister_id, method, args: &GetArchivesArgs| {
            canister_id == expected_canister_id
                && method == "icrc3_get_archives"
                && args == &GetArchivesArgs { from: None }
        })
        .times(1)
        .return_const(mocked_result);
}

async fn execute_now<R: CanisterRuntime>(task: Task, runtime: &R) -> Result<(), TaskError> {
    TaskExecution {
        task_type: task,
        execute_at_ns: 0,
    }
    .execute(runtime)
    .await
}

mod metrics {
    use crate::management::CallError;
    use crate::scheduler::metrics::observe_task_duration;
    use crate::scheduler::{Reason, Task, TaskError, encode_orchestrator_metrics};
    use std::time::Duration;

    #[test]
    fn should_aggregate_task_durations() {
        observe_task_duration(&Task::MaybeTopUp, &Ok(()), 0, 1);
        observe_task_duration(
            &Task::MaybeTopUp,
            &Ok(()),
            0,
            Duration::from_millis(6_500).as_nanos() as u64,
        );
        observe_task_duration(
            &Task::MaybeTopUp,
            &Err(TaskError::InterCanisterCallError(CallError {
                method: "error".to_string(),
                reason: Reason::OutOfCycles,
            })),
            0,
            Duration::from_millis(22_500).as_nanos() as u64,
        );

        let mut encoder = ic_metrics_encoder::MetricsEncoder::new(Vec::new(), 12346789);
        encode_orchestrator_metrics(&mut encoder).unwrap();
        let bytes = encoder.into_inner();
        let metrics_text = String::from_utf8(bytes).unwrap();

        let actual = metrics_text.trim();
        let expected = r#"
# HELP orchestrator_tasks_duration_seconds Histogram of task execution durations in seconds.
# TYPE orchestrator_tasks_duration_seconds histogram
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="0.1"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="0.5"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="1"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="2"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="3"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="4"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="5"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="6"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="7"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="8"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="9"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="10"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="12"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="14"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="16"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="18"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="20"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="25"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="30"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="35"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="40"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="50"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="100"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="200"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="500"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="ok",le="+Inf"} 2 12346789
orchestrator_tasks_duration_seconds_sum{task="maybe_top_up",result="ok"} 6.500000001 12346789
orchestrator_tasks_duration_seconds_count{task="maybe_top_up",result="ok"} 2 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="0.1"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="0.5"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="1"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="2"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="3"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="4"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="5"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="6"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="7"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="8"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="9"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="10"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="12"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="14"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="16"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="18"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="20"} 0 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="25"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="30"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="35"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="40"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="50"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="100"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="200"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="500"} 1 12346789
orchestrator_tasks_duration_seconds_bucket{task="maybe_top_up",result="err",le="+Inf"} 1 12346789
orchestrator_tasks_duration_seconds_sum{task="maybe_top_up",result="err"} 22.5 12346789
orchestrator_tasks_duration_seconds_count{task="maybe_top_up",result="err"} 1 12346789
"#
        .trim();
        assert_eq!(
            actual, expected,
            "BUG: Unexpected task durations histogram. Actual:\n{actual}\nexpected:\n{expected}"
        );
    }
}

mod mock {
    use crate::management::CanisterRuntime;
    use crate::scheduler::CallError;
    use async_trait::async_trait;
    use candid::CandidType;
    use candid::Principal;
    use core::fmt::Debug;
    use mockall::mock;
    use serde::de::DeserializeOwned;
    use std::marker::Send;

    mock! {
        pub CanisterRuntime{}

        #[async_trait]
        impl CanisterRuntime for CanisterRuntime {

            fn id(&self) -> Principal;

            fn time(&self) -> u64;

            fn global_timer_set(&self, timestamp: u64);

            async fn create_canister(
                &self,
                controllers: Vec<Principal>,
                cycles_for_canister_creation: u64,
            ) -> Result<Principal, CallError>;

            async fn stop_canister(&self, canister_id: Principal) -> Result<(), CallError>;

            async fn start_canister(&self, canister_id: Principal) -> Result<(), CallError>;

            async fn install_code(
                &self,
                canister_id: Principal,
                wasm_module:Vec<u8>,
                arg: Vec<u8>,
            ) -> Result<(), CallError>;

            async fn upgrade_canister(
                &self,
                canister_id: Principal,
                wasm_module:Vec<u8>,
            ) -> Result<(), CallError>;

            async fn canister_cycles(
                &self,
                canister_id: Principal,
            ) -> Result<u128, CallError>;

            fn send_cycles(
                &self,
                canister_id: Principal,
                cycles: u128
            ) -> Result<(), CallError>;

            async fn call_canister<I, O>(
                &self,
                canister_id: Principal,
                method: &str,
                args: I,
            ) -> Result<O, CallError>
            where
                I: CandidType + Debug + Send + 'static,
                O: CandidType + DeserializeOwned + Debug + 'static;
        }
    }
}

mod install_ledger_suite_args {
    use crate::candid::{AddErc20Arg, InitArg, LedgerInitArg};
    use crate::scheduler::tests::{MINTER_PRINCIPAL, usdc_metadata};
    use crate::scheduler::{ChainId, Erc20Token, InstallLedgerSuiteArgs, InvalidAddErc20ArgError};
    use crate::state::test_fixtures::{expect_panic_with_message, new_state, new_state_from};
    use crate::state::{GitCommitHash, IndexWasm, LedgerSuiteVersion, LedgerWasm, WasmHash};
    use crate::storage::test_fixtures::{
        embedded_ledger_suite_version, empty_task_queue, empty_wasm_store,
    };
    use crate::storage::{WasmStore, record_icrc1_ledger_suite_wasms};
    use assert_matches::assert_matches;
    use candid::Nat;
    use proptest::collection::vec;
    use proptest::{prop_assert_eq, proptest};

    const ERC20_CONTRACT_ADDRESS: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    #[test]
    fn should_error_if_minter_id_missing() {
        let state = new_state();
        let wasm_store = wasm_store_with_icrc1_ledger_suite();

        assert_matches!(
            InstallLedgerSuiteArgs::validate_add_erc20(&state, &wasm_store, valid_add_erc20_arg()),
            Err(InvalidAddErc20ArgError::InternalError( error )) if error.contains("minter principal")
        );
    }

    #[test]
    fn should_error_if_contract_is_already_managed() {
        let mut state = new_state_from(InitArg {
            minter_id: Some(MINTER_PRINCIPAL),
            ..Default::default()
        });
        let wasm_store = wasm_store_with_icrc1_ledger_suite();
        state.update_ledger_suite_version(embedded_ledger_suite_version());
        let arg = valid_add_erc20_arg();
        let contract: Erc20Token = arg.contract.clone().try_into().unwrap();
        state.record_new_erc20_token(contract.clone(), usdc_metadata());

        assert_eq!(
            InstallLedgerSuiteArgs::validate_add_erc20(&state, &wasm_store, arg),
            Err(InvalidAddErc20ArgError::Erc20ContractAlreadyManaged(
                contract
            ))
        );
    }

    proptest! {
        #[test]
        fn queue_holds_one_copy_of_each_task(
            timestamps in vec(1_000_000_u64..1_000_000_000, 2..100),
        ) {
            use crate::scheduler::{TaskExecution, Task};
            use crate::storage::TaskQueue;

            let mut task_queue: TaskQueue = empty_task_queue();
            let mut min_ts = u64::MAX;
            for (i, ts) in timestamps.iter().enumerate() {
                min_ts = min_ts.min(*ts);
                assert_eq!(task_queue.schedule_at(*ts, Task::MaybeTopUp), min_ts);
                prop_assert_eq!(task_queue.len(), 1, "queue len: {}", task_queue.len());

                let task = task_queue.pop_if_ready(u64::MAX).unwrap();

                prop_assert_eq!(task_queue.len(), 0);

                prop_assert_eq!(&task, &TaskExecution{
                    execute_at_ns: timestamps[0..=i].iter().cloned().min().unwrap(),
                    task_type: Task::MaybeTopUp
                });
                task_queue.schedule_at(task.execute_at_ns, task.task_type);

                prop_assert_eq!(task_queue.len(), 1);
            }
        }

        #[test]
        fn should_error_on_invalid_ethereum_address(invalid_address in "0x[0-9a-fA-F]{0,39}|[0-9a-fA-F]{41,}") {
            let mut state = new_state();
            let wasm_store = wasm_store_with_icrc1_ledger_suite();
            state.update_ledger_suite_version(embedded_ledger_suite_version());
            let mut arg = valid_add_erc20_arg();
            arg.contract.address = invalid_address;
            assert_matches!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, &wasm_store, arg),
                Err(InvalidAddErc20ArgError::InvalidErc20Contract(_))
            );
        }

        #[test]
        fn should_error_on_large_chain_id(offset in 0_u128..=u64::MAX as u128) {
            let mut state = new_state();
            let wasm_store = wasm_store_with_icrc1_ledger_suite();
            state.update_ledger_suite_version(embedded_ledger_suite_version());
            let mut arg = valid_add_erc20_arg();
            arg.contract.chain_id = Nat::from((u64::MAX as u128) + offset);

            assert_matches!(
                InstallLedgerSuiteArgs::validate_add_erc20(&state, &wasm_store, arg),
                Err(InvalidAddErc20ArgError::InvalidErc20Contract(_))
            );
        }
    }

    #[test]
    fn should_panic_when_ledger_suite_version_missing() {
        let state = new_state_from(InitArg {
            minter_id: Some(MINTER_PRINCIPAL),
            ..Default::default()
        });
        let wasm_store = wasm_store_with_icrc1_ledger_suite();
        assert_eq!(state.ledger_suite_version(), None);

        expect_panic_with_message(
            || {
                InstallLedgerSuiteArgs::validate_add_erc20(
                    &state,
                    &wasm_store,
                    valid_add_erc20_arg(),
                )
            },
            "ledger suite version missing",
        );
    }

    #[test]
    fn should_panic_when_ledger_suite_version_not_in_wasm_store() {
        for version in [
            LedgerSuiteVersion {
                ledger_compressed_wasm_hash: WasmHash::default(),
                ..embedded_ledger_suite_version()
            },
            LedgerSuiteVersion {
                index_compressed_wasm_hash: WasmHash::default(),
                ..embedded_ledger_suite_version()
            },
        ] {
            let mut state = new_state_from(InitArg {
                minter_id: Some(MINTER_PRINCIPAL),
                ..Default::default()
            });
            state.update_ledger_suite_version(version);
            let wasm_store = wasm_store_with_icrc1_ledger_suite();

            expect_panic_with_message(
                || {
                    InstallLedgerSuiteArgs::validate_add_erc20(
                        &state,
                        &wasm_store,
                        valid_add_erc20_arg(),
                    )
                },
                "wasm hash missing",
            );
        }
    }

    #[test]
    fn should_accept_valid_erc20_arg() {
        let mut state = new_state_from(InitArg {
            minter_id: Some(MINTER_PRINCIPAL),
            ..Default::default()
        });
        let wasm_store = wasm_store_with_icrc1_ledger_suite();
        state.update_ledger_suite_version(embedded_ledger_suite_version());
        let arg = valid_add_erc20_arg();
        let ledger_init_arg = arg.ledger_init_arg.clone();

        let result = InstallLedgerSuiteArgs::validate_add_erc20(&state, &wasm_store, arg).unwrap();

        assert_eq!(
            result,
            InstallLedgerSuiteArgs {
                contract: Erc20Token(ChainId(1), ERC20_CONTRACT_ADDRESS.parse().unwrap()),
                minter_id: MINTER_PRINCIPAL,
                ledger_init_arg,
                ledger_compressed_wasm_hash: LedgerWasm::from(crate::state::LEDGER_BYTECODE)
                    .hash()
                    .clone(),
                index_compressed_wasm_hash: IndexWasm::from(crate::state::INDEX_BYTECODE)
                    .hash()
                    .clone(),
            }
        );
    }

    fn valid_add_erc20_arg() -> AddErc20Arg {
        AddErc20Arg {
            contract: crate::candid::Erc20Contract {
                chain_id: Nat::from(1_u8),
                address: ERC20_CONTRACT_ADDRESS.to_string(),
            },
            ledger_init_arg: LedgerInitArg {
                transfer_fee: 10_000_u32.into(),
                decimals: 6,
                token_name: "USD Coin".to_string(),
                token_symbol: "USDC".to_string(),
                token_logo: "".to_string(),
            },
        }
    }

    fn wasm_store_with_icrc1_ledger_suite() -> WasmStore {
        let mut store = empty_wasm_store();
        assert_eq!(
            record_icrc1_ledger_suite_wasms(
                &mut store,
                1_620_328_630_000_000_000,
                GitCommitHash::default(),
            ),
            Ok(embedded_ledger_suite_version())
        );
        store
    }
}
