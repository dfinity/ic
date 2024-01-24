use crate::candid::InitArg;
use crate::management::{CallError, Reason};
use crate::scheduler::tests::mock::MockCanisterRuntime;
use crate::scheduler::{Erc20Contract, Task, TaskError, Tasks};
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
    tasks.add_task(Task::InstallLedgerSuite(usdc()));
    let mut runtime = MockCanisterRuntime::new();

    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    let mut create_canister_call_counter = 0_u8;
    runtime.expect_create_canister().times(2).returning(
        move |_| match create_canister_call_counter {
            0 => {
                create_canister_call_counter += 1;
                Ok(LEDGER_PRINCIPAL)
            }
            1 => Ok(INDEX_PRINCIPAL),

            _ => panic!("create_canister called too many times!"),
        },
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
        })
    );
}

#[tokio::test]
async fn should_not_retry_successful_operation_after_failing_one() {
    init_state();
    let mut tasks = Tasks::default();
    tasks.add_task(Task::InstallLedgerSuite(usdc()));
    let mut runtime = MockCanisterRuntime::new();

    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    runtime
        .expect_create_canister()
        .times(1)
        .return_const(Ok(LEDGER_PRINCIPAL));
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
    runtime
        .expect_create_canister()
        .times(1)
        .return_const(Err(expected_error.clone()));

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
        })
    );

    runtime.checkpoint();
    runtime
        .expect_id()
        .times(1)
        .return_const(ORCHESTRATOR_PRINCIPAL);
    runtime
        .expect_create_canister()
        .times(1)
        .return_const(Ok(INDEX_PRINCIPAL));
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
        })
    );
}

fn init_state() {
    crate::state::init_state(State::from(InitArg {
        ledger_wasm: vec![],
        index_wasm: vec![],
        archive_wasm: vec![],
    }));
}

fn usdc() -> Erc20Contract {
    crate::candid::Erc20Contract {
        chain_id: 1_u8.into(),
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
    }
    .try_into()
    .unwrap()
}

fn read_index_wasm_hash() -> WasmHash {
    read_state(|s| s.index_wasm().hash().clone())
}

fn read_ledger_wasm_hash() -> WasmHash {
    read_state(|s| s.ledger_wasm().hash().clone())
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
