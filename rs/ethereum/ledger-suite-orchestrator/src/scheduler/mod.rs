#[cfg(test)]
mod tests;

use crate::logs::INFO;
use crate::management::{CallError, CanisterRuntime};
use crate::state::{
    mutate_state, read_state, Canisters, Index, Ledger, ManageSingleCanister,
    ManagedCanisterStatus, RetrieveCanisterWasm, State,
};
use candid::{CandidType, Encode, Principal};
use ic_canister_log::log;
use ic_ethereum_types::Address;
use ic_icrc1_index_ng::{IndexArg, InitArg as IndexInitArg};
use ic_icrc1_ledger::{ArchiveOptions, InitArgs as LedgerInitArgs, LedgerArgument};
use icrc_ledger_types::icrc1::account::Account;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::str::FromStr;

/// A list of *independent* tasks to be executed in order.
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Tasks(VecDeque<Task>);

impl Tasks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_task(&mut self, task: Task) {
        self.0.push_back(task);
    }
}

impl Tasks {
    // TODO XC-29: next task should be executed if the current one failed.
    /// Execute task one by one in order and stop at the first failure.
    /// If a task succeeds, it is removed from the queue.
    /// If a task fails, it is put back at the front of the queue.
    pub async fn execute<R: CanisterRuntime>(&mut self, runtime: &R) -> Result<(), TaskError> {
        while let Some(task) = self.0.pop_front() {
            match task.execute(runtime).await {
                Ok(()) => {
                    log!(INFO, "task {:?} accomplished", task);
                }
                Err(e) => {
                    log!(INFO, "task {:?} failed: {:?}", task, e);
                    self.0.push_front(task);
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum Task {
    InstallLedgerSuite(Erc20Contract),
}

#[derive(Debug, PartialEq, Clone)]
pub enum TaskError {
    CanisterCreationError(CallError),
    InstallCodeError(CallError),
}

impl Task {
    pub async fn execute<R: CanisterRuntime>(&self, runtime: &R) -> Result<(), TaskError> {
        match self {
            Task::InstallLedgerSuite(contract) => install_ledger_suite(contract, runtime).await,
        }
    }
}

async fn install_ledger_suite<R: CanisterRuntime>(
    contract: &Erc20Contract,
    runtime: &R,
) -> Result<(), TaskError> {
    let ledger_canister_id = create_canister_once::<Ledger, _>(contract, runtime).await?;

    //TODO XC-29: init args should come from `contract` argument
    let ledger_arg = LedgerInitArgs {
        minting_account: Account {
            owner: Principal::anonymous(),
            subaccount: None,
        },
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: 10_000_u32.into(),
        decimals: None,
        token_name: "Test Token".to_string(),
        token_symbol: "XTK".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: 1000,
            num_blocks_to_archive: 1000,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            //TODO: orchestrator must control the archive to be able to upgrade it. We should validate the given config
            controller_id: runtime.id().into(),
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    };
    install_canister_once::<Ledger, _, _>(contract, &LedgerArgument::Init(ledger_arg), runtime)
        .await?;

    let _index_principal = create_canister_once::<Index, _>(contract, runtime).await?;
    let index_arg = Some(IndexArg::Init(IndexInitArg {
        ledger_id: ledger_canister_id,
    }));
    install_canister_once::<Index, _, _>(contract, &index_arg, runtime).await?;
    Ok(())
}

async fn create_canister_once<C, R>(
    contract: &Erc20Contract,
    runtime: &R,
) -> Result<Principal, TaskError>
where
    C: Debug,
    Canisters: ManageSingleCanister<C>,
    R: CanisterRuntime,
{
    if let Some(canister_id) = read_state(|s| {
        s.managed_status::<C>(contract)
            .map(ManagedCanisterStatus::canister_id)
            .cloned()
    }) {
        return Ok(canister_id);
    }
    let canister_id = match runtime.create_canister(100_000_000_000).await {
        Ok(id) => {
            log!(
                INFO,
                "created {} canister for {:?} at '{}'",
                Canisters::display_name(),
                contract,
                id
            );
            id
        }
        Err(e) => {
            log!(
                INFO,
                "failed to create {} canister for {:?}: {}",
                Canisters::display_name(),
                contract,
                e
            );
            return Err(TaskError::CanisterCreationError(e));
        }
    };
    mutate_state(|s| s.record_created_canister::<C>(contract, canister_id));
    Ok(canister_id)
}

async fn install_canister_once<C, R, I>(
    contract: &Erc20Contract,
    init_args: &I,
    runtime: &R,
) -> Result<(), TaskError>
where
    C: Debug,
    Canisters: ManageSingleCanister<C>,
    State: RetrieveCanisterWasm<C>,
    R: CanisterRuntime,
    I: Debug + CandidType,
{
    let canister_id = match read_state(|s| s.managed_status::<C>(contract).cloned()) {
        None => {
            panic!(
                "BUG: {} canister is not yet created",
                Canisters::display_name()
            )
        }
        Some(ManagedCanisterStatus::Created { canister_id }) => canister_id,
        Some(ManagedCanisterStatus::Installed { .. }) => return Ok(()),
    };

    let wasm = read_state(|s| s.retrieve_wasm().clone());
    let wasm_hash = wasm.hash().clone();

    match runtime
        .install_code(
            canister_id,
            wasm,
            Encode!(init_args).expect("BUG: failed to encode init arg"),
        )
        .await
    {
        Ok(_) => {
            log!(
                INFO,
                "successfully installed {} canister for {:?} at '{}' with init args {:?}",
                Canisters::display_name(),
                contract,
                canister_id,
                init_args
            );
        }
        Err(e) => {
            log!(
                INFO,
                "failed to install {} canister for {:?} at '{}' with init args {:?}: {}",
                Canisters::display_name(),
                contract,
                canister_id,
                init_args,
                e
            );
            return Err(TaskError::InstallCodeError(e));
        }
    };

    mutate_state(|s| s.record_installed_canister::<C>(contract, wasm_hash));

    Ok(())
}

#[derive(Debug, PartialEq, Clone, Ord, PartialOrd, Eq, Serialize, Deserialize)]
pub struct Erc20Contract(ChainId, Address);

#[derive(Debug, PartialEq, Clone, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(u64);

impl TryFrom<crate::candid::Erc20Contract> for Erc20Contract {
    type Error = String;

    fn try_from(contract: crate::candid::Erc20Contract) -> Result<Self, Self::Error> {
        use num_traits::cast::ToPrimitive;

        Ok(Self(
            ChainId(contract.chain_id.0.to_u64().ok_or("chain_id is not u64")?),
            Address::from_str(&contract.address)?,
        ))
    }
}
