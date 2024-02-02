#[cfg(test)]
mod tests;

use crate::candid::{AddErc20Arg, LedgerInitArg};
use crate::logs::INFO;
use crate::management::{CallError, CanisterRuntime};
use crate::state::{
    mutate_state, read_state, Canisters, Index, Ledger, ManageSingleCanister,
    ManagedCanisterStatus, RetrieveCanisterWasm, State, WasmHash,
};
use candid::{CandidType, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use ic_icrc1_index_ng::{IndexArg, InitArg as IndexInitArg};
use ic_icrc1_ledger::{ArchiveOptions, InitArgs as LedgerInitArgs, LedgerArgument};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::str::FromStr;

const HUNDRED_TRILLIONS: u64 = 100_000_000_000_000;
const THREE_GIGA_BYTES: u64 = 3_221_225_472;

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
                    if e.is_recoverable() {
                        log!(INFO, "task {:?} failed: {:?}. Will retry later.", task, e);
                        self.0.push_front(task);
                    } else {
                        log!(INFO, "ERROR: task {:?} failed with unrecoverable error: {:?}. Task is discarded.", task, e);
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum Task {
    InstallLedgerSuite(InstallLedgerSuiteArgs),
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct InstallLedgerSuiteArgs {
    contract: Erc20Contract,
    ledger_init_arg: LedgerInitArg,
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
}

#[derive(Debug, PartialEq, Clone)]
pub enum InvalidAddErc20ArgError {
    InvalidErc20Contract(String),
    InvalidWasmHash(String),
    Erc20ContractAlreadyManaged(Erc20Contract),
    WasmHashNotFound(WasmHash),
}

impl InstallLedgerSuiteArgs {
    pub fn validate_add_erc20(
        state: &State,
        args: AddErc20Arg,
    ) -> Result<InstallLedgerSuiteArgs, InvalidAddErc20ArgError> {
        let contract = Erc20Contract::try_from(args.contract.clone())
            .map_err(|e| InvalidAddErc20ArgError::InvalidErc20Contract(e.to_string()))?;
        if let Some(_canisters) = state.managed_canisters(&contract) {
            return Err(InvalidAddErc20ArgError::Erc20ContractAlreadyManaged(
                contract,
            ));
        }
        let ledger_compressed_wasm_hash = WasmHash::from_str(&args.ledger_compressed_wasm_hash)
            .map_err(|e| {
                InvalidAddErc20ArgError::InvalidWasmHash(format!(
                    "Invalid ledger compressed wasm hash: {}",
                    e
                ))
            })?;
        let index_compressed_wasm_hash = WasmHash::from_str(&args.index_compressed_wasm_hash)
            .map_err(|e| {
                InvalidAddErc20ArgError::InvalidWasmHash(format!(
                    "Invalid index compressed wasm hash: {}",
                    e
                ))
            })?;
        if ledger_compressed_wasm_hash == index_compressed_wasm_hash {
            return Err(InvalidAddErc20ArgError::InvalidWasmHash(format!(
                "ledger and index compressed wasm hash have the same value: {}",
                ledger_compressed_wasm_hash
            )));
        }
        if RetrieveCanisterWasm::<Ledger>::retrieve_wasm(state, &ledger_compressed_wasm_hash)
            .is_none()
        {
            return Err(InvalidAddErc20ArgError::WasmHashNotFound(
                ledger_compressed_wasm_hash,
            ));
        }
        if RetrieveCanisterWasm::<Index>::retrieve_wasm(state, &index_compressed_wasm_hash)
            .is_none()
        {
            return Err(InvalidAddErc20ArgError::WasmHashNotFound(
                index_compressed_wasm_hash,
            ));
        }
        Ok(Self {
            contract,
            ledger_init_arg: args.ledger_init_arg,
            ledger_compressed_wasm_hash,
            index_compressed_wasm_hash,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum TaskError {
    CanisterCreationError(CallError),
    InstallCodeError(CallError),
    WasmHashNotFound(WasmHash),
}

impl TaskError {
    /// If the error is recoverable, the task should be retried.
    /// Otherwise, the task should be discarded.
    fn is_recoverable(&self) -> bool {
        match self {
            TaskError::CanisterCreationError(_) => true,
            TaskError::InstallCodeError(_) => true,
            TaskError::WasmHashNotFound(_) => false,
        }
    }
}

impl Task {
    pub async fn execute<R: CanisterRuntime>(&self, runtime: &R) -> Result<(), TaskError> {
        match self {
            Task::InstallLedgerSuite(args) => install_ledger_suite(args, runtime).await,
        }
    }
}

async fn install_ledger_suite<R: CanisterRuntime>(
    args: &InstallLedgerSuiteArgs,
    runtime: &R,
) -> Result<(), TaskError> {
    let ledger_canister_id = create_canister_once::<Ledger, _>(&args.contract, runtime).await?;
    install_canister_once::<Ledger, _, _>(
        &args.contract,
        &args.ledger_compressed_wasm_hash,
        &LedgerArgument::Init(icrc1_ledger_init_arg(
            args.ledger_init_arg.clone(),
            runtime.id().into(),
        )),
        runtime,
    )
    .await?;

    let _index_principal = create_canister_once::<Index, _>(&args.contract, runtime).await?;
    let index_arg = Some(IndexArg::Init(IndexInitArg {
        ledger_id: ledger_canister_id,
    }));
    install_canister_once::<Index, _, _>(
        &args.contract,
        &args.index_compressed_wasm_hash,
        &index_arg,
        runtime,
    )
    .await?;
    Ok(())
}

fn icrc1_ledger_init_arg(
    ledger_init_arg: LedgerInitArg,
    archive_controller_id: PrincipalId,
) -> LedgerInitArgs {
    use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as LedgerMetadataValue;

    LedgerInitArgs {
        minting_account: ledger_init_arg.minting_account,
        fee_collector_account: ledger_init_arg.fee_collector_account,
        initial_balances: ledger_init_arg.initial_balances,
        transfer_fee: ledger_init_arg.transfer_fee,
        decimals: ledger_init_arg.decimals,
        token_name: ledger_init_arg.token_name,
        token_symbol: ledger_init_arg.token_symbol,
        metadata: vec![(
            "icrc1:logo".to_string(),
            LedgerMetadataValue::from(ledger_init_arg.token_logo),
        )],
        archive_options: icrc1_archive_options(archive_controller_id),
        max_memo_length: ledger_init_arg.max_memo_length,
        feature_flags: ledger_init_arg.feature_flags,
        maximum_number_of_accounts: ledger_init_arg.maximum_number_of_accounts,
        accounts_overflow_trim_quantity: ledger_init_arg.accounts_overflow_trim_quantity,
    }
}

fn icrc1_archive_options(archive_controller_id: PrincipalId) -> ArchiveOptions {
    ArchiveOptions {
        trigger_threshold: 2_000,
        num_blocks_to_archive: 1_000,
        node_max_memory_size_bytes: Some(THREE_GIGA_BYTES),
        max_message_size_bytes: None,
        controller_id: archive_controller_id,
        cycles_for_archive_creation: Some(HUNDRED_TRILLIONS),
        max_transactions_per_response: None,
    }
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
    wasm_hash: &WasmHash,
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

    let wasm = read_state(|s| s.retrieve_wasm(wasm_hash).cloned()).ok_or_else(|| {
        log!(
            INFO,
            "ERROR: failed to install {} canister for {:?} at '{}': wasm hash not found",
            Canisters::display_name(),
            contract,
            canister_id
        );
        TaskError::WasmHashNotFound(wasm_hash.clone())
    })?;

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

    mutate_state(|s| s.record_installed_canister::<C>(contract, wasm_hash.clone()));

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
