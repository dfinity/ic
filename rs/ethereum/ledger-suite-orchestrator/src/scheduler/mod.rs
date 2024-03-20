#[cfg(test)]
pub mod test_fixtures;
#[cfg(test)]
mod tests;

use crate::candid::{AddCkErc20Token, AddErc20Arg, LedgerInitArg, UpgradeArg};
use crate::logs::DEBUG;
use crate::logs::INFO;
use crate::management::{CallError, CanisterRuntime, Reason};
use crate::state::{
    mutate_state, read_state, Canisters, CanistersMetadata, Index, Ledger, ManageSingleCanister,
    ManagedCanisterStatus, State, WasmHash,
};
use crate::storage::{
    read_wasm_store, validate_wasm_hashes, wasm_store_try_get, StorableWasm, WasmHashError,
    WasmStore, WasmStoreError,
};
use candid::{CandidType, Encode, Nat, Principal};
use futures::future;
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use ic_icrc1_index_ng::{IndexArg, InitArg as IndexInitArg};
use ic_icrc1_ledger::{ArchiveOptions, InitArgs as LedgerInitArgs, LedgerArgument};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::str::FromStr;

pub const TEN_TRILLIONS: u64 = 10_000_000_000_000; // 10 TC
pub const HUNDRED_TRILLIONS: u64 = 100_000_000_000_000; // 100 TC

// We need at least 220 TC to be able to spawn ledger suite (200 TC).
pub const MINIMUM_ORCHESTRATOR_CYCLES: u64 = 220_000_000_000_000;
// We need at least 110 TC for ledger to spawn archive.
pub const MINIMUM_MONITORED_CANISTER_CYCLES: u64 = 110_000_000_000_000;

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

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, task: Task) -> bool {
        self.0.contains(&task)
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

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub enum Task {
    InstallLedgerSuite(InstallLedgerSuiteArgs),
    MaybeTopUp,
    NotifyErc20Added {
        erc20_token: Erc20Token,
        minter_id: Principal,
    },
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct UpgradeOrchestratorArgs {
    ledger_compressed_wasm_hash: Option<WasmHash>,
    index_compressed_wasm_hash: Option<WasmHash>,
    archive_compressed_wasm_hash: Option<WasmHash>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum InvalidUpgradeArgError {
    WasmHashError(WasmHashError),
}

impl UpgradeOrchestratorArgs {
    pub fn validate_upgrade_arg(
        wasm_store: &WasmStore,
        arg: UpgradeArg,
    ) -> Result<UpgradeOrchestratorArgs, InvalidUpgradeArgError> {
        let [ledger_compressed_wasm_hash, index_compressed_wasm_hash, archive_compressed_wasm_hash] =
            validate_wasm_hashes(
                wasm_store,
                arg.ledger_compressed_wasm_hash.as_deref(),
                arg.index_compressed_wasm_hash.as_deref(),
                arg.archive_compressed_wasm_hash.as_deref(),
            )
            .map_err(InvalidUpgradeArgError::WasmHashError)?;
        Ok(UpgradeOrchestratorArgs {
            ledger_compressed_wasm_hash,
            index_compressed_wasm_hash,
            archive_compressed_wasm_hash,
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct InstallLedgerSuiteArgs {
    contract: Erc20Token,
    ledger_init_arg: LedgerInitArg,
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
}

impl InstallLedgerSuiteArgs {
    pub fn erc20_contract(&self) -> &Erc20Token {
        &self.contract
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum InvalidAddErc20ArgError {
    InvalidErc20Contract(String),
    Erc20ContractAlreadyManaged(Erc20Token),
    WasmHashError(WasmHashError),
}

impl InstallLedgerSuiteArgs {
    pub fn validate_add_erc20(
        state: &State,
        wasm_store: &WasmStore,
        args: AddErc20Arg,
    ) -> Result<InstallLedgerSuiteArgs, InvalidAddErc20ArgError> {
        let contract = Erc20Token::try_from(args.contract.clone())
            .map_err(|e| InvalidAddErc20ArgError::InvalidErc20Contract(e.to_string()))?;
        if let Some(_canisters) = state.managed_canisters(&contract) {
            return Err(InvalidAddErc20ArgError::Erc20ContractAlreadyManaged(
                contract,
            ));
        }
        let [ledger_compressed_wasm_hash, index_compressed_wasm_hash, _archive_compressed_wasm_hash] =
            validate_wasm_hashes(
                wasm_store,
                Some(&args.ledger_compressed_wasm_hash),
                Some(&args.index_compressed_wasm_hash),
                None,
            )
            .map_err(InvalidAddErc20ArgError::WasmHashError)?;

        Ok(Self {
            contract,
            ledger_init_arg: args.ledger_init_arg,
            ledger_compressed_wasm_hash: ledger_compressed_wasm_hash.unwrap(),
            index_compressed_wasm_hash: index_compressed_wasm_hash.unwrap(),
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum TaskError {
    CanisterCreationError(CallError),
    InstallCodeError(CallError),
    CanisterStatusError(CallError),
    WasmHashNotFound(WasmHash),
    WasmStoreError(WasmStoreError),
    LedgerNotFound(Erc20Token),
    InterCanisterCallError(CallError),
}

impl TaskError {
    /// If the error is recoverable, the task should be retried.
    /// Otherwise, the task should be discarded.
    fn is_recoverable(&self) -> bool {
        match self {
            TaskError::CanisterCreationError(_) => true,
            TaskError::InstallCodeError(_) => true,
            TaskError::CanisterStatusError(_) => true,
            TaskError::WasmHashNotFound(_) => false,
            TaskError::WasmStoreError(_) => false,
            TaskError::LedgerNotFound(_) => true, //ledger may not yet be created
            TaskError::InterCanisterCallError(CallError { method: _, reason }) => match reason {
                Reason::OutOfCycles => true,
                Reason::CanisterError(_) => false,
                Reason::Rejected(_) => false,
                Reason::TransientInternalError(_) => true,
                Reason::InternalError(_) => false,
            },
        }
    }
}

impl Task {
    pub async fn execute<R: CanisterRuntime>(&self, runtime: &R) -> Result<(), TaskError> {
        match self {
            Task::InstallLedgerSuite(args) => install_ledger_suite(args, runtime).await,
            Task::MaybeTopUp => maybe_top_up(runtime).await,
            Task::NotifyErc20Added {
                erc20_token,
                minter_id,
            } => notify_erc20_added(erc20_token, minter_id, runtime).await,
        }
    }
}

async fn maybe_top_up<R: CanisterRuntime>(runtime: &R) -> Result<(), TaskError> {
    let mut principals: Vec<Principal> = read_state(|s| {
        s.managed_canisters_iter()
            .flat_map(|(_, canisters)| canisters.collect_principals())
            .chain(std::iter::once(runtime.id()))
            .collect()
    });

    let mut results =
        future::join_all(principals.iter().map(|p| runtime.canister_cycles(*p))).await;
    assert!(!results.is_empty());

    let mut orchestrator_cycle_balance = match results
        .pop()
        .expect("BUG: should at least fetch the orchestrator balance")
    {
        Ok(balance) => balance,
        Err(e) => {
            log!(
                INFO,
                "[maybe_top_up] failed to get orchestrator status, with error: {:?}",
                e
            );
            return Err(TaskError::CanisterStatusError(e));
        }
    };
    principals.pop();

    for (canister_id, cycles_result) in principals.iter().zip(results) {
        match cycles_result {
            Ok(balance) => {
                if balance < MINIMUM_MONITORED_CANISTER_CYCLES as u128
                    && orchestrator_cycle_balance > MINIMUM_ORCHESTRATOR_CYCLES as u128
                {
                    match runtime.send_cycles(*canister_id, TEN_TRILLIONS.into()) {
                        Ok(()) => {
                            orchestrator_cycle_balance -= TEN_TRILLIONS as u128;
                            log!(
                                DEBUG,
                                "[maybe_top_up] topped up canister {canister_id} with previous balance {balance}"
                            );
                        }
                        Err(e) => {
                            log!(
                                INFO,
                                "[maybe_top_up] failed to send cycles to {}, with error: {:?}",
                                canister_id,
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                log!(
                    INFO,
                    "[maybe_top_up] failed to get canister status of {}, with error: {:?}",
                    canister_id,
                    e
                );
            }
        }
    }

    Ok(())
}

async fn install_ledger_suite<R: CanisterRuntime>(
    args: &InstallLedgerSuiteArgs,
    runtime: &R,
) -> Result<(), TaskError> {
    record_new_erc20_token_once(
        args.contract.clone(),
        CanistersMetadata {
            ckerc20_token_symbol: args.ledger_init_arg.token_symbol.clone(),
        },
    );
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

fn record_new_erc20_token_once(contract: Erc20Token, metadata: CanistersMetadata) {
    mutate_state(|s| {
        if s.managed_canisters(&contract).is_some() {
            return;
        }
        s.record_new_erc20_token(contract, metadata);
    });
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
        more_controller_ids: None,
        cycles_for_archive_creation: Some(HUNDRED_TRILLIONS),
        max_transactions_per_response: None,
    }
}

async fn create_canister_once<C, R>(
    contract: &Erc20Token,
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
    let canister_id = match runtime
        .create_canister(controllers_of_children_canisters(runtime), 100_000_000_000)
        .await
    {
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

fn controllers_of_children_canisters<R: CanisterRuntime>(runtime: &R) -> Vec<Principal> {
    let more_controllers = read_state(|s| s.more_controller_ids().to_vec());
    vec![runtime.id()]
        .into_iter()
        .chain(more_controllers)
        .collect()
}

async fn install_canister_once<C, R, I>(
    contract: &Erc20Token,
    wasm_hash: &WasmHash,
    init_args: &I,
    runtime: &R,
) -> Result<(), TaskError>
where
    C: Debug + StorableWasm + Send,
    Canisters: ManageSingleCanister<C>,
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

    let wasm = match read_wasm_store(|s| wasm_store_try_get::<C>(s, wasm_hash)) {
        Ok(Some(wasm)) => Ok(wasm),
        Ok(None) => {
            log!(
                INFO,
                "ERROR: failed to install {} canister for {:?} at '{}': wasm hash {} not found",
                Canisters::display_name(),
                contract,
                canister_id,
                wasm_hash
            );
            Err(TaskError::WasmHashNotFound(wasm_hash.clone()))
        }
        Err(e) => {
            log!(
                INFO,
                "ERROR: failed to install {} canister for {:?} at '{}': {:?}",
                Canisters::display_name(),
                contract,
                canister_id,
                e
            );
            Err(TaskError::WasmStoreError(e))
        }
    }?;

    match runtime
        .install_code(
            canister_id,
            wasm.to_bytes(),
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

async fn notify_erc20_added<R: CanisterRuntime>(
    token: &Erc20Token,
    minter_id: &Principal,
    runtime: &R,
) -> Result<(), TaskError> {
    let managed_canisters = read_state(|s| s.managed_canisters(token).cloned());
    match managed_canisters {
        Some(Canisters {
            ledger: Some(ledger),
            metadata,
            ..
        }) => {
            let args = AddCkErc20Token {
                chain_id: Nat::from(*token.chain_id().as_ref()),
                address: token.address().to_string(),
                ckerc20_token_symbol: metadata.ckerc20_token_symbol,
                ckerc20_ledger_id: *ledger.canister_id(),
            };
            runtime
                .call_canister(*minter_id, "add_ckerc20_token", args)
                .await
                .map_err(TaskError::InterCanisterCallError)
        }
        _ => Err(TaskError::LedgerNotFound(token.clone())),
    }
}

#[derive(Debug, PartialEq, Clone, Ord, PartialOrd, Eq, Serialize, Deserialize)]
pub struct Erc20Token(ChainId, Address);

impl Erc20Token {
    pub fn chain_id(&self) -> &ChainId {
        &self.0
    }

    pub fn address(&self) -> &Address {
        &self.1
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(u64);

impl AsRef<u64> for ChainId {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl TryFrom<crate::candid::Erc20Contract> for Erc20Token {
    type Error = String;

    fn try_from(contract: crate::candid::Erc20Contract) -> Result<Self, Self::Error> {
        use num_traits::cast::ToPrimitive;

        Ok(Self(
            ChainId(contract.chain_id.0.to_u64().ok_or("chain_id is not u64")?),
            Address::from_str(&contract.address)?,
        ))
    }
}
