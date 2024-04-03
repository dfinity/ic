#[cfg(test)]
pub mod test_fixtures;
#[cfg(test)]
mod tests;

use crate::candid::{AddCkErc20Token, AddErc20Arg, CyclesManagement, LedgerInitArg, UpgradeArg};
use crate::logs::DEBUG;
use crate::logs::INFO;
use crate::management::IcCanisterRuntime;
use crate::management::{CallError, CanisterRuntime, Reason};
use crate::state::{
    mutate_state, read_state, Canisters, CanistersMetadata, Index, Ledger, ManageSingleCanister,
    ManagedCanisterStatus, State, WasmHash,
};
use crate::storage::{
    read_wasm_store, validate_wasm_hashes, wasm_store_try_get, StorableWasm, TaskQueue,
    WasmHashError, WasmStore, WasmStoreError, TASKS,
};
use candid::{CandidType, Encode, Nat, Principal};
use futures::future;
use ic0;
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use ic_icrc1_index_ng::{IndexArg, InitArg as IndexInitArg};
use ic_icrc1_ledger::{ArchiveOptions, InitArgs as LedgerInitArgs, LedgerArgument};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::str::FromStr;
use std::time::Duration;

pub const TEN_TRILLIONS: u64 = 10_000_000_000_000; // 10 TC
pub const HUNDRED_TRILLIONS: u64 = 100_000_000_000_000; // 100 TC

// We need at least 220 TC to be able to spawn ledger suite (200 TC).
pub const MINIMUM_ORCHESTRATOR_CYCLES: u64 = 220_000_000_000_000;
// We need at least 110 TC for ledger to spawn archive.
pub const MINIMUM_MONITORED_CANISTER_CYCLES: u64 = 110_000_000_000_000;

const SEC_NANOS: u64 = 1_000_000_000;

const THREE_GIGA_BYTES: u64 = 3_221_225_472;

const IC_CANISTER_RUNTIME: IcCanisterRuntime = IcCanisterRuntime {};

thread_local! {
    static LAST_GLOBAL_TIMER: Cell<u64> = Cell::default();
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Ord, PartialOrd)]
pub enum Task {
    InstallLedgerSuite(InstallLedgerSuiteArgs),
    MaybeTopUp,
    NotifyErc20Added {
        erc20_token: Erc20Token,
        minter_id: Principal,
    },
}

impl Task {
    fn is_periodic(&self) -> bool {
        match self {
            Task::InstallLedgerSuite(_) => false,
            Task::MaybeTopUp => true,
            Task::NotifyErc20Added { .. } => false,
        }
    }
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Deserialize, Serialize)]
pub struct TaskExecution {
    pub execute_at_ns: u64,
    pub task_type: Task,
}

fn set_global_timer(ts: u64) {
    LAST_GLOBAL_TIMER.with(|v| v.set(ts));

    // SAFETY: setting the global timer is always safe; it does not
    // mutate any canister memory.
    unsafe {
        ic0::global_timer_set(ts as i64);
    }
}

impl TaskQueue {
    /// Schedules the given task at the specified time.  Returns the
    /// time that the caller should pass to the set_global_timer
    /// function.
    ///
    /// NOTE: The queue keeps only one copy of each task. If the
    /// caller submits multiple identical tasks with the same
    /// deadline, the queue keeps the task with the earliest deadline.
    pub fn schedule_at(&mut self, execute_at_ns: u64, task_type: Task) -> u64 {
        let old_deadline = self.deadline_by_task.get(&task_type).unwrap_or(u64::MAX);

        if execute_at_ns <= old_deadline {
            let old_task = TaskExecution {
                execute_at_ns: old_deadline,
                task_type,
            };

            self.queue.remove(&old_task);
            self.deadline_by_task
                .insert(old_task.task_type.clone(), execute_at_ns);
            self.queue.insert(
                TaskExecution {
                    execute_at_ns,
                    task_type: old_task.task_type,
                },
                (),
            );
        }

        self.next_execution_timestamp().unwrap_or(execute_at_ns)
    }

    fn next_execution_timestamp(&self) -> Option<u64> {
        self.queue.first_key_value().map(|(t, _)| t.execute_at_ns)
    }

    /// Removes the first task from the queue that's ready for
    /// execution.
    pub fn pop_if_ready(&mut self, now: u64) -> Option<TaskExecution> {
        if self.next_execution_timestamp()? <= now {
            let task = self
                .queue
                .pop_first()
                .expect("unreachable: couldn't pop from a non-empty queue");
            self.deadline_by_task.remove(&task.0.task_type);
            Some(task.0)
        } else {
            None
        }
    }

    /// Returns true if the queue is not empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Returns the number of tasks in the queue.
    pub fn len(&self) -> usize {
        self.queue.len() as usize
    }
}

/// Schedules a task for execution after the given delay.
pub fn schedule_after(delay: Duration, work: Task) {
    let now_nanos = ic_cdk::api::time();
    let execute_at_ns = now_nanos.saturating_add(delay.as_secs().saturating_mul(SEC_NANOS));

    let execution_time = TASKS.with(|t| t.borrow_mut().schedule_at(execute_at_ns, work));
    set_global_timer(execution_time);
}

/// Schedules a task for immediate execution.
pub fn schedule_now(work: Task) {
    schedule_after(Duration::from_secs(0), work)
}

/// Dequeues the next task ready for execution from the minter task queue.
pub fn pop_if_ready() -> Option<TaskExecution> {
    let now = ic_cdk::api::time();
    let task = TASKS.with(|t| t.borrow_mut().pop_if_ready(now));
    if let Some(next_execution) = TASKS.with(|t| t.borrow().next_execution_timestamp()) {
        set_global_timer(next_execution);
    }
    task
}

/// Returns the current value of the global task timer.
pub fn global_timer() -> u64 {
    LAST_GLOBAL_TIMER.with(|v| v.get())
}

pub fn timer() {
    const RETRY_FREQUENCY: Duration = Duration::from_secs(5);
    const ONE_HOUR: Duration = Duration::from_secs(60 * 60);

    if let Some(task) = pop_if_ready() {
        ic_cdk::spawn(async {
            let _guard = match crate::guard::TimerGuard::new(task.task_type.clone()) {
                Some(guard) => guard,
                None => return,
            };
            if task.task_type.is_periodic() {
                schedule_after(ONE_HOUR, task.task_type.clone());
            }
            match task.execute(&IC_CANISTER_RUNTIME).await {
                Ok(()) => {
                    log!(INFO, "task {:?} accomplished", task.task_type);
                }
                Err(e) => {
                    if e.is_recoverable() {
                        log!(INFO, "task {:?} failed: {:?}. Will retry later.", task, e);
                        schedule_after(RETRY_FREQUENCY, task.task_type);
                    } else {
                        log!(INFO, "ERROR: task {:?} failed with unrecoverable error: {:?}. Task is discarded.", task, e);
                    }
                }
            }
        });
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq, Ord, PartialOrd)]
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

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct InstallLedgerSuiteArgs {
    contract: Erc20Token,
    ledger_init_arg: LedgerInitArg,
    ledger_compressed_wasm_hash: WasmHash,
    index_compressed_wasm_hash: WasmHash,
}

impl PartialOrd for InstallLedgerSuiteArgs {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InstallLedgerSuiteArgs {
    fn cmp(&self, other: &Self) -> Ordering {
        self.contract.cmp(&other.contract)
    }
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
                Reason::CanisterError(msg) => {
                    msg.ends_with("is stopped") || msg.ends_with("is stopping")
                }
                Reason::Rejected(_) => false,
                Reason::TransientInternalError(_) => true,
                Reason::InternalError(_) => false,
            },
        }
    }
}

impl TaskExecution {
    pub async fn execute<R: CanisterRuntime>(&self, runtime: &R) -> Result<(), TaskError> {
        match &self.task_type {
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
    if principals.len() == 1 {
        return Ok(());
    }

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

    let cycles_management = read_state(|s| s.cycles_management().clone());
    let minimum_orchestrator_cycles =
        cycles_to_u128(cycles_management.minimum_orchestrator_cycles());
    let minimum_monitored_canister_cycles =
        cycles_to_u128(cycles_management.minimum_monitored_canister_cycles());
    let top_up_amount = cycles_to_u128(cycles_management.cycles_top_up_increment);

    log!(INFO, "[maybe_top_up] ",);
    for (canister_id, cycles_result) in principals.iter().zip(results) {
        match cycles_result {
            Ok(balance) => {
                if balance < minimum_monitored_canister_cycles
                    && orchestrator_cycle_balance > minimum_orchestrator_cycles
                {
                    match runtime.send_cycles(*canister_id, top_up_amount) {
                        Ok(()) => {
                            orchestrator_cycle_balance -= top_up_amount;
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

fn cycles_to_u128(cycles: Nat) -> u128 {
    cycles
        .0
        .to_u128()
        .expect("BUG: cycles does not fit in a u128")
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
    let CyclesManagement {
        cycles_for_ledger_creation,
        cycles_for_index_creation,
        cycles_for_archive_creation,
        ..
    } = read_state(|s| s.cycles_management().clone());
    let ledger_canister_id =
        create_canister_once::<Ledger, _>(&args.contract, runtime, cycles_for_ledger_creation)
            .await?;
    install_canister_once::<Ledger, _, _>(
        &args.contract,
        &args.ledger_compressed_wasm_hash,
        &LedgerArgument::Init(icrc1_ledger_init_arg(
            args.ledger_init_arg.clone(),
            runtime.id().into(),
            cycles_for_archive_creation,
        )),
        runtime,
    )
    .await?;

    let _index_principal =
        create_canister_once::<Index, _>(&args.contract, runtime, cycles_for_index_creation)
            .await?;
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
    read_state(|s| {
        let erc20_token = args.erc20_contract().clone();
        if let Some(&minter_id) = s.minter_id() {
            schedule_now(Task::NotifyErc20Added {
                erc20_token,
                minter_id,
            });
        }
    });
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
    cycles_for_archive_creation: Nat,
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
        archive_options: icrc1_archive_options(archive_controller_id, cycles_for_archive_creation),
        max_memo_length: ledger_init_arg.max_memo_length,
        feature_flags: ledger_init_arg.feature_flags,
        maximum_number_of_accounts: ledger_init_arg.maximum_number_of_accounts,
        accounts_overflow_trim_quantity: ledger_init_arg.accounts_overflow_trim_quantity,
    }
}

fn icrc1_archive_options(
    archive_controller_id: PrincipalId,
    cycles_for_archive_creation: Nat,
) -> ArchiveOptions {
    ArchiveOptions {
        trigger_threshold: 2_000,
        num_blocks_to_archive: 1_000,
        node_max_memory_size_bytes: Some(THREE_GIGA_BYTES),
        max_message_size_bytes: None,
        controller_id: archive_controller_id,
        more_controller_ids: None,
        cycles_for_archive_creation: Some(
            cycles_for_archive_creation
                .0
                .to_u64()
                .expect("BUG: cycles for archive creation does not fit in a u64"),
        ),
        max_transactions_per_response: None,
    }
}

async fn create_canister_once<C, R>(
    contract: &Erc20Token,
    runtime: &R,
    cycles_for_canister_creation: Nat,
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
        .create_canister(
            controllers_of_children_canisters(runtime),
            cycles_for_canister_creation
                .0
                .to_u64()
                .expect("BUG: cycles for canister creation does not fit in a u64"),
        )
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
        Ok(Self(
            ChainId(contract.chain_id.0.to_u64().ok_or("chain_id is not u64")?),
            Address::from_str(&contract.address)?,
        ))
    }
}
