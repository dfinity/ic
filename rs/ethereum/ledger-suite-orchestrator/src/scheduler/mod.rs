mod metrics;
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
    mutate_state, read_state, Archive, Canister, Canisters, CanistersMetadata, Index,
    IndexCanister, Ledger, LedgerCanister, LedgerSuiteVersion, ManageSingleCanister,
    ManagedCanisterStatus, State, WasmHash,
};
use crate::storage::{
    read_wasm_store, validate_wasm_hashes, wasm_store_contain, wasm_store_try_get, StorableWasm,
    TaskQueue, WasmHashError, WasmStore, WasmStoreError, TASKS,
};
use candid::{CandidType, Encode, Nat, Principal};
use futures::future;
use ic_base_types::PrincipalId;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use ic_icrc1_index_ng::{IndexArg, InitArg as IndexInitArg};
use ic_icrc1_ledger::{ArchiveOptions, InitArgs as LedgerInitArgs, LedgerArgument};
use icrc_ledger_types::icrc3::archive::{GetArchivesArgs, GetArchivesResult};
pub use metrics::encode_orchestrator_metrics;
use metrics::observe_task_duration;
use num_traits::ToPrimitive;
use scopeguard::ScopeGuard;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display};
use std::iter::once;
use std::str::FromStr;
use std::time::Duration;

const SEC_NANOS: u64 = 1_000_000_000;

const THREE_GIGA_BYTES: u64 = 3_221_225_472;

pub const IC_CANISTER_RUNTIME: IcCanisterRuntime = IcCanisterRuntime {};

thread_local! {
    static LAST_GLOBAL_TIMER: Cell<u64> = Cell::default();
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub enum Task {
    InstallLedgerSuite(InstallLedgerSuiteArgs),
    UpgradeLedgerSuite(UpgradeLedgerSuite),
    MaybeTopUp,
    DiscoverArchives,
    NotifyErc20Added {
        erc20_token: Erc20Token,
        minter_id: Principal,
    },
    ManageAlreadyInstalledLedgerSuite(ManageInstalledCanisters),
}

impl Task {
    fn is_periodic(&self) -> bool {
        match self {
            Task::InstallLedgerSuite(_) => false,
            Task::MaybeTopUp => true,
            Task::NotifyErc20Added { .. } => false,
            Task::DiscoverArchives => true,
            Task::UpgradeLedgerSuite(_) => false,
            Task::ManageAlreadyInstalledLedgerSuite(_) => false,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct TaskExecution {
    pub execute_at_ns: u64,
    pub task_type: Task,
}

fn set_global_timer<R: CanisterRuntime>(ts: u64, runtime: &R) {
    LAST_GLOBAL_TIMER.with(|v| v.set(ts));
    runtime.global_timer_set(ts);
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
pub fn schedule_after<R: CanisterRuntime>(delay: Duration, work: Task, runtime: &R) {
    log!(DEBUG, "Scheduling task {:?} after {:?}", work, delay);
    let now_nanos = runtime.time();
    let execute_at_ns = now_nanos.saturating_add(delay.as_secs().saturating_mul(SEC_NANOS));

    let execution_time = TASKS.with(|t| t.borrow_mut().schedule_at(execute_at_ns, work));
    set_global_timer(execution_time, runtime);
}

/// Schedules a task for immediate execution.
pub fn schedule_now<R: CanisterRuntime>(work: Task, runtime: &R) {
    schedule_after(Duration::from_secs(0), work, runtime)
}

/// Dequeues the next task ready for execution from the minter task queue.
pub fn pop_if_ready<R: CanisterRuntime>(runtime: &R) -> Option<TaskExecution> {
    let now = runtime.time();
    let task = TASKS.with(|t| t.borrow_mut().pop_if_ready(now));
    if let Some(next_execution) = TASKS.with(|t| t.borrow().next_execution_timestamp()) {
        set_global_timer(next_execution, runtime);
    }
    task
}

/// Returns the current value of the global task timer.
pub fn global_timer() -> u64 {
    LAST_GLOBAL_TIMER.with(|v| v.get())
}

pub fn timer<R: CanisterRuntime + 'static>(runtime: R) {
    if let Some(task) = pop_if_ready(&runtime) {
        ic_cdk::spawn(run_task(task, runtime));
    }
}

async fn run_task<R: CanisterRuntime>(task: TaskExecution, runtime: R) {
    const RETRY_FREQUENCY: Duration = Duration::from_secs(5);
    const ONE_HOUR: Duration = Duration::from_secs(60 * 60);

    if task.task_type.is_periodic() {
        schedule_after(ONE_HOUR, task.task_type.clone(), &runtime);
    }
    let _guard = match crate::guard::TimerGuard::new(task.task_type.clone()) {
        Some(guard) => guard,
        None => return,
    };
    let rerun_task_guard = scopeguard::guard(task.task_type.clone(), |task_type| {
        schedule_after(RETRY_FREQUENCY, task_type, &runtime);
    });
    let start = runtime.time();
    let result = task.execute(&runtime).await;
    let end = runtime.time();
    observe_task_duration(&task.task_type, &result, start, end);

    match result {
        Ok(()) => {
            let _task_type = ScopeGuard::into_inner(rerun_task_guard);
            log!(INFO, "task {:?} accomplished", task.task_type);
        }
        Err(e) => {
            if e.is_recoverable() {
                log!(INFO, "task {:?} failed: {:?}. Will retry later.", task, e);
            } else {
                let _task_type = ScopeGuard::into_inner(rerun_task_guard);
                log!(
                    INFO,
                    "ERROR: task {:?} failed with unrecoverable error: {:?}. Task is discarded.",
                    task,
                    e
                );
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct UpgradeLedgerSuite {
    subtasks: Vec<UpgradeLedgerSuiteSubtask>,
    next_subtask_index: usize,
}

impl UpgradeLedgerSuite {
    /// Create a new upgrade ledger suite task containing multiple subtasks
    /// depending on which canisters need to be upgraded. Due to the dependencies between the canisters of a ledger suite, e.g.,
    /// the index pulls transactions from the ledger, the order of the subtasks is important.
    ///
    /// The order of the subtasks is as follows:
    /// 1. Upgrade the index canister
    /// 2. Upgrade the ledger canister
    /// 3. Fetch the list of archives from the ledger and upgrade all archive canisters
    ///
    /// For each canister, upgrading involves 3 (potentially failing) steps:
    /// 1. Stop the canister
    /// 2. Upgrade the canister
    /// 3. Start the canister
    ///
    /// Note that after having upgraded the index, but before having upgraded the ledger, the upgraded index may fetch information from the not yet upgraded ledger.
    /// However, this is deemed preferable to trying to do some kind of atomic upgrade,
    /// where the ledger would be stopped before upgrading the index, since this would result in 2 canisters being stopped at the same time,
    /// which could be more problematic, especially if for some unexpected reason the upgrade fails.
    fn new(
        contract: Erc20Token,
        ledger_compressed_wasm_hash: Option<WasmHash>,
        index_compressed_wasm_hash: Option<WasmHash>,
        archive_compressed_wasm_hash: Option<WasmHash>,
    ) -> Self {
        let mut subtasks = Vec::new();
        if let Some(index_compressed_wasm_hash) = index_compressed_wasm_hash {
            subtasks.push(UpgradeLedgerSuiteSubtask::UpgradeIndex {
                contract: contract.clone(),
                compressed_wasm_hash: index_compressed_wasm_hash,
            });
        }
        if let Some(ledger_compressed_wasm_hash) = ledger_compressed_wasm_hash {
            subtasks.push(UpgradeLedgerSuiteSubtask::UpgradeLedger {
                contract: contract.clone(),
                compressed_wasm_hash: ledger_compressed_wasm_hash,
            });
        }
        if let Some(archive_compressed_wasm_hash) = archive_compressed_wasm_hash {
            subtasks.push(UpgradeLedgerSuiteSubtask::DiscoverArchives {
                contract: contract.clone(),
            });
            subtasks.push(UpgradeLedgerSuiteSubtask::UpgradeArchives {
                contract: contract.clone(),
                compressed_wasm_hash: archive_compressed_wasm_hash,
            });
        }
        Self {
            subtasks,
            next_subtask_index: 0,
        }
    }

    fn builder(erc20_token: Erc20Token) -> UpgradeLedgerSuiteBuilder {
        UpgradeLedgerSuiteBuilder::new(erc20_token)
    }
}

struct UpgradeLedgerSuiteBuilder {
    erc20_token: Erc20Token,
    ledger_wasm_hash: Option<WasmHash>,
    index_wasm_hash: Option<WasmHash>,
    archive_wasm_hash: Option<WasmHash>,
}

impl UpgradeLedgerSuiteBuilder {
    fn new(erc20_token: Erc20Token) -> Self {
        Self {
            erc20_token,
            ledger_wasm_hash: None,
            index_wasm_hash: None,
            archive_wasm_hash: None,
        }
    }

    fn ledger_wasm_hash<T: Into<Option<WasmHash>>>(mut self, ledger_wasm_hash: T) -> Self {
        self.ledger_wasm_hash = ledger_wasm_hash.into();
        self
    }

    fn index_wasm_hash<T: Into<Option<WasmHash>>>(mut self, index_wasm_hash: T) -> Self {
        self.index_wasm_hash = index_wasm_hash.into();
        self
    }

    fn archive_wasm_hash<T: Into<Option<WasmHash>>>(mut self, archive_wasm_hash: T) -> Self {
        self.archive_wasm_hash = archive_wasm_hash.into();
        self
    }

    fn build(self) -> UpgradeLedgerSuite {
        UpgradeLedgerSuite::new(
            self.erc20_token,
            self.ledger_wasm_hash,
            self.index_wasm_hash,
            self.archive_wasm_hash,
        )
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub enum UpgradeLedgerSuiteSubtask {
    UpgradeIndex {
        contract: Erc20Token,
        compressed_wasm_hash: WasmHash,
    },
    UpgradeLedger {
        contract: Erc20Token,
        compressed_wasm_hash: WasmHash,
    },
    DiscoverArchives {
        contract: Erc20Token,
    },
    UpgradeArchives {
        contract: Erc20Token,
        compressed_wasm_hash: WasmHash,
    },
}

impl UpgradeLedgerSuiteSubtask {
    pub async fn execute<R: CanisterRuntime>(
        &self,
        runtime: &R,
    ) -> Result<(), UpgradeLedgerSuiteError> {
        match self {
            UpgradeLedgerSuiteSubtask::UpgradeIndex {
                contract,
                compressed_wasm_hash,
            } => {
                log!(
                    INFO,
                    "Upgrading index canister for {:?} to {}",
                    contract,
                    compressed_wasm_hash
                );
                let canisters = read_state(|s| s.managed_canisters(contract).cloned()).ok_or(
                    UpgradeLedgerSuiteError::Erc20TokenNotFound(contract.clone()),
                )?;
                let canister_id = ensure_canister_is_installed(contract, canisters.index)?;
                upgrade_canister::<Index, _>(canister_id, compressed_wasm_hash, runtime).await
            }
            UpgradeLedgerSuiteSubtask::UpgradeLedger {
                contract,
                compressed_wasm_hash,
            } => {
                log!(
                    INFO,
                    "Upgrading ledger canister for {:?} to {}",
                    contract,
                    compressed_wasm_hash
                );
                let canisters = read_state(|s| s.managed_canisters(contract).cloned()).ok_or(
                    UpgradeLedgerSuiteError::Erc20TokenNotFound(contract.clone()),
                )?;
                let canister_id = ensure_canister_is_installed(contract, canisters.ledger)?;
                upgrade_canister::<Ledger, _>(canister_id, compressed_wasm_hash, runtime).await
            }
            UpgradeLedgerSuiteSubtask::DiscoverArchives { contract } => {
                log!(INFO, "Discovering archive canister(s) for {:?}", contract);
                discover_archives(select_equal_to(contract), runtime)
                    .await
                    .map_err(UpgradeLedgerSuiteError::DiscoverArchivesError)
            }
            UpgradeLedgerSuiteSubtask::UpgradeArchives {
                contract,
                compressed_wasm_hash,
            } => {
                let archives = read_state(|s| s.managed_canisters(contract).cloned())
                    .ok_or(UpgradeLedgerSuiteError::Erc20TokenNotFound(
                        contract.clone(),
                    ))?
                    .archives;
                if archives.is_empty() {
                    log!(
                        INFO,
                        "No archive canisters found for {:?}. Skipping upgrade of archives.",
                        contract
                    );
                    return Ok(());
                }
                log!(
                    INFO,
                    "Upgrading archive canisters {} for {:?} to {}",
                    display_iter(&archives),
                    contract,
                    compressed_wasm_hash
                );
                //We expect usually 0 or 1 archive, so a simple sequential strategy is good enough.
                for canister_id in archives {
                    upgrade_canister::<Archive, _>(canister_id, compressed_wasm_hash, runtime)
                        .await?;
                }
                Ok(())
            }
        }
    }
}

impl Iterator for UpgradeLedgerSuite {
    type Item = UpgradeLedgerSuiteSubtask;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_subtask_index >= self.subtasks.len() {
            return None;
        }
        let result = self.subtasks.get(self.next_subtask_index);
        self.next_subtask_index += 1;
        result.cloned()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.subtasks.len() - self.next_subtask_index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for UpgradeLedgerSuite {}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct UpgradeOrchestratorArgs {
    ledger_compressed_wasm_hash: Option<WasmHash>,
    index_compressed_wasm_hash: Option<WasmHash>,
    archive_compressed_wasm_hash: Option<WasmHash>,
}

#[derive(Clone, PartialEq, Debug)]
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

    pub fn new_ledger_suite_version(self, old: LedgerSuiteVersion) -> LedgerSuiteVersion {
        LedgerSuiteVersion {
            ledger_compressed_wasm_hash: self
                .ledger_compressed_wasm_hash
                .unwrap_or(old.ledger_compressed_wasm_hash),
            index_compressed_wasm_hash: self
                .index_compressed_wasm_hash
                .unwrap_or(old.index_compressed_wasm_hash),
            archive_compressed_wasm_hash: self
                .archive_compressed_wasm_hash
                .unwrap_or(old.archive_compressed_wasm_hash),
        }
    }

    pub fn upgrade_ledger_suite(&self) -> bool {
        self.ledger_compressed_wasm_hash.is_some()
            || self.index_compressed_wasm_hash.is_some()
            || self.archive_compressed_wasm_hash.is_some()
    }

    pub fn into_task(self, contract: Erc20Token) -> UpgradeLedgerSuite {
        UpgradeLedgerSuite::builder(contract)
            .ledger_wasm_hash(self.ledger_compressed_wasm_hash)
            .index_wasm_hash(self.index_compressed_wasm_hash)
            .archive_wasm_hash(self.archive_compressed_wasm_hash)
            .build()
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct InstallLedgerSuiteArgs {
    contract: Erc20Token,
    minter_id: Principal,
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

#[derive(Clone, PartialEq, Debug)]
pub enum InvalidAddErc20ArgError {
    InvalidErc20Contract(String),
    Erc20ContractAlreadyManaged(Erc20Token),
    WasmHashError(WasmHashError),
    InternalError(String),
}

impl InstallLedgerSuiteArgs {
    pub fn validate_add_erc20(
        state: &State,
        wasm_store: &WasmStore,
        args: AddErc20Arg,
    ) -> Result<InstallLedgerSuiteArgs, InvalidAddErc20ArgError> {
        let contract = Erc20Token::try_from(args.contract.clone())
            .map_err(|e| InvalidAddErc20ArgError::InvalidErc20Contract(e.to_string()))?;
        let minter_id =
            state
                .minter_id()
                .cloned()
                .ok_or(InvalidAddErc20ArgError::InternalError(
                    "ERROR: minter principal not set in state".to_string(),
                ))?;
        if let Some(_canisters) = state.managed_canisters(&contract) {
            return Err(InvalidAddErc20ArgError::Erc20ContractAlreadyManaged(
                contract,
            ));
        }
        let (ledger_compressed_wasm_hash, index_compressed_wasm_hash) = {
            let LedgerSuiteVersion {
                ledger_compressed_wasm_hash,
                index_compressed_wasm_hash,
                archive_compressed_wasm_hash: _,
            } = state
                .ledger_suite_version()
                .expect("ERROR: ledger suite version missing");
            //TODO XC-138: move read method to state and ensure that hash is in store and remove this.
            assert!(
                //nothing can be changed in AddErc20Arg to fix this.
                wasm_store_contain::<Ledger>(wasm_store, ledger_compressed_wasm_hash),
                "BUG: ledger compressed wasm hash missing"
            );
            assert!(
                //nothing can be changed in AddErc20Arg to fix this.
                wasm_store_contain::<Index>(wasm_store, index_compressed_wasm_hash),
                "BUG: index compressed wasm hash missing"
            );
            (
                ledger_compressed_wasm_hash.clone(),
                index_compressed_wasm_hash.clone(),
            )
        };
        Ok(Self {
            contract,
            minter_id,
            ledger_init_arg: args.ledger_init_arg,
            ledger_compressed_wasm_hash,
            index_compressed_wasm_hash,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum TaskError {
    CanisterCreationError(CallError),
    InstallCodeError(CallError),
    CanisterStatusError(CallError),
    WasmHashNotFound(WasmHash),
    WasmStoreError(WasmStoreError),
    LedgerNotFound(Erc20Token),
    InterCanisterCallError(CallError),
    InsufficientCyclesToTopUp { required: u128, available: u128 },
    DiscoverArchivesError(DiscoverArchivesError),
    UpgradeLedgerSuiteError(UpgradeLedgerSuiteError),
    ManageAlreadyInstalledLedgerSuiteError(ManageAlreadyInstalledLedgerSuiteError),
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
            TaskError::InterCanisterCallError(e) => is_recoverable(e),
            TaskError::InsufficientCyclesToTopUp { .. } => false, //top-up task is periodic, will retry on next interval
            TaskError::DiscoverArchivesError(e) => e.is_recoverable(),
            TaskError::UpgradeLedgerSuiteError(e) => e.is_recoverable(),
            TaskError::ManageAlreadyInstalledLedgerSuiteError(e) => e.is_recoverable(),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum DiscoverArchivesError {
    InterCanisterCallError(CallError),
}

impl DiscoverArchivesError {
    fn is_recoverable(&self) -> bool {
        match self {
            DiscoverArchivesError::InterCanisterCallError(e) => is_recoverable(e),
        }
    }
}

impl From<DiscoverArchivesError> for TaskError {
    fn from(value: DiscoverArchivesError) -> Self {
        TaskError::DiscoverArchivesError(value)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum UpgradeLedgerSuiteError {
    Erc20TokenNotFound(Erc20Token),
    CanisterNotReady {
        erc20_token: Erc20Token,
        status: Option<ManagedCanisterStatus>,
        message: String,
    },
    StopCanisterError(CallError),
    StartCanisterError(CallError),
    UpgradeCanisterError(CallError),
    WasmHashNotFound(WasmHash),
    WasmStoreError(WasmStoreError),
    DiscoverArchivesError(DiscoverArchivesError),
}

impl UpgradeLedgerSuiteError {
    fn is_recoverable(&self) -> bool {
        match self {
            UpgradeLedgerSuiteError::Erc20TokenNotFound(_) => false,
            UpgradeLedgerSuiteError::CanisterNotReady { .. } => true,
            UpgradeLedgerSuiteError::WasmHashNotFound(_) => false,
            UpgradeLedgerSuiteError::WasmStoreError(_) => false,
            UpgradeLedgerSuiteError::StopCanisterError(_) => true,
            UpgradeLedgerSuiteError::StartCanisterError(_) => true,
            UpgradeLedgerSuiteError::UpgradeCanisterError(_) => true,
            UpgradeLedgerSuiteError::DiscoverArchivesError(e) => e.is_recoverable(),
        }
    }
}

impl From<UpgradeLedgerSuiteError> for TaskError {
    fn from(value: UpgradeLedgerSuiteError) -> Self {
        TaskError::UpgradeLedgerSuiteError(value)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum ManageAlreadyInstalledLedgerSuiteError {}

impl ManageAlreadyInstalledLedgerSuiteError {
    fn is_recoverable(&self) -> bool {
        todo!("Implement this")
    }
}

impl From<ManageAlreadyInstalledLedgerSuiteError> for TaskError {
    fn from(value: ManageAlreadyInstalledLedgerSuiteError) -> Self {
        TaskError::ManageAlreadyInstalledLedgerSuiteError(value)
    }
}

fn is_recoverable(e: &CallError) -> bool {
    match &e.reason {
        Reason::OutOfCycles => true,
        Reason::CanisterError(msg) => msg.ends_with("is stopped") || msg.ends_with("is stopping"),
        Reason::Rejected(_) => false,
        Reason::TransientInternalError(_) => true,
        Reason::InternalError(_) => false,
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
            Task::DiscoverArchives => Ok(discover_archives(select_all(), runtime).await?),
            Task::UpgradeLedgerSuite(upgrade) => Ok(upgrade_ledger_suite(upgrade, runtime).await?),
            Task::ManageAlreadyInstalledLedgerSuite(args) => {
                Ok(manage_already_installed_ledger_suite(args, runtime).await?)
            }
        }
    }
}

async fn maybe_top_up<R: CanisterRuntime>(runtime: &R) -> Result<(), TaskError> {
    let managed_principals: BTreeSet<Principal> = read_state(|s| s.managed_principals());
    if managed_principals.is_empty() {
        log!(INFO, "[maybe_top_up]: No managed canisters to top-up");
        return Ok(());
    }
    let cycles_management = read_state(|s| s.cycles_management().clone());
    let minimum_orchestrator_cycles =
        cycles_to_u128(cycles_management.minimum_orchestrator_cycles());
    let minimum_monitored_canister_cycles =
        cycles_to_u128(cycles_management.minimum_monitored_canister_cycles());
    let top_up_amount = cycles_to_u128(cycles_management.cycles_top_up_increment.clone());
    log!(
        INFO,
        "[maybe_top_up]: Managed canisters {}. \
        Cycles management: {cycles_management:?}. \
    Required amount of cycles for orchestrator to be able to top-up: {minimum_orchestrator_cycles}. \
    Monitored canister minimum target cycles balance {minimum_monitored_canister_cycles}", display_iter(&managed_principals)
    );

    let mut orchestrator_cycle_balance = match runtime.canister_cycles(runtime.id()).await {
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
    if orchestrator_cycle_balance < minimum_orchestrator_cycles {
        return Err(TaskError::InsufficientCyclesToTopUp {
            required: minimum_orchestrator_cycles,
            available: orchestrator_cycle_balance,
        });
    }

    let results = future::join_all(
        managed_principals
            .iter()
            .map(|p| runtime.canister_cycles(*p)),
    )
    .await;
    assert!(!results.is_empty());

    for (canister_id, cycles_result) in managed_principals.iter().zip(results) {
        match cycles_result {
            Ok(balance) => {
                match (
                    balance.cmp(&minimum_monitored_canister_cycles),
                    orchestrator_cycle_balance.cmp(&minimum_orchestrator_cycles),
                ) {
                    (Ordering::Greater, _) | (Ordering::Equal, _) => {
                        log!(
                            DEBUG,
                            "[maybe_top_up] canister {canister_id} has enough cycles {balance}"
                        );
                    }
                    (_, Ordering::Less) => {
                        return Err(TaskError::InsufficientCyclesToTopUp {
                            required: minimum_orchestrator_cycles,
                            available: orchestrator_cycle_balance,
                        });
                    }
                    (Ordering::Less, Ordering::Equal) | (Ordering::Less, Ordering::Greater) => {
                        log!(
                            DEBUG,
                            "[maybe_top_up] Sending {top_up_amount} cycles to canister {canister_id} with current balance {balance}"
                        );
                        match runtime.send_cycles(*canister_id, top_up_amount) {
                            Ok(()) => {
                                orchestrator_cycle_balance -= top_up_amount;
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

    let more_controllers = read_state(|s| s.more_controller_ids().to_vec())
        .into_iter()
        .map(PrincipalId)
        .collect();
    install_canister_once::<Ledger, _, _>(
        &args.contract,
        &args.ledger_compressed_wasm_hash,
        &LedgerArgument::Init(icrc1_ledger_init_arg(
            args.minter_id,
            args.ledger_init_arg.clone(),
            runtime.id().into(),
            more_controllers,
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
        retrieve_blocks_from_ledger_interval_seconds: None,
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
            schedule_now(
                Task::NotifyErc20Added {
                    erc20_token,
                    minter_id,
                },
                runtime,
            );
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
    minter_id: Principal,
    ledger_init_arg: LedgerInitArg,
    archive_controller_id: PrincipalId,
    archive_more_controller_ids: Vec<PrincipalId>,
    cycles_for_archive_creation: Nat,
) -> LedgerInitArgs {
    use ic_icrc1_ledger::FeatureFlags as LedgerFeatureFlags;
    use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as LedgerMetadataValue;
    use icrc_ledger_types::icrc1::account::Account as LedgerAccount;

    const LEDGER_FEE_SUBACCOUNT: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x0f, 0xee,
    ];
    const MAX_MEMO_LENGTH: u16 = 80;
    const ICRC2_FEATURE: LedgerFeatureFlags = LedgerFeatureFlags { icrc2: true };

    LedgerInitArgs {
        minting_account: LedgerAccount::from(minter_id),
        fee_collector_account: Some(LedgerAccount {
            owner: minter_id,
            subaccount: Some(LEDGER_FEE_SUBACCOUNT),
        }),
        initial_balances: vec![],
        transfer_fee: ledger_init_arg.transfer_fee,
        decimals: Some(ledger_init_arg.decimals),
        token_name: ledger_init_arg.token_name,
        token_symbol: ledger_init_arg.token_symbol,
        metadata: vec![(
            "icrc1:logo".to_string(),
            LedgerMetadataValue::from(ledger_init_arg.token_logo),
        )],
        archive_options: icrc1_archive_options(
            archive_controller_id,
            archive_more_controller_ids,
            cycles_for_archive_creation,
        ),
        max_memo_length: Some(MAX_MEMO_LENGTH),
        feature_flags: Some(ICRC2_FEATURE),
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    }
}

fn icrc1_archive_options(
    archive_controller_id: PrincipalId,
    archive_more_controller_ids: Vec<PrincipalId>,
    cycles_for_archive_creation: Nat,
) -> ArchiveOptions {
    ArchiveOptions {
        trigger_threshold: 2_000,
        num_blocks_to_archive: 1_000,
        node_max_memory_size_bytes: Some(THREE_GIGA_BYTES),
        max_message_size_bytes: None,
        controller_id: archive_controller_id,
        more_controller_ids: Some(archive_more_controller_ids),
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

async fn discover_archives<R: CanisterRuntime, F: Fn(&Erc20Token) -> bool>(
    selector: F,
    runtime: &R,
) -> Result<(), DiscoverArchivesError> {
    let ledgers: BTreeMap<_, _> = read_state(|s| {
        s.managed_canisters_iter()
            .filter(|(token, _)| selector(token))
            .filter_map(|(token, canisters)| {
                canisters
                    .ledger_canister_id()
                    .cloned()
                    .map(|ledger_id| (token.clone(), ledger_id))
            })
            .collect()
    });
    if ledgers.is_empty() {
        return Ok(());
    }
    log!(
        INFO,
        "[discover_archives]: discovering archives for {:?}",
        ledgers
    );
    let results = future::join_all(
        ledgers
            .values()
            .map(|p| call_ledger_icrc3_get_archives(*p, runtime)),
    )
    .await;
    let mut errors: Vec<(Erc20Token, Principal, DiscoverArchivesError)> = Vec::new();
    for ((token, ledger), result) in ledgers.into_iter().zip(results) {
        match result {
            Ok(archives) => {
                //order is not guaranteed by the API of icrc3_get_archives.
                let archives: BTreeSet<_> = archives.into_iter().map(|a| a.canister_id).collect();
                log!(
                    DEBUG,
                    "[discover_archives]: archives for ERC-20 token {:?} with ledger {}: {}",
                    token,
                    ledger,
                    display_iter(&archives)
                );
                mutate_state(|s| s.record_archives(&token, archives.into_iter().collect()));
            }
            Err(e) => errors.push((token, ledger, e)),
        }
    }
    if !errors.is_empty() {
        log!(
            INFO,
            "[discover_archives]: {} errors. Failed to discover archives for {:?}",
            errors.len(),
            errors
        );
        let first_error = errors.swap_remove(0);
        return Err(first_error.2);
    }
    Ok(())
}

async fn call_ledger_icrc3_get_archives<R: CanisterRuntime>(
    ledger_id: Principal,
    runtime: &R,
) -> Result<GetArchivesResult, DiscoverArchivesError> {
    let args = GetArchivesArgs { from: None };
    runtime
        .call_canister(ledger_id, "icrc3_get_archives", args)
        .await
        .map_err(DiscoverArchivesError::InterCanisterCallError)
}

fn select_all<T>() -> impl Fn(&T) -> bool {
    |_| true
}

fn select_equal_to<T: PartialEq>(expected_value: &T) -> impl Fn(&T) -> bool + '_ {
    move |x| x == expected_value
}

async fn upgrade_ledger_suite<R: CanisterRuntime>(
    upgrade_ledger_suite: &UpgradeLedgerSuite,
    runtime: &R,
) -> Result<(), UpgradeLedgerSuiteError> {
    let mut upgrade_ledger_suite = upgrade_ledger_suite.clone();
    if let Some(subtask) = upgrade_ledger_suite.next() {
        subtask.execute(runtime).await?;
        if upgrade_ledger_suite.len() > 0 {
            schedule_now(Task::UpgradeLedgerSuite(upgrade_ledger_suite), runtime);
        }
    }
    Ok(())
}

fn ensure_canister_is_installed<T>(
    erc20_token: &Erc20Token,
    canister: Option<Canister<T>>,
) -> Result<Principal, UpgradeLedgerSuiteError> {
    match canister {
        None => Err(UpgradeLedgerSuiteError::CanisterNotReady {
            erc20_token: erc20_token.clone(),
            status: None,
            message: "canister not yet created".to_string(),
        }),
        Some(canister) => match canister.status() {
            ManagedCanisterStatus::Created { canister_id } => {
                Err(UpgradeLedgerSuiteError::CanisterNotReady {
                    erc20_token: erc20_token.clone(),
                    status: Some(ManagedCanisterStatus::Created {
                        canister_id: *canister_id,
                    }),
                    message: "canister not yet installed".to_string(),
                })
            }
            ManagedCanisterStatus::Installed {
                canister_id,
                installed_wasm_hash: _,
            } => Ok(*canister_id),
        },
    }
}

async fn upgrade_canister<T: StorableWasm, R: CanisterRuntime>(
    canister_id: Principal,
    wasm_hash: &WasmHash,
    runtime: &R,
) -> Result<(), UpgradeLedgerSuiteError> {
    let wasm = match read_wasm_store(|s| wasm_store_try_get::<T>(s, wasm_hash)) {
        Ok(Some(wasm)) => Ok(wasm),
        Ok(None) => Err(UpgradeLedgerSuiteError::WasmHashNotFound(wasm_hash.clone())),
        Err(e) => Err(UpgradeLedgerSuiteError::WasmStoreError(e)),
    }?;

    log!(DEBUG, "Stopping canister {}", canister_id);
    runtime
        .stop_canister(canister_id)
        .await
        .map_err(UpgradeLedgerSuiteError::StopCanisterError)?;

    log!(
        DEBUG,
        "Upgrading wasm module of canister {} to {}",
        canister_id,
        wasm_hash
    );
    runtime
        .upgrade_canister(canister_id, wasm.to_bytes())
        .await
        .map_err(UpgradeLedgerSuiteError::UpgradeCanisterError)?;

    log!(DEBUG, "Starting canister {}", canister_id);
    runtime
        .start_canister(canister_id)
        .await
        .map_err(UpgradeLedgerSuiteError::StartCanisterError)?;

    log!(
        DEBUG,
        "Upgrade of canister {} to {} completed",
        canister_id,
        wasm_hash
    );
    Ok(())
}

async fn manage_already_installed_ledger_suite<R: CanisterRuntime>(
    _upgrade_ledger_suite: &ManageInstalledCanisters,
    _runtime: &R,
) -> Result<(), ManageAlreadyInstalledLedgerSuiteError> {
    // TODO XC-189: logic
    Ok(())
}

pub struct ManageInstalledCanisters {
    erc20_token: Erc20Token,
    metadata: CanistersMetadata,
    ledger: LedgerCanister,
    index: IndexCanister,
    archives: Vec<Principal>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum InvalidManageInstalledCanistersError {
    InvalidErc20Contract(String),
    Erc20ContractAlreadyManaged(Erc20Token),
    WasmHashError(WasmHashError),
    AlreadyManagedPrincipals(BTreeSet<Principal>),
}

impl ManageInstalledCanisters {
    fn validate(
        state: &State,
        args: crate::candid::ManageInstalledCanisters,
    ) -> Result<ManageInstalledCanisters, InvalidManageInstalledCanistersError> {
        let erc20_token = Erc20Token::try_from(args.erc20_contract).map_err(|e| {
            InvalidManageInstalledCanistersError::InvalidErc20Contract(e.to_string())
        })?;
        if let Some(_canisters) = state.managed_canisters(&erc20_token) {
            return Err(
                InvalidManageInstalledCanistersError::Erc20ContractAlreadyManaged(erc20_token),
            );
        }
        let ledger = args
            .ledger
            .try_into_canister()
            .map_err(InvalidManageInstalledCanistersError::WasmHashError)?;
        let index = args
            .index
            .try_into_canister()
            .map_err(InvalidManageInstalledCanistersError::WasmHashError)?;
        let archives = args.archives.unwrap_or_default();

        let installed_principals: BTreeSet<Principal> = once(ledger.canister_id().clone())
            .chain(once(index.canister_id().clone()))
            .chain(archives.clone().into_iter())
            .collect();
        let overlapping_principals: BTreeSet<_> = state
            .managed_principals()
            .intersection(&installed_principals)
            .collect();
        if !overlapping_principals.is_empty() {
            return Err(
                InvalidManageInstalledCanistersError::AlreadyManagedPrincipals(
                    overlapping_principals,
                ),
            );
        }
        let metadata = CanistersMetadata {
            ckerc20_token_symbol: args.ckerc20_token_symbol,
        };
        Ok(ManageInstalledCanisters {
            erc20_token,
            metadata,
            ledger,
            index,
            archives,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub struct Erc20Token(ChainId, Address);

impl Erc20Token {
    pub fn chain_id(&self) -> &ChainId {
        &self.0
    }

    pub fn address(&self) -> &Address {
        &self.1
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
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

fn display_iter<I: Display, T: IntoIterator<Item = I>>(v: T) -> String {
    format!(
        "[{}]",
        v.into_iter()
            .map(|x| format!("{}", x))
            .collect::<Vec<_>>()
            .join(", ")
    )
}
