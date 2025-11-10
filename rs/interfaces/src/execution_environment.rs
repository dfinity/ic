//! The execution environment public interface.
mod errors;

pub use errors::{CanisterBacktrace, CanisterOutOfCyclesError, HypervisorError, TrapCode};
use ic_base_types::NumBytes;
use ic_error_types::UserError;
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    Cycles, ExecutionRound, Height, NodeId, NumInstructions, Randomness, RegistryVersion,
    ReplicaVersion, Time,
    batch::{CanisterCyclesCostSchedule, ChainKeyData},
    ingress::{IngressStatus, WasmResult},
    messages::{
        CertificateDelegation, CertificateDelegationMetadata, MessageId, Query, SignedIngress,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::{Infallible, TryFrom},
    fmt,
    ops::{AddAssign, SubAssign},
    sync::Arc,
    time::Duration,
};
use strum_macros::EnumIter;
use thiserror::Error;
use tower::util::BoxCloneService;

/// Instance execution statistics. The stats are cumulative and
/// contain measurements from the point in time when the instance was
/// created up until the moment they are requested.
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct InstanceStats {
    /// Total number of (host) OS pages (4KiB) accessed (read or written) by the instance
    /// and loaded into the linear memory.
    pub wasm_accessed_pages: usize,
    /// Non-deterministic number of accessed OS (4 KiB) pages (read + write).
    pub wasm_accessed_os_pages_count: usize,
    /// Non-deterministic number of accessed Wasm (64 KiB) pages (read + write).
    pub wasm_accessed_wasm_pages_count: usize,

    /// Total number of (host) OS pages (4KiB) modified by the instance.
    /// By definition a page that has been dirtied has also been accessed,
    /// hence this dirtied_pages <= accessed_pages
    pub wasm_dirty_pages: usize,
    /// Non-deterministic number of dirty OS (4 KiB) pages (write).
    pub wasm_dirty_os_pages_count: usize,
    /// Non-deterministic number of dirty Wasm (64 KiB) pages (write).
    pub wasm_dirty_wasm_pages_count: usize,

    /// Number of times a write access is handled when the page has already been
    /// read.
    pub wasm_read_before_write_count: usize,

    /// Number of times a write access is handled when the page has not yet been
    /// read.
    pub wasm_direct_write_count: usize,

    /// Number of sigsegv handled.
    pub wasm_sigsegv_count: usize,

    /// Number of calls to mmap.
    pub wasm_mmap_count: usize,

    /// Number of calls to mprotect.
    pub wasm_mprotect_count: usize,

    /// Number of pages loaded by copying the data.
    pub wasm_copy_page_count: usize,

    /// Total time spent in SIGSEGV handler for heap.
    pub wasm_sigsegv_handler_duration: Duration,

    /// Number of accessed OS pages (4KiB) in stable memory.
    pub stable_accessed_pages: usize,

    /// Number of modified OS pages (4KiB) in stable memory.
    pub stable_dirty_pages: usize,

    /// Number of times a write access is handled when the page has already been
    /// read.
    pub stable_read_before_write_count: usize,

    /// Number of times a write access is handled when the page has not yet been
    /// read.
    pub stable_direct_write_count: usize,

    /// Number of sigsegv handled.
    pub stable_sigsegv_count: usize,

    /// Number of calls to mmap for stable memory.
    pub stable_mmap_count: usize,

    /// Number of calls to mprotect for stable memory.
    pub stable_mprotect_count: usize,

    /// Number of pages loaded by copying the data in stable memory.
    pub stable_copy_page_count: usize,

    /// Total time spent in SIGSEGV handler for stable memory.
    pub stable_sigsegv_handler_duration: Duration,
}

impl InstanceStats {
    // Returns the sum of dirty pages over the wasm heap and stable memory.
    // Will be used when computing the heap delta at the end of the message.
    pub fn dirty_pages(&self) -> usize {
        self.wasm_dirty_pages + self.stable_dirty_pages
    }
    // Returns the sum of accessed pages over the wasm heap and stable memory.
    pub fn accessed_pages(&self) -> usize {
        self.wasm_accessed_pages + self.stable_accessed_pages
    }
}

/// Errors that can be returned when fetching the available memory on a subnet.
#[derive(Debug)]
pub enum SubnetAvailableMemoryError {
    InsufficientMemory {
        execution_requested: NumBytes,
        guaranteed_response_message_requested: NumBytes,
        wasm_custom_sections_requested: NumBytes,
        available_execution: i64,
        available_guaranteed_response_messages: i64,
        available_wasm_custom_sections: i64,
    },
}

/// Performance counter type.
#[derive(Debug)]
pub enum PerformanceCounterType {
    // The number of WebAssembly instructions the canister has executed since
    // the beginning of the current message execution.
    Instructions(i64),
    // The number of WebAssembly instructions the canister has executed since
    // the creation of the current call context.
    CallContextInstructions(i64),
}

/// System API call ids to track their execution (in alphabetical order).
#[derive(Eq, PartialEq, Ord, PartialOrd, Debug, EnumIter)]
pub enum SystemApiCallId {
    /// Tracker for `ic0.accept_message())`
    AcceptMessage,
    /// Tracker for `ic0.call_cycles_add()`
    CallCyclesAdd,
    /// Tracker for `ic0.call_cycles_add128()`
    CallCyclesAdd128,
    /// Tracker for `ic0.call_data_append()`
    CallDataAppend,
    /// Tracker for `ic0.call_new()`
    CallNew,
    /// Tracker for `ic0.call_on_cleanup()`
    CallOnCleanup,
    /// Tracker for `ic0.call_perform()`
    CallPerform,
    /// Tracker for `ic0.call_with_best_effort_response()`
    CallWithBestEffortResponse,
    /// Tracker for `ic0.canister_cycle_balance()`
    CanisterCycleBalance,
    /// Tracker for `ic0.canister_cycle_balance128()`
    CanisterCycleBalance128,
    /// Tracker for `ic0.canister_liquid_cycle_balance128()`
    CanisterLiquidCycleBalance128,
    /// Tracker for `ic0.canister_self_copy()`
    CanisterSelfCopy,
    /// Tracker for `ic0.canister_self_size()`
    CanisterSelfSize,
    /// Tracker for `ic0.canister_status()`
    CanisterStatus,
    /// Tracker for `ic0.canister_version()`
    CanisterVersion,
    /// Tracker for `ic0.root_key_size()`
    RootKeySize,
    /// Tracker for `ic0.root_key_copy()`
    RootKeyCopy,
    /// Tracker for `ic0.certified_data_set()`
    CertifiedDataSet,
    /// Tracker for `ic0.cost_call()`
    CostCall,
    /// Tracker for `ic0.cost_create_canister()`
    CostCreateCanister,
    /// Tracker for `ic0.cost_http_request()`
    CostHttpRequest,
    /// Tracker for `ic0.cost_http_request_v2()`
    CostHttpRequestV2,
    /// Tracker for `ic0.cost_sign_with_ecdsa()`
    CostSignWithEcdsa,
    /// Tracker for `ic0.cost_sign_with_schnorr()`
    CostSignWithSchnorr,
    /// Tracker for `ic0.cost_vetkd_derive_key()`
    CostVetkdDeriveKey,
    /// Tracker for `ic0.cycles_burn128()`
    CyclesBurn128,
    /// Tracker for `ic0.data_certificate_copy()`
    DataCertificateCopy,
    /// Tracker for `ic0.data_certificate_present()`
    DataCertificatePresent,
    /// Tracker for `ic0.data_certificate_size()`
    DataCertificateSize,
    /// Tracker for `ic0.debug_print()`
    DebugPrint,
    /// Tracker for `ic0.global_timer_set()`
    GlobalTimerSet,
    /// Tracker for `ic0.in_replicated_execution()`
    InReplicatedExecution,
    /// Tracker for `ic0.is_controller()`
    IsController,
    /// Tracker for `ic0.mint_cycles128()`
    MintCycles128,
    /// Tracker for `ic0.msg_arg_data_copy()`
    MsgArgDataCopy,
    /// Tracker for `ic0.msg_arg_data_size()`
    MsgArgDataSize,
    /// Tracker for `ic0.msg_caller_copy()`
    MsgCallerCopy,
    /// Tracker for `ic0.msg_caller_size()`
    MsgCallerSize,
    /// Tracker for `ic0.msg_cycles_accept()`
    MsgCyclesAccept,
    /// Tracker for `ic0.msg_cycles_accept128()`
    MsgCyclesAccept128,
    /// Tracker for `ic0.msg_cycles_available()`
    MsgCyclesAvailable,
    /// Tracker for `ic0.msg_cycles_available128()`
    MsgCyclesAvailable128,
    /// Tracker for `ic0.msg_cycles_refunded()`
    MsgCyclesRefunded,
    /// Tracker for `ic0.msg_cycles_refunded128()`
    MsgCyclesRefunded128,
    /// Tracker for `ic0.msg_deadline()`
    MsgDeadline,
    /// Tracker for `ic0.msg_method_name_copy()`
    MsgMethodNameCopy,
    /// Tracker for `ic0.msg_method_name_size()`
    MsgMethodNameSize,
    /// Tracker for `ic0.msg_reject()`
    MsgReject,
    /// Tracker for `ic0.msg_reject_code()`
    MsgRejectCode,
    /// Tracker for `ic0.msg_reject_msg_copy()`
    MsgRejectMsgCopy,
    /// Tracker for `ic0.msg_reject_msg_size()`
    MsgRejectMsgSize,
    /// Tracker for `ic0.msg_reply()`
    MsgReply,
    /// Tracker for `ic0.msg_reply_data_append()`
    MsgReplyDataAppend,
    /// Tracker for `__.out_of_instructions()`
    OutOfInstructions,
    /// Tracker for `ic0.performance_counter()`
    PerformanceCounter,
    /// Tracker for `ic0.subnet_self_size()`
    SubnetSelfSize,
    /// Tracker for `ic0.subnet_self_copy()`
    SubnetSelfCopy,
    /// Tracker for `ic0.stable64_grow()`
    Stable64Grow,
    /// Tracker for `ic0.stable64_read()`
    Stable64Read,
    /// Tracker for `ic0.stable64_size()`
    Stable64Size,
    /// Tracker for `ic0.stable64_write())`
    Stable64Write,
    /// Tracker for `ic0.stable_grow()`
    StableGrow,
    /// Tracker for `ic0.stable_read()`
    StableRead,
    /// Tracker for `ic0.stable_size()`
    StableSize,
    /// Tracker for `ic0.stable_write())`
    StableWrite,
    /// Tracker for `ic0.time()`
    Time,
    /// Tracker for `ic0.trap()`
    Trap,
    /// Tracker for `__.try_grow_wasm_memory()`
    TryGrowWasmMemory,
    /// Tracker for `ic0.env_var_count()`
    EnvVarCount,
    /// Tracker for `ic0.env_var_name_size()`
    EnvVarNameSize,
    /// Tracker for `ic0.env_var_name_copy()`
    EnvVarNameCopy,
    /// Tracker for `ic0.env_var_name_exists()`
    EnvVarNameExists,
    /// Tracker for `ic0.env_var_value_size()`
    EnvVarValueSize,
    /// Tracker for `ic0.env_var_value_copy()`
    EnvVarValueCopy,
}

/// System API call counters, i.e. how many times each tracked System API call
/// was invoked.
#[derive(Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct SystemApiCallCounters {
    /// Counter for `ic0.data_certificate_copy()`
    pub data_certificate_copy: usize,
    /// Counter for `ic0.canister_cycle_balance()`
    pub canister_cycle_balance: usize,
    /// Counter for `ic0.canister_cycle_balance128()`
    pub canister_cycle_balance128: usize,
    /// Counter for `ic0.canister_liquid_cycle_balance128()`
    pub canister_liquid_cycle_balance128: usize,
    /// Counter for `ic0.time()`
    pub time: usize,
}

impl SystemApiCallCounters {
    pub fn saturating_add(&mut self, rhs: Self) {
        self.data_certificate_copy = self
            .data_certificate_copy
            .saturating_add(rhs.data_certificate_copy);
        self.canister_cycle_balance = self
            .canister_cycle_balance
            .saturating_add(rhs.canister_cycle_balance);
        self.canister_cycle_balance128 = self
            .canister_cycle_balance128
            .saturating_add(rhs.canister_cycle_balance128);
        self.canister_liquid_cycle_balance128 = self
            .canister_liquid_cycle_balance128
            .saturating_add(rhs.canister_liquid_cycle_balance128);
        self.time = self.time.saturating_add(rhs.time);
    }
}

/// Tracks the available memory on a subnet. The main idea is to separately track
/// the execution available memory, the message available memory and the wasm custom
/// sections available memory. The different flavors of memory are independent of each
/// other; they are collected in one struct because one often needs to allocate multiple
/// types of memory at the same time.
///
/// Note that there are situations where execution available memory is smaller than
/// the wasm custom sections memory, i.e. when the memory is consumed by something
/// other than wasm custom sections.
#[derive(Copy, Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct SubnetAvailableMemory {
    /// The execution memory available on the subnet, i.e. the canister memory
    /// (Wasm binary, Wasm memory, stable memory) without message memory.
    execution_memory: i64,
    /// The memory available for guaranteed response messages.
    ///
    /// As opposed to best-effort message memory (which can be reclaimed by shedding
    /// messages) guaranteed response message memory must be reserved ahead of time
    /// and is thus subject to availability.
    guaranteed_response_message_memory: i64,
    /// The memory available for Wasm custom sections.
    wasm_custom_sections_memory: i64,
}

impl SubnetAvailableMemory {
    /// This function should only be used in tests.
    #[doc(hidden)]
    pub fn new_for_testing(
        execution_memory: i64,
        guaranteed_response_message_memory: i64,
        wasm_custom_sections_memory: i64,
    ) -> Self {
        // We do not apply scaling in tests that create `SubnetAvailableMemory` manually.
        let scaling_factor = 1;
        SubnetAvailableMemory::new_scaled(
            execution_memory,
            guaranteed_response_message_memory,
            wasm_custom_sections_memory,
            scaling_factor,
        )
    }

    pub fn new_scaled(
        execution_memory: i64,
        guaranteed_response_message_memory: i64,
        wasm_custom_sections_memory: i64,
        scaling_factor: i64,
    ) -> Self {
        SubnetAvailableMemory {
            execution_memory: execution_memory / scaling_factor,
            guaranteed_response_message_memory: guaranteed_response_message_memory / scaling_factor,
            wasm_custom_sections_memory: wasm_custom_sections_memory / scaling_factor,
        }
    }

    /// Returns the execution available memory.
    pub fn get_execution_memory(&self) -> i64 {
        self.execution_memory
    }

    /// Returns the memory available for guaranteed response messages.
    pub fn get_guaranteed_response_message_memory(&self) -> i64 {
        self.guaranteed_response_message_memory
    }

    /// Returns the memory available for Wasm custom sections, ignoring the
    /// execution available memory.
    pub fn get_wasm_custom_sections_memory(&self) -> i64 {
        self.wasm_custom_sections_memory
    }

    /// Returns `Ok(())` if the subnet has enough available room for allocating
    /// the given bytes in each of the memory types.
    /// Otherwise, it returns an error.
    ///
    /// Note that memory types are independent from each other and their limits
    /// are checked independently.
    pub fn check_available_memory(
        &self,
        execution_requested: NumBytes,
        guaranteed_response_message_requested: NumBytes,
        wasm_custom_sections_requested: NumBytes,
    ) -> Result<(), SubnetAvailableMemoryError> {
        let is_available =
            |requested: NumBytes, available: i64| match i64::try_from(requested.get()) {
                Ok(x) => x <= available || x == 0,
                Err(_) => false,
            };

        if is_available(execution_requested, self.execution_memory)
            && is_available(
                guaranteed_response_message_requested,
                self.guaranteed_response_message_memory,
            )
            && is_available(
                wasm_custom_sections_requested,
                self.wasm_custom_sections_memory,
            )
        {
            Ok(())
        } else {
            Err(SubnetAvailableMemoryError::InsufficientMemory {
                execution_requested,
                guaranteed_response_message_requested,
                wasm_custom_sections_requested,
                available_execution: self.execution_memory,
                available_guaranteed_response_messages: self.guaranteed_response_message_memory,
                available_wasm_custom_sections: self.wasm_custom_sections_memory,
            })
        }
    }

    /// Try to use some memory capacity and fail if not enough is available.
    ///
    /// `self.execution_memory`, `self.guaranteed_response_message_memory` and `self.wasm_custom_sections_memory`
    /// are independent of each other. However, this function will not allocate anything if
    /// there is not enough of either one of them (and return an error instead).
    pub fn try_decrement(
        &mut self,
        execution_requested: NumBytes,
        guaranteed_response_message_requested: NumBytes,
        wasm_custom_sections_requested: NumBytes,
    ) -> Result<(), SubnetAvailableMemoryError> {
        self.check_available_memory(
            execution_requested,
            guaranteed_response_message_requested,
            wasm_custom_sections_requested,
        )?;
        self.execution_memory -= execution_requested.get() as i64;
        self.guaranteed_response_message_memory -=
            guaranteed_response_message_requested.get() as i64;
        self.wasm_custom_sections_memory -= wasm_custom_sections_requested.get() as i64;
        Ok(())
    }

    /// Updates (increments/decrements) the available execution memory
    /// by the given number of bytes.
    /// This function should only be used to account for canister history
    /// in the available execution memory.
    /// This is because we do not want an operation tracked in canister history
    /// to fail due to insufficient available execution memory
    /// to update canister history.
    /// Note that the available memory can become negative after this change.
    pub fn update_execution_memory_unchecked(
        &mut self,
        execution_memory_change: SubnetAvailableExecutionMemoryChange,
    ) {
        match execution_memory_change {
            SubnetAvailableExecutionMemoryChange::Allocated(allocated_bytes) => {
                self.execution_memory -= allocated_bytes.get() as i64;
            }
            SubnetAvailableExecutionMemoryChange::Deallocated(deallocated_bytes) => {
                self.execution_memory += deallocated_bytes.get() as i64;
            }
        }
    }

    pub fn increment(
        &mut self,
        execution_amount: NumBytes,
        guaranteed_response_message_amount: NumBytes,
        wasm_custom_sections_amount: NumBytes,
    ) {
        self.execution_memory += execution_amount.get() as i64;
        self.guaranteed_response_message_memory += guaranteed_response_message_amount.get() as i64;
        self.wasm_custom_sections_memory += wasm_custom_sections_amount.get() as i64;
    }

    /// Increments the available memory by the given number of bytes.
    pub fn apply_reservation(
        &mut self,
        execution_amount: NumBytes,
        guaranteed_response_message_amount: NumBytes,
        wasm_custom_sections_amount: NumBytes,
    ) {
        self.execution_memory += execution_amount.get() as i64;
        self.guaranteed_response_message_memory += guaranteed_response_message_amount.get() as i64;
        self.wasm_custom_sections_memory += wasm_custom_sections_amount.get() as i64;
    }

    /// Decrements the available memory by the given number of bytes.
    /// It undoes the changes done by `apply_reservation()`.
    /// Note that the available memory can become negative after this change.
    pub fn revert_reservation(
        &mut self,
        execution_amount: NumBytes,
        guaranteed_response_message_amount: NumBytes,
        wasm_custom_sections_amount: NumBytes,
    ) {
        self.execution_memory -= execution_amount.get() as i64;
        self.guaranteed_response_message_memory -= guaranteed_response_message_amount.get() as i64;
        self.wasm_custom_sections_memory -= wasm_custom_sections_amount.get() as i64;
    }
}

/// Represents an update (allocation/deallocation)
/// of the subnet available execution memory
/// by the given number of bytes.
/// This enum should only be used to account for canister history
/// in the subnet available execution memory.
/// This is because we do not want an operation tracked in canister history
/// to fail due to insufficient available execution memory
/// to update canister history.
pub enum SubnetAvailableExecutionMemoryChange {
    Allocated(NumBytes),
    Deallocated(NumBytes),
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum ExecutionMode {
    Replicated,
    NonReplicated,
}

pub type HypervisorResult<T> = Result<T, HypervisorError>;

/// Interface for the component to filter out ingress messages that
/// the canister is not willing to accept.
pub type IngressFilterService =
    BoxCloneService<(ProvisionalWhitelist, SignedIngress), Result<(), UserError>, Infallible>;

/// Errors that can occur when handling a query execution request.
#[derive(Debug, Error)]
pub enum QueryExecutionError {
    #[error("Certified state is not available yet")]
    CertifiedStateUnavailable,
}

/// The response type to a `call()` request in [`QueryExecutionService`].
/// An Ok response contains the response from the canister and the batch time at the time of execution.
pub type QueryExecutionResponse =
    Result<(Result<WasmResult, UserError>, Time), QueryExecutionError>;

/// The input type to a `call()` request in [`QueryExecutionService`].
#[derive(Debug)]
pub struct QueryExecutionInput {
    pub query: Query,
    pub certificate_delegation_with_metadata:
        Option<(CertificateDelegation, CertificateDelegationMetadata)>,
}

/// Interface for the component to execute queries.
pub type QueryExecutionService =
    BoxCloneService<QueryExecutionInput, QueryExecutionResponse, Infallible>;

/// The input type to a `call()` request in [`TransformExecutionService`].
#[derive(Debug)]
pub struct TransformExecutionInput {
    pub query: Query,
}

/// Interface for the component to execute canister http transform.
pub type TransformExecutionService =
    BoxCloneService<TransformExecutionInput, QueryExecutionResponse, Infallible>;

/// Errors that can be returned when reading/writing from/to ingress history.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum IngressHistoryError {
    StateRemoved(Height),
    StateNotAvailableYet(Height),
}

/// Interface for reading the history of ingress messages.
#[allow(clippy::type_complexity)]
pub trait IngressHistoryReader: Send + Sync {
    /// Returns a function that can be used to query the status for a given
    /// `message_id` using the latest execution state.
    fn get_latest_status(&self) -> Box<dyn Fn(&MessageId) -> IngressStatus>;

    /// Return a function that can be used to query the status for a given
    /// `message_id` using the state at given `height`.
    ///
    /// Return an error if the the state is not available.
    fn get_status_at_height(
        &self,
        height: Height,
    ) -> Result<Box<dyn Fn(&MessageId) -> IngressStatus>, IngressHistoryError>;
}

/// Interface for updating the history of ingress messages.
pub trait IngressHistoryWriter: Send + Sync {
    /// Type of state this Writer can update.
    ///
    /// Should typically be `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Sets the status of a message. Returns the message's previous status.
    ///
    /// The allowed status transitions are:
    /// * "None" -> {"Received", "Processing", "Completed", "Failed"}
    /// * "Received" -> {"Processing", "Completed", "Failed"}
    /// * "Processing" -> {"Processing", "Completed", "Failed"}
    fn set_status(
        &self,
        state: &mut Self::State,
        message_id: MessageId,
        status: IngressStatus,
    ) -> Arc<IngressStatus>;
}

/// A trait for handling `out_of_instructions()` calls from the Wasm module.
pub trait OutOfInstructionsHandler {
    // This function is invoked if the Wasm instruction counter is negative.
    //
    // If it is impossible to recover from the out-of-instructions error then
    // the function returns `Err(HypervisorError::InstructionLimitExceeded)`.
    // Otherwise, the function returns a new positive instruction counter.
    fn out_of_instructions(&self, instruction_counter: i64) -> HypervisorResult<i64>;

    // Invoked only when a long execution dirties many memory pages to yield control
    // and start the copy only in a new slice. This is a performance improvement.
    fn yield_for_dirty_memory_copy(&self) -> HypervisorResult<i64>;
}

/// Indicates the type of stable memory API being used.
pub enum StableMemoryApi {
    Stable64 = 0,
    Stable32 = 1,
}

impl TryFrom<i32> for StableMemoryApi {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Stable64),
            1 => Ok(Self::Stable32),
            _ => Err(()),
        }
    }
}

#[test]
fn stable_memory_api_round_trip() {
    for i in 0..10 {
        if let Ok(api) = StableMemoryApi::try_from(i) {
            assert_eq!(i, api as i32)
        }
    }
}

/// Indicates whether an attempt to grow stable memory succeeded or failed.
pub enum StableGrowOutcome {
    Success,
    Failure,
}

/// A trait for providing all necessary imports to a Wasm module.
pub trait SystemApi {
    /// Stores the execution error, so that the user can evaluate it later.
    fn set_execution_error(&mut self, error: HypervisorError);

    /// Returns the reference to the execution error.
    fn get_execution_error(&self) -> Option<&HypervisorError>;

    /// Returns the amount of instructions needed to copy `num_bytes`.
    fn get_num_instructions_from_bytes(&self, num_bytes: NumBytes) -> NumInstructions;

    /// Returns the subnet type the replica runs on.
    fn subnet_type(&self) -> SubnetType;

    /// Returns the message instruction limit, which is the total instruction
    /// limit for all slices combined.
    fn message_instruction_limit(&self) -> NumInstructions;

    /// Returns the number of instructions executed in the current message,
    /// which is the sum of instructions executed in all slices including the
    /// current one.
    fn message_instructions_executed(&self, instruction_counter: i64) -> NumInstructions;

    /// Returns the instruction limit for the current execution slice.
    fn slice_instruction_limit(&self) -> NumInstructions;

    /// Returns the number of instructions executed in the current slice.
    fn slice_instructions_executed(&self, instruction_counter: i64) -> NumInstructions;

    /// Return the total number of instructions executed in the call context.
    fn call_context_instructions_executed(&self) -> NumInstructions;

    /// Canister id of the executing canister.
    fn canister_id(&self) -> ic_types::CanisterId;

    /// Returns the number of environment variables.
    fn ic0_env_var_count(&self) -> HypervisorResult<usize>;

    /// Returns the size of the environment variable name at the given index.
    ///
    /// # Panics
    ///
    /// This traps if the index is out of bounds.
    fn ic0_env_var_name_size(&self, index: usize) -> HypervisorResult<usize>;

    /// Copies the environment variable name at the given index into memory.
    ///
    /// # Panics
    ///
    /// This traps if the index is out of bounds.
    fn ic0_env_var_name_copy(
        &self,
        index: usize,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Checks if an environment variable with the given name exists.
    /// Returns 1 if the environment variable with the given name exists, 0 otherwise.
    ///
    /// # Panics
    ///
    /// This traps if:
    ///     - the name is too long
    ///     - the name is not a valid UTF-8 string.
    fn ic0_env_var_name_exists(
        &self,
        name_src: usize,
        name_size: usize,
        heap: &[u8],
    ) -> HypervisorResult<i32>;

    /// Returns the size of the value for the environment variable with the given name.
    ///
    ///
    /// # Panics
    ///
    /// This traps if:
    ///     - the name is too long
    ///     - the name is not a valid UTF-8 string.
    ///     - the environment variable with the given name is not found
    fn ic0_env_var_value_size(
        &self,
        name_src: usize,
        name_size: usize,
        heap: &[u8],
    ) -> HypervisorResult<usize>;

    /// Copies the value of the environment variable with the given name into memory.
    ///
    ///
    /// # Panics
    ///
    /// This traps if:
    ///     - the name is too long
    ///     - the name is not a valid UTF-8 string.
    ///     - the environment variable with the given name is not found.
    fn ic0_env_var_value_copy(
        &self,
        name_src: usize,
        name_size: usize,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Copies `size` bytes starting from `offset` inside the opaque caller blob
    /// and copies them to heap[dst..dst+size]. The caller is the canister
    /// id in case of requests or the user id in case of an ingress message.
    fn ic0_msg_caller_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the size of the opaque caller blob.
    fn ic0_msg_caller_size(&self) -> HypervisorResult<usize>;

    /// Returns the size of msg.payload.
    fn ic0_msg_arg_data_size(&self) -> HypervisorResult<usize>;

    /// Copies `length` bytes from msg.payload[offset..offset+size] to
    /// memory[dst..dst+size].
    fn ic0_msg_arg_data_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Used to look up the size of the method_name that the message wants to
    /// call. Can only be called in the context of inspecting messages.
    fn ic0_msg_method_name_size(&self) -> HypervisorResult<usize>;

    /// Used to copy the method_name that the message wants to call to heap. Can
    /// only be called in the context of inspecting messages.
    fn ic0_msg_method_name_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    // If the canister calls this method, then the message will be accepted
    // otherwise rejected. Can only be called in the context of accepting
    // messages.
    fn ic0_accept_message(&mut self) -> HypervisorResult<()>;

    /// Copies the data referred to by src/size out of the canister and appends
    /// it to the (initially empty) data reply.
    fn ic0_msg_reply_data_append(
        &mut self,
        src: usize,
        size: usize,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    /// Replies to the sender with the data assembled using
    /// `msg_reply_data_append`.
    fn ic0_msg_reply(&mut self) -> HypervisorResult<()>;

    /// Returns the reject code, if the current function is invoked as a
    /// reject callback.
    ///
    /// It returns the special “no error” code 0 if the callback is not invoked
    /// as a reject callback
    fn ic0_msg_reject_code(&self) -> HypervisorResult<i32>;

    /// Replies to sender with an error message
    fn ic0_msg_reject(&mut self, src: usize, size: usize, heap: &[u8]) -> HypervisorResult<()>;

    /// Returns the length of the reject message in bytes.
    ///
    /// # Panics
    ///
    /// This traps if not invoked from a reject callback.
    fn ic0_msg_reject_msg_size(&self) -> HypervisorResult<usize>;

    /// Copies length bytes from self.reject_msg[offset..offset+size] to
    /// memory[dst..dst+size]
    ///
    /// # Panics
    ///
    /// This traps if offset+size is greater than the size of the reject
    /// message, or if dst+size exceeds the size of the Wasm memory, or if not
    /// called from inside a reject callback.
    fn ic0_msg_reject_msg_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the size of the blob corresponding to the id of the canister.
    fn ic0_canister_self_size(&self) -> HypervisorResult<usize>;

    /// Copies `size` bytes starting from `offset` in the id blob of the
    /// canister to heap[dst..dst+size].
    fn ic0_canister_self_copy(
        &mut self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Outputs the specified bytes on the heap as a string on STDOUT.
    fn ic0_debug_print(&self, src: usize, size: usize, heap: &[u8]) -> HypervisorResult<()>;

    /// Traps, with a possibly helpful message
    fn ic0_trap(&self, src: usize, size: usize, heap: &[u8]) -> HypervisorResult<()>;

    /// Begins assembling a call to the canister specified by
    /// callee_src/callee_size at method name_src/name_size. Two mandatory
    /// callbacks are recorded which will be invoked on success and error
    /// respectively.
    ///
    /// Subsequent calls to other `call_*` apis set further attributes of this
    /// call until the call is concluded (with `ic0.call_perform) or discarded
    /// (by returning without calling `ic0.call_perform` or by starting a new
    /// call with `ic0.call_new`).
    #[allow(clippy::too_many_arguments)]
    fn ic0_call_new(
        &mut self,
        callee_src: usize,
        callee_size: usize,
        name_src: usize,
        name_len: usize,
        reply_fun: u32,
        reply_env: u64,
        reject_fun: u32,
        reject_env: u64,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    /// Appends the specified bytes to the argument of the call. Initially, the
    /// argument is empty. This can be called multiple times between
    /// `ic0.call_new` and `ic0.call_perform`.
    fn ic0_call_data_append(
        &mut self,
        src: usize,
        size: usize,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    /// Relaxes the response delivery guarantee to be best effort, asking the system to respond at the
    /// latest after `timeout_seconds` have elapsed. Best effort means the system may also respond with
    /// a `SYS_UNKNOWN` reject code, signifying that the call may or may not have been processed by
    /// the callee. Then, even if the callee produces a response, it will not be delivered to the caller.
    /// Any value for `timeout_seconds` is permitted, but is silently bounded by the `MAX_CALL_TIMEOUT`
    /// system constant; i.e., larger timeouts are treated as equivalent to `MAX_CALL_TIMEOUT` and do not
    /// cause an error.
    ///
    /// This method can be called only in between `ic0.call_new` and `ic0.call_perform`, and at most once at that.
    /// Otherwise, it traps. A different timeout can be specified for each call.
    fn ic0_call_with_best_effort_response(&mut self, timeout_seconds: u32) -> HypervisorResult<()>;

    /// The deadline, in nanoseconds since 1970-01-01, after which the caller might stop waiting for a response.
    ///
    /// For calls with best-effort responses, the deadline is computed based on the time the call was made, and
    /// the `timeout_seconds` parameter provided by the caller. For other calls, a deadline of 0 will be returned.
    fn ic0_msg_deadline(&self) -> HypervisorResult<u64>;

    /// Specifies the closure to be called if the reply/reject closures trap.
    /// Can be called at most once between `ic0.call_new` and
    /// `ic0.call_perform`.
    ///
    /// See <https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-call>
    fn ic0_call_on_cleanup(&mut self, fun: u32, env: u64) -> HypervisorResult<()>;

    /// (deprecated) Please use `ic0_call_cycles_add128` instead, as this API
    /// can only add a 64-bit value.
    ///
    /// Adds cycles to a call by moving them from the
    /// canister's balance onto the call under construction.
    /// The cycles are deducted immediately from the canister's
    /// balance and moved back if the call cannot be performed (e.g. if
    /// `ic0.call_perform` signals an error or if the canister invokes
    /// `ic0.call_new` or returns without invoking `ic0.call_perform`).
    ///
    /// This traps if trying to transfer more cycles than are in the current
    /// balance of the canister.
    fn ic0_call_cycles_add(&mut self, amount: u64) -> HypervisorResult<()>;

    /// Adds cycles to a call by moving them from the canister's balance onto
    /// the call under construction. The cycles are deducted immediately
    /// from the canister's balance and moved back if the call cannot be
    /// performed (e.g. if `ic0.call_perform` signals an error or if the
    /// canister invokes `ic0.call_new` or returns without invoking
    /// `ic0.call_perform`).
    ///
    /// This traps if trying to transfer more cycles than are in the current
    /// balance of the canister.
    fn ic0_call_cycles_add128(&mut self, amount: Cycles) -> HypervisorResult<()>;

    /// This call concludes assembling the call. It queues the call message to
    /// the given destination, but does not actually act on it until the current
    /// WebAssembly function returns without trapping.
    ///
    /// If the system returns 0, then the system was able to enqueue the call,
    /// if a non-zero value is returned then the call could not be enqueued.
    ///
    /// After `ic0.call_perform` and before the next `ic0.call_new`, all other
    /// `ic0.call_*` calls trap.
    fn ic0_call_perform(&mut self) -> HypervisorResult<i32>;

    /// Same implementation as `ic0_stable_read`, but doesn't do any bounds
    /// checks on the stable memory size. This is part of the hidden API and
    /// should only be called from instrumented code that has already done the
    /// bounds checks within Wasm code. Calls that access pages outsize of
    /// the current stable memory size will get zeros for those pages.
    fn stable_read_without_bounds_checks(
        &self,
        dst: u64,
        offset: u64,
        size: u64,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// The canister can query the IC for the current time.
    fn ic0_time(&mut self) -> HypervisorResult<Time>;

    /// The canister can set a global one-off timer at the specific time.
    fn ic0_global_timer_set(&mut self, time: Time) -> HypervisorResult<Time>;

    /// The canister can query the IC for its version.
    fn ic0_canister_version(&self) -> HypervisorResult<u64>;

    /// The canister can query the "performance counter", which is
    /// a deterministic monotonically increasing integer approximating
    /// the amount of work the canister has done since the beginning of
    /// the current execution.
    ///
    /// The argument type decides which performance counter to return:
    ///     0 : instruction counter. The number of WebAssembly
    ///         instructions the system has determined that the canister
    ///         has executed.
    ///     1 : call context instruction counter. The number of WebAssembly
    ///         instructions the canister has executed within the call context
    ///         of the current Message Execution since the Call Context creation.
    ///
    /// Note: as the instruction counters are not available on the SystemApi level,
    /// the `ic0_performance_counter_helper()` in `wasmtime_embedder` module does
    /// most of the work. Yet the function is still implemented here for the consistency.
    fn ic0_performance_counter(
        &self,
        performance_counter_type: PerformanceCounterType,
    ) -> HypervisorResult<u64>;

    /// This system call is not part of the public spec and it is invoked when
    /// Wasm execution has run out of instructions.
    ///
    /// If it is impossible to recover from the out-of-instructions error then
    /// the functions return `Err(HypervisorError::InstructionLimitExceeded)`.
    /// Otherwise, the function return a new non-negative instruction counter.
    fn out_of_instructions(&mut self, instruction_counter: i64) -> HypervisorResult<i64>;

    /// This system call is not part of the public spec and it is invoked when
    /// Wasm execution has a large number of dirty pages that, for performance reasons,
    /// should be copied in a new execution slice.
    fn yield_for_dirty_memory_copy(&mut self) -> HypervisorResult<i64>;

    /// This system call is not part of the public spec. It's called after a
    /// native `memory.grow` has been executed to check whether there's enough
    /// available memory left.
    fn try_grow_wasm_memory(
        &mut self,
        native_memory_grow_res: i64,
        additional_wasm_pages: u64,
    ) -> HypervisorResult<()>;

    /// Attempts to allocate memory before calling stable grow. Will also check
    /// that the current size if valid for the stable memory API being used and
    /// the resulting size doesn't exceed the maximum stable memory limit.
    ///
    /// This is enough to guarantee that growing the stable memory from within
    /// wasm will succeed.
    fn try_grow_stable_memory(
        &mut self,
        current_size: u64,
        additional_pages: u64,
        max_size: u64,
        stable_memory_api: StableMemoryApi,
    ) -> HypervisorResult<StableGrowOutcome>;

    /// (deprecated) Please use `ic0_canister_cycle_balance128` instead.
    /// This API supports only 64-bit values.
    ///
    /// Returns the current balance in cycles.
    ///
    /// Traps if current canister balance cannot fit in a 64-bit value.
    fn ic0_canister_cycle_balance(&mut self) -> HypervisorResult<u64>;

    /// This system call indicates the current cycle balance
    /// of the canister.
    ///
    /// The amount of cycles is represented by a 128-bit value
    /// and is copied in the canister memory starting
    /// starting at the location `dst`.
    fn ic0_canister_cycle_balance128(
        &mut self,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// This system call indicates the current liquid cycle balance
    /// of the canister that the canister can spend without getting frozen.
    ///
    /// The amount of cycles is represented by a 128-bit value
    /// and is copied in the canister memory starting
    /// starting at the location `dst`.
    fn ic0_canister_liquid_cycle_balance128(
        &mut self,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// (deprecated) Please use `ic0_msg_cycles_available128` instead.
    /// This API supports only 64-bit values.
    ///
    /// Cycles sent in the current call and still available.
    ///
    /// Traps if the amount of cycles available cannot fit in a 64-bit value.
    fn ic0_msg_cycles_available(&self) -> HypervisorResult<u64>;

    /// This system call indicates the amount of cycles sent
    /// in the current call and still available.
    ///
    /// The amount of cycles is represented by a 128-bit value
    /// and is copied in the canister memory starting
    /// starting at the location `dst`.
    fn ic0_msg_cycles_available128(&self, dst: usize, heap: &mut [u8]) -> HypervisorResult<()>;

    /// (deprecated) Please use `ic0_msg_cycles_refunded128` instead.
    /// This API supports only 64-bit values.
    ///
    /// Cycles that came back with the response, as a refund.
    ///
    /// Traps if the amount of refunded cycles cannot fit in a 64-bit value.
    fn ic0_msg_cycles_refunded(&self) -> HypervisorResult<u64>;

    /// This system call indicates the amount of cycles sent
    /// that came back with the response as a refund.
    ///
    /// The amount of cycles is represented by a 128-bit value
    /// and is copied in the canister memory starting
    /// starting at the location `dst`.
    fn ic0_msg_cycles_refunded128(&self, dst: usize, heap: &mut [u8]) -> HypervisorResult<()>;

    /// (deprecated) Please use `ic0_msg_cycles_accept128` instead.
    /// This API supports only 64-bit values.
    ///
    /// This moves cycles from the
    /// call to the canister balance. It can be called multiple times, each
    /// time adding more cycles to the balance.
    ///
    /// It moves no more cycles than `max_amount`.
    ///
    /// It moves no more cycles than available according to
    /// `ic0.msg_cycles_available`, and
    ///
    /// The canister balance afterwards does not exceed
    /// maximum amount of cycles it can hold (public spec refers to this
    /// constant as MAX_CANISTER_BALANCE) minus any possible outstanding
    /// balances. However, canisters on system subnets have no balance
    /// limit.
    ///
    /// EXE-117: the last point is not properly handled yet.  In particular, a
    /// refund can come back to the canister after this call finishes which
    /// causes the canister's balance to overflow.
    fn ic0_msg_cycles_accept(&mut self, max_amount: u64) -> HypervisorResult<u64>;

    /// This moves cycles from the call to the canister balance.
    /// It can be called multiple times, each time adding more cycles to the
    /// balance.
    ///
    /// It moves no more cycles than `max_amount`.
    ///
    /// It moves no more cycles than available according to
    /// `ic0.msg_cycles_available128`, and
    ///
    /// The canister balance afterwards does not exceed
    /// maximum amount of cycles it can hold (public spec refers to this
    /// constant as MAX_CANISTER_BALANCE) minus any possible outstanding
    /// balances. However, canisters on system subnets have no balance
    /// limit.
    ///
    /// EXE-117: the last point is not properly handled yet.  In particular, a
    /// refund can come back to the canister after this call finishes which
    /// causes the canister's balance to overflow.
    fn ic0_msg_cycles_accept128(
        &mut self,
        max_amount: Cycles,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Used to look up the size of the root key.
    fn ic0_root_key_size(&self) -> HypervisorResult<usize>;

    /// Used to copy the root key (starting at `offset` and copying `size` bytes)
    /// to the calling canister's heap at the location specified by `dst`.
    fn ic0_root_key_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Sets the certified data for the canister.
    /// See: <https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-certified-data>
    fn ic0_certified_data_set(
        &mut self,
        src: usize,
        size: usize,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    /// If run in non-replicated execution (i.e. query),
    /// returns 1 if the data certificate is present, 0 otherwise.
    /// If run in replicated execution (i.e. an update call or a certified
    /// query), returns 0.
    fn ic0_data_certificate_present(&self) -> HypervisorResult<i32>;

    /// Returns the size of the data certificate if it is present
    /// (i.e. data_certificate_present returns 1).
    /// Traps if data_certificate_present returns 0.
    fn ic0_data_certificate_size(&self) -> HypervisorResult<usize>;

    /// Copies the data certificate into the heap if it is present
    /// (i.e. data_certificate_present returns 1).
    /// Traps if data_certificate_present returns 0.
    fn ic0_data_certificate_copy(
        &mut self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the current status of the canister.  `1` indicates
    /// running, `2` indicates stopping, and `3` indicates stopped.
    fn ic0_canister_status(&self) -> HypervisorResult<u32>;

    /// Mints the `amount` cycles
    /// Adds cycles to the canister's balance.
    ///
    /// Adds no more cycles than `amount`. The balance afterwards cannot
    /// exceed u128::MAX, so the amount added may be less than `amount`.
    ///
    /// The amount of cycles added to the canister's balance is
    /// represented by a 128-bit value and is copied in the canister
    /// memory starting at the location `dst`.
    fn ic0_mint_cycles128(
        &mut self,
        amount: Cycles,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Checks whether the principal identified by src/size is one of the
    /// controllers of the canister. If yes, then a value of 1 is returned,
    /// otherwise a 0 is returned. It can be called multiple times.
    ///
    /// This system call traps if src+size exceeds the size of the WebAssembly memory.
    fn ic0_is_controller(&self, src: usize, size: usize, heap: &[u8]) -> HypervisorResult<u32>;

    /// If run in replicated execution (i.e. an update call or a certified
    /// query), returns 1.
    /// If run in non-replicated execution (i.e. query),
    /// returns 0 if the data certificate is present, 1 otherwise.
    fn ic0_in_replicated_execution(&self) -> HypervisorResult<i32>;

    /// Burns the provided `amount` cycles.
    /// Removes cycles from the canister's balance.
    ///
    /// Removes no more cycles than `amount`.
    ///
    /// If the canister does not have enough cycles, it burns as much
    /// as possible while the canister does not freeze.
    fn ic0_cycles_burn128(
        &mut self,
        amount: Cycles,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// This system call returns the amount of cycles that a canister needs to
    /// be above the freezing threshold in order to successfully make an
    /// inter-canister call. This includes the base cost for an inter-canister
    /// call, the cost for each byte transmitted in the request, the cost for
    /// the transmission of the largest possible response, and the cost for
    /// executing the largest possible response callback.
    ///
    /// The cost is determined by the byte length of the method name and the
    /// length of the encoded payload.
    ///
    /// The amount of cycles is represented by a 128-bit value and is copied
    /// to the canister memory starting at the location `dst`.
    fn ic0_cost_call(
        &self,
        method_name_size: u64,
        payload_size: u64,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// This system call indicates the cycle cost of creating a canister on
    /// the same subnet, i.e., the management canister's `create_canister`.
    ///
    /// The amount of cycles is represented by a 128-bit value and is copied
    /// to the canister memory starting at the location `dst`.
    fn ic0_cost_create_canister(&self, dst: usize, heap: &mut [u8]) -> HypervisorResult<()>;

    /// This system call indicates the cycle cost of making an http outcall,
    /// i.e., the management canister's `http_request`.
    ///
    /// `request_size` is the sum of the lengths of the variable request parts, as
    /// documented in the interface specification.
    /// `max_res_bytes` is the maximum number of response bytes the caller wishes to
    /// accept.
    ///
    /// The amount of cycles is represented by a 128-bit value and is copied
    /// to the canister memory starting at the location `dst`.
    fn ic0_cost_http_request(
        &self,
        request_size: u64,
        max_res_bytes: u64,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    fn ic0_cost_http_request_v2(
        &self,
        params_src: usize,
        params_size: usize,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// This system call indicates the cycle cost of signing with ecdsa,
    /// i.e., the management canister's `sign_with_ecdsa`, for the key
    /// (whose name is given by textual representation at heap location `src`
    /// with byte length `size`) and the provided curve.
    ///
    /// Traps if `src`+`size` exceeds the size of the WebAssembly memory.
    /// Returns 0 on success.
    /// Returns 1 if an unknown curve variant was provided.
    /// Returns 2 if the given curve variant does not have a key with the
    /// name provided via `src`/`size`.
    ///
    ///
    /// The amount of cycles is represented by a 128-bit value and is copied
    /// to the canister memory starting at the location `dst` if the return
    /// value is 0.
    fn ic0_cost_sign_with_ecdsa(
        &self,
        src: usize,
        size: usize,
        curve: u32,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<u32>;

    /// This system call indicates the cycle cost of signing with schnorr,
    /// i.e., the management canister's `sign_with_schnorr` for the key
    /// (whose name is given by textual representation at heap location `src`
    /// with byte length `size`) and the provided algorithm.
    ///
    /// Traps if `src`/`size` exceeds the size of the WebAssembly memory.
    /// Returns 0 on success.
    /// Returns 1 if an unknown algorithm variant was provided.
    /// Returns 2 if the given algorithm variant does not have a key with the
    /// name provided via `src`/`size`.
    ///
    /// The amount of cycles is represented by a 128-bit value and is copied
    /// to the canister memory starting at the location `dst` if the return
    /// value is 0.
    fn ic0_cost_sign_with_schnorr(
        &self,
        src: usize,
        size: usize,
        algorithm: u32,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<u32>;

    /// This system call indicates the cycle cost of vetkd key derivation,
    /// i.e., the management canister's `vetkd_derive_key` for the key
    /// (whose name is given by textual representation at heap location `src`
    /// with byte length `size`) and the provided curve.
    ///
    /// Traps if `src`/`size` exceeds the size of the WebAssembly memory.
    /// Returns 0 on success.
    /// Returns 1 if an unknown curve variant was provided.
    /// Returns 2 if the given curve variant does not have a key with the
    /// name provided via `src`/`size`.
    ///
    /// The amount of cycles is represented by a 128-bit value and is copied
    /// to the canister memory starting at the location `dst` if the return
    /// value is 0.
    fn ic0_cost_vetkd_derive_key(
        &self,
        src: usize,
        size: usize,
        curve: u32,
        dst: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<u32>;

    /// Used to look up the size of the subnet Id of the calling canister.
    fn ic0_subnet_self_size(&self) -> HypervisorResult<usize>;

    /// Used to copy the subnet Id of the calling canister to its heap
    /// at the location specified by `dst` and `offset`.
    fn ic0_subnet_self_copy(
        &self,
        dst: usize,
        offset: usize,
        size: usize,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]

/// Indicate whether a checkpoint will be taken after the current round or not.
pub enum ExecutionRoundType {
    CheckpointRound,
    OrdinaryRound,
}

/// Execution round properties collected form the last DKG summary block.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ExecutionRoundSummary {
    /// The next checkpoint round height.
    ///
    /// In a case of a subnet recovery, the DSM will observe an instant
    /// jump for the `batch_number` and `next_checkpoint_height` values.
    /// The `next_checkpoint_height`, if set, should be always greater
    /// than the `batch_number`.
    pub next_checkpoint_round: ExecutionRound,
    /// The current checkpoint interval length.
    ///
    /// The DKG interval length is normally 499 rounds (199 for system subnets).
    pub current_interval_length: ExecutionRound,
}

/// Configuration of execution that comes from the registry.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct RegistryExecutionSettings {
    pub max_number_of_canisters: u64,
    pub provisional_whitelist: ProvisionalWhitelist,
    pub chain_key_settings: BTreeMap<MasterPublicKeyId, ChainKeySettings>,
    pub subnet_size: usize,
    pub node_ids: BTreeSet<NodeId>,
    pub registry_version: RegistryVersion,
    pub canister_cycles_cost_schedule: CanisterCyclesCostSchedule,
}

/// Chain key configuration of execution that comes from the registry.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ChainKeySettings {
    pub max_queue_size: u32,
    pub pre_signatures_to_create_in_advance: u32,
}

pub trait Scheduler: Send {
    /// Type modelling the replicated state.
    ///
    /// Should typically be
    /// `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Executes a list of messages. Triggered by the Coordinator as part of
    /// processing a batch.
    ///
    /// # Configuration parameters that might affect a round's execution
    ///
    /// * `scheduler_cores`: number of concurrent threads that the scheduler can
    ///   use during an execution round.
    /// * `max_instructions_per_round`: max number of instructions a single
    ///   round on a single thread can
    ///   consume.
    /// * `max_instructions_per_message`: max number of instructions a single
    ///   message execution can consume.
    ///
    /// # Walkthrough of a round
    ///
    /// The scheduler decides on a deterministic and fair order of canisters to
    /// execute on each thread (not fully implemented yet).
    /// For each thread we want to schedule **at least** a `pulse` for the first
    /// canister. The canister's `pulse` can consume the entire round of the
    /// thread if it has enough messages or, if not, we can give a `pulse` to
    /// the next canister. Similarly, the second canister can use the rest
    /// of the round of the thread if it has enough messages or we can give
    /// a `pulse` to the next canister and so on.
    ///
    /// # Constraints
    ///
    /// * To be able to start a pulse for a canister we need to have at least
    ///   `max_instructions_per_message` left in the current round (basically we
    ///   need a guarantee that we are able to execute successfully at least one
    ///   message).
    /// * The round (and thus the first `pulse`) starts with a limit of
    ///   `max_instructions_per_round`. When the `pulse` ends it returns how
    ///   many instructions is left which is used to update the limit for the
    ///   next `pulse` and if the above constraint is satisfied, we can start
    ///   the `pulse`. And so on.
    /// * Deterministic time slicing puts additional constraints on the states.
    ///   Normally states form a chain, where the result of one execution
    ///   becomes the input of the subsequent execution. The chain may break due
    ///   to state sync, which starts a new execution chain. The function
    ///   assumes that the old chain will be completely abandoned and the
    ///   function will never be called on the old chain.
    #[allow(clippy::too_many_arguments)]
    fn execute_round(
        &self,
        state: Self::State,
        randomness: Randomness,
        chain_key_data: ChainKeyData,
        replica_version: &ReplicaVersion,
        current_round: ExecutionRound,
        round_summary: Option<ExecutionRoundSummary>,
        current_round_type: ExecutionRoundType,
        registry_settings: &RegistryExecutionSettings,
    ) -> Self::State;
}

/// Combination of memory used by and reserved for guaranteed response messages
/// and memory used by best-effort messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MessageMemoryUsage {
    /// Memory used by and reserved for guaranteed response canister messages, in
    /// bytes.
    pub guaranteed_response: NumBytes,

    /// Memory used by best-effort canister messages, in bytes.
    pub best_effort: NumBytes,
}

impl MessageMemoryUsage {
    pub const ZERO: MessageMemoryUsage = MessageMemoryUsage {
        guaranteed_response: NumBytes::new(0),
        best_effort: NumBytes::new(0),
    };

    /// Returns the total memory used by all canister messages (guaranteed response
    /// or best-effort).
    pub fn total(&self) -> NumBytes {
        self.guaranteed_response + self.best_effort
    }

    /// Calculates `self` + `rhs`.
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether an
    /// arithmetic overflow would occur on either field. If an overflow would have
    /// occurred then the wrapped value is returned.
    pub fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        let (guaranteed_response, overflow1) = self
            .guaranteed_response
            .get()
            .overflowing_add(rhs.guaranteed_response.get());
        let (best_effort, overflow2) = self
            .best_effort
            .get()
            .overflowing_add(rhs.best_effort.get());
        (
            Self {
                guaranteed_response: guaranteed_response.into(),
                best_effort: best_effort.into(),
            },
            overflow1 || overflow2,
        )
    }

    /// Returns `true` iff both fields of `self` are greater than or equal to the
    /// corresponding fields of `rhs`.
    pub fn ge(&self, rhs: Self) -> bool {
        self.guaranteed_response >= rhs.guaranteed_response && self.best_effort >= rhs.best_effort
    }
}

impl AddAssign<MessageMemoryUsage> for MessageMemoryUsage {
    fn add_assign(&mut self, rhs: MessageMemoryUsage) {
        self.guaranteed_response += rhs.guaranteed_response;
        self.best_effort += rhs.best_effort;
    }
}

impl SubAssign<MessageMemoryUsage> for MessageMemoryUsage {
    fn sub_assign(&mut self, rhs: MessageMemoryUsage) {
        self.guaranteed_response -= rhs.guaranteed_response;
        self.best_effort -= rhs.best_effort;
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct WasmExecutionOutput {
    pub wasm_result: Result<Option<WasmResult>, HypervisorError>,
    pub num_instructions_left: NumInstructions,
    pub allocated_bytes: NumBytes,
    pub allocated_guaranteed_response_message_bytes: NumBytes,
    pub new_memory_usage: Option<NumBytes>,
    pub new_message_memory_usage: Option<MessageMemoryUsage>,
    pub instance_stats: InstanceStats,
    /// How many times each tracked System API call was invoked.
    pub system_api_call_counters: SystemApiCallCounters,
}

impl fmt::Display for WasmExecutionOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wasm_result_str = match &self.wasm_result {
            Ok(result) => match result {
                None => "None".to_string(),
                Some(wasm_result) => format!("{wasm_result}"),
            },
            Err(err) => format!("{err}"),
        };
        write!(
            f,
            "wasm_result => [{}], instructions left => {}, instance_stats => [ accessed pages => {}, dirty pages => {}]",
            wasm_result_str,
            self.num_instructions_left,
            self.instance_stats.wasm_accessed_pages + self.instance_stats.stable_accessed_pages,
            self.instance_stats.wasm_dirty_pages + self.instance_stats.stable_dirty_pages,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_memory() {
        let available = SubnetAvailableMemory::new_for_testing(20, 10, 4);
        assert_eq!(available.get_execution_memory(), 20);
        assert_eq!(available.get_guaranteed_response_message_memory(), 10);
        assert_eq!(available.get_wasm_custom_sections_memory(), 4);

        let available = SubnetAvailableMemory::new_scaled(20, 10, 4, 2);
        assert_eq!(available.get_execution_memory(), 10);
        assert_eq!(available.get_guaranteed_response_message_memory(), 5);
        assert_eq!(available.get_wasm_custom_sections_memory(), 2);
    }

    #[test]
    fn test_subnet_available_memory() {
        let mut available: SubnetAvailableMemory =
            SubnetAvailableMemory::new_for_testing(1 << 30, (1 << 30) - 5, 1 << 20);
        assert!(
            available
                .try_decrement(NumBytes::from(10), NumBytes::from(5), NumBytes::from(5))
                .is_ok()
        );
        assert!(
            available
                .try_decrement(
                    NumBytes::from((1 << 30) - 10),
                    NumBytes::from((1 << 30) - 10),
                    NumBytes::from(0),
                )
                .is_ok()
        );
        assert!(
            available
                .try_decrement(NumBytes::from(1), NumBytes::from(1), NumBytes::from(1))
                .is_err()
        );
        assert!(
            available
                .try_decrement(NumBytes::from(1), NumBytes::from(0), NumBytes::from(0))
                .is_err()
        );

        let mut available: SubnetAvailableMemory =
            SubnetAvailableMemory::new_for_testing(1 << 30, (1 << 30) - 5, 1 << 20);
        assert!(
            available
                .try_decrement(NumBytes::from(10), NumBytes::from(5), NumBytes::from(5))
                .is_ok()
        );
        assert!(
            available
                .try_decrement(
                    NumBytes::from((1 << 20) - 5),
                    NumBytes::from(0),
                    NumBytes::from((1 << 20) - 5),
                )
                .is_ok()
        );
        assert!(
            available
                .try_decrement(NumBytes::from(1), NumBytes::from(1), NumBytes::from(1))
                .is_err()
        );
        assert!(
            available
                .try_decrement(NumBytes::from(1), NumBytes::from(0), NumBytes::from(0))
                .is_ok()
        );

        let mut available: SubnetAvailableMemory =
            SubnetAvailableMemory::new_for_testing(1 << 30, -1, -1);
        assert!(
            available
                .try_decrement(NumBytes::from(1), NumBytes::from(1), NumBytes::from(1))
                .is_err()
        );
        assert!(
            available
                .try_decrement(NumBytes::from(10), NumBytes::from(0), NumBytes::from(0))
                .is_ok()
        );
        assert!(
            available
                .try_decrement(
                    NumBytes::from((1 << 30) - 10),
                    NumBytes::from(0),
                    NumBytes::from(0)
                )
                .is_ok()
        );
        assert!(
            available
                .try_decrement(NumBytes::from(1), NumBytes::from(0), NumBytes::from(0))
                .is_err()
        );

        assert!(
            available
                .try_decrement(
                    NumBytes::from(u64::MAX),
                    NumBytes::from(0),
                    NumBytes::from(0)
                )
                .is_err()
        );
        assert!(
            available
                .try_decrement(
                    NumBytes::from(u64::MAX),
                    NumBytes::from(u64::MAX),
                    NumBytes::from(u64::MAX)
                )
                .is_err()
        );
        assert!(
            available
                .try_decrement(
                    NumBytes::from(i64::MAX as u64 + 1),
                    NumBytes::from(0),
                    NumBytes::from(0)
                )
                .is_err()
        );
        assert!(
            available
                .try_decrement(
                    NumBytes::from(i64::MAX as u64 + 1),
                    NumBytes::from(i64::MAX as u64 + 1),
                    NumBytes::from(i64::MAX as u64 + 1),
                )
                .is_err()
        );

        let mut available = SubnetAvailableMemory::new_for_testing(44, 45, 30);
        assert_eq!(available.get_execution_memory(), 44);
        assert_eq!(available.get_guaranteed_response_message_memory(), 45);
        assert_eq!(available.get_wasm_custom_sections_memory(), 30);
        available.increment(NumBytes::from(1), NumBytes::from(2), NumBytes::from(3));
        assert_eq!(available.get_execution_memory(), 45);
        assert_eq!(available.get_guaranteed_response_message_memory(), 47);
        assert_eq!(available.get_wasm_custom_sections_memory(), 33);
    }
}
