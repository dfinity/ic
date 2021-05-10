//! The execution environment public interface.
mod errors;

use crate::{messages::CanisterInputMessage, state_manager::StateManagerError};
pub use errors::{CanisterHeartbeatError, MessageAcceptanceError};
pub use errors::{HypervisorError, TrapCode};
use ic_base_types::{NumBytes, SubnetId};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    ingress::{IngressStatus, WasmResult},
    messages::{MessageId, SignedIngressContent, UserQuery},
    user_error::UserError,
    Height, NumInstructions, Time,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

/// Instance execution statistics. The stats are cumulative and
/// contain measurements from the point in time when the instance was
/// created up until the moment they are requested.
#[derive(Serialize, Deserialize, Clone)]
pub struct InstanceStats {
    /// Total number of (host) pages accessed (read or written) by the instance
    /// and loaded into the linear memory.
    pub accessed_pages: usize,

    /// Total number of (host) pages modified by the instance.
    /// By definition a page that has been dirtied has also been accessed,
    /// hence this dirtied_pages <= accessed_pages
    pub dirty_pages: usize,
}

/// Errors that can be returned when fetching the available memory on a subnet.
pub enum SubnetAvailableMemoryError {
    InsufficientMemory {
        requested: NumBytes,
        available: NumBytes,
    },
}

/// This struct is used to manage the view of the current amount of memory
/// available on the subnet between multiple canisters executing in parallel.
///
/// The problem is that when canisters with no memory reservations want to
/// expand their memory consumption, we need to ensure that they do not go over
/// subnet's capacity. As we execute canisters in parallel, we need to
/// provide them with a way to view the latest state of memory availble in a
/// thread safe way. Hence, we use `Arc<RwLock<>>` here.
#[derive(Serialize, Deserialize, Clone)]
pub struct SubnetAvailableMemory(Arc<RwLock<NumBytes>>);

impl SubnetAvailableMemory {
    pub fn new(amount: NumBytes) -> Self {
        Self(Arc::new(RwLock::new(amount)))
    }

    /// Try to use some memory capacity and fail if not enough is available
    pub fn try_decrement(&self, requested: NumBytes) -> Result<(), SubnetAvailableMemoryError> {
        let mut available = self.0.write().unwrap();
        if requested <= *available {
            *available -= requested;
            Ok(())
        } else {
            Err(SubnetAvailableMemoryError::InsufficientMemory {
                requested,
                available: *available,
            })
        }
    }
}

/// ExecutionEnvironment is the component responsible for executing messages
/// on the IC.
pub trait ExecutionEnvironment: Sync + Send {
    /// Type modelling the replicated state.
    ///
    /// Should typically be
    /// `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Type modelling the canister state.
    ///
    /// Should typically be
    /// `ic_replicated_state::CanisterState`.
    // Note [Associated Types in Interfaces]
    type CanisterState;

    /// Executes a message sent to a subnet.
    //
    // A deterministic cryptographically secure pseudo-random number generator
    // is created per round and per thread and passed to this method to be used
    // while responding to randomness requests (i.e. raw_rand). Using the type
    // "&mut RngCore" imposes a problem with our usage of "mockall" library in
    // the test_utilities. Mockall's doc states: "The only restrictions on
    // mocking generic methods are that all generic parameters must be 'static,
    // and generic lifetime parameters are not allowed." Hence, the type of the
    // parameter is "&mut (dyn RngCore + 'static)".
    #[allow(clippy::too_many_arguments)]
    fn execute_subnet_message(
        &self,
        msg: CanisterInputMessage,
        state: Self::State,
        instructions_limit: NumInstructions,
        rng: &mut (dyn RngCore + 'static),
        provisional_whitelist: &ProvisionalWhitelist,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> Self::State;

    /// Executes a message sent to a canister.
    #[allow(clippy::too_many_arguments)]
    fn execute_canister_message(
        &self,
        canister_state: Self::CanisterState,
        instructions_limit: NumInstructions,
        msg: CanisterInputMessage,
        time: Time,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<ExecuteMessageResult<Self::CanisterState>>;

    /// Asks the canister if it is willing to accept the provided ingress
    /// message.
    fn should_accept_ingress_message(
        &self,
        state: Arc<Self::State>,
        provisional_whitelist: &ProvisionalWhitelist,
        ingress: &SignedIngressContent,
    ) -> Result<(), MessageAcceptanceError>;

    /// Executes a heartbeat of a given canister.
    fn execute_canister_heartbeat(
        &self,
        canister_state: Self::CanisterState,
        instructions_limit: NumInstructions,
        routing_table: Arc<RoutingTable>,
        subnet_records: Arc<BTreeMap<SubnetId, SubnetType>>,
        time: Time,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> ExecResult<(
        Self::CanisterState,
        NumInstructions,
        Result<NumBytes, CanisterHeartbeatError>,
    )>;

    /// Look up the current amount of memory available on the subnet.
    /// EXC-185 will make this method obsolete.
    fn subnet_available_memory(&self, state: &Self::State) -> NumBytes;
}

/// The data structure returned by
/// `ExecutionEnvironment.execute_canister_message()`.
pub struct ExecuteMessageResult<CanisterState> {
    /// The `CanisterState` after message execution
    pub canister: CanisterState,
    /// The amount of instructions left after message execution. This must be <=
    /// to the instructions_limit that `execute_canister_message()` was called
    /// with.
    pub num_instructions_left: NumInstructions,
    /// Optional status for an Ingress message if available.
    pub ingress_status: Option<(MessageId, IngressStatus)>,
    /// The size of the heap delta the canister produced
    pub heap_delta: NumBytes,
}

/// An underlying struct/helper for implementing select() on multiple
/// AsyncResult<T>'s. If an AsyncResult is really an ongoing computation, we
/// have to obtain its result from a channel. However, some AsyncResults are of
/// type EarlyResult, which only emulates being async, but in reality is a ready
/// value (mostly used for early errors). In such case, there is no channel
/// present and we can simply return the value without waiting.
pub enum TrySelect<T> {
    EarlyResult(T),
    // These Box<Any>'s are here only to hide internal data types from the interfaces crate.
    // These are known types (crossbeam channnel, WasmExecutionOutput),
    // and if we restructure our dependency tree we may put the real types here.
    Channel(
        Box<dyn std::any::Any + 'static>,
        Box<dyn FnOnce(Box<dyn std::any::Any + 'static>) -> T>,
    ),
}

/// An execution can finish successfully or get interrupted (out of cycles).
pub enum ExecResultVariant<T> {
    Completed(T),
    Interrupted(Box<dyn InterruptedExec<T>>),
}

// Most likely these traits can be moved to embedders crate if we restructure
// ExecutionEnvironment a little.

/// An async result which allows for sync wait and select.
pub trait AsyncResult<T> {
    fn get(self: Box<Self>) -> ExecResultVariant<T>;
    fn try_select(self: Box<Self>) -> TrySelect<T>;
}

/// Interrupted execution. Can be resumed or canceled.
pub trait InterruptedExec<T> {
    fn resume(self: Box<Self>, cycles_topup: NumInstructions) -> ExecResult<T>;
    fn cancel(self: Box<Self>) -> ExecResult<T>;
}

impl<A: 'static> dyn InterruptedExec<A> {
    /// Add post-processing on the output received after resume/cancel.
    pub fn and_then<B: 'static, F: 'static + FnOnce(A) -> B>(
        self: Box<Self>,
        f: F,
    ) -> Box<dyn InterruptedExec<B>> {
        Box::new(ResumeTokenWrapper {
            resume_token: self,
            f,
        })
    }
}

// A wrapper which allows for post processing of the ExecResult returned by
// original resume/cancel.
struct ResumeTokenWrapper<A, B, F: FnOnce(A) -> B> {
    resume_token: Box<dyn InterruptedExec<A>>,
    f: F,
}

impl<A, B, F> InterruptedExec<B> for ResumeTokenWrapper<A, B, F>
where
    A: 'static,
    B: 'static,
    F: 'static + FnOnce(A) -> B,
{
    fn resume(self: Box<Self>, cycles_topup: NumInstructions) -> ExecResult<B> {
        self.resume_token.resume(cycles_topup).and_then(self.f)
    }

    fn cancel(self: Box<Self>) -> ExecResult<B> {
        self.resume_token.cancel().and_then(self.f)
    }
}

/// Generic async result of an execution.
pub struct ExecResult<T> {
    result: Box<dyn AsyncResult<T>>,
}

impl<T> ExecResult<T> {
    pub fn new(result: Box<dyn AsyncResult<T>>) -> Self {
        Self { result }
    }

    /// Wait for the result
    pub fn get(self) -> ExecResultVariant<T> {
        self.result.get()
    }

    /// Wait for the final result without allowing for a pause.
    /// If pause occurs, the execution is automatically cancelled.
    pub fn get_no_pause(self) -> T {
        match self.result.get() {
            ExecResultVariant::Completed(x) => x,
            ExecResultVariant::Interrupted(resume_token) => {
                if let ExecResultVariant::Completed(x) = resume_token.cancel().get() {
                    x
                } else {
                    panic!("Unexpected response from execution cancel request");
                }
            }
        }
    }

    /// This function allows to extract an underlying channel to perform a
    /// select. It is used to implement 'ic_embedders::ExecSelect' and is
    /// not meant to be used explicitly.
    pub fn try_select(self) -> TrySelect<T> {
        self.result.try_select()
    }
}

impl<A: 'static> ExecResult<A> {
    /// Add post-processing on the result.
    pub fn and_then<B: 'static, F: 'static + FnOnce(A) -> B>(self, f: F) -> ExecResult<B> {
        ExecResult::new(Box::new(ExecResultWrapper { result: self, f }))
    }
}

// A wrapper which allows for post processing of the original ExecResult.
struct ExecResultWrapper<A, B, F: FnOnce(A) -> B> {
    result: ExecResult<A>,
    f: F,
}

impl<A, B, F> AsyncResult<B> for ExecResultWrapper<A, B, F>
where
    A: 'static,
    B: 'static,
    F: 'static + FnOnce(A) -> B,
{
    fn get(self: Box<Self>) -> ExecResultVariant<B> {
        match self.result.get() {
            ExecResultVariant::Completed(x) => ExecResultVariant::Completed((self.f)(x)),
            ExecResultVariant::Interrupted(resume_token) => {
                ExecResultVariant::Interrupted(resume_token.and_then(self.f))
            }
        }
    }

    fn try_select(self: Box<Self>) -> TrySelect<B> {
        let f = self.f;
        match self.result.try_select() {
            TrySelect::EarlyResult(res) => TrySelect::EarlyResult(f(res)),
            TrySelect::Channel(a, p) => TrySelect::Channel(a, Box::new(move |x| f(p(x)))),
        }
    }
}

/// Sync result implementing async interface.
pub struct EarlyResult<T> {
    result: T,
}

impl<T: 'static> EarlyResult<T> {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(result: T) -> ExecResult<T> {
        ExecResult {
            result: Box::new(Self { result }),
        }
    }
}

impl<T: 'static> AsyncResult<T> for EarlyResult<T> {
    fn get(self: Box<Self>) -> ExecResultVariant<T> {
        ExecResultVariant::Completed(self.result)
    }

    fn try_select(self: Box<Self>) -> TrySelect<T> {
        TrySelect::EarlyResult(self.result)
    }
}

pub type HypervisorResult<T> = Result<T, HypervisorError>;

/// Interface for the component to execute queries on canisters.  It can be used
/// by the HttpHandler and other system components to execute queries.
pub trait QueryHandler: Send + Sync {
    /// Type of state managed by StateReader.
    ///
    /// Should typically be `ic_replicated_state::ReplicatedState`.
    // Note [Associated Types in Interfaces]
    type State;

    /// Handle a query of type `UserQuery` which was sent by an end user.
    fn query(
        &self,
        q: UserQuery,
        processing_state: Arc<Self::State>,
        data_certificate: Vec<u8>,
    ) -> Result<WasmResult, UserError>;
}

/// Errors that can be returned when reading/writing from/to ingress history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressHistoryError {
    StateRemoved(Height),
    StateNotAvailableYet(Height),
}

impl From<StateManagerError> for IngressHistoryError {
    fn from(source: StateManagerError) -> Self {
        match source {
            StateManagerError::StateRemoved(height) => Self::StateRemoved(height),
            StateManagerError::StateNotCommittedYet(height) => Self::StateNotAvailableYet(height),
        }
    }
}

/// Interface for reading the history of ingress messages.
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

    /// Allows to set status on a message.
    ///
    /// The allowed status transitions are:
    /// * "None" -> {"Received", "Processing", "Completed", "Failed"}
    /// * "Received" -> {"Processing", "Completed", "Failed"}
    /// * "Processing" -> {"Processing", "Completed", "Failed"}
    fn set_status(&self, state: &mut Self::State, message_id: MessageId, status: IngressStatus);
}

/// A trait for providing all necessary imports to a Wasm module.
pub trait SystemApi {
    /// Stores the execution error, so that the user can evaluate it later.
    fn set_execution_error(&mut self, error: HypervisorError);

    /// Returns the reference to the execution error.
    fn get_execution_error(&self) -> Option<&HypervisorError>;

    /// Returns the amount of available instructions.
    fn get_available_num_instructions(&self) -> NumInstructions;

    /// Returns the stable memory delta that the canister produced
    fn get_stable_memory_delta_pages(&self) -> usize;

    /// Sets the amount of available instructions.
    fn set_available_num_instructions(&mut self, num_instructions: NumInstructions);

    /// Copies `size` bytes starting from `offset` inside the opaque caller blob
    /// and copies them to heap[dst..dst+size]. The caller is the canister
    /// id in case of requests or the user id in case of an ingress message.
    fn ic0_msg_caller_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the size of the opaque caller blob.
    fn ic0_msg_caller_size(&self) -> HypervisorResult<u32>;

    /// Returns the size of msg.payload.
    fn ic0_msg_arg_data_size(&self) -> HypervisorResult<u32>;

    /// Copies `length` bytes from msg.payload[offset..offset+size] to
    /// memory[dst..dst+size].
    fn ic0_msg_arg_data_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Used to look up the size of the method_name that the message wants to
    /// call. Can only be called in the context of inspecting messages.
    fn ic0_msg_method_name_size(&self) -> HypervisorResult<u32>;

    /// Used to copy the method_name that the message wants to call to heap. Can
    /// only be called in the context of inspecting messages.
    fn ic0_msg_method_name_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
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
        src: u32,
        size: u32,
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
    fn ic0_msg_reject(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()>;

    /// Returns the length of the reject message in bytes.
    ///
    /// # Panics
    ///
    /// This traps if not invoked from a reject callback.
    fn ic0_msg_reject_msg_size(&self) -> HypervisorResult<u32>;

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
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the size of the blob corresponding to the id of the canister.
    fn ic0_canister_self_size(&self) -> HypervisorResult<usize>;

    /// Copies `size` bytes starting from `offset` in the id blob of the
    /// canister to heap[dst..dst+size].
    fn ic0_canister_self_copy(
        &mut self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the size of the blob corresponding to the id of the controller.
    fn ic0_controller_size(&self) -> HypervisorResult<usize>;

    /// Copies `size` bytes starting from `offset` in the id blob of the
    /// controller to heap[dst..dst+size].
    fn ic0_controller_copy(
        &mut self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Outputs the specified bytes on the heap as a string on STDOUT.
    fn ic0_debug_print(&self, src: u32, size: u32, heap: &[u8]);

    /// Just like `exec` in C replaces the current process with a new process,
    /// this system call replaces the current canister with a new canister.
    fn ic0_exec(&mut self, bytes: Vec<u8>, payload: Vec<u8>) -> HypervisorError;

    /// Traps, with a possibly helpful message
    fn ic0_trap(&self, src: u32, size: u32, heap: &[u8]) -> HypervisorError;

    /// Creates a pending inter-canister message that will be scheduled if the
    /// current message execution completes successfully.
    #[allow(clippy::too_many_arguments)]
    fn ic0_call_simple(
        &mut self,
        callee_src: u32,
        callee_size: u32,
        method_name_src: u32,
        method_name_len: u32,
        reply_fun: u32,
        reply_env: u32,
        reject_fun: u32,
        reject_env: u32,
        data_src: u32,
        data_len: u32,
        heap: &[u8],
    ) -> HypervisorResult<i32>;

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
        callee_src: u32,
        callee_size: u32,
        name_src: u32,
        name_len: u32,
        reply_fun: u32,
        reply_env: u32,
        reject_fun: u32,
        reject_env: u32,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    /// Appends the specified bytes to the argument of the call. Initially, the
    /// argument is empty. This can be called multiple times between
    /// `ic0.call_new` and `ic0.call_perform`.
    fn ic0_call_data_append(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()>;

    /// Specifies the closure to be called if the reply/reject closures trap.
    /// Can be called at most once between `ic0.call_new` and
    /// `ic0.call_perform`.
    ///
    /// See https://sdk.dfinity.org/docs/interface-spec/index.html#system-api-call
    fn ic0_call_on_cleanup(&mut self, fun: u32, env: u32) -> HypervisorResult<()>;

    /// Adds cycles to a call by moving them from the canister's balance onto
    /// the call under construction. The cycles are deducted immediately
    /// from the canister's balance and moved back if the call cannot be
    /// performed (e.g. if `ic0.call_perform` signals an error or if the
    /// canister invokes `ic0.call_new` or returns without invoking
    /// `ic0.call_perform`).
    ///
    /// This traps if trying to transfer more cycles than are in the current
    /// balance of the canister.
    fn ic0_call_cycles_add(&mut self, amount: u64) -> HypervisorResult<()>;

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

    /// Returns the current size of the stable memory in WebAssembly pages.
    fn ic0_stable_size(&self) -> HypervisorResult<u32>;

    /// Tries to grow the stable memory by additional_pages many pages
    /// containing zeros.
    /// If successful, returns the previous size of the memory (in pages).
    /// Otherwise, returns -1
    fn ic0_stable_grow(&mut self, additional_pages: u32) -> HypervisorResult<i32>;

    /// Copies the data referred to by offset/size out of the stable memory and
    /// replaces the corresponding bytes starting at dst in the canister memory.
    ///
    /// This system call traps if dst+size exceeds the size of the WebAssembly
    /// memory or offset+size exceeds the size of the stable memory.
    fn ic0_stable_read(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Copies the data referred to by src/size out of the canister and replaces
    /// the corresponding segment starting at offset in the stable memory.
    ///
    /// This system call traps if src+size exceeds the size of the WebAssembly
    /// memory or offset+size exceeds the size of the stable memory.
    fn ic0_stable_write(
        &mut self,
        offset: u32,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> HypervisorResult<()>;

    fn ic0_time(&self) -> HypervisorResult<Time>;

    /// This system call is not part of the public spec and used by the
    /// hypervisor, when execution runs out of instructions. Higher levels
    /// can decide how to proceed, by either providing more instructions
    /// or aborting the execution (typically with an out-of-instructions
    /// error).
    fn out_of_instructions(&self) -> HypervisorResult<NumInstructions>;

    /// This system call is not part of the public spec. It's called after a
    /// native `memory.grow` has been called to check whether there's enough
    /// available memory left.
    fn update_available_memory(
        &mut self,
        native_memory_grow_res: i32,
        additional_pages: u32,
    ) -> HypervisorResult<i32>;

    /// Returns the current balance in cycles.
    fn ic0_canister_cycle_balance(&self) -> HypervisorResult<u64>;

    /// Cycles sent in the current call and still available.
    fn ic0_msg_cycles_available(&self) -> HypervisorResult<u64>;

    /// Cycles that came back with the response, as a refund.
    fn ic0_msg_cycles_refunded(&self) -> HypervisorResult<u64>;

    /// This moves cycles from the call to the canister balance.
    /// It can be called multiple times, each time adding more cycles to the
    /// balance.
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

    /// Sets the certified data for the canister.
    /// See: https://sdk.dfinity.org/docs/interface-spec/index.html#system-api-certified-data
    fn ic0_certified_data_set(&mut self, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()>;

    /// If run in non-replicated execution (i.e. query),
    /// returns 1 if the data certificate is present, 0 otherwise.
    /// If run in replicated execution (i.e. an update call or a certified
    /// query), returns 0.
    fn ic0_data_certificate_present(&self) -> HypervisorResult<i32>;

    /// Returns the size of the data certificate if it is present
    /// (i.e. data_certificate_present returns 1).
    /// Traps if data_certificate_present returns 0.
    fn ic0_data_certificate_size(&self) -> HypervisorResult<i32>;

    /// Copies the data certificate into the heap if it is present
    /// (i.e. data_certificate_present returns 1).
    /// Traps if data_certificate_present returns 0.
    fn ic0_data_certificate_copy(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()>;

    /// Returns the current status of the canister.  `1` indicates
    /// running, `2` indicates stopping, and `3` indicates stopped.
    fn ic0_canister_status(&self) -> HypervisorResult<u32>;

    /// Mints the `amount` cycles
    /// Adds cycles to the canister's balance.
    ///
    /// Adds no more cycles than `amount`.
    ///
    /// The canister balance afterwards does not exceed
    /// maximum amount of cycles it can hold.
    /// However, canisters on system subnets have no balance limit.
    ///
    /// Returns the amount of cycles added to the canister's balance.
    fn ic0_mint_cycles(&mut self, amount: u64) -> HypervisorResult<u64>;
}
