use ic_base_types::NumBytes;
use ic_interfaces::execution_environment::HypervisorResult;
use ic_replicated_state::{
    canister_state::system_state::CanisterStatus, StableMemoryError, StateError,
};
use ic_types::{
    messages::{CallContextId, CallbackId, Request},
    methods::Callback,
    CanisterId, ComputeAllocation, Cycles, PrincipalId,
};

/// The abstract interface through which canister user code can
/// affect the canister system state. This layer is a slightly higher
/// level of abstraction than "raw" system call code -- it is assumed
/// that system call code has already resolved/demarshalled raw syscall
/// arguments.
pub trait SystemStateAccessor {
    /// Obtains the canister ID.
    fn canister_id(&self) -> CanisterId;

    /// Obtains the controller of this canister.
    fn controller(&self) -> PrincipalId;

    /// Increases the balance of the canister by `amount`
    fn mint_cycles(&self, amount: Cycles) -> HypervisorResult<()>;

    /// Accepts cycles from given call context.
    fn msg_cycles_accept(&self, call_context_id: &CallContextId, max_amount: Cycles) -> Cycles;

    /// Determines cycles given in call context.
    fn msg_cycles_available(&self, call_context_id: &CallContextId) -> HypervisorResult<Cycles>;

    /// Determines size of stable memory in Web assembly pages.
    fn stable_size(&self) -> u32;

    /// Grows stable memory by specified amount.
    fn stable_grow(&self, additional_pages: u32) -> i32;

    /// Reads from stable memory back to heap.
    fn stable_read(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> Result<(), StableMemoryError>;

    /// Writes from heap to stable memory.
    fn stable_write(
        &self,
        offset: u32,
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> Result<(), StableMemoryError>;

    /// Current cycles balance of the canister.
    fn canister_cycles_balance(&self) -> Cycles;

    /// Withdraws cycles from canister's balance.
    fn canister_cycles_withdraw(
        &self,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
        amount: Cycles,
    ) -> HypervisorResult<()>;

    /// (Re-)add cycles to canister. This is intended to be used to
    /// reclaim cycles from unfulfilled requests.
    fn canister_cycles_refund(&self, cycles: Cycles);

    /// Set certified data.
    fn set_certified_data(&self, data: Vec<u8>);

    /// Registers callback for call return.
    fn register_callback(&self, callback: Callback) -> CallbackId;

    /// Unregister callback for call return.
    fn unregister_callback(&self, callback_id: CallbackId) -> Option<Callback>;

    /// Pushes outgoing request.
    fn push_output_request(
        &self,
        canister_current_memory_usage: NumBytes,
        canister_compute_allocation: ComputeAllocation,
        msg: Request,
    ) -> Result<(), (StateError, Request)>;

    /// Current status of canister.
    fn canister_status(&self) -> CanisterStatus;
}
