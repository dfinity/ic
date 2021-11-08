use ic_cycles_account_manager::{CyclesAccountManager, CyclesAccountManagerError};
use ic_interfaces::execution_environment::{
    HypervisorError, HypervisorResult,
    TrapCode::{HeapOutOfBounds, StableMemoryOutOfBounds, StableMemoryTooBigFor32Bit},
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::system_state::CanisterStatus, page_map, Memory, NumWasmPages64, StateError,
    SystemState,
};
use ic_types::{
    messages::{CallContextId, CallbackId, Request},
    methods::Callback,
    CanisterId, ComputeAllocation, Cycles, NumInstructions, PrincipalId,
    MAX_STABLE_MEMORY_IN_BYTES,
};
use std::ops::DerefMut;
use std::{cell::RefCell, convert::TryInto, sync::Arc};

use crate::system_state_accessor::SystemStateAccessor;
use ic_base_types::NumBytes;

const WASM_PAGE_SIZE_IN_BYTES: u64 = 64 * 1024;
const MAX_64_BIT_STABLE_MEMORY_IN_PAGES: u64 = MAX_STABLE_MEMORY_IN_BYTES / WASM_PAGE_SIZE_IN_BYTES;
const MAX_32_BIT_STABLE_MEMORY_IN_PAGES: u64 = if 64 * 1024 < MAX_64_BIT_STABLE_MEMORY_IN_PAGES {
    64 * 1024 // 4GiB
} else {
    MAX_64_BIT_STABLE_MEMORY_IN_PAGES
};

// Number of bytes that can be copied from/to canister's heap with one
// instruction.
const BYTES_PER_INSTRUCTION: NumBytes = NumBytes::new(1);

#[doc(hidden)]
pub struct SystemStateAccessorDirect {
    system_state: RefCell<SystemState>,
    cycles_account_manager: Arc<CyclesAccountManager>,
    /// We could update the PageMap stored in the system state directly, but it
    /// will be not efficient if the canister issues many write requests to
    /// nearby memory locations, which is a common case (serializing Candid
    /// directly to stable memory, for example).  Using a long-lived buffer
    /// allows us to allocate a dirty page once and modify it in-place in
    /// subsequent calls.
    stable_memory_buffer: RefCell<page_map::Buffer>,
    stable_memory_size: RefCell<NumWasmPages64>,
}

impl SystemStateAccessorDirect {
    pub fn new(
        system_state: SystemState,
        cycles_account_manager: Arc<CyclesAccountManager>,
        stable_memory: &Memory<NumWasmPages64>,
    ) -> Self {
        Self {
            cycles_account_manager: Arc::clone(&cycles_account_manager),
            system_state: RefCell::new(system_state),
            stable_memory_buffer: RefCell::new(page_map::Buffer::new(
                stable_memory.page_map.clone(),
            )),
            stable_memory_size: RefCell::new(stable_memory.size),
        }
    }

    /// Drop the `SystemStateAccessorDirect` and get out it's resulting
    /// `SystemState` and stable memory.
    pub fn release_system_state(self) -> (SystemState, Memory<NumWasmPages64>) {
        (
            self.system_state.into_inner(),
            Memory::new(
                self.stable_memory_buffer.into_inner().into_page_map(),
                self.stable_memory_size.into_inner(),
            ),
        )
    }
}

impl SystemStateAccessor for SystemStateAccessorDirect {
    fn canister_id(&self) -> CanisterId {
        self.system_state.borrow().canister_id()
    }

    fn controller(&self) -> PrincipalId {
        *self.system_state.borrow().controller()
    }

    fn get_num_instructions_from_bytes(&self, num_bytes: NumBytes) -> NumInstructions {
        match self.cycles_account_manager.subnet_type() {
            SubnetType::System => NumInstructions::from(0),
            SubnetType::Application | SubnetType::VerifiedApplication => {
                NumInstructions::from(num_bytes / BYTES_PER_INSTRUCTION)
            }
        }
    }

    fn mint_cycles(&self, amount_to_mint: Cycles) -> HypervisorResult<()> {
        let mut system_state = self.system_state.borrow_mut();
        self.cycles_account_manager
            .mint_cycles(&mut system_state, amount_to_mint)
            .map_err(|CyclesAccountManagerError::ContractViolation(msg)| {
                HypervisorError::ContractViolation(msg)
            })
    }

    fn msg_cycles_accept(
        &self,
        call_context_id: &CallContextId,
        amount_to_accept: Cycles,
    ) -> Cycles {
        let mut system_state = self.system_state.borrow_mut();

        // Scale amount that can be accepted by CYCLES_LIMIT_PER_CANISTER.
        let amount_to_accept = self
            .cycles_account_manager
            .check_max_cycles_can_add(system_state.cycles_balance, amount_to_accept);

        // Scale amount that can be accepted by what is actually available on
        // the call context.
        let call_context_manager = system_state.call_context_manager_mut().unwrap();
        let call_context = call_context_manager
            .call_context_mut(*call_context_id)
            .unwrap();
        let amount_available = call_context.available_cycles();
        let amount_to_accept = std::cmp::min(amount_available, amount_to_accept);

        // Withdraw and accept the cycles
        call_context.withdraw_cycles(amount_to_accept).unwrap();
        self.cycles_account_manager
            .add_cycles(&mut system_state, amount_to_accept);
        amount_to_accept
    }

    fn msg_cycles_available(&self, call_context_id: &CallContextId) -> HypervisorResult<Cycles> {
        let system_state = self.system_state.borrow();
        // A call context manager exists as the canister is either in
        // `Running` or `Stopping` status when executing a message so
        // this unwrap should be safe.
        let call_context_manager = system_state.call_context_manager().unwrap();
        // A call context with `call_context_id` should already exist (it was created
        // when the original message was received).
        let call_context = call_context_manager.call_context(*call_context_id).unwrap();
        Ok(call_context.available_cycles())
    }

    fn stable_size(&self) -> HypervisorResult<u32> {
        let size = self.stable_memory_size.borrow().get();
        if size > MAX_32_BIT_STABLE_MEMORY_IN_PAGES {
            return Err(HypervisorError::Trapped(StableMemoryTooBigFor32Bit));
        }

        // Safe as we confirmed above the value is small enough to fit into 32-bits.
        Ok(size.try_into().unwrap())
    }

    fn stable_grow(&self, additional_pages: u32) -> HypervisorResult<i32> {
        let initial_page_count = self.stable_size()? as u64;
        let additional_pages = additional_pages as u64;

        if additional_pages + initial_page_count > MAX_32_BIT_STABLE_MEMORY_IN_PAGES {
            return Ok(-1);
        }

        *self.stable_memory_size.borrow_mut() =
            NumWasmPages64::from(initial_page_count + additional_pages);

        Ok(initial_page_count
            .try_into()
            .expect("could not fit initial page count in 32 bits, although 32-bit api is used"))
    }

    fn stable_read(
        &self,
        dst: u32,
        offset: u32,
        size: u32,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let (dst, offset, size) = (dst as usize, offset as usize, size as usize);

        if offset + size > (self.stable_size()? as usize * WASM_PAGE_SIZE_IN_BYTES as usize) {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        if dst + size > heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }
        self.stable_memory_buffer
            .borrow()
            .read(&mut heap[dst..dst + size], offset);
        Ok(())
    }

    fn stable_write(&self, offset: u32, src: u32, size: u32, heap: &[u8]) -> HypervisorResult<()> {
        let (src, offset, size) = (src as usize, offset as usize, size as usize);

        if offset + size > (self.stable_size()? as usize * WASM_PAGE_SIZE_IN_BYTES as usize) {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        if src + size > heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }

        self.stable_memory_buffer
            .borrow_mut()
            .write(&heap[src..src + size], offset);
        Ok(())
    }

    fn stable64_size(&self) -> HypervisorResult<u64> {
        Ok(self.stable_memory_size.borrow().get())
    }

    fn stable64_grow(&self, additional_pages: u64) -> HypervisorResult<i64> {
        let initial_page_count = self.stable64_size()?;

        let (page_count, overflow) = additional_pages.overflowing_add(initial_page_count);
        if overflow || page_count > MAX_64_BIT_STABLE_MEMORY_IN_PAGES {
            return Ok(-1);
        }

        *self.stable_memory_size.borrow_mut() =
            NumWasmPages64::from(initial_page_count + additional_pages);

        Ok(initial_page_count as i64)
    }

    fn stable64_read(
        &self,
        dst: u64,
        offset: u64,
        size: u64,
        heap: &mut [u8],
    ) -> HypervisorResult<()> {
        let (dst, offset, size) = (dst as usize, offset as usize, size as usize);

        let (stable_memory_size_in_bytes, overflow) = self
            .stable64_size()?
            .overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
        if overflow {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (stable_memory_end, overflow) = offset.overflowing_add(size);
        if overflow || stable_memory_end > stable_memory_size_in_bytes as usize {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (heap_end, overflow) = dst.overflowing_add(size);
        if overflow || heap_end > heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }
        self.stable_memory_buffer
            .borrow()
            .read(&mut heap[dst..heap_end], offset);
        Ok(())
    }

    fn stable64_write(
        &self,
        offset: u64,
        src: u64,
        size: u64,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let (src, offset, size) = (src as usize, offset as usize, size as usize);

        let (stable_memory_size_in_bytes, overflow) = self
            .stable64_size()?
            .overflowing_mul(WASM_PAGE_SIZE_IN_BYTES);
        if overflow {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (stable_memory_end, overflow) = offset.overflowing_add(size);
        if overflow || stable_memory_end > stable_memory_size_in_bytes as usize {
            return Err(HypervisorError::Trapped(StableMemoryOutOfBounds));
        }

        let (heap_end, overflow) = src.overflowing_add(size);
        if overflow || heap_end > heap.len() {
            return Err(HypervisorError::Trapped(HeapOutOfBounds));
        }

        self.stable_memory_buffer
            .borrow_mut()
            .write(&heap[src..heap_end], offset);
        Ok(())
    }

    fn canister_cycles_balance(&self) -> Cycles {
        self.system_state.borrow().cycles_balance
    }

    fn canister_cycles_withdraw(
        &self,
        canister_current_memory_usage: NumBytes,
        compute_allocation: ComputeAllocation,
        amount: Cycles,
    ) -> HypervisorResult<()> {
        let mut system_state = self.system_state.borrow_mut();
        self.cycles_account_manager
            .withdraw_cycles_for_transfer(
                &mut system_state,
                canister_current_memory_usage,
                compute_allocation,
                amount,
            )
            .map_err(HypervisorError::InsufficientCyclesBalance)?;
        Ok(())
    }

    fn canister_cycles_refund(&self, cycles: Cycles) {
        self.cycles_account_manager
            .add_cycles(&mut self.system_state.borrow_mut(), cycles);
    }

    fn set_certified_data(&self, data: Vec<u8>) {
        self.system_state.borrow_mut().certified_data = data;
    }

    fn register_callback(&self, callback: Callback) -> CallbackId {
        let mut system_state = self.system_state.borrow_mut();
        // A call context manager exists as the canister is either in
        // `Running` or `Stopping` status when executing a message so
        // this unwrap should be safe.
        let call_context_manager = system_state.call_context_manager_mut().unwrap();
        call_context_manager.register_callback(callback)
    }

    fn unregister_callback(&self, callback_id: CallbackId) -> Option<Callback> {
        let mut system_state = self.system_state.borrow_mut();
        // A call context manager exists as the canister is either in
        // `Running` or `Stopping` status when executing a message so
        // this unwrap should be safe.
        let call_context_manager = system_state.call_context_manager_mut().unwrap();
        call_context_manager.unregister_callback(callback_id)
    }

    fn push_output_request(
        &self,
        canister_current_memory_usage: NumBytes,
        compute_allocation: ComputeAllocation,
        msg: Request,
    ) -> Result<(), (StateError, Request)> {
        if let Err(err) = self.cycles_account_manager.withdraw_request_cycles(
            self.system_state.borrow_mut().deref_mut(),
            canister_current_memory_usage,
            compute_allocation,
            &msg,
        ) {
            return Err((StateError::CanisterOutOfCycles(err), msg));
        }
        self.system_state.borrow_mut().push_output_request(msg)
    }

    fn canister_status(&self) -> CanisterStatus {
        self.system_state.borrow().status.clone()
    }
}
