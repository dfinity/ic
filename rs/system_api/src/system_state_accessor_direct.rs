use ic_cycles_account_manager::{CyclesAccountManager, CyclesAccountManagerError};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_replicated_state::{StateError, SystemState};
use ic_types::{
    messages::{CallContextId, CallbackId, Request},
    methods::Callback,
    ComputeAllocation, Cycles,
};
use std::ops::DerefMut;
use std::{cell::RefCell, sync::Arc};

use crate::system_state_accessor::SystemStateAccessor;
use ic_base_types::NumBytes;

#[doc(hidden)]
pub struct SystemStateAccessorDirect {
    system_state: RefCell<SystemState>,
    cycles_account_manager: Arc<CyclesAccountManager>,
}

impl SystemStateAccessorDirect {
    pub fn new(
        system_state: SystemState,
        cycles_account_manager: Arc<CyclesAccountManager>,
    ) -> Self {
        Self {
            cycles_account_manager: Arc::clone(&cycles_account_manager),
            system_state: RefCell::new(system_state),
        }
    }

    /// Drop the `SystemStateAccessorDirect` and get out it's resulting
    /// `SystemState` and stable memory.
    pub fn release_system_state(self) -> SystemState {
        self.system_state.into_inner()
    }
}

impl SystemStateAccessor for SystemStateAccessorDirect {
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
}
