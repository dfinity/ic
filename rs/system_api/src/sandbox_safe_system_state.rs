use std::{collections::BTreeMap, convert::TryFrom, convert::TryInto};

use ic_base_types::{CanisterId, NumBytes, NumSeconds, PrincipalId};
use ic_cycles_account_manager::{CyclesAccountManager, CyclesAccountManagerError};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::DEFAULT_QUEUE_CAPACITY, CanisterStatus, StateError, SystemState,
};
use ic_types::{
    messages::{CallContextId, CallbackId, Request},
    methods::Callback,
    nominal_cycles::NominalCycles,
    ComputeAllocation, Cycles, MemoryAllocation,
};
use serde::{Deserialize, Serialize};

use crate::CERTIFIED_DATA_MAX_LENGTH;

/// The information that canisters can see about their own status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CanisterStatusView {
    Running,
    Stopping,
    Stopped,
}

impl CanisterStatusView {
    pub fn from_full_status(full_status: &CanisterStatus) -> Self {
        match full_status {
            CanisterStatus::Running { .. } => Self::Running,
            CanisterStatus::Stopping { .. } => Self::Stopping,
            CanisterStatus::Stopped => Self::Stopped,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallbackUpdate {
    Register(CallbackId, Callback),
    Unregister(CallbackId),
}

/// Tracks changes to the system state that the canister has requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStateChanges {
    pub(super) new_certified_data: Option<Vec<u8>>,
    pub(super) callback_updates: Vec<CallbackUpdate>,
    cycles_balance_change: i128,
    cycles_consumed: Cycles,
    call_context_balance_taken: BTreeMap<CallContextId, Cycles>,
    request_slots_used: BTreeMap<CanisterId, usize>,
    requests: Vec<Request>,
}

impl Default for SystemStateChanges {
    fn default() -> Self {
        Self {
            new_certified_data: None,
            callback_updates: vec![],
            cycles_balance_change: 0,
            cycles_consumed: Cycles::from(0),
            call_context_balance_taken: BTreeMap::new(),
            request_slots_used: BTreeMap::new(),
            requests: vec![],
        }
    }
}

impl SystemStateChanges {
    /// Checks that no cycles were created during the execution of this message
    /// (unless the canister is the cycles minting canister). Returns None if
    /// there was overflow during the calculation.
    fn cycle_change_is_valid(&self, is_cmc_canister: bool) -> Option<bool> {
        let mut universal_cycle_change = 0;
        universal_cycle_change += self.cycles_balance_change;
        for call_context_balance_taken in self.call_context_balance_taken.values() {
            universal_cycle_change = universal_cycle_change
                .checked_sub(call_context_balance_taken.get().try_into().ok()?)?;
        }
        for req in self.requests.iter() {
            universal_cycle_change =
                universal_cycle_change.checked_add(req.payment.get().try_into().ok()?)?;
        }
        if is_cmc_canister {
            Some(true)
        } else {
            // Check that no cycles were created.
            Some(universal_cycle_change <= 0)
        }
    }

    /// Verify that the changes to the system state are sound and apply them to
    /// the system state if they are.
    ///
    /// # Panic
    ///
    /// This will panic if the changes are invalid. That could indicate that a
    /// canister has broken out of wasmtime.
    pub fn apply_changes(self, system_state: &mut SystemState) {
        // Verify total cycle change is not positive and update cycles balance.
        assert!(self
            .cycle_change_is_valid(system_state.canister_id == CYCLES_MINTING_CANISTER_ID)
            .unwrap());
        if self.cycles_balance_change >= 0 {
            system_state.cycles_balance += Cycles::from(self.cycles_balance_change as u128);
        } else {
            let new_balance = system_state
                .cycles_balance
                .get()
                .checked_sub(-self.cycles_balance_change as u128)
                .unwrap();
            system_state.cycles_balance = Cycles::from(new_balance);
        }

        // Observe consumed cycles.
        system_state
            .canister_metrics
            .consumed_cycles_since_replica_started +=
            NominalCycles::from_cycles(self.cycles_consumed);

        // Verify we don't accept more cycles than are available from each call
        // context and update each call context balance
        if !self.call_context_balance_taken.is_empty() {
            let call_context_manager = system_state.call_context_manager_mut().unwrap();
            for (context_id, amount_taken) in &self.call_context_balance_taken {
                let call_context = call_context_manager
                    .call_context_mut(*context_id)
                    .expect("Canister accepted cycles from invalid call context");
                call_context
                    .withdraw_cycles(*amount_taken)
                    .expect("Canister accepted more cycles than available from call context");
            }
        }

        // Push outgoing messages.
        for msg in &self.requests {
            system_state
                .push_output_request(msg.clone())
                .expect("Unable to send new request");
        }

        // Verify new certified data isn't too long and set it.
        if let Some(certified_data) = self.new_certified_data.as_ref() {
            assert!(certified_data.len() <= CERTIFIED_DATA_MAX_LENGTH as usize);
            system_state.certified_data = certified_data.clone();
        }

        // Verify callback ids and register new callbacks.
        for update in self.callback_updates {
            match update {
                CallbackUpdate::Register(expected_id, callback) => {
                    let id = system_state
                        .call_context_manager_mut()
                        .unwrap()
                        .register_callback(callback);
                    assert_eq!(id, expected_id);
                }
                CallbackUpdate::Unregister(callback_id) => {
                    let _callback = system_state
                        .call_context_manager_mut()
                        .unwrap()
                        .unregister_callback(callback_id)
                        .expect("Tried to unregister callback with an id that isn't in use");
                }
            }
        }
    }
}

/// A version of the `SystemState` that can be used in a sandboxed process.
/// Changes are separately tracked so that we can verify the changes are valid
/// before applying them to the actual system state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSafeSystemState {
    /// Only public for tests
    #[doc(hidden)]
    pub system_state_changes: SystemStateChanges,
    pub(super) canister_id: CanisterId,
    pub(super) controller: PrincipalId,
    pub(super) status: CanisterStatusView,
    pub(super) subnet_type: SubnetType,
    freeze_threshold: NumSeconds,
    memory_allocation: MemoryAllocation,
    initial_cycles_balance: Cycles,
    call_context_balances: BTreeMap<CallContextId, Cycles>,
    cycles_account_manager: CyclesAccountManager,
    // None indicates that we are in a context where the canister cannot
    // register callbacks (e.g. running the `start` method when installing a
    // canister.)
    next_callback_id: Option<u64>,
    available_request_slots: BTreeMap<CanisterId, usize>,
}

impl SandboxSafeSystemState {
    /// Only public for use in tests.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_internal(
        canister_id: CanisterId,
        controller: PrincipalId,
        status: CanisterStatusView,
        freeze_threshold: NumSeconds,
        memory_allocation: MemoryAllocation,
        initial_cycles_balance: Cycles,
        call_context_balances: BTreeMap<CallContextId, Cycles>,
        cycles_account_manager: CyclesAccountManager,
        next_callback_id: Option<u64>,
        available_request_slots: BTreeMap<CanisterId, usize>,
    ) -> Self {
        Self {
            canister_id,
            controller,
            status,
            subnet_type: cycles_account_manager.subnet_type(),
            freeze_threshold,
            memory_allocation,
            system_state_changes: SystemStateChanges::default(),
            initial_cycles_balance,
            call_context_balances,
            cycles_account_manager,
            next_callback_id,
            available_request_slots,
        }
    }

    pub fn new(system_state: &SystemState, cycles_account_manager: CyclesAccountManager) -> Self {
        let call_context_balances = match system_state.call_context_manager() {
            Some(call_context_manager) => call_context_manager
                .call_contexts()
                .iter()
                .map(|(id, context)| (*id, context.available_cycles()))
                .collect(),
            None => BTreeMap::new(),
        };
        let available_request_slots = system_state.available_output_request_slots();
        Self::new_internal(
            system_state.canister_id,
            *system_state.controller(),
            CanisterStatusView::from_full_status(&system_state.status),
            system_state.freeze_threshold,
            system_state.memory_allocation,
            system_state.cycles_balance,
            call_context_balances,
            cycles_account_manager,
            system_state
                .call_context_manager()
                .map(|c| c.next_callback_id()),
            available_request_slots,
        )
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn changes(self) -> SystemStateChanges {
        self.system_state_changes
    }

    pub fn take_changes(&mut self) -> SystemStateChanges {
        std::mem::take(&mut self.system_state_changes)
    }

    /// Only public for use in tests.
    #[doc(hidden)]
    pub fn register_callback(&mut self, callback: Callback) -> HypervisorResult<CallbackId> {
        match &mut self.next_callback_id {
            Some(next_callback_id) => {
                *next_callback_id += 1;
                let id = CallbackId::from(*next_callback_id);
                self.system_state_changes
                    .callback_updates
                    .push(CallbackUpdate::Register(id, callback));
                Ok(id)
            }
            None => Err(HypervisorError::ContractViolation(
                "Tried to register a callback in a context where it isn't allowed.".to_string(),
            )),
        }
    }

    pub(super) fn unregister_callback(&mut self, id: CallbackId) {
        self.system_state_changes
            .callback_updates
            .push(CallbackUpdate::Unregister(id))
    }

    pub(super) fn cycles_balance(&self) -> Cycles {
        let cycle_change = self.system_state_changes.cycles_balance_change;
        if cycle_change >= 0 {
            Cycles::from(
                self.initial_cycles_balance
                    .get()
                    .checked_add(cycle_change as u128)
                    .unwrap(),
            )
        } else {
            Cycles::from(
                self.initial_cycles_balance
                    .get()
                    .checked_sub(-cycle_change as u128)
                    .unwrap(),
            )
        }
    }

    pub(super) fn msg_cycles_available(&self, call_context_id: CallContextId) -> Cycles {
        let initial_available = *self
            .call_context_balances
            .get(&call_context_id)
            .unwrap_or(&Cycles::from(0));
        let already_taken = *self
            .system_state_changes
            .call_context_balance_taken
            .get(&call_context_id)
            .unwrap_or(&Cycles::from(0));
        initial_available - already_taken
    }

    fn update_balance_change(&mut self, new_balance: Cycles) {
        let new_change = i128::try_from(new_balance.get())
            .unwrap()
            .checked_sub(i128::try_from(self.initial_cycles_balance.get()).unwrap())
            .unwrap();
        self.system_state_changes.cycles_balance_change = new_change;
    }

    /// Same as [`update_balance_change`], but asserts the balance has decreased
    /// and marks the difference as cycles consumed (i.e. burned and not
    /// transfered).
    fn update_balance_change_consuming(&mut self, new_balance: Cycles) {
        let new_change = i128::try_from(new_balance.get())
            .unwrap()
            .checked_sub(i128::try_from(self.initial_cycles_balance.get()).unwrap())
            .unwrap();
        // Assert that the balance has decreased.
        assert!(new_change <= self.system_state_changes.cycles_balance_change);
        let consumed =
            Cycles::from((self.system_state_changes.cycles_balance_change - new_change) as u128);
        self.system_state_changes.cycles_consumed += consumed;
        self.system_state_changes.cycles_balance_change = new_change;
    }

    pub(super) fn mint_cycles(&mut self, amount_to_mint: Cycles) -> HypervisorResult<()> {
        let mut new_balance = self.cycles_balance();
        let result = self
            .cycles_account_manager
            .mint_cycles(self.canister_id, &mut new_balance, amount_to_mint)
            .map_err(|CyclesAccountManagerError::ContractViolation(msg)| {
                HypervisorError::ContractViolation(msg)
            });
        self.update_balance_change(new_balance);
        result
    }

    pub(super) fn refund_cycles(&mut self, cycles: Cycles) {
        let mut new_balance = self.cycles_balance();
        self.cycles_account_manager
            .add_cycles(&mut new_balance, cycles);
        self.update_balance_change(new_balance);
    }

    pub(super) fn msg_cycles_accept(
        &mut self,
        call_context_id: CallContextId,
        amount_to_accept: Cycles,
    ) -> Cycles {
        let mut new_balance = self.cycles_balance();
        // Scale amount that can be accepted by CYCLES_LIMIT_PER_CANISTER.
        let amount_to_accept = self
            .cycles_account_manager
            .check_max_cycles_can_add(new_balance, amount_to_accept);

        // Scale amount that can be accepted by what is actually available on
        // the call context.
        let amount_available = Cycles::from(
            self.call_context_balances
                .get(&call_context_id)
                .unwrap()
                .get()
                .checked_sub(
                    self.system_state_changes
                        .call_context_balance_taken
                        .get(&call_context_id)
                        .unwrap_or(&Cycles::from(0))
                        .get(),
                )
                .unwrap(),
        );
        let amount_to_accept = std::cmp::min(amount_available, amount_to_accept);

        // Withdraw and accept the cycles
        *self
            .system_state_changes
            .call_context_balance_taken
            .entry(call_context_id)
            .or_insert_with(|| Cycles::from(0)) += amount_to_accept;

        self.cycles_account_manager
            .add_cycles(&mut new_balance, amount_to_accept);

        self.update_balance_change(new_balance);
        amount_to_accept
    }

    pub(super) fn canister_cycles_withdraw(
        &mut self,
        canister_current_memory_usage: NumBytes,
        compute_allocation: ComputeAllocation,
        amount: Cycles,
    ) -> HypervisorResult<()> {
        let mut new_balance = self.cycles_balance();
        let result = self
            .cycles_account_manager
            .withdraw_cycles_for_transfer(
                self.canister_id,
                self.freeze_threshold,
                self.memory_allocation,
                canister_current_memory_usage,
                compute_allocation,
                &mut new_balance,
                amount,
            )
            .map_err(HypervisorError::InsufficientCyclesBalance);
        self.update_balance_change(new_balance);
        result
    }

    /// Only public for use in tests
    #[doc(hidden)]
    pub fn push_output_request(
        &mut self,
        canister_current_memory_usage: NumBytes,
        compute_allocation: ComputeAllocation,
        msg: Request,
    ) -> Result<(), (StateError, Request)> {
        let mut new_balance = self.cycles_balance();
        if let Err(err) = self.cycles_account_manager.withdraw_request_cycles(
            self.canister_id,
            &mut new_balance,
            self.freeze_threshold,
            self.memory_allocation,
            canister_current_memory_usage,
            compute_allocation,
            &msg,
        ) {
            return Err((StateError::CanisterOutOfCycles(err), msg));
        }
        let initial_available_slots = self
            .available_request_slots
            .get(&msg.receiver)
            .unwrap_or(&DEFAULT_QUEUE_CAPACITY);
        let used_slots = self
            .system_state_changes
            .request_slots_used
            .entry(msg.receiver)
            .or_insert(0);
        if *used_slots >= *initial_available_slots {
            return Err((
                StateError::QueueFull {
                    capacity: DEFAULT_QUEUE_CAPACITY,
                },
                msg,
            ));
        }
        self.system_state_changes.requests.push(msg);
        *used_slots += 1;
        self.update_balance_change_consuming(new_balance);
        Ok(())
    }
}
