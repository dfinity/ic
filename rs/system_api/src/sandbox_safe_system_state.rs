use std::collections::{BTreeMap, BTreeSet};

use ic_base_types::{CanisterId, NumBytes, NumSeconds, PrincipalId, SubnetId};
use ic_constants::{LOG_CANISTER_OPERATION_CYCLES_THRESHOLD, SMALL_APP_SUBNET_MAX_SIZE};
use ic_cycles_account_manager::{CyclesAccountManager, CyclesAccountManagerError};
use ic_error_types::RejectCode;
use ic_ic00_types::IC_00;
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_logger::{info, ReplicaLogger};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::DEFAULT_QUEUE_CAPACITY, CallOrigin, CanisterStatus, NetworkTopology,
    SystemState,
};
use ic_types::{
    messages::{CallContextId, CallbackId, RejectContext, Request},
    methods::Callback,
    nominal_cycles::NominalCycles,
    CanisterTimer, ComputeAllocation, Cycles, MemoryAllocation, NumInstructions, NumPages, Time,
};
use ic_wasm_types::WasmEngineError;
use serde::{Deserialize, Serialize};

use crate::{cycles_balance_change::CyclesBalanceChange, routing, CERTIFIED_DATA_MAX_LENGTH};

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
    cycles_balance_change: CyclesBalanceChange,
    cycles_consumed: Cycles,
    call_context_balance_taken: BTreeMap<CallContextId, Cycles>,
    request_slots_used: BTreeMap<CanisterId, usize>,
    requests: Vec<Request>,
    pub(super) new_global_timer: Option<CanisterTimer>,
}

impl Default for SystemStateChanges {
    fn default() -> Self {
        Self {
            new_certified_data: None,
            callback_updates: vec![],
            cycles_balance_change: CyclesBalanceChange::zero(),
            cycles_consumed: Cycles::zero(),
            call_context_balance_taken: BTreeMap::new(),
            request_slots_used: BTreeMap::new(),
            requests: vec![],
            new_global_timer: None,
        }
    }
}

impl SystemStateChanges {
    /// Checks that no cycles were created during the execution of this message
    /// (unless the canister is the cycles minting canister).
    fn validate_cycle_change(&self, is_cmc_canister: bool) -> HypervisorResult<()> {
        let mut universal_cycle_change = self.cycles_balance_change;
        for call_context_balance_taken in self.call_context_balance_taken.values() {
            universal_cycle_change =
                universal_cycle_change + CyclesBalanceChange::removed(*call_context_balance_taken);
        }
        for req in self.requests.iter() {
            universal_cycle_change =
                universal_cycle_change + CyclesBalanceChange::added(req.payment);
        }
        if is_cmc_canister || universal_cycle_change <= CyclesBalanceChange::zero() {
            Ok(())
        } else {
            Err(HypervisorError::WasmEngineError(
                WasmEngineError::FailedToApplySystemChanges(format!(
                    "Invalid cycle change: {:?}",
                    universal_cycle_change
                )),
            ))
        }
    }

    /// Returns number of removed cycles in the state changes.
    pub fn removed_cycles(&self) -> Cycles {
        self.cycles_balance_change.get_removed_cycles()
    }

    /// Verify that the changes to the system state are sound and apply them to
    /// the system state if they are.
    pub fn apply_changes(
        self,
        time: Time,
        system_state: &mut SystemState,
        network_topology: &NetworkTopology,
        own_subnet_id: SubnetId,
        logger: &ReplicaLogger,
    ) -> HypervisorResult<()> {
        fn error<S: ToString>(message: S) -> HypervisorError {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToApplySystemChanges(
                message.to_string(),
            ))
        }

        // Verify total cycle change is not positive and update cycles balance.
        self.validate_cycle_change(system_state.canister_id == CYCLES_MINTING_CANISTER_ID)?;
        self.cycles_balance_change
            .apply_ref(system_state.balance_mut());

        // Observe consumed cycles.
        system_state
            .canister_metrics
            .consumed_cycles_since_replica_started +=
            NominalCycles::from_cycles(self.cycles_consumed);

        // Verify we don't accept more cycles than are available from each call
        // context and update each call context balance
        if !self.call_context_balance_taken.is_empty() {
            let own_canister_id = system_state.canister_id;
            let call_context_manager = system_state
                .call_context_manager_mut()
                .ok_or_else(|| error("Call context manager does not exists"))?;
            for (context_id, amount_taken) in &self.call_context_balance_taken {
                let call_context = call_context_manager
                    .call_context_mut(*context_id)
                    .ok_or_else(|| error("Canister accepted cycles from invalid call context"))?;
                call_context.withdraw_cycles(*amount_taken).map_err(|_| {
                    error("Canister accepted more cycles than available from call context")
                })?;
                if (*amount_taken).get() > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
                    match call_context.call_origin() {
                        CallOrigin::CanisterUpdate(origin_canister_id, _)
                        | CallOrigin::CanisterQuery(origin_canister_id, _) => info!(
                            logger,
                            "Canister {} accepted {} cycles from canister {}.",
                            own_canister_id,
                            *amount_taken,
                            origin_canister_id
                        ),
                        _ => (),
                    };
                }
            }
        }

        // Push outgoing messages.
        let mut callback_changes = BTreeMap::new();
        for mut msg in self.requests {
            if msg.receiver == IC_00 {
                // This is a request to ic:00. Update the receiver to be the appropriate
                // subnet and also update the corresponding callback.
                match routing::resolve_destination(
                    network_topology,
                    msg.method_name.as_str(),
                    msg.method_payload.as_slice(),
                    own_subnet_id,
                )
                .map(|id| CanisterId::new(id).unwrap())
                {
                    Ok(destination_subnet) => {
                        let sent_cycles = msg.payment.get();
                        msg.receiver = destination_subnet;
                        callback_changes.insert(msg.sender_reply_callback, destination_subnet);
                        system_state
                            .push_output_request(msg.into(), time)
                            .map_err(|e| {
                                error(format!("Failed to push output request: {:?}", e))
                            })?;
                        if sent_cycles > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
                            info!(
                                logger,
                                "Canister {} sent {} cycles to canister {}.",
                                system_state.canister_id,
                                sent_cycles,
                                destination_subnet
                            );
                        }
                    }
                    Err(err) => {
                        info!(
                                logger,
                                "Error routing IC00 message: sender id {}, method_name {}, resolve error: {:?}.",
                                msg.sender, msg.method_name, err
                            );

                        let reject_context = RejectContext {
                            code: RejectCode::DestinationInvalid,
                            message: format!(
                                "Unable to route management canister request {}: {:?}",
                                msg.method_name, err
                            ),
                        };
                        system_state
                            .reject_ic00_output_request(msg, reject_context)
                            .map_err(|e| {
                                error(format!("Failed to push IC00 reject response: {:?}", e))
                            })?;
                    }
                }
            } else {
                let sent_cycles = msg.payment.get();
                let msg_receiver = msg.receiver;
                system_state
                    .push_output_request(msg.into(), time)
                    .map_err(|e| error(format!("Failed to push output request: {:?}", e)))?;
                if sent_cycles > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
                    info!(
                        logger,
                        "Canister {} sent {} cycles to canister {}.",
                        system_state.canister_id,
                        sent_cycles,
                        msg_receiver
                    );
                }
            }
        }

        // Verify callback ids and register new callbacks.
        for update in self.callback_updates {
            let call_context_manager = system_state
                .call_context_manager_mut()
                .ok_or_else(|| error("Call context manager does not exists"))?;
            match update {
                CallbackUpdate::Register(expected_id, mut callback) => {
                    if let Some(receiver) = callback_changes.get(&expected_id) {
                        callback.respondent = Some(*receiver);
                    }
                    let id = call_context_manager.register_callback(callback);
                    if id != expected_id {
                        return Err(error("Failed to register update callback"));
                    }
                }
                CallbackUpdate::Unregister(callback_id) => {
                    let _callback = call_context_manager
                        .unregister_callback(callback_id)
                        .ok_or_else(|| {
                            error("Tried to unregister callback with an id that isn't in use")
                        });
                }
            }
        }

        // Verify new certified data isn't too long and set it.
        if let Some(certified_data) = self.new_certified_data.as_ref() {
            if certified_data.len() > CERTIFIED_DATA_MAX_LENGTH as usize {
                return Err(error("Certified data is too large"));
            }
            system_state.certified_data = certified_data.clone();
        }

        // Update canister global timer
        if let Some(new_global_timer) = self.new_global_timer {
            system_state.global_timer = new_global_timer;
        }

        Ok(())
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
    pub(super) subnet_size: usize,
    dirty_page_overhead: NumInstructions,
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
    ic00_available_request_slots: usize,
    ic00_aliases: BTreeSet<CanisterId>,
    global_timer: CanisterTimer,
    canister_version: u64,
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
        ic00_available_request_slots: usize,
        ic00_aliases: BTreeSet<CanisterId>,
        subnet_size: usize,
        dirty_page_overhead: NumInstructions,
        global_timer: CanisterTimer,
        canister_version: u64,
    ) -> Self {
        Self {
            canister_id,
            controller,
            status,
            subnet_type: cycles_account_manager.subnet_type(),
            subnet_size,
            dirty_page_overhead,
            freeze_threshold,
            memory_allocation,
            system_state_changes: SystemStateChanges::default(),
            initial_cycles_balance,
            call_context_balances,
            cycles_account_manager,
            next_callback_id,
            available_request_slots,
            ic00_available_request_slots,
            ic00_aliases,
            global_timer,
            canister_version,
        }
    }

    pub fn new(
        system_state: &SystemState,
        cycles_account_manager: CyclesAccountManager,
        network_topology: &NetworkTopology,
        dirty_page_overhead: NumInstructions,
    ) -> Self {
        let call_context_balances = match system_state.call_context_manager() {
            Some(call_context_manager) => call_context_manager
                .call_contexts()
                .iter()
                .map(|(id, context)| (*id, context.available_cycles()))
                .collect(),
            None => BTreeMap::new(),
        };
        let available_request_slots = system_state.available_output_request_slots();

        // Compute the available slots for IC_00 requests as the minimum of available
        // slots across any queue to a subnet explicitly or IC_00 itself.
        let mut ic00_aliases: BTreeSet<CanisterId> = network_topology
            .subnets
            .keys()
            .map(|id| CanisterId::new(id.get()).unwrap())
            .collect();
        ic00_aliases.insert(CanisterId::ic_00());
        let ic00_available_request_slots = ic00_aliases
            .iter()
            .map(|id| {
                available_request_slots
                    .get(id)
                    .cloned()
                    .unwrap_or(DEFAULT_QUEUE_CAPACITY)
            })
            .min()
            .unwrap_or(DEFAULT_QUEUE_CAPACITY);
        let subnet_size = network_topology
            .get_subnet_size(&cycles_account_manager.get_subnet_id())
            .unwrap_or(SMALL_APP_SUBNET_MAX_SIZE);

        Self::new_internal(
            system_state.canister_id,
            *system_state.controller(),
            CanisterStatusView::from_full_status(&system_state.status),
            system_state.freeze_threshold,
            system_state.memory_allocation,
            system_state.balance(),
            call_context_balances,
            cycles_account_manager,
            system_state
                .call_context_manager()
                .map(|c| c.next_callback_id()),
            available_request_slots,
            ic00_available_request_slots,
            ic00_aliases,
            subnet_size,
            dirty_page_overhead,
            system_state.global_timer,
            system_state.canister_version,
        )
    }

    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn global_timer(&self) -> CanisterTimer {
        self.global_timer
    }

    pub fn canister_version(&self) -> u64 {
        self.canister_version
    }

    pub fn set_global_timer(&mut self, timer: CanisterTimer) {
        // Update both sandbox global timer and the changes.
        self.system_state_changes.new_global_timer = Some(timer);
        self.global_timer = timer;
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

    /// Only public for use in tests.
    #[doc(hidden)]
    pub fn unregister_callback(&mut self, id: CallbackId) {
        self.system_state_changes
            .callback_updates
            .push(CallbackUpdate::Unregister(id))
    }

    pub(super) fn cycles_balance(&self) -> Cycles {
        let cycles_change = self.system_state_changes.cycles_balance_change;
        cycles_change.apply(self.initial_cycles_balance)
    }

    pub(super) fn msg_cycles_available(&self, call_context_id: CallContextId) -> Cycles {
        let initial_available = *self
            .call_context_balances
            .get(&call_context_id)
            .unwrap_or(&Cycles::zero());
        let already_taken = *self
            .system_state_changes
            .call_context_balance_taken
            .get(&call_context_id)
            .unwrap_or(&Cycles::zero());
        initial_available - already_taken
    }

    fn update_balance_change(&mut self, new_balance: Cycles) {
        self.system_state_changes.cycles_balance_change =
            CyclesBalanceChange::new(self.initial_cycles_balance, new_balance);
    }

    /// Same as [`update_balance_change`], but asserts the balance has decreased
    /// and marks the difference as cycles consumed (i.e. burned and not
    /// transferred).
    fn update_balance_change_consuming(&mut self, new_balance: Cycles) {
        let old_balance = self.cycles_balance();
        assert!(
            new_balance <= old_balance,
            "Unexpected increase of cycles balances {} => {}",
            old_balance,
            new_balance
        );
        let consumed = old_balance - new_balance;
        self.system_state_changes.cycles_consumed += consumed;
        self.update_balance_change(new_balance);
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
                        .unwrap_or(&Cycles::zero())
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
            .or_insert_with(Cycles::zero) += amount_to_accept;

        self.cycles_account_manager
            .add_cycles(&mut new_balance, amount_to_accept);

        self.update_balance_change(new_balance);
        amount_to_accept
    }

    pub fn prepayment_for_response_execution(&self) -> Cycles {
        self.cycles_account_manager
            .prepayment_for_response_execution(self.subnet_size)
    }

    pub fn prepayment_for_response_transmission(&self) -> Cycles {
        self.cycles_account_manager
            .prepayment_for_response_transmission(self.subnet_size)
    }

    pub(super) fn withdraw_cycles_for_transfer(
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
                self.subnet_size,
            )
            .map_err(HypervisorError::InsufficientCyclesBalance);
        self.update_balance_change(new_balance);
        result
    }

    pub fn push_output_request(
        &mut self,
        canister_current_memory_usage: NumBytes,
        compute_allocation: ComputeAllocation,
        msg: Request,
        prepayment_for_response_execution: Cycles,
        prepayment_for_response_transmission: Cycles,
    ) -> Result<(), Request> {
        let mut new_balance = self.cycles_balance();
        if self
            .cycles_account_manager
            .withdraw_request_cycles(
                self.canister_id,
                &mut new_balance,
                self.freeze_threshold,
                self.memory_allocation,
                canister_current_memory_usage,
                compute_allocation,
                &msg,
                prepayment_for_response_execution,
                prepayment_for_response_transmission,
                self.subnet_size,
            )
            .is_err()
        {
            return Err(msg);
        }

        // If the request is targeted to IC_00 or one of the known subnets
        // count it towards the available slots for IC_00 requests.
        if self.ic00_aliases.contains(&msg.receiver) {
            if self.ic00_available_request_slots == 0 {
                return Err(msg);
            }
            self.ic00_available_request_slots -= 1;
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
            return Err(msg);
        }
        self.system_state_changes.requests.push(msg);
        *used_slots += 1;
        self.update_balance_change_consuming(new_balance);
        Ok(())
    }

    /// Calculate the cost for newly created dirty pages.
    pub fn dirty_page_cost(&self, dirty_pages: NumPages) -> HypervisorResult<NumInstructions> {
        let (inst, overflow) = dirty_pages
            .get()
            .overflowing_mul(self.dirty_page_overhead.get());
        if overflow {
            Err(HypervisorError::ContractViolation(format!("Overflow calculating instruction cost for dirty pages - conversion rate: {}, dirty_pages: {}", self.dirty_page_overhead, dirty_pages)))
        } else {
            Ok(NumInstructions::from(inst))
        }
    }
}
