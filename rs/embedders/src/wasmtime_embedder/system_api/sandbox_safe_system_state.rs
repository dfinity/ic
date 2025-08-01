use std::collections::{BTreeMap, BTreeSet};

use super::{
    cycles_balance_change::CyclesBalanceChange, routing, routing::ResolveDestinationError, ApiType,
    CERTIFIED_DATA_MAX_LENGTH,
};
use ic_base_types::{CanisterId, NumBytes, NumOsPages, NumSeconds, PrincipalId, SubnetId};
use ic_cycles_account_manager::{
    CyclesAccountManager, CyclesAccountManagerError, ResourceSaturation,
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_limits::{LOG_CANISTER_OPERATION_CYCLES_THRESHOLD, SMALL_APP_SUBNET_MAX_SIZE};
use ic_logger::{info, ReplicaLogger};
use ic_management_canister_types_private::{
    CanisterStatusType, CreateCanisterArgs, InstallChunkedCodeArgs, InstallCodeArgsV2,
    LoadCanisterSnapshotArgs, MasterPublicKeyId, Method as Ic00Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs, RenameCanisterArgs, UninstallCodeArgs,
    UpdateSettingsArgs, IC_00,
};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::{
    is_low_wasm_memory_hook_condition_satisfied, CyclesUseCase,
};
use ic_replicated_state::{
    canister_state::execution_state::WasmExecutionMode, canister_state::DEFAULT_QUEUE_CAPACITY,
    CallOrigin, ExecutionTask, MessageMemoryUsage, NetworkTopology, SystemState,
};
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::{
    messages::{CallContextId, CallbackId, RejectContext, Request, RequestMetadata, NO_DEADLINE},
    methods::Callback,
    time::CoarseTime,
    CanisterLog, CanisterTimer, ComputeAllocation, Cycles, MemoryAllocation, NumInstructions, Time,
};
use ic_wasm_types::WasmEngineError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// The ICP mainnet root key.
const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

/// The information that canisters can see about their own status.
#[derive(Copy, Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum CanisterStatusView {
    Running,
    Stopping,
    Stopped,
}

impl CanisterStatusView {
    pub fn from_canister_status_type(status: CanisterStatusType) -> Self {
        match status {
            CanisterStatusType::Running => Self::Running,
            CanisterStatusType::Stopping => Self::Stopping,
            CanisterStatusType::Stopped => Self::Stopped,
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum CallbackUpdate {
    Register(CallbackId, Callback),
    Unregister(CallbackId),
}

/// Tracks changes to the system state that the canister has requested.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SystemStateModifications {
    pub(super) new_certified_data: Option<Vec<u8>>,
    // pub for testing
    pub callback_updates: Vec<CallbackUpdate>,
    pub(super) cycles_balance_change: CyclesBalanceChange,
    // The cycles that move from the main balance to the reserved balance.
    // Invariant: `cycles_balance_change` contains
    // `CyclesBalanceChange::Removed(reserved_cycles)`.
    pub(super) reserved_cycles: Cycles,
    pub(super) consumed_cycles_by_use_case: BTreeMap<CyclesUseCase, Cycles>,
    pub(super) call_context_balance_taken: Option<(CallContextId, Cycles)>,
    pub(super) request_slots_used: BTreeMap<CanisterId, usize>,
    pub(super) requests: Vec<Request>,
    pub(super) new_global_timer: Option<CanisterTimer>,
    pub(super) canister_log: CanisterLog,
    pub on_low_wasm_memory_hook_condition_check_result: Option<bool>,
    pub(super) should_bump_canister_version: bool,
}

impl Default for SystemStateModifications {
    fn default() -> Self {
        Self {
            new_certified_data: None,
            callback_updates: vec![],
            cycles_balance_change: CyclesBalanceChange::zero(),
            reserved_cycles: Cycles::zero(),
            consumed_cycles_by_use_case: BTreeMap::new(),
            call_context_balance_taken: None,
            request_slots_used: BTreeMap::new(),
            requests: vec![],
            new_global_timer: None,
            canister_log: Default::default(),
            on_low_wasm_memory_hook_condition_check_result: None,
            should_bump_canister_version: false,
        }
    }
}

impl SystemStateModifications {
    /// Checks that no cycles were created during the execution of this message
    /// (unless the canister is the cycles minting canister).
    fn validate_cycle_change(&self, is_cmc_canister: bool) -> HypervisorResult<()> {
        let mut expected_change = CyclesBalanceChange::zero();

        if let Some((_, call_context_balance_taken)) = self.call_context_balance_taken {
            expected_change =
                expected_change + CyclesBalanceChange::added(call_context_balance_taken);
        }

        for req in self.requests.iter() {
            expected_change = expected_change + CyclesBalanceChange::removed(req.payment);
        }

        for (_use_case, amount) in self.consumed_cycles_by_use_case.iter() {
            expected_change = expected_change + CyclesBalanceChange::removed(*amount);
        }

        expected_change = expected_change + CyclesBalanceChange::removed(self.reserved_cycles);

        // If the canister is not the cycles minting canister, then the balance
        // change coming from the Wasm execution must match the expected balance
        // change that we just computed.
        if is_cmc_canister || self.cycles_balance_change == expected_change {
            Ok(())
        } else {
            Err(HypervisorError::WasmEngineError(
                WasmEngineError::FailedToApplySystemChanges(format!(
                    "Invalid cycle change: expected {:?}, got {:?}",
                    expected_change, self.cycles_balance_change
                )),
            ))
        }
    }

    /// Returns number of removed cycles in the state changes.
    pub fn removed_cycles(&self) -> Cycles {
        self.cycles_balance_change.get_removed_cycles()
    }

    /// Returns number of newly created callbacks (i.e. enqueued requests).
    pub fn callbacks_created(&self) -> usize {
        self.requests.len()
    }

    fn error<S: ToString>(message: S) -> HypervisorError {
        HypervisorError::WasmEngineError(WasmEngineError::FailedToApplySystemChanges(
            message.to_string(),
        ))
    }

    fn reject_subnet_message_routing(
        system_state: &mut SystemState,
        subnet_ids: &BTreeSet<PrincipalId>,
        msg: Request,
        err: ResolveDestinationError,
        logger: &ReplicaLogger,
    ) -> HypervisorResult<()> {
        info!(
            logger,
            "Error routing IC00 message: sender id {}, method_name {}, resolve error: {:?}.",
            msg.sender,
            msg.method_name,
            err
        );
        let reject_context = RejectContext::new(
            RejectCode::DestinationInvalid,
            format!(
                "Unable to route management canister request {}: {:?}",
                msg.method_name, err
            ),
        );
        system_state
            .reject_subnet_output_request(msg, reject_context, subnet_ids)
            .map_err(|e| Self::error(format!("Failed to push IC00 reject response: {:?}", e)))?;
        Ok(())
    }

    fn reject_subnet_message_user_error(
        system_state: &mut SystemState,
        subnet_ids: &BTreeSet<PrincipalId>,
        msg: Request,
        err: UserError,
        logger: &ReplicaLogger,
    ) -> HypervisorResult<()> {
        info!(
            logger,
            "Error validating IC00 message: sender id {}, method_name {}, error: {}.",
            msg.sender,
            msg.method_name,
            err
        );

        let reject_context = RejectContext::new(err.code().into(), err.to_string());
        system_state
            .reject_subnet_output_request(msg, reject_context, subnet_ids)
            .map_err(|e| Self::error(format!("Failed to push IC00 reject response: {:?}", e)))?;
        Ok(())
    }

    fn push_message(
        system_state: &mut SystemState,
        time: Time,
        msg: Request,
        logger: &ReplicaLogger,
    ) -> HypervisorResult<()> {
        let sent_cycles = msg.payment.get();
        let msg_receiver = msg.receiver;
        system_state
            .push_output_request(msg.into(), time)
            .map_err(|e| Self::error(format!("Failed to push output request: {:?}", e)))?;
        if sent_cycles > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
            info!(
                logger,
                "Canister {} sent {} cycles to canister {}.",
                system_state.canister_id,
                sent_cycles,
                msg_receiver
            );
        }
        Ok(())
    }

    fn get_sender_canister_version(msg: &Request) -> Result<Option<u64>, UserError> {
        let method = Ic00Method::from_str(&msg.method_name);
        let payload = msg.method_payload();
        match method {
            Ok(Ic00Method::InstallCode) => InstallCodeArgsV2::decode(payload)
                .map(|record| record.get_sender_canister_version()),
            Ok(Ic00Method::InstallChunkedCode) => InstallChunkedCodeArgs::decode(payload)
                .map(|record| record.get_sender_canister_version()),
            Ok(Ic00Method::CreateCanister) => CreateCanisterArgs::decode(payload)
                .map(|record| record.get_sender_canister_version()),
            Ok(Ic00Method::UpdateSettings) => UpdateSettingsArgs::decode(payload)
                .map(|record| record.get_sender_canister_version()),
            Ok(Ic00Method::UninstallCode) => UninstallCodeArgs::decode(payload)
                .map(|record| record.get_sender_canister_version()),
            Ok(Ic00Method::ProvisionalCreateCanisterWithCycles) => {
                ProvisionalCreateCanisterWithCyclesArgs::decode(payload)
                    .map(|record| record.get_sender_canister_version())
            }
            Ok(Ic00Method::LoadCanisterSnapshot) => LoadCanisterSnapshotArgs::decode(payload)
                .map(|record| record.get_sender_canister_version()),
            Ok(Ic00Method::RenameCanister) => RenameCanisterArgs::decode(payload)
                .map(|record| record.get_sender_canister_version()),
            Ok(Ic00Method::SignWithECDSA)
            | Ok(Ic00Method::CanisterStatus)
            | Ok(Ic00Method::CanisterInfo)
            | Ok(Ic00Method::StartCanister)
            | Ok(Ic00Method::StopCanister)
            | Ok(Ic00Method::DeleteCanister)
            | Ok(Ic00Method::RawRand)
            | Ok(Ic00Method::DepositCycles)
            | Ok(Ic00Method::HttpRequest)
            | Ok(Ic00Method::SetupInitialDKG)
            | Ok(Ic00Method::ECDSAPublicKey)
            | Ok(Ic00Method::ReshareChainKey)
            | Ok(Ic00Method::SchnorrPublicKey)
            | Ok(Ic00Method::SignWithSchnorr)
            | Ok(Ic00Method::VetKdPublicKey)
            | Ok(Ic00Method::VetKdDeriveKey)
            | Ok(Ic00Method::ProvisionalTopUpCanister)
            | Ok(Ic00Method::BitcoinSendTransactionInternal)
            | Ok(Ic00Method::BitcoinGetSuccessors)
            | Ok(Ic00Method::BitcoinGetBalance)
            | Ok(Ic00Method::BitcoinGetUtxos)
            | Ok(Ic00Method::BitcoinGetBlockHeaders)
            | Ok(Ic00Method::BitcoinSendTransaction)
            | Ok(Ic00Method::BitcoinGetCurrentFeePercentiles)
            | Ok(Ic00Method::NodeMetricsHistory)
            | Ok(Ic00Method::SubnetInfo)
            | Ok(Ic00Method::FetchCanisterLogs)
            | Ok(Ic00Method::UploadChunk)
            | Ok(Ic00Method::StoredChunks)
            | Ok(Ic00Method::ClearChunkStore)
            | Ok(Ic00Method::TakeCanisterSnapshot)
            | Ok(Ic00Method::ListCanisterSnapshots)
            | Ok(Ic00Method::DeleteCanisterSnapshot)
            | Ok(Ic00Method::ReadCanisterSnapshotMetadata)
            | Ok(Ic00Method::ReadCanisterSnapshotData)
            | Ok(Ic00Method::UploadCanisterSnapshotMetadata)
            | Ok(Ic00Method::UploadCanisterSnapshotData) => Ok(None),
            Err(_) => Err(UserError::new(
                ErrorCode::CanisterMethodNotFound,
                format!("Management canister has no method '{}'", msg.method_name),
            )),
        }
    }

    fn validate_sender_canister_version(
        msg: &Request,
        canister_version_from_system: u64,
    ) -> Result<(), UserError> {
        match Self::get_sender_canister_version(msg)? {
            None => Ok(()),
            Some(sender_canister_version) => {
                if sender_canister_version == canister_version_from_system {
                    Ok(())
                } else {
                    Err(UserError::new(
                      ErrorCode::CanisterContractViolation,
                      format!("Management canister call payload includes sender canister version {:?} that does not match the actual sender canister version {}.", sender_canister_version, canister_version_from_system))
                    )
                }
            }
        }
    }

    /// Verify that the changes to the system state are sound and apply them to
    /// the system state if they are.
    pub fn apply_changes(
        mut self,
        time: Time,
        system_state: &mut SystemState,
        network_topology: &NetworkTopology,
        own_subnet_id: SubnetId,
        logger: &ReplicaLogger,
    ) -> HypervisorResult<RequestMetadataStats> {
        // Verify total cycle change is not positive and update cycles balance.
        self.validate_cycle_change(system_state.canister_id == CYCLES_MINTING_CANISTER_ID)?;
        self.apply_balance_changes(system_state);

        if let Some(hook_condition_check_result) =
            self.on_low_wasm_memory_hook_condition_check_result
        {
            if hook_condition_check_result {
                system_state
                    .task_queue
                    .enqueue(ExecutionTask::OnLowWasmMemory);
            } else {
                system_state
                    .task_queue
                    .remove(ExecutionTask::OnLowWasmMemory);
            }
        }

        // Verify we don't accept more cycles than are available from call
        // context and update the call context balance.
        if let Some((context_id, call_context_balance_taken)) = self.call_context_balance_taken {
            if call_context_balance_taken != Cycles::zero() {
                let own_canister_id = system_state.canister_id;

                let call_context = system_state
                    .withdraw_cycles(context_id, call_context_balance_taken)
                    .map_err(Self::error)?;
                if (call_context_balance_taken).get() > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
                    match call_context.call_origin() {
                        CallOrigin::CanisterUpdate(origin_canister_id, _, _)
                        | CallOrigin::CanisterQuery(origin_canister_id, _) => info!(
                            logger,
                            "Canister {} accepted {} cycles from canister {}.",
                            own_canister_id,
                            call_context_balance_taken,
                            origin_canister_id
                        ),
                        _ => (),
                    };
                }
            }
        }

        // Get a clone of the request metadata of outgoing requests (they are all equivalent)
        // and their number. This will be used for call tree metrics.
        let best_effort_request_count = self
            .requests
            .iter()
            .filter(|req| req.is_best_effort())
            .count() as u64;
        let request_stats = RequestMetadataStats {
            metadata: self
                .requests
                .first()
                .map_or_else(Default::default, |request| request.metadata.clone()),
            best_effort_request_count,
            guaranteed_response_request_count: self.requests.len() as u64
                - best_effort_request_count,
        };

        // Push outgoing messages.
        let mut callback_changes = BTreeMap::new();
        let nns_subnet_id = network_topology.nns_subnet_id;
        let subnet_ids: BTreeSet<PrincipalId> =
            network_topology.subnets.keys().map(|s| s.get()).collect();
        for mut msg in self.requests {
            if msg.receiver == IC_00 {
                match Self::validate_sender_canister_version(&msg, system_state.canister_version) {
                    Ok(()) => {
                        // This is a request to ic:00. Update the receiver to be the appropriate
                        // subnet and also update the corresponding callback.
                        match routing::resolve_destination(
                            network_topology,
                            msg.method_name.as_str(),
                            msg.method_payload.as_slice(),
                            own_subnet_id,
                            system_state.canister_id,
                            logger,
                        )
                        .map(CanisterId::unchecked_from_principal)
                        {
                            Ok(destination_subnet) => {
                                msg.receiver = destination_subnet;
                                callback_changes
                                    .insert(msg.sender_reply_callback, destination_subnet);
                                Self::push_message(system_state, time, msg, logger)?;
                            }
                            Err(err) => {
                                Self::reject_subnet_message_routing(
                                    system_state,
                                    &subnet_ids,
                                    msg,
                                    err,
                                    logger,
                                )?;
                            }
                        }
                    }
                    Err(err) => {
                        Self::reject_subnet_message_user_error(
                            system_state,
                            &subnet_ids,
                            msg,
                            err,
                            logger,
                        )?;
                    }
                }
            } else if subnet_ids.contains(&msg.receiver.get()) {
                match Self::validate_sender_canister_version(&msg, system_state.canister_version) {
                    Ok(()) => {
                        if own_subnet_id != nns_subnet_id {
                            // This is a management canister call providing the target subnet ID
                            // directly in the request. This is only allowed for NNS canisters.
                            let err = ResolveDestinationError::AlreadyResolved(msg.receiver.get());
                            Self::reject_subnet_message_routing(
                                system_state,
                                &subnet_ids,
                                msg,
                                err,
                                logger,
                            )?;
                        } else {
                            Self::push_message(system_state, time, msg, logger)?;
                        }
                    }
                    Err(err) => {
                        Self::reject_subnet_message_user_error(
                            system_state,
                            &subnet_ids,
                            msg,
                            err,
                            logger,
                        )?;
                    }
                }
            } else {
                Self::push_message(system_state, time, msg, logger)?;
            }
        }

        // Register and unregister callbacks.
        for update in self.callback_updates {
            match update {
                CallbackUpdate::Register(expected_id, mut callback) => {
                    if let Some(receiver) = callback_changes.get(&expected_id) {
                        callback.respondent = *receiver;
                    }
                    let id = system_state
                        .register_callback(callback)
                        .map_err(|_| Self::error("Call context manager does not exist"))?;
                    if id != expected_id {
                        return Err(Self::error("Failed to register update callback"));
                    }
                }
                CallbackUpdate::Unregister(callback_id) => {
                    system_state
                        .unregister_callback(callback_id)
                        .map_err(|_| Self::error("Call context manager does not exist"))?
                        .ok_or_else(|| {
                            Self::error("Tried to unregister callback with an ID that isn't in use")
                        })?;
                }
            }
        }

        // Verify new certified data isn't too long and set it.
        if let Some(certified_data) = self.new_certified_data.as_ref() {
            if certified_data.len() > CERTIFIED_DATA_MAX_LENGTH {
                return Err(Self::error("Certified data is too large"));
            }
            system_state.certified_data.clone_from(certified_data);
        }

        // Update canister global timer
        if let Some(new_global_timer) = self.new_global_timer {
            system_state.global_timer = new_global_timer;
        }

        // Append canister log.
        system_state.canister_log.append(&mut self.canister_log);

        // Bump the canister version after all changes have been applied.
        if self.should_bump_canister_version {
            system_state.canister_version += 1;
        }

        Ok(request_stats)
    }

    /// Applies the balance change to the given state.
    pub fn apply_balance_changes(&self, state: &mut SystemState) {
        let initial_balance = state.balance();

        // `self.cycles_balance_change` consists of:
        // - CyclesBalanceChange::added(cycles_accepted_from_the_call_context)
        // - CyclesBalanceChange::remove(cycles_sent_via_outgoing_calls)
        // - CyclesBalanceChange::remove(cycles_consumed_by_various_fees)
        // - CyclesBalanceChange::remove(reserved_cycles)
        //
        // The latter two cases are applied with higher-level helpers, so we
        // need to compute the balance change with those cases excluded.
        let mut adjusted_balance_change = self.cycles_balance_change;
        for (_use_case, amount) in self.consumed_cycles_by_use_case.iter() {
            adjusted_balance_change = adjusted_balance_change + CyclesBalanceChange::added(*amount)
        }

        // Exclude the reserved cycles.
        adjusted_balance_change =
            adjusted_balance_change + CyclesBalanceChange::added(self.reserved_cycles);

        // Apply the main cycles balance change without the consumed and reserved cycles.
        match adjusted_balance_change {
            CyclesBalanceChange::Added(added) => {
                state.add_cycles(added, CyclesUseCase::NonConsumed)
            }
            CyclesBalanceChange::Removed(removed) => {
                state.remove_cycles(removed, CyclesUseCase::NonConsumed)
            }
        }

        // Apply the consumed cycles with the use case metrics recording.
        for (use_case, amount) in self.consumed_cycles_by_use_case.iter() {
            state.remove_cycles(*amount, *use_case);
        }

        // Apply the reserved cycles. This must succeed because the cycle
        // changes were validated. If it doesn't succeed then, it is better to
        // crash here to avoid making the cycle balance incorrect.
        state.reserve_cycles(self.reserved_cycles).unwrap();

        // All changes applied above should be equivalent to simply applying
        // `self.cycles_balance_change` to the initial balance.
        let expected_balance = match self.cycles_balance_change {
            CyclesBalanceChange::Added(added) => initial_balance + added,
            CyclesBalanceChange::Removed(removed) => initial_balance - removed,
        };
        assert_eq!(state.balance(), expected_balance);
    }

    fn add_consumed_cycles(&mut self, consumed_cycles: &[(CyclesUseCase, Cycles)]) {
        for (use_case, amount) in consumed_cycles.iter() {
            *self
                .consumed_cycles_by_use_case
                .entry(*use_case)
                .or_insert_with(|| Cycles::new(0)) += *amount;
        }
    }

    #[cfg(test)]
    fn default_with_cycles_changes(
        cycles_balance_change: CyclesBalanceChange,
        consumed_cycles_by_use_case: BTreeMap<CyclesUseCase, Cycles>,
    ) -> SystemStateModifications {
        SystemStateModifications {
            cycles_balance_change,
            consumed_cycles_by_use_case,
            ..Default::default()
        }
    }
}

/// A version of the `SystemState` that can be used in a sandboxed process.
/// Changes are separately tracked so that we can verify the changes are valid
/// before applying them to the actual system state.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SandboxSafeSystemState {
    /// Only public for tests
    #[doc(hidden)]
    pub system_state_modifications: SystemStateModifications,
    pub(super) canister_id: CanisterId,
    pub(super) status: CanisterStatusView,
    pub(super) subnet_type: SubnetType,
    pub(super) subnet_size: usize,
    pub(super) cost_schedule: CanisterCyclesCostSchedule,
    dirty_page_overhead: NumInstructions,
    freeze_threshold: NumSeconds,
    memory_allocation: MemoryAllocation,
    wasm_memory_threshold: NumBytes,
    compute_allocation: ComputeAllocation,
    environment_variables: BTreeMap<String, String>,
    initial_cycles_balance: Cycles,
    initial_reserved_balance: Cycles,
    reserved_balance_limit: Option<Cycles>,
    call_context_balance: Option<Cycles>,
    call_context_deadline: Option<CoarseTime>,
    cycles_account_manager: CyclesAccountManager,
    // None indicates that we are in a context where the canister cannot
    // register callbacks (e.g. running the `start` method when installing a
    // canister.)
    next_callback_id: Option<u64>,
    /// The number of calls / callbacks that can still be made. This is the maximum
    /// available in either the subnet shared pool or the canister quota.
    available_callbacks: u64,
    available_request_slots: BTreeMap<CanisterId, usize>,
    ic00_available_request_slots: usize,
    ic00_aliases: BTreeSet<CanisterId>,
    global_timer: CanisterTimer,
    canister_version: u64,
    controllers: BTreeSet<PrincipalId>,
    pub(super) request_metadata: RequestMetadata,
    caller: Option<PrincipalId>,
    pub is_wasm64_execution: bool,
    network_topology: NetworkTopology,
}

impl SandboxSafeSystemState {
    /// Only public for use in tests.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_internal(
        canister_id: CanisterId,
        status: CanisterStatusView,
        freeze_threshold: NumSeconds,
        memory_allocation: MemoryAllocation,
        wasm_memory_threshold: NumBytes,
        compute_allocation: ComputeAllocation,
        environment_variables: BTreeMap<String, String>,
        initial_cycles_balance: Cycles,
        initial_reserved_balance: Cycles,
        reserved_balance_limit: Option<Cycles>,
        call_context_id: Option<CallContextId>,
        call_context_balance: Option<Cycles>,
        call_context_deadline: Option<CoarseTime>,
        cycles_account_manager: CyclesAccountManager,
        next_callback_id: Option<u64>,
        available_callbacks: u64,
        available_request_slots: BTreeMap<CanisterId, usize>,
        ic00_available_request_slots: usize,
        ic00_aliases: BTreeSet<CanisterId>,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        dirty_page_overhead: NumInstructions,
        global_timer: CanisterTimer,
        canister_version: u64,
        controllers: BTreeSet<PrincipalId>,
        request_metadata: RequestMetadata,
        caller: Option<PrincipalId>,
        next_canister_log_record_idx: u64,
        is_wasm64_execution: bool,
        network_topology: NetworkTopology,
    ) -> Self {
        Self {
            canister_id,
            status,
            subnet_type: cycles_account_manager.subnet_type(),
            subnet_size,
            cost_schedule,
            dirty_page_overhead,
            freeze_threshold,
            memory_allocation,
            environment_variables,
            wasm_memory_threshold,
            compute_allocation,
            system_state_modifications: SystemStateModifications {
                // Start indexing new batch of canister log records from the given index.
                canister_log: CanisterLog::new_with_next_index(next_canister_log_record_idx),
                call_context_balance_taken: call_context_id
                    .map(|call_context_id| (call_context_id, Cycles::zero())),
                ..SystemStateModifications::default()
            },
            initial_cycles_balance,
            initial_reserved_balance,
            reserved_balance_limit,
            call_context_balance,
            call_context_deadline,
            cycles_account_manager,
            next_callback_id,
            available_callbacks,
            available_request_slots,
            ic00_available_request_slots,
            ic00_aliases,
            global_timer,
            canister_version,
            controllers,
            request_metadata,
            caller,
            is_wasm64_execution,
            network_topology,
        }
    }

    pub fn new_for_testing(
        system_state: &SystemState,
        cycles_account_manager: CyclesAccountManager,
        network_topology: &NetworkTopology,
        dirty_page_overhead: NumInstructions,
        compute_allocation: ComputeAllocation,
        available_callbacks: u64,
        request_metadata: RequestMetadata,
        caller: Option<PrincipalId>,
        call_context_id: Option<CallContextId>,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Self {
        Self::new(
            system_state,
            cycles_account_manager,
            network_topology,
            dirty_page_overhead,
            compute_allocation,
            available_callbacks,
            request_metadata,
            caller,
            call_context_id,
            // We can assume a Wasm32 environment in tests for now.
            false,
            cost_schedule,
        )
    }

    pub fn new(
        system_state: &SystemState,
        cycles_account_manager: CyclesAccountManager,
        network_topology: &NetworkTopology,
        dirty_page_overhead: NumInstructions,
        compute_allocation: ComputeAllocation,
        available_callbacks: u64,
        request_metadata: RequestMetadata,
        caller: Option<PrincipalId>,
        call_context_id: Option<CallContextId>,
        is_wasm64_execution: bool,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Self {
        let call_context = call_context_id.and_then(|call_context_id| {
            system_state
                .call_context_manager()
                .and_then(|call_context_manager| {
                    call_context_manager.call_contexts().get(&call_context_id)
                })
        });

        let call_context_balance = call_context.map(|call_context| call_context.available_cycles());

        let call_context_deadline = call_context.and_then(|call_context| call_context.deadline());

        let available_request_slots = system_state.available_output_request_slots();

        // Compute the available slots for IC_00 requests as the minimum of available
        // slots across any queue to a subnet explicitly, the bitcoin canisters or
        // IC_00 itself.
        let mut ic00_aliases: BTreeSet<CanisterId> = network_topology
            .subnets
            .keys()
            .map(|id| CanisterId::unchecked_from_principal(id.get()))
            .collect();
        ic00_aliases.insert(CanisterId::ic_00());
        if let Some(bitcoin_testnet_canister_id) = network_topology.bitcoin_testnet_canister_id {
            ic00_aliases.insert(bitcoin_testnet_canister_id);
        }
        if let Some(bitcoin_mainnet_canister_id) = network_topology.bitcoin_mainnet_canister_id {
            ic00_aliases.insert(bitcoin_mainnet_canister_id);
        }
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
            CanisterStatusView::from_canister_status_type(system_state.status()),
            system_state.freeze_threshold,
            system_state.memory_allocation,
            system_state.wasm_memory_threshold,
            compute_allocation,
            system_state.environment_variables.clone().into(),
            system_state.balance(),
            system_state.reserved_balance(),
            system_state.reserved_balance_limit(),
            call_context_id,
            call_context_balance,
            call_context_deadline,
            cycles_account_manager,
            system_state
                .call_context_manager()
                .map(|c| c.next_callback_id()),
            available_callbacks,
            available_request_slots,
            ic00_available_request_slots,
            ic00_aliases,
            subnet_size,
            cost_schedule,
            dirty_page_overhead,
            system_state.global_timer,
            system_state.canister_version,
            system_state.controllers.clone(),
            request_metadata,
            caller,
            system_state.canister_log.next_idx(),
            is_wasm64_execution,
            network_topology.clone(),
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

    pub fn environment_variables(&self) -> &BTreeMap<String, String> {
        &self.environment_variables
    }

    pub fn cost_schedule(&self) -> CanisterCyclesCostSchedule {
        self.cost_schedule
    }

    pub fn set_global_timer(&mut self, timer: CanisterTimer) {
        // Update both sandbox global timer and the changes.
        self.system_state_modifications.new_global_timer = Some(timer);
        self.global_timer = timer;
    }

    pub fn take_changes(&mut self) -> SystemStateModifications {
        std::mem::take(&mut self.system_state_modifications)
    }

    /// Only public for use in tests.
    #[doc(hidden)]
    pub fn register_callback(&mut self, callback: Callback) -> HypervisorResult<CallbackId> {
        match &mut self.next_callback_id {
            Some(next_callback_id) => {
                *next_callback_id += 1;
                let id = CallbackId::from(*next_callback_id);
                self.system_state_modifications
                    .callback_updates
                    .push(CallbackUpdate::Register(id, callback));
                Ok(id)
            }
            None => Err(HypervisorError::ToolchainContractViolation {
                error: "Tried to register a callback in a context where it isn't allowed."
                    .to_string(),
            }),
        }
    }

    /// Only public for use in tests.
    #[doc(hidden)]
    pub fn unregister_callback(&mut self, id: CallbackId) {
        self.system_state_modifications
            .callback_updates
            .push(CallbackUpdate::Unregister(id))
    }

    /// Computes the current main balance of the canister based
    /// on the initial value and the changes during the execution.
    pub(super) fn cycles_balance(&self) -> Cycles {
        let cycles_change = self.system_state_modifications.cycles_balance_change;
        cycles_change.apply(self.initial_cycles_balance)
    }

    /// Computes the current liquid main balance of the canister that the canister can spend
    /// without getting frozen based on the initial value and the changes during the execution.
    pub(super) fn liquid_cycles_balance(
        &self,
        current_memory_usage: NumBytes,
        current_message_memory_usage: MessageMemoryUsage,
    ) -> Cycles {
        let cycles = self.cycles_balance();
        let threshold = self.cycles_account_manager.freeze_threshold_cycles(
            self.freeze_threshold,
            self.memory_allocation,
            current_memory_usage,
            current_message_memory_usage,
            self.compute_allocation,
            self.subnet_size,
            self.cost_schedule,
            self.reserved_balance(),
        );
        // Here we rely on the saturating subtraction for Cycles.
        cycles - threshold
    }

    /// Computes the current reserved balance of the canister based
    /// on the initial value and the changes during the execution.
    pub(super) fn reserved_balance(&self) -> Cycles {
        self.initial_reserved_balance + self.system_state_modifications.reserved_cycles
    }

    pub(super) fn msg_cycles_available(&self) -> Cycles {
        let initial_available = self.call_context_balance.unwrap_or(Cycles::zero());

        let already_taken = self
            .system_state_modifications
            .call_context_balance_taken
            .map_or(Cycles::zero(), |(_, balance_taken)| balance_taken);

        initial_available - already_taken
    }

    /// Returns the deadline of `CallContext`.
    pub fn msg_deadline(&self) -> CoarseTime {
        self.call_context_deadline.unwrap_or(NO_DEADLINE)
    }

    fn update_balance_change(&mut self, new_balance: Cycles) {
        self.system_state_modifications.cycles_balance_change =
            CyclesBalanceChange::new(self.initial_cycles_balance, new_balance);
    }

    /// Same as [`update_balance_change`], but asserts the balance has decreased
    /// and marks the difference as cycles consumed (i.e. burned and not
    /// transferred).
    fn update_balance_change_consuming(
        &mut self,
        new_balance: Cycles,
        consumed_cycles: &[(CyclesUseCase, Cycles)],
    ) {
        let old_balance = self.cycles_balance();
        assert!(
            new_balance <= old_balance,
            "Unexpected increase of cycles balances {} => {}",
            old_balance,
            new_balance
        );

        self.system_state_modifications
            .add_consumed_cycles(consumed_cycles);
        self.update_balance_change(new_balance);
    }

    pub(super) fn mint_cycles(&mut self, amount_to_mint: Cycles) -> HypervisorResult<Cycles> {
        let mut new_balance = self.cycles_balance();
        let result = self
            .cycles_account_manager
            .mint_cycles(self.canister_id, &mut new_balance, amount_to_mint)
            .map_err(|CyclesAccountManagerError::ContractViolation(msg)| {
                HypervisorError::ToolchainContractViolation { error: msg }
            });
        self.update_balance_change(new_balance);
        result
    }

    /// Burns min(balance - freezing_treshold, amount_to_burn) cycles from the canister's
    /// balance and returns the number of burned cycles.
    pub(super) fn cycles_burn128(
        &mut self,
        amount_to_burn: Cycles,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
    ) -> Cycles {
        let mut new_balance = self.cycles_balance();
        let burned_cycles = self.cycles_account_manager.cycles_burn(
            &mut new_balance,
            amount_to_burn,
            self.freeze_threshold,
            self.memory_allocation,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            self.compute_allocation,
            self.subnet_size,
            self.cost_schedule,
            self.reserved_balance(),
        );
        self.update_balance_change_consuming(
            new_balance,
            &[(CyclesUseCase::BurnedCycles, burned_cycles)],
        );
        burned_cycles
    }

    pub(super) fn refund_cycles(&mut self, cycles: Cycles) {
        let mut new_balance = self.cycles_balance();
        new_balance += cycles;
        self.update_balance_change(new_balance);
    }

    pub(super) fn msg_cycles_accept(&mut self, amount_to_accept: Cycles) -> Cycles {
        let mut new_balance = self.cycles_balance();

        // It is safe to unwrap since msg_cycles_accept and msg_cycles_accept128 are
        // available only forApiType::{Update, ReplicatedQuery, ReplyCallback,
        // RejectCallBack} and all of them have CallContextId, hence
        // SystemStateModifications::call_context_balance_taken will never be `None`.
        debug_assert!(self
            .system_state_modifications
            .call_context_balance_taken
            .is_some());

        let balance_taken = &mut self
            .system_state_modifications
            .call_context_balance_taken
            .as_mut()
            .unwrap()
            .1;

        // Scale amount that can be accepted by what is actually available on
        // the call context.
        let amount_available = Cycles::from(
            self.call_context_balance
                .unwrap()
                .get()
                .checked_sub(balance_taken.get())
                .unwrap(),
        );

        let amount_to_accept = std::cmp::min(amount_available, amount_to_accept);

        // Withdraw and accept the cycles
        *balance_taken += amount_to_accept;

        new_balance += amount_to_accept;

        self.update_balance_change(new_balance);
        amount_to_accept
    }

    pub fn prepayment_for_response_execution(&self) -> Cycles {
        self.cycles_account_manager
            .prepayment_for_response_execution(
                self.subnet_size,
                self.cost_schedule,
                WasmExecutionMode::from_is_wasm64(self.is_wasm64_execution),
            )
    }

    pub fn prepayment_for_response_transmission(&self) -> Cycles {
        self.cycles_account_manager
            .prepayment_for_response_transmission(self.subnet_size, self.cost_schedule)
    }

    pub(super) fn withdraw_cycles_for_transfer(
        &mut self,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        amount: Cycles,
        reveal_top_up: bool,
    ) -> HypervisorResult<()> {
        let mut new_balance = self.cycles_balance();
        let result = self
            .cycles_account_manager
            .withdraw_cycles_for_transfer(
                self.canister_id,
                self.freeze_threshold,
                self.memory_allocation,
                canister_current_memory_usage,
                canister_current_message_memory_usage,
                self.compute_allocation,
                &mut new_balance,
                amount,
                self.subnet_size,
                self.cost_schedule,
                self.reserved_balance(),
                reveal_top_up,
            )
            .map_err(HypervisorError::InsufficientCyclesBalance);
        self.update_balance_change(new_balance);
        result
    }

    #[allow(clippy::result_large_err)]
    pub fn push_output_request(
        &mut self,
        canister_current_memory_usage: NumBytes,
        canister_current_message_memory_usage: MessageMemoryUsage,
        msg: Request,
        prepayment_for_response_execution: Cycles,
        prepayment_for_response_transmission: Cycles,
    ) -> Result<(), Request> {
        if self.available_callbacks == 0 {
            return Err(msg);
        }
        self.available_callbacks -= 1;

        let mut new_balance = self.cycles_balance();
        let consumed_cycles = match self.cycles_account_manager.withdraw_request_cycles(
            self.canister_id,
            &mut new_balance,
            self.freeze_threshold,
            self.memory_allocation,
            canister_current_memory_usage,
            canister_current_message_memory_usage,
            self.compute_allocation,
            &msg,
            prepayment_for_response_execution,
            prepayment_for_response_transmission,
            self.subnet_size,
            self.cost_schedule,
            self.reserved_balance(),
            // if the canister is frozen, the controller should call canister_status
            // to learn the top up balance instead of getting it from an error
            // message to a canister method making downstream call
            false,
        ) {
            Ok(consumed_cycles) => consumed_cycles,
            Err(_) => return Err(msg),
        };

        // If the request is targeted to any of the known aliases of IC_00,
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
            .system_state_modifications
            .request_slots_used
            .entry(msg.receiver)
            .or_insert(0);
        if *used_slots >= *initial_available_slots {
            return Err(msg);
        }
        self.system_state_modifications.requests.push(msg);
        *used_slots += 1;
        self.update_balance_change_consuming(new_balance, &consumed_cycles);
        Ok(())
    }

    /// Calculate the cost for newly created dirty pages.
    pub fn dirty_page_cost(&self, dirty_pages: NumOsPages) -> HypervisorResult<NumInstructions> {
        let (inst, overflow) = dirty_pages
            .get()
            .overflowing_mul(self.dirty_page_overhead.get());
        if overflow {
            Err(HypervisorError::ToolchainContractViolation{error: format!("Overflow calculating instruction cost for dirty pages - conversion rate: {}, dirty_pages: {}", self.dirty_page_overhead, dirty_pages)})
        } else {
            Ok(NumInstructions::from(inst))
        }
    }

    pub fn is_controller(&self, principal_id: &PrincipalId) -> bool {
        self.controllers.contains(principal_id)
    }

    /// Checks the cycles balance against the freezing threshold with the new
    /// memory usage if that's needed for the given API type.
    ///
    /// If the old memory usage is higher than the new memory usage, then
    /// no check is performed.
    ///
    /// Returns `Err(HypervisorError::InsufficientCyclesInMemoryGrow)` if the
    /// canister would become frozen with the new memory usage.
    /// Otherwise, returns `Ok(())`.
    pub(super) fn check_freezing_threshold_for_memory_grow(
        &self,
        api_type: &ApiType,
        current_message_memory_usage: MessageMemoryUsage,
        old_memory_usage: NumBytes,
        new_memory_usage: NumBytes,
    ) -> HypervisorResult<()> {
        let should_check = self.should_check_freezing_threshold_for_memory_grow(api_type);
        if !should_check || old_memory_usage >= new_memory_usage {
            return Ok(());
        }
        match self.memory_allocation {
            MemoryAllocation::Reserved(limit) if new_memory_usage <= limit => Ok(()),
            MemoryAllocation::Reserved(_) | MemoryAllocation::BestEffort => {
                // Note that currently the memory usage of a canister cannot
                // exceed its reserved limit. The `Reserved(_)` case is
                // actually unreachable here, but we still handle it to keep
                // this code robust.
                let threshold = self.cycles_account_manager.freeze_threshold_cycles(
                    self.freeze_threshold,
                    self.memory_allocation,
                    new_memory_usage,
                    current_message_memory_usage,
                    self.compute_allocation,
                    self.subnet_size,
                    self.cost_schedule,
                    self.reserved_balance(),
                );
                if self.cycles_balance() >= threshold {
                    Ok(())
                } else {
                    Err(HypervisorError::InsufficientCyclesInMemoryGrow {
                        bytes: new_memory_usage - old_memory_usage,
                        available: self.cycles_balance(),
                        threshold,
                        reveal_top_up: self.caller_is_controller(),
                    })
                }
            }
        }
    }

    /// Checks the cycles balance against the freezing threshold with the new total
    /// (guaranteed response plus best-effort) message memory usage if that's needed
    /// for the given API type.
    ///
    /// If the old message memory usage is higher than the new message memory usage,
    /// then no check is performed.
    ///
    /// Returns `Err(HypervisorError::InsufficientCyclesInMessageMemoryGrow)`
    /// if the canister would become frozen with the new message memory usage.
    /// Otherwise, returns `Ok(())`.
    pub(super) fn check_freezing_threshold_for_message_memory_grow(
        &self,
        api_type: &ApiType,
        current_memory_usage: NumBytes,
        old_message_memory_usage: MessageMemoryUsage,
        new_message_memory_usage: MessageMemoryUsage,
    ) -> HypervisorResult<()> {
        let should_check = self.should_check_freezing_threshold_for_memory_grow(api_type);
        if !should_check || old_message_memory_usage.total() >= new_message_memory_usage.total() {
            return Ok(());
        }

        let threshold = self.cycles_account_manager.freeze_threshold_cycles(
            self.freeze_threshold,
            self.memory_allocation,
            current_memory_usage,
            new_message_memory_usage,
            self.compute_allocation,
            self.subnet_size,
            self.cost_schedule,
            self.reserved_balance(),
        );
        if self.cycles_balance() >= threshold {
            Ok(())
        } else {
            Err(HypervisorError::InsufficientCyclesInMessageMemoryGrow {
                bytes: new_message_memory_usage.total() - old_message_memory_usage.total(),
                available: self.cycles_balance(),
                threshold,
                reveal_top_up: self.caller_is_controller(),
            })
        }
    }

    // Returns `true` if the freezing threshold needs to be checked for the given
    // API type when growing memory.
    fn should_check_freezing_threshold_for_memory_grow(&self, api_type: &ApiType) -> bool {
        match api_type {
            ApiType::Update { .. } | ApiType::SystemTask { .. } => true,

            ApiType::Start { .. } | ApiType::Init { .. } | ApiType::PreUpgrade { .. } => {
                // Individual endpoints of install_code do not check the
                // freezing threshold. Instead, it is checked at the end of
                // install_code.
                false
            }

            ApiType::InspectMessage { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. } => {
                // Queries do not check the freezing threshold because the state
                // changes are disarded anyways.
                false
            }

            ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::Cleanup { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::CompositeCleanup { .. } => {
                // Response callbacks are specified to not check the freezing
                // threshold.
                false
            }
        }
    }

    /// Reserves cycles for the given number of allocated bytes at the given
    /// subnet memory saturation if:
    /// - the message type requires reservation and
    /// - the canister has a best-effort memory allocation and
    /// - there are enough cycles in the main balance.
    ///
    /// The reserved cycles are removed from the main balance and added to the
    /// reserved balance. In pseudocode, reserving means:
    ///   - `self.system_state_modifications.cycles_balance_change -= reserved_cycles`
    ///   - `self.system_state_modifications.reserved_cycles += reserved_cycles`
    pub(super) fn reserve_storage_cycles(
        &mut self,
        allocated_bytes: NumBytes,
        subnet_memory_saturation: &ResourceSaturation,
        api_type: &ApiType,
    ) -> HypervisorResult<()> {
        if !self.should_reserve_storage_cycles(api_type) {
            return Ok(());
        }
        match self.memory_allocation {
            MemoryAllocation::Reserved(_) => Ok(()),
            MemoryAllocation::BestEffort => {
                let cycles_to_reserve = self.cycles_account_manager.storage_reservation_cycles(
                    allocated_bytes,
                    subnet_memory_saturation,
                    self.subnet_size,
                    self.cost_schedule,
                );

                if let Some(limit) = self.reserved_balance_limit {
                    if self.reserved_balance() + cycles_to_reserve > limit {
                        return Err(HypervisorError::ReservedCyclesLimitExceededInMemoryGrow {
                            bytes: allocated_bytes,
                            requested: self.reserved_balance() + cycles_to_reserve,
                            limit,
                        });
                    }
                }

                let old_balance = self.cycles_balance();
                if old_balance < cycles_to_reserve {
                    return Err(HypervisorError::InsufficientCyclesInMemoryGrow {
                        bytes: allocated_bytes,
                        available: old_balance,
                        threshold: cycles_to_reserve,
                        reveal_top_up: self.caller_is_controller(),
                    });
                }
                let new_balance = old_balance - cycles_to_reserve;
                self.update_balance_change(new_balance);
                self.system_state_modifications.reserved_cycles += cycles_to_reserve;
                Ok(())
            }
        }
    }

    /// Condition for `OnLowWasmMemoryHook` is satisfied if the following holds:
    ///
    /// 1. In the case of `memory_allocation`
    ///    `wasm_memory_threshold >= min(memory_allocation - memory_usage_without_wasm_memory, wasm_memory_limit) - wasm_memory_usage`
    /// 2. Without memory allocation
    ///    `wasm_memory_threshold >= wasm_memory_limit - wasm_memory_usage`
    ///
    /// Note: if `wasm_memory_limit` is not set, its default value is 4 GiB.
    pub fn update_status_of_low_wasm_memory_hook_condition(
        &mut self,
        memory_allocation: Option<NumBytes>,
        wasm_memory_limit: Option<NumBytes>,
        memory_usage: NumBytes,
        wasm_memory_usage: NumBytes,
    ) {
        let is_condition_satisfied = is_low_wasm_memory_hook_condition_satisfied(
            memory_usage,
            wasm_memory_usage,
            memory_allocation,
            wasm_memory_limit,
            self.wasm_memory_threshold,
        );

        self.system_state_modifications
            .on_low_wasm_memory_hook_condition_check_result = Some(is_condition_satisfied);
    }

    // Returns `true` if storage cycles need to be reserved for the given
    // API type when growing memory.
    fn should_reserve_storage_cycles(&self, api_type: &ApiType) -> bool {
        match api_type {
            ApiType::Update { .. }
            | ApiType::SystemTask { .. }
            | ApiType::ReplyCallback { .. }
            | ApiType::RejectCallback { .. }
            | ApiType::Cleanup { .. } => true,

            ApiType::Start { .. } | ApiType::Init { .. } | ApiType::PreUpgrade { .. } => {
                // Individual endpoints of install_code do not reserve cycles.
                // Instead, it is reserved at the end of install_code.
                false
            }

            ApiType::InspectMessage { .. }
            | ApiType::ReplicatedQuery { .. }
            | ApiType::NonReplicatedQuery { .. }
            | ApiType::CompositeQuery { .. }
            | ApiType::CompositeReplyCallback { .. }
            | ApiType::CompositeRejectCallback { .. }
            | ApiType::CompositeCleanup { .. } => {
                // Queries do not reserve storage cycles because the state
                // changes are discarded anyways.
                false
            }
        }
    }

    /// Appends a log record to the system state changes.
    pub fn append_canister_log(&mut self, time: &Time, content: Vec<u8>) {
        self.system_state_modifications
            .canister_log
            .add_record(time.as_nanos_since_unix_epoch(), content);
    }

    /// Takes collected canister log records.
    pub fn take_canister_log(&mut self) -> CanisterLog {
        std::mem::take(&mut self.system_state_modifications.canister_log)
    }

    /// Returns collected canister log records.
    pub fn canister_log(&self) -> &CanisterLog {
        &self.system_state_modifications.canister_log
    }

    fn caller_is_controller(&self) -> bool {
        if let Some(caller) = self.caller {
            self.controllers.contains(&caller)
        } else {
            false
        }
    }

    pub fn get_root_key(&self) -> Vec<u8> {
        let root_subnet_id = self.network_topology.nns_subnet_id;
        self.network_topology
            .subnets
            .get(&root_subnet_id)
            .map(|subnet_topology| subnet_topology.public_key.clone())
            .unwrap_or(IC_ROOT_KEY.to_vec())
    }

    pub fn get_subnet_id(&self) -> SubnetId {
        self.cycles_account_manager.get_subnet_id()
    }

    pub fn get_cycles_account_manager(&self) -> &CyclesAccountManager {
        &self.cycles_account_manager
    }

    /// Look up key in `chain_key_enabled_subnets`, then extract all subnets
    /// for that key and return the replication factor of the biggest one.
    pub fn get_key_replication_factor(&self, key: MasterPublicKeyId) -> Option<usize> {
        let subnets_with_key = self.network_topology.chain_key_enabled_subnets(&key);
        subnets_with_key
            .iter()
            .map(|subnet_id| {
                self.network_topology.get_subnet_size(subnet_id).unwrap() // we got the subnet_id from the same collection
            })
            .max()
    }
}

/// Holds the metadata and the number of downstream requests. Requests created during the same
/// execution have the same metadata. This fact is reflected by the use of a counter, rather than
/// a list of identical metadata.
///
/// This is used for call tree metrics.
pub struct RequestMetadataStats {
    pub metadata: RequestMetadata,
    pub best_effort_request_count: u64,
    pub guaranteed_response_request_count: u64,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ic_base_types::NumSeconds;
    use ic_config::subnet_config::{CyclesAccountManagerConfig, SchedulerConfig};
    use ic_cycles_account_manager::CyclesAccountManager;
    use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        canister_state::system_state::CyclesUseCase, NetworkTopology, SystemState,
    };
    use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id, user_test_id};
    use ic_types::{
        batch::CanisterCyclesCostSchedule,
        messages::{RequestMetadata, NO_DEADLINE},
        time::CoarseTime,
        CanisterTimer, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
        Time,
    };

    use super::{CanisterStatusView, SandboxSafeSystemState, SystemStateModifications};
    use crate::wasmtime_embedder::system_api::cycles_balance_change::CyclesBalanceChange;

    #[test]
    fn test_apply_balance_changes() {
        let mut system_state = SystemState::new_running_for_testing(
            canister_test_id(0),
            user_test_id(1).get(),
            Cycles::new(1_000_000_000),
            NumSeconds::from(100_000),
        );

        let initial_cycles_balance = system_state.balance();

        let removed = Cycles::new(500_000);
        let consumed = Cycles::new(100_000);
        let system_state_modifications = SystemStateModifications::default_with_cycles_changes(
            CyclesBalanceChange::Removed(removed),
            BTreeMap::from([(CyclesUseCase::RequestAndResponseTransmission, consumed)]),
        );

        system_state_modifications.apply_balance_changes(&mut system_state);

        assert_eq!(initial_cycles_balance - removed, system_state.balance());

        let initial_cycles_balance = system_state.balance();

        let removed = Cycles::new(500_000);
        let consumed = Cycles::new(600_000);
        let system_state_modifications = SystemStateModifications::default_with_cycles_changes(
            CyclesBalanceChange::Removed(removed),
            BTreeMap::from([(CyclesUseCase::RequestAndResponseTransmission, consumed)]),
        );

        system_state_modifications.apply_balance_changes(&mut system_state);

        assert_eq!(initial_cycles_balance - removed, system_state.balance());

        let initial_cycles_balance = system_state.balance();

        let added = Cycles::new(500_000);
        let consumed = Cycles::new(100_000);
        let system_state_modifications = SystemStateModifications::default_with_cycles_changes(
            CyclesBalanceChange::Added(added),
            BTreeMap::from([(CyclesUseCase::RequestAndResponseTransmission, consumed)]),
        );

        system_state_modifications.apply_balance_changes(&mut system_state);

        assert_eq!(initial_cycles_balance + added, system_state.balance());

        let initial_cycles_balance = system_state.balance();

        let added = Cycles::new(500_000);
        let consumed = Cycles::new(600_000);
        let system_state_modifications = SystemStateModifications::default_with_cycles_changes(
            CyclesBalanceChange::Added(added),
            BTreeMap::from([(CyclesUseCase::RequestAndResponseTransmission, consumed)]),
        );

        system_state_modifications.apply_balance_changes(&mut system_state);

        assert_eq!(initial_cycles_balance + added, system_state.balance());
    }

    fn helper_msg_deadline(call_context_deadline: Option<CoarseTime>) -> CoarseTime {
        let sandbox_state = SandboxSafeSystemState::new_internal(
            canister_test_id(0),
            CanisterStatusView::Running,
            NumSeconds::from(3600),
            MemoryAllocation::BestEffort,
            NumBytes::new(0),
            ComputeAllocation::default(),
            Default::default(),
            Cycles::new(1_000_000),
            Cycles::zero(),
            None,
            None,
            None,
            call_context_deadline,
            CyclesAccountManager::new(
                NumInstructions::from(1_000_000_000),
                SubnetType::Application,
                subnet_test_id(0),
                CyclesAccountManagerConfig::application_subnet(),
            ),
            Some(0),
            0,
            BTreeMap::new(),
            0,
            BTreeSet::new(),
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
            SchedulerConfig::application_subnet().dirty_page_overhead,
            CanisterTimer::Inactive,
            0,
            BTreeSet::new(),
            RequestMetadata::new(0, Time::from_nanos_since_unix_epoch(0)),
            None,
            0,
            // Wasm32 execution environment. Sufficient in testing.
            false,
            NetworkTopology::default(),
        );
        sandbox_state.msg_deadline()
    }

    #[test]
    fn test_msg_deadline() {
        // `NO_DEADLINE` is returned when CallContext does not have `deadline` set.
        assert_eq!(helper_msg_deadline(None), NO_DEADLINE);

        let deadline = CoarseTime::from_secs_since_unix_epoch(100);

        // Otherwise the correct `deadline` is returned.
        assert_eq!(helper_msg_deadline(Some(deadline)), deadline);
    }

    fn helper_create_state_for_hook_status(wasm_memory_threshold: u64) -> SandboxSafeSystemState {
        SandboxSafeSystemState::new_internal(
            canister_test_id(0),
            CanisterStatusView::Running,
            NumSeconds::from(3600),
            MemoryAllocation::BestEffort,
            NumBytes::new(wasm_memory_threshold),
            ComputeAllocation::default(),
            Default::default(),
            Cycles::new(1_000_000),
            Cycles::zero(),
            None,
            None,
            None,
            None,
            CyclesAccountManager::new(
                NumInstructions::from(1_000_000_000),
                SubnetType::Application,
                subnet_test_id(0),
                CyclesAccountManagerConfig::application_subnet(),
            ),
            Some(0),
            0,
            BTreeMap::new(),
            0,
            BTreeSet::new(),
            SMALL_APP_SUBNET_MAX_SIZE,
            CanisterCyclesCostSchedule::Normal,
            SchedulerConfig::application_subnet().dirty_page_overhead,
            CanisterTimer::Inactive,
            0,
            BTreeSet::new(),
            RequestMetadata::new(0, Time::from_nanos_since_unix_epoch(0)),
            None,
            0,
            // Wasm32 execution environment. Sufficient in testing.
            false,
            NetworkTopology::default(),
        )
    }

    const GIB: u64 = 1 << 30;

    fn helper_is_condition_satisfied_for_on_low_wasm_memory_hook(
        wasm_memory_threshold: u64,
        memory_allocation: Option<u64>,
        wasm_memory_limit: Option<u64>,
        memory_usage: u64,
        wasm_memory_usage: u64,
    ) -> bool {
        let wasm_memory_limit = wasm_memory_limit.unwrap_or(4 * GIB);
        let memory_usage_without_wasm_memory = memory_usage - wasm_memory_usage;
        let wasm_capacity = memory_allocation.map_or(wasm_memory_limit, |memory_allocation| {
            std::cmp::min(
                memory_allocation - memory_usage_without_wasm_memory,
                wasm_memory_limit,
            )
        });

        wasm_capacity < wasm_memory_usage + wasm_memory_threshold
    }
    #[test]
    fn test_on_low_wasm_memory_hook_condition_update() {
        for wasm_memory_threshold in [0, GIB, 2 * GIB, 3 * GIB, 4 * GIB] {
            for memory_allocation in [None, Some(GIB), Some(2 * GIB), Some(3 * GIB), Some(4 * GIB)]
            {
                for wasm_memory_limit in
                    [None, Some(GIB), Some(2 * GIB), Some(3 * GIB), Some(4 * GIB)]
                {
                    for memory_usage_without_wasm_memory in [0, GIB] {
                        for wasm_memory_usage in [0, GIB, 2 * GIB, 3 * GIB, 4 * GIB] {
                            let mut state =
                                helper_create_state_for_hook_status(wasm_memory_threshold);

                            assert_eq!(
                                state
                                    .system_state_modifications
                                    .on_low_wasm_memory_hook_condition_check_result,
                                None
                            );

                            let memory_usage = wasm_memory_usage + memory_usage_without_wasm_memory;

                            state.update_status_of_low_wasm_memory_hook_condition(
                                memory_allocation.map(|m| m.into()),
                                wasm_memory_limit.map(|m| m.into()),
                                memory_usage.into(),
                                wasm_memory_usage.into(),
                            );

                            assert_eq!(
                                state
                                    .system_state_modifications
                                    .on_low_wasm_memory_hook_condition_check_result
                                    .unwrap(),
                                helper_is_condition_satisfied_for_on_low_wasm_memory_hook(
                                    wasm_memory_threshold,
                                    memory_allocation,
                                    wasm_memory_limit,
                                    memory_usage,
                                    wasm_memory_usage
                                )
                            );
                        }
                    }
                }
            }
        }
    }
}
