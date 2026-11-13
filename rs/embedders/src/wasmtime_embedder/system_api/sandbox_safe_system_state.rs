use std::collections::{BTreeMap, BTreeSet};

use super::{
    ApiType, CERTIFIED_DATA_MAX_LENGTH, cycles_balance_change::CyclesBalanceChange, routing,
    routing::ResolveDestinationError,
};
use ic_base_types::{CanisterId, NumBytes, NumSeconds, PrincipalId, SubnetId};
use ic_cycles_account_manager::{
    CyclesAccountManager, CyclesAccountManagerError, ResourceSaturation,
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult, MessageMemoryUsage};
use ic_limits::LOG_CANISTER_OPERATION_CYCLES_THRESHOLD;
use ic_logger::{ReplicaLogger, info};
use ic_management_canister_types_private::{
    CanisterStatusType, CreateCanisterArgs, IC_00, InstallChunkedCodeArgs, InstallCodeArgsV2,
    LoadCanisterSnapshotArgs, MasterPublicKeyId, Method as Ic00Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs, RenameCanisterArgs, TakeCanisterSnapshotArgs,
    UninstallCodeArgs, UpdateSettingsArgs,
};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::execution_state::WasmExecutionMode;
use ic_replicated_state::{
    CallOrigin, NetworkTopology, OutputRequest, SystemState, canister_state::DEFAULT_QUEUE_CAPACITY,
};
use ic_types::canister_log::CanisterLogMetrics;
use ic_types::{
    CanisterLog, CanisterTimer, ComputeAllocation, MemoryAllocation, Time,
    messages::{CallContextId, NO_DEADLINE, RejectContext, RequestMetadata},
    time::CoarseTime,
};
use ic_types_cycles::{
    BurnedCycles, CompoundCycles, Cycles, CyclesAccountManagerSubnetConfig, CyclesUseCaseKind,
    Instructions, RequestAndResponseTransmission,
};
use ic_wasm_types::WasmEngineError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

/// The ICP mainnet root key.
const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

/// The information that canisters can see about their own status.
#[derive(Copy, Clone, PartialEq, Debug, Deserialize, Serialize)]
pub enum CanisterStatusView {
    Running = 1,
    Stopping = 2,
    Stopped = 3,
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

/// Cycles consumed via System API calls during message execution.
#[derive(Copy, Clone, PartialEq, Debug, Default, Deserialize, Serialize)]
pub(crate) struct ConsumedCyclesDuringExecution {
    burned: Option<CompoundCycles<BurnedCycles>>,
    instructions: Option<CompoundCycles<Instructions>>,
    request_and_response_transmission: Option<CompoundCycles<RequestAndResponseTransmission>>,
}

impl ConsumedCyclesDuringExecution {
    // Returns a list of the real amounts that the canister's balance should be
    // updated with.
    fn iter_over_real(&self) -> Vec<Cycles> {
        // Decompose self to force the compiler to complain in case new fields
        // are added.
        let ConsumedCyclesDuringExecution {
            burned,
            instructions,
            request_and_response_transmission,
        } = self;

        let mut res = vec![];
        if let Some(x) = burned {
            res.push(x.real());
        }
        if let Some(x) = instructions {
            res.push(x.real());
        }
        if let Some(x) = request_and_response_transmission {
            res.push(x.real());
        }
        res
    }

    // Merges `other` onto `self`. If both contain fields that are
    // not `None` then the result is the sum of the values contained,
    // otherwise the resulting merge amount is set to the one that
    // contains a value.
    fn merge(&mut self, other: ConsumedCyclesDuringExecution) {
        fn merge_helper<T: CyclesUseCaseKind>(
            first: Option<CompoundCycles<T>>,
            second: Option<CompoundCycles<T>>,
        ) -> Option<CompoundCycles<T>> {
            match (first, second) {
                (Some(x), Some(y)) => Some(x + y),
                (Some(x), None) => Some(x),
                (None, Some(y)) => Some(y),
                (None, None) => None,
            }
        }

        self.burned = merge_helper(self.burned, other.burned);
        self.instructions = merge_helper(self.instructions, other.instructions);
        self.request_and_response_transmission = merge_helper(
            self.request_and_response_transmission,
            other.request_and_response_transmission,
        );
    }
}

/// Tracks changes to the system state that the canister has requested.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SystemStateModifications {
    pub(super) new_certified_data: Option<Vec<u8>>,
    pub(super) cycles_balance_change: CyclesBalanceChange,
    // The cycles that move from the main balance to the reserved balance.
    // Invariant: `cycles_balance_change` contains
    // `CyclesBalanceChange::Removed(reserved_cycles)`.
    pub(super) reserved_cycles: Cycles,
    pub(super) consumed_cycles_by_use_case: ConsumedCyclesDuringExecution,
    pub(super) call_context_balance_taken: Option<(CallContextId, Cycles)>,
    pub(super) request_slots_used: BTreeMap<CanisterId, usize>,
    pub(super) requests: Vec<OutputRequest>,
    pub(super) new_global_timer: Option<CanisterTimer>,
    pub(super) canister_log: CanisterLog,
    pub(super) should_bump_canister_version: bool,
}

impl Default for SystemStateModifications {
    fn default() -> Self {
        Self {
            new_certified_data: None,
            cycles_balance_change: CyclesBalanceChange::zero(),
            reserved_cycles: Cycles::zero(),
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution::default(),
            call_context_balance_taken: None,
            request_slots_used: BTreeMap::new(),
            requests: vec![],
            new_global_timer: None,
            canister_log: CanisterLog::default_delta(),
            should_bump_canister_version: false,
        }
    }
}

/// Appends the given canister log records produced by an execution to the
/// canister log of the given system state, leaving `delta_log` empty.
pub fn append_canister_log<Metrics: CanisterLogMetrics>(
    delta_log: &mut CanisterLog,
    system_state: &mut SystemState,
    metrics: &Metrics,
) {
    if !delta_log.is_empty() {
        metrics.observe_delta_log_size(delta_log.bytes_used());
    }
    system_state.log_memory_store.append_delta_log(delta_log);
}

impl SystemStateModifications {
    /// Checks that the sum of the given prepayments (real and nominal parts
    /// separately) equals the consumed cycles of the corresponding use case.
    fn validate_prepayment_total<T: CyclesUseCaseKind>(
        prepayments: impl Iterator<Item = CompoundCycles<T>>,
        consumed: Option<CompoundCycles<T>>,
        description: &str,
    ) -> HypervisorResult<()> {
        let overflow = || {
            Self::error(format!(
                "Invalid request prepayments: {description} prepayments overflow"
            ))
        };
        let (mut real, mut nominal) = (0_u128, 0_u128);
        for prepayment in prepayments {
            real = real
                .checked_add(prepayment.real().get())
                .ok_or_else(overflow)?;
            nominal = nominal
                .checked_add(prepayment.nominal().get())
                .ok_or_else(overflow)?;
        }
        let (consumed_real, consumed_nominal) =
            consumed.map_or((0, 0), |c| (c.real().get(), c.nominal().get()));
        if (real, nominal) != (consumed_real, consumed_nominal) {
            return Err(Self::error(format!(
                "Invalid request prepayments: {description} prepayments total (real: {real}, nominal: {nominal}), but consumed cycles are (real: {consumed_real}, nominal: {consumed_nominal})"
            )));
        }
        Ok(())
    }

    /// Checks that every cycle prepayment stored in an outgoing request is
    /// backed by cycles consumed during this execution.
    fn validate_request_prepayments(&self) -> HypervisorResult<()> {
        for request in &self.requests {
            let response = request.prepayment_for_response_transmission;
            let call = request.prepayment_for_call_transmission;
            if response.real() > call.real() || response.nominal() > call.nominal() {
                return Err(Self::error(format!(
                    "Invalid request prepayments: response transmission prepayment {:?} exceeds call transmission prepayment {:?}",
                    response, call
                )));
            }
        }

        Self::validate_prepayment_total(
            self.requests
                .iter()
                .map(|request| request.prepayment_for_response_execution),
            self.consumed_cycles_by_use_case.instructions,
            "response execution",
        )?;
        Self::validate_prepayment_total(
            self.requests
                .iter()
                .map(|request| request.prepayment_for_call_transmission),
            self.consumed_cycles_by_use_case
                .request_and_response_transmission,
            "call transmission",
        )
    }

    /// Checks that no cycles were created during the execution of this message
    /// (unless the canister is the cycles minting canister).
    fn validate_cycle_change(
        &self,
        system_state: &SystemState,
        is_composite_query: bool,
    ) -> HypervisorResult<()> {
        // Composite query state is ephemeral and intentionally retains outgoing
        // requests while discarding their cycle charges.
        if !is_composite_query {
            self.validate_request_prepayments()?;
        }

        let accepted_cycles = match self.call_context_balance_taken {
            Some((call_context_id, amount)) if !amount.is_zero() => {
                let available = system_state
                    .call_context_manager()
                    .and_then(|manager| manager.call_context(call_context_id))
                    .map(|context| context.available_cycles())
                    .ok_or_else(|| {
                        Self::error("Canister accepted cycles from invalid call context")
                    })?;
                if amount > available {
                    return Err(Self::error(format!(
                        "Canister accepted {} cycles from a call context with only {} cycles",
                        amount, available
                    )));
                }
                amount
            }
            Some((_, _)) | None => Cycles::zero(),
        };

        let mut removed_cycles = 0_u128;
        for amount in self
            .requests
            .iter()
            .map(|request| request.payment)
            .chain(self.consumed_cycles_by_use_case.iter_over_real())
            .chain(std::iter::once(self.reserved_cycles))
        {
            removed_cycles = removed_cycles
                .checked_add(amount.get())
                .ok_or_else(|| Self::error("Invalid cycle change: removed cycles overflow"))?;
        }
        let removed_cycles = Cycles::new(removed_cycles);
        let expected_change = if accepted_cycles >= removed_cycles {
            CyclesBalanceChange::added(accepted_cycles - removed_cycles)
        } else {
            CyclesBalanceChange::removed(removed_cycles - accepted_cycles)
        };

        // If the canister is not the cycles minting canister, then the balance
        // change coming from the Wasm execution must match the expected balance
        // change that we just computed.
        if system_state.canister_id() != CYCLES_MINTING_CANISTER_ID
            && self.cycles_balance_change != expected_change
        {
            return Err(HypervisorError::WasmEngineError(
                WasmEngineError::FailedToApplySystemChanges(format!(
                    "Invalid cycle change: expected {:?}, got {:?}",
                    expected_change, self.cycles_balance_change
                )),
            ));
        }

        self.validate_balance_changes(system_state)
    }

    /// Checks that `apply_balance_changes` applies these changes to the given
    /// state exactly, i.e., every step is covered by the balance, no step
    /// overflows, and the reservation of cycles succeeds.
    fn validate_balance_changes(&self, system_state: &SystemState) -> HypervisorResult<()> {
        let error = || {
            Self::error(format!(
                "Invalid cycle change: cannot apply {:?} with consumed cycles {:?} and reserved cycles {} to balance {}",
                self.cycles_balance_change,
                self.consumed_cycles_by_use_case.iter_over_real(),
                self.reserved_cycles,
                system_state.balance()
            ))
        };

        // The main balance change excludes the consumed and reserved cycles,
        // see `apply_balance_changes`.
        let (mut added, removed) = match self.cycles_balance_change {
            CyclesBalanceChange::Added(added) => (added.get(), 0),
            CyclesBalanceChange::Removed(removed) => (0, removed.get()),
        };
        for amount in self
            .consumed_cycles_by_use_case
            .iter_over_real()
            .into_iter()
            .chain(std::iter::once(self.reserved_cycles))
        {
            added = added.checked_add(amount.get()).ok_or_else(error)?;
        }
        let mut balance = if added >= removed {
            system_state.balance().get().checked_add(added - removed)
        } else {
            system_state.balance().get().checked_sub(removed - added)
        }
        .ok_or_else(error)?;

        for amount in self.consumed_cycles_by_use_case.iter_over_real() {
            balance = balance.checked_sub(amount.get()).ok_or_else(error)?;
        }

        // `can_reserve_cycles` does not detect an overflow of the reserved balance.
        system_state
            .reserved_balance()
            .get()
            .checked_add(self.reserved_cycles.get())
            .ok_or_else(error)?;

        system_state
            .can_reserve_cycles(self.reserved_cycles, Cycles::new(balance))
            .map_err(|err| Self::error(format!("Invalid cycle change: {err:?}")))
    }

    /// Returns number of removed cycles in the state changes.
    pub fn removed_cycles(&self) -> Cycles {
        self.cycles_balance_change.get_removed_cycles()
    }

    /// Returns the number of *additional* reserved cycles.
    pub fn reserved_cycles(&self) -> Cycles {
        self.reserved_cycles
    }

    /// Returns the requests that have been enqueued.
    pub fn requests(&self) -> &[OutputRequest] {
        &self.requests
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
        msg: OutputRequest,
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
            .map_err(|e| Self::error(format!("Failed to push IC00 reject response: {e:?}")))?;
        Ok(())
    }

    fn reject_subnet_message_user_error(
        system_state: &mut SystemState,
        subnet_ids: &BTreeSet<PrincipalId>,
        msg: OutputRequest,
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
            .map_err(|e| Self::error(format!("Failed to push IC00 reject response: {e:?}")))?;
        Ok(())
    }

    fn push_message(
        system_state: &mut SystemState,
        time: Time,
        msg: OutputRequest,
        logger: &ReplicaLogger,
    ) -> HypervisorResult<()> {
        let sent_cycles = msg.payment.get();
        let msg_receiver = msg.receiver;
        system_state
            .push_output_request(msg, time)
            .map_err(|e| Self::error(format!("Failed to push output request: {e:?}")))?;
        if sent_cycles > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
            info!(
                logger,
                "Canister {} sent {} cycles to canister {}.",
                system_state.canister_id(),
                sent_cycles,
                msg_receiver
            );
        }
        Ok(())
    }

    fn get_sender_canister_version(msg: &OutputRequest) -> Result<Option<u64>, UserError> {
        let method = Ic00Method::from_str(&msg.method_name);
        let payload = msg.method_payload.as_slice();
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
            Ok(Ic00Method::TakeCanisterSnapshot) => TakeCanisterSnapshotArgs::decode(payload)
                .map(|record| record.get_sender_canister_version()),
            Ok(Ic00Method::SignWithECDSA)
            | Ok(Ic00Method::CanisterStatus)
            | Ok(Ic00Method::CanisterInfo)
            | Ok(Ic00Method::CanisterMetadata)
            | Ok(Ic00Method::ListCanisters)
            | Ok(Ic00Method::StartCanister)
            | Ok(Ic00Method::StopCanister)
            | Ok(Ic00Method::DeleteCanister)
            | Ok(Ic00Method::RawRand)
            | Ok(Ic00Method::DepositCycles)
            | Ok(Ic00Method::FlexibleHttpRequest)
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
            | Ok(Ic00Method::SubnetMetrics)
            | Ok(Ic00Method::SubnetInfo)
            | Ok(Ic00Method::FetchCanisterLogs)
            | Ok(Ic00Method::UploadChunk)
            | Ok(Ic00Method::StoredChunks)
            | Ok(Ic00Method::ClearChunkStore)
            | Ok(Ic00Method::ListCanisterSnapshots)
            | Ok(Ic00Method::DeleteCanisterSnapshot)
            | Ok(Ic00Method::ReadCanisterSnapshotMetadata)
            | Ok(Ic00Method::ReadCanisterSnapshotData)
            | Ok(Ic00Method::UploadCanisterSnapshotMetadata)
            | Ok(Ic00Method::UploadCanisterSnapshotData)
            | Ok(Ic00Method::CanisterMetrics) => Ok(None),
            Err(_) => Err(UserError::new(
                ErrorCode::CanisterMethodNotFound,
                format!("Management canister has no method '{}'", msg.method_name),
            )),
        }
    }

    fn validate_sender_canister_version(
        msg: &OutputRequest,
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
                        format!(
                            "Management canister call payload includes sender canister version {sender_canister_version:?} that does not match the actual sender canister version {canister_version_from_system}."
                        ),
                    ))
                }
            }
        }
    }

    /// Appends the canister log records produced by the execution to the
    /// canister log of the given system state, leaving the delta log empty.
    ///
    /// Canister logs must be persisted even if the execution fails at any
    /// point, so this is called on whichever system state is persisted
    /// eventually, also in case the other changes are not applied.
    pub fn apply_canister_log<Metrics: CanisterLogMetrics>(
        &mut self,
        system_state: &mut SystemState,
        metrics: &Metrics,
    ) {
        append_canister_log(&mut self.canister_log, system_state, metrics);
    }

    /// Takes the canister log records produced by the execution, leaving the
    /// delta log empty.
    ///
    /// The caller is responsible for persisting the returned canister log
    /// records (see `append_canister_log()`).
    pub fn take_canister_log(&mut self) -> CanisterLog {
        self.canister_log.take()
    }

    /// Like `apply_canister_log()`, but appends the canister log records to
    /// the canister logs of two system states, e.g., if it is not known yet
    /// which of them is persisted eventually. Both canister logs must be equal
    /// before the records are appended.
    pub fn apply_canister_log_to_both<Metrics: CanisterLogMetrics>(
        &mut self,
        system_state: &mut SystemState,
        other_system_state: &mut SystemState,
        metrics: &Metrics,
    ) {
        debug_assert!(
            system_state.log_memory_store == other_system_state.log_memory_store,
            "Both system states must have the same canister log before applying the delta log"
        );
        self.apply_canister_log(system_state, metrics);
        // `apply_canister_log()` drains the delta log, so calling it again would
        // not append the records. Copy the updated canister log instead.
        other_system_state.log_memory_store = system_state.log_memory_store.clone();
    }

    /// Verify that the changes to the system state are sound and apply them to
    /// the system state if they are.
    pub fn apply_changes(
        self,
        time: Time,
        system_state: &mut SystemState,
        network_topology: &NetworkTopology,
        own_subnet_id: SubnetId,
        is_composite_query: bool,
        logger: &ReplicaLogger,
    ) -> HypervisorResult<RequestMetadataStats> {
        debug_assert!(
            self.canister_log.is_empty(),
            "Canister logs must be applied via `apply_canister_log()` before applying the other changes"
        );

        // Verify total cycle change is not positive and update cycles balance.
        self.validate_cycle_change(system_state, is_composite_query)?;
        self.apply_balance_changes(system_state);

        // Verify we don't accept more cycles than are available from call
        // context and update the call context balance.
        if let Some((context_id, call_context_balance_taken)) = self.call_context_balance_taken
            && call_context_balance_taken != Cycles::zero()
        {
            let own_canister_id = system_state.canister_id();

            let call_context = system_state
                .withdraw_cycles(context_id, call_context_balance_taken)
                .map_err(Self::error)?;
            if (call_context_balance_taken).get() > LOG_CANISTER_OPERATION_CYCLES_THRESHOLD {
                match call_context.call_origin() {
                    CallOrigin::CanisterUpdate(origin_canister_id, ..)
                    | CallOrigin::CanisterQuery(origin_canister_id, ..) => info!(
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
        let nns_subnet_id = network_topology.nns_subnet_id;
        let subnet_ids: BTreeSet<PrincipalId> =
            network_topology.subnets().keys().map(|s| s.get()).collect();
        for mut msg in self.requests {
            if !is_composite_query && msg.receiver == IC_00 {
                match Self::validate_sender_canister_version(&msg, system_state.canister_version())
                {
                    Ok(()) => {
                        // This is a request to the management canister.
                        // Update the receiver to the appropriate subnet.
                        match routing::resolve_destination(
                            network_topology,
                            msg.method_name.as_str(),
                            msg.method_payload.as_slice(),
                            own_subnet_id,
                            system_state.canister_id(),
                            logger,
                        )
                        .map(CanisterId::unchecked_from_principal)
                        {
                            Ok(destination_subnet) => {
                                msg.receiver = destination_subnet;
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
            } else if !is_composite_query && subnet_ids.contains(&msg.receiver.get()) {
                match Self::validate_sender_canister_version(&msg, system_state.canister_version())
                {
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
                // A request made by a composite query (including from its callbacks) is
                // neither validated nor routed here, no matter its receiver: if it is
                // addressed to `IC_00`, it is executed by the query handler against the
                // state of the own subnet (or rejected by it if the method cannot be
                // executed in non-replicated mode; note that composite queries are
                // always executed in non-replicated mode); if it provides a subnet ID
                // directly as the receiver, it is rejected by the query handler with
                // `CanisterNotFound` since only requests addressed to `IC_00` are executed
                // as management canister calls in a composite query.
                //
                // In particular, such a request must not be rejected here: the reject
                // response would be pushed onto the canister's input queue, which is
                // never inducted while evaluating a query call graph, and hence the
                // composite query would fail with `CanisterDidNotReply`.
                Self::push_message(system_state, time, msg, logger)?;
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

        // Bump the canister version after all changes have been applied.
        if self.should_bump_canister_version {
            system_state.bump_canister_version();
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
        for amount in self.consumed_cycles_by_use_case.iter_over_real() {
            adjusted_balance_change = adjusted_balance_change + CyclesBalanceChange::added(amount)
        }

        // Exclude the reserved cycles.
        adjusted_balance_change =
            adjusted_balance_change + CyclesBalanceChange::added(self.reserved_cycles);

        // Apply the main cycles balance change without the consumed and reserved cycles.
        match adjusted_balance_change {
            CyclesBalanceChange::Added(added) => state.add_cycles(added),
            CyclesBalanceChange::Removed(removed) => state.remove_cycles(removed),
        }

        // Apply the consumed cycles with the use case metrics recording.
        let ConsumedCyclesDuringExecution {
            burned,
            instructions,
            request_and_response_transmission,
        } = self.consumed_cycles_by_use_case;
        if let Some(x) = burned {
            state.consume_cycles(x);
        }
        if let Some(x) = instructions {
            state.consume_cycles(x);
        }
        if let Some(x) = request_and_response_transmission {
            state.consume_cycles(x);
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

    #[cfg(test)]
    fn default_with_cycles_changes(
        cycles_balance_change: CyclesBalanceChange,
        consumed_cycles_by_use_case: ConsumedCyclesDuringExecution,
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
    pub(super) subnet_cycles_config: CyclesAccountManagerSubnetConfig,
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
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    network_topology: Arc<NetworkTopology>,
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
        available_callbacks: u64,
        available_request_slots: BTreeMap<CanisterId, usize>,
        ic00_available_request_slots: usize,
        ic00_aliases: BTreeSet<CanisterId>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
        global_timer: CanisterTimer,
        canister_version: u64,
        controllers: BTreeSet<PrincipalId>,
        request_metadata: RequestMetadata,
        caller: Option<PrincipalId>,
        next_canister_log_record_idx: u64,
        canister_log_memory_limit: usize,
        is_wasm64_execution: bool,
        network_topology: Arc<NetworkTopology>,
    ) -> Self {
        Self {
            canister_id,
            status,
            subnet_type: cycles_account_manager.subnet_type(),
            subnet_cycles_config,
            freeze_threshold,
            memory_allocation,
            environment_variables,
            wasm_memory_threshold,
            compute_allocation,
            system_state_modifications: SystemStateModifications {
                canister_log: CanisterLog::new_delta_with_next_index(
                    // Start indexing new batch of canister log records from the given index.
                    next_canister_log_record_idx,
                    canister_log_memory_limit,
                ),
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
        network_topology: Arc<NetworkTopology>,
        compute_allocation: ComputeAllocation,
        available_callbacks: u64,
        request_metadata: RequestMetadata,
        caller: Option<PrincipalId>,
        call_context_id: Option<CallContextId>,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
    ) -> Self {
        Self::new(
            system_state,
            cycles_account_manager,
            network_topology,
            compute_allocation,
            available_callbacks,
            request_metadata,
            caller,
            call_context_id,
            // We can assume a Wasm32 environment in tests for now.
            false,
            subnet_cycles_config,
        )
    }

    pub fn new(
        system_state: &SystemState,
        cycles_account_manager: CyclesAccountManager,
        network_topology: Arc<NetworkTopology>,
        compute_allocation: ComputeAllocation,
        available_callbacks: u64,
        request_metadata: RequestMetadata,
        caller: Option<PrincipalId>,
        call_context_id: Option<CallContextId>,
        is_wasm64_execution: bool,
        subnet_cycles_config: CyclesAccountManagerSubnetConfig,
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
            .subnets()
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
        let (next_canister_log_record_idx, canister_log_memory_limit) = {
            let lms = &system_state.log_memory_store;
            (lms.next_idx(), lms.byte_capacity())
        };

        Self::new_internal(
            system_state.canister_id(),
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
            available_callbacks,
            available_request_slots,
            ic00_available_request_slots,
            ic00_aliases,
            subnet_cycles_config,
            system_state.global_timer,
            system_state.canister_version(),
            system_state.controllers.clone(),
            request_metadata,
            caller,
            next_canister_log_record_idx,
            canister_log_memory_limit,
            is_wasm64_execution,
            network_topology,
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

    pub fn subnet_cycles_config(&self) -> CyclesAccountManagerSubnetConfig {
        self.subnet_cycles_config
    }

    pub fn set_global_timer(&mut self, timer: CanisterTimer) {
        // Update both sandbox global timer and the changes.
        self.system_state_modifications.new_global_timer = Some(timer);
        self.global_timer = timer;
    }

    pub fn take_changes(&mut self) -> SystemStateModifications {
        std::mem::take(&mut self.system_state_modifications)
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
            self.subnet_cycles_config,
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
        consumed_cycles: ConsumedCyclesDuringExecution,
    ) {
        let old_balance = self.cycles_balance();
        assert!(
            new_balance <= old_balance,
            "Unexpected increase of cycles balances {old_balance} => {new_balance}"
        );

        self.system_state_modifications
            .consumed_cycles_by_use_case
            .merge(consumed_cycles);
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
            self.subnet_cycles_config,
            self.reserved_balance(),
        );
        self.update_balance_change_consuming(
            new_balance,
            ConsumedCyclesDuringExecution {
                burned: Some(CompoundCycles::new(
                    burned_cycles,
                    self.subnet_cycles_config.cost_schedule,
                )),
                ..Default::default()
            },
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
        debug_assert!(
            self.system_state_modifications
                .call_context_balance_taken
                .is_some()
        );

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

    pub fn prepayment_for_response_execution(&self) -> CompoundCycles<Instructions> {
        self.cycles_account_manager
            .prepayment_for_response_execution(
                self.subnet_cycles_config,
                WasmExecutionMode::from_is_wasm64(self.is_wasm64_execution),
            )
    }

    pub fn prepayment_for_response_transmission(
        &self,
    ) -> CompoundCycles<RequestAndResponseTransmission> {
        self.cycles_account_manager
            .prepayment_for_response_transmission(self.subnet_cycles_config)
    }

    pub fn xnet_total_transmission_fee(
        &self,
        payload_size: NumBytes,
    ) -> CompoundCycles<RequestAndResponseTransmission> {
        self.cycles_account_manager
            .xnet_total_transmission_fee(payload_size, self.subnet_cycles_config)
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
                self.subnet_cycles_config,
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
        msg: OutputRequest,
    ) -> Result<(), OutputRequest> {
        if self.available_callbacks == 0 {
            return Err(msg);
        }
        self.available_callbacks -= 1;

        let mut new_balance = self.cycles_balance();
        if self
            .cycles_account_manager
            .withdraw_request_cycles(
                self.canister_id,
                &mut new_balance,
                self.freeze_threshold,
                self.memory_allocation,
                canister_current_memory_usage,
                canister_current_message_memory_usage,
                self.compute_allocation,
                msg.prepayment_for_response_execution,
                msg.prepayment_for_call_transmission,
                self.subnet_cycles_config,
                self.reserved_balance(),
                // if the canister is frozen, the controller should call canister_status
                // to learn the top up balance instead of getting it from an error
                // message to a canister method making downstream call
                false,
            )
            .is_err()
        {
            return Err(msg);
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

        *used_slots += 1;
        let consumed_cycles = ConsumedCyclesDuringExecution {
            instructions: Some(msg.prepayment_for_response_execution),
            request_and_response_transmission: Some(msg.prepayment_for_call_transmission),
            ..Default::default()
        };
        self.system_state_modifications.requests.push(msg);
        self.update_balance_change_consuming(new_balance, consumed_cycles);
        Ok(())
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
        let threshold = self.cycles_account_manager.freeze_threshold_cycles(
            self.freeze_threshold,
            self.memory_allocation,
            new_memory_usage,
            current_message_memory_usage,
            self.compute_allocation,
            self.subnet_cycles_config,
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
            self.subnet_cycles_config,
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
    ) -> HypervisorResult<()> {
        let cycles_to_reserve = self
            .cycles_account_manager
            .storage_reservation_cycles(
                allocated_bytes,
                subnet_memory_saturation,
                self.subnet_cycles_config,
            )
            .real();

        if let Some(limit) = self.reserved_balance_limit
            && self.reserved_balance() + cycles_to_reserve > limit
        {
            return Err(HypervisorError::ReservedCyclesLimitExceededInMemoryGrow {
                bytes: allocated_bytes,
                requested: self.reserved_balance() + cycles_to_reserve,
                limit,
            });
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

    /// Appends a log record to the system state changes.
    pub fn append_canister_log(&mut self, time: &Time, content: Vec<u8>) {
        self.system_state_modifications
            .canister_log
            .add_record(time.as_nanos_since_unix_epoch(), content);
    }

    /// Takes collected canister log records.
    pub fn take_canister_log(&mut self) -> CanisterLog {
        self.system_state_modifications.canister_log.take()
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
            .subnets()
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
    /// for that key and return the subnet cycles config of the biggest one.
    /// These data are all returned together because their existence is contingent on the key.
    pub fn get_key_subnet_details(
        &self,
        key: MasterPublicKeyId,
    ) -> Option<CyclesAccountManagerSubnetConfig> {
        let subnets_with_key = self.network_topology.chain_key_enabled_subnets(&key);
        subnets_with_key
            .iter()
            .filter_map(|subnet_id| {
                let size = self.network_topology.get_subnet_size(subnet_id)?;
                let cost_schedule = self
                    .network_topology
                    .subnets()
                    .get(subnet_id)?
                    .cost_schedule;
                let reference_subnet_size =
                    self.network_topology.get_reference_subnet_size(subnet_id)?;
                Some((size, cost_schedule, reference_subnet_size))
            })
            .max_by_key(|&(size, cost_schedule, _)| (size, cost_schedule))
            .map(|(size, cost_schedule, reference_subnet_size)| {
                CyclesAccountManagerSubnetConfig::new(size, cost_schedule, reference_subnet_size)
            })
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
    use ic_config::subnet_config::CyclesAccountManagerConfig;
    use ic_cycles_account_manager::{CyclesAccountManager, CyclesAccountManagerSubnetConfig};
    use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
    use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        CallOrigin, NetworkTopology, SystemState, testing::OutputRequestBuilder,
    };
    use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id, user_test_id};
    use ic_types::{
        CanisterId, CanisterTimer, ComputeAllocation, MAX_DELTA_LOG_MEMORY_LIMIT, MemoryAllocation,
        NumBytes, NumInstructions, Time,
        messages::{CallContextId, CallbackId, NO_DEADLINE, RequestMetadata},
        time::CoarseTime,
    };
    use ic_types_cycles::{
        BurnedCycles, CanisterCyclesCostSchedule, CompoundCycles, Cycles, CyclesUseCase,
        CyclesUseCaseKind, Instructions, NominalCycles, RequestAndResponseTransmission,
    };

    use super::{CanisterStatusView, SandboxSafeSystemState, SystemStateModifications};
    use crate::wasmtime_embedder::system_api::{
        cycles_balance_change::CyclesBalanceChange,
        sandbox_safe_system_state::ConsumedCyclesDuringExecution,
    };

    fn prepayment<T: CyclesUseCaseKind>(amount: u128) -> CompoundCycles<T> {
        CompoundCycles::new(Cycles::new(amount), CanisterCyclesCostSchedule::Normal)
    }

    fn output_request() -> OutputRequestBuilder {
        OutputRequestBuilder::new()
            .sender(canister_test_id(0))
            .receiver(canister_test_id(1))
    }

    fn free_prepayment<T: CyclesUseCaseKind>(amount: u128) -> CompoundCycles<T> {
        CompoundCycles::new(Cycles::new(amount), CanisterCyclesCostSchedule::Free)
    }

    fn system_state_with_id(canister_id: CanisterId, balance: Cycles) -> SystemState {
        SystemState::new_running_for_testing(
            canister_id,
            user_test_id(1).get(),
            balance,
            NumSeconds::from(100_000),
        )
    }

    fn system_state(balance: Cycles) -> SystemState {
        system_state_with_id(canister_test_id(0), balance)
    }

    /// Adds a call context with the given cycles to `system_state`.
    fn new_call_context(system_state: &mut SystemState, cycles: Cycles) -> CallContextId {
        system_state
            .new_call_context(
                CallOrigin::CanisterUpdate(
                    canister_test_id(2),
                    CallbackId::from(0),
                    NO_DEADLINE,
                    String::new(),
                ),
                cycles,
                Time::from_nanos_since_unix_epoch(0),
                RequestMetadata::default(),
                None,
            )
            .unwrap()
    }

    fn assert_apply_changes(
        system_state: SystemState,
        modifications: SystemStateModifications,
        expect_applied: bool,
    ) {
        assert_apply_changes_impl(system_state, modifications, false, expect_applied)
    }

    /// Applies `modifications` to `system_state` and asserts that they are
    /// either applied with the expected balances, call-context withdrawals,
    /// consumption metrics, requests and callbacks, or rejected by cycle
    /// validation with the system state left untouched.
    fn assert_apply_changes_impl(
        mut system_state: SystemState,
        modifications: SystemStateModifications,
        is_composite_query: bool,
        expect_applied: bool,
    ) {
        let initial_state = system_state.clone();
        let num_requests = modifications.requests.len();
        let reserved_cycles = modifications.reserved_cycles;
        let call_context_balance_taken = modifications.call_context_balance_taken;
        let consumed_cycles = modifications.consumed_cycles_by_use_case;
        let expected_balance = match modifications.cycles_balance_change {
            CyclesBalanceChange::Added(added) => initial_state.balance() + added,
            CyclesBalanceChange::Removed(removed) => initial_state.balance() - removed,
        };

        let result = modifications.apply_changes(
            Time::from_nanos_since_unix_epoch(0),
            &mut system_state,
            &NetworkTopology::default(),
            subnet_test_id(1),
            is_composite_query,
            &ic_logger::replica_logger::no_op_logger(),
        );

        if expect_applied {
            assert!(result.is_ok(), "{:?}", result.as_ref().err());
            assert_eq!(system_state.balance(), expected_balance);
            assert_eq!(
                system_state.reserved_balance(),
                initial_state.reserved_balance() + reserved_cycles
            );
            assert_eq!(
                system_state.queues().output_queues_message_count(),
                num_requests
            );
            let call_context_manager = system_state.call_context_manager().unwrap();
            assert_eq!(call_context_manager.callbacks().len(), num_requests);
            for (&context_id, initial_context) in initial_state
                .call_context_manager()
                .unwrap()
                .call_contexts()
                .iter()
            {
                let withdrawn = call_context_balance_taken
                    .filter(|(id, _)| *id == context_id)
                    .map_or(Cycles::zero(), |(_, amount)| amount);
                assert_eq!(
                    call_context_manager
                        .call_context(context_id)
                        .unwrap()
                        .available_cycles(),
                    initial_context.available_cycles() - withdrawn,
                    "Unexpected balance for call context {context_id:?}"
                );
            }

            let initial_metrics = initial_state.canister_metrics();
            let metrics = system_state.canister_metrics();
            let burned = consumed_cycles
                .burned
                .map_or(NominalCycles::zero(), |c| c.nominal());
            let mut total_consumed = NominalCycles::zero();
            for (use_case, amount) in [
                (CyclesUseCase::BurnedCycles, burned),
                (
                    CyclesUseCase::Instructions,
                    consumed_cycles
                        .instructions
                        .map_or(NominalCycles::zero(), |c| c.nominal()),
                ),
                (
                    CyclesUseCase::RequestAndResponseTransmission,
                    consumed_cycles
                        .request_and_response_transmission
                        .map_or(NominalCycles::zero(), |c| c.nominal()),
                ),
            ] {
                total_consumed += amount;
                assert_eq!(
                    metrics
                        .consumed_cycles_by_use_cases()
                        .get(&use_case)
                        .copied()
                        .unwrap_or_default(),
                    initial_metrics
                        .consumed_cycles_by_use_cases()
                        .get(&use_case)
                        .copied()
                        .unwrap_or_default()
                        + amount,
                    "Unexpected consumed cycles for {use_case:?}"
                );
                // Request prepayments enter the monotonic metrics only when settled.
                let settled = if use_case == CyclesUseCase::BurnedCycles {
                    amount
                } else {
                    NominalCycles::zero()
                };
                assert_eq!(
                    metrics
                        .consumed_cycles_by_use_cases_monotonic()
                        .get(&use_case)
                        .copied()
                        .unwrap_or_default(),
                    initial_metrics
                        .consumed_cycles_by_use_cases_monotonic()
                        .get(&use_case)
                        .copied()
                        .unwrap_or_default()
                        + settled,
                    "Unexpected monotonic consumed cycles for {use_case:?}"
                );
            }
            assert_eq!(
                metrics.consumed_cycles(),
                initial_metrics.consumed_cycles() + total_consumed
            );
            assert_eq!(
                metrics.consumed_cycles_monotonic(),
                initial_metrics.consumed_cycles_monotonic() + burned
            );
        } else {
            assert!(result.is_err());
            assert_eq!(system_state, initial_state);
        }
    }

    #[test]
    fn valid_request_prepayments_are_accepted() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(40)),
            requests: vec![
                output_request()
                    .prepayment_for_response_execution(prepayment(10))
                    .prepayment_for_response_transmission(prepayment(20))
                    .prepayment_for_call_transmission(prepayment(30))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                instructions: Some(prepayment(10)),
                request_and_response_transmission: Some(prepayment(30)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, true);
    }

    #[test]
    fn valid_free_request_prepayments_are_accepted() {
        // On the free cost schedule, the real parts are zero and only the
        // nominal parts are tracked.
        let modifications = SystemStateModifications {
            requests: vec![
                output_request()
                    .prepayment_for_response_execution(free_prepayment(10))
                    .prepayment_for_response_transmission(free_prepayment(20))
                    .prepayment_for_call_transmission(free_prepayment(30))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                instructions: Some(free_prepayment(10)),
                request_and_response_transmission: Some(free_prepayment(30)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, true);
    }

    #[test]
    fn mixed_cycle_changes_update_existing_balances_and_metrics() {
        let mut system_state = system_state(Cycles::new(1_000));
        system_state.consume_cycles(prepayment::<BurnedCycles>(5));
        system_state.consume_cycles(prepayment::<Instructions>(7));
        system_state.consume_cycles(prepayment::<RequestAndResponseTransmission>(11));
        system_state.reserve_cycles(Cycles::new(5)).unwrap();
        let call_context_id = new_call_context(&mut system_state, Cycles::new(200));
        // An unrelated call context must retain its balance.
        new_call_context(&mut system_state, Cycles::new(300));
        let mut request = output_request()
            .payment(Cycles::new(100))
            .prepayment_for_response_execution(prepayment(10))
            .prepayment_for_response_transmission(prepayment(20))
            .prepayment_for_call_transmission(prepayment(30))
            .build();
        request.call_context_id = call_context_id;
        let modifications = SystemStateModifications {
            // Accept 100, send 100, consume 60, and reserve 40 cycles.
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(100)),
            call_context_balance_taken: Some((call_context_id, Cycles::new(100))),
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                burned: Some(prepayment(20)),
                instructions: Some(prepayment(10)),
                request_and_response_transmission: Some(prepayment(30)),
            },
            reserved_cycles: Cycles::new(40),
            requests: vec![request],
            ..Default::default()
        };

        assert_apply_changes(system_state, modifications, true);
    }

    #[test]
    fn forged_request_prepayments_are_rejected() {
        let modifications = SystemStateModifications {
            // The sandbox claims that only 10 cycles were withdrawn, while
            // storing a callback prepayment that would later refund 100.
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(10)),
            requests: vec![
                output_request()
                    .prepayment_for_response_execution(prepayment(100))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                instructions: Some(prepayment(10)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, false);
    }

    #[test]
    fn forged_call_transmission_prepayments_are_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(10)),
            requests: vec![
                output_request()
                    .prepayment_for_call_transmission(prepayment(100))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                request_and_response_transmission: Some(prepayment(10)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, false);
    }

    #[test]
    fn request_prepayments_below_consumed_cycles_are_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(100)),
            requests: vec![
                output_request()
                    .prepayment_for_response_execution(prepayment(10))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                instructions: Some(prepayment(100)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, false);
    }

    #[test]
    fn forged_nominal_request_prepayments_are_rejected() {
        // The real parts match (zero), but the nominal parts do not.
        let modifications = SystemStateModifications {
            requests: vec![
                output_request()
                    .prepayment_for_response_execution(free_prepayment(100))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                instructions: Some(free_prepayment(10)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, false);
    }

    #[test]
    fn response_transmission_prepayment_must_not_exceed_call_prepayment() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(30)),
            requests: vec![
                output_request()
                    .prepayment_for_response_transmission(prepayment(31))
                    .prepayment_for_call_transmission(prepayment(30))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                request_and_response_transmission: Some(prepayment(30)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, false);
    }

    #[test]
    fn nominal_response_transmission_prepayment_must_not_exceed_call_prepayment() {
        let modifications = SystemStateModifications {
            requests: vec![
                output_request()
                    .prepayment_for_response_transmission(free_prepayment(31))
                    .prepayment_for_call_transmission(free_prepayment(30))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                request_and_response_transmission: Some(free_prepayment(30)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, false);
    }

    #[test]
    fn overflowing_request_prepayment_totals_are_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(u128::MAX)),
            requests: vec![
                output_request()
                    .prepayment_for_response_execution(prepayment(u128::MAX))
                    .build(),
                output_request()
                    .prepayment_for_response_execution(prepayment(1))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                instructions: Some(prepayment(u128::MAX)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(u128::MAX)), modifications, false);
    }

    #[test]
    fn overflowing_nominal_request_prepayment_totals_are_rejected() {
        let modifications = SystemStateModifications {
            requests: vec![
                output_request()
                    .prepayment_for_response_execution(free_prepayment(u128::MAX))
                    .build(),
                output_request()
                    .prepayment_for_response_execution(free_prepayment(1))
                    .build(),
            ],
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                instructions: Some(free_prepayment(u128::MAX)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(1_000)), modifications, false);
    }

    #[test]
    fn composite_query_request_prepayments_are_not_validated() {
        // Composite queries discard the cycle charges of their outgoing
        // requests.
        let modifications = SystemStateModifications {
            requests: vec![
                output_request()
                    .prepayment_for_response_execution(prepayment(100))
                    .build(),
            ],
            ..Default::default()
        };

        assert_apply_changes_impl(system_state(Cycles::new(1_000)), modifications, true, true);
    }

    #[test]
    fn request_payment_above_replica_balance_is_rejected() {
        let payment = Cycles::new(1_000);
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(payment),
            requests: vec![output_request().payment(payment).build()],
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(10)), modifications, false);
    }

    #[test]
    fn request_payment_backed_by_accepted_cycles_is_accepted() {
        let payment = Cycles::new(1_000);
        let mut system_state = system_state(Cycles::new(10));
        let call_context_id = new_call_context(&mut system_state, payment);
        let modifications = SystemStateModifications {
            call_context_balance_taken: Some((call_context_id, payment)),
            requests: vec![output_request().payment(payment).build()],
            ..Default::default()
        };

        assert_apply_changes(system_state, modifications, true);
    }

    #[test]
    fn accepting_more_than_available_call_context_cycles_is_rejected() {
        let mut system_state = system_state(Cycles::new(10));
        let call_context_id = new_call_context(&mut system_state, Cycles::new(100));
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::added(Cycles::new(101)),
            call_context_balance_taken: Some((call_context_id, Cycles::new(101))),
            ..Default::default()
        };

        assert_apply_changes(system_state, modifications, false);
    }

    #[test]
    fn accepting_cycles_from_unknown_call_context_is_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::added(Cycles::new(100)),
            call_context_balance_taken: Some((CallContextId::from(42), Cycles::new(100))),
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(10)), modifications, false);
    }

    #[test]
    fn balance_overflow_is_rejected() {
        // The balance would temporarily overflow when the accepted cycles are
        // added before the burned cycles are consumed.
        let mut system_state = system_state(Cycles::new(u128::MAX));
        let call_context_id = new_call_context(&mut system_state, Cycles::new(1));
        let modifications = SystemStateModifications {
            call_context_balance_taken: Some((call_context_id, Cycles::new(1))),
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                burned: Some(prepayment(1)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state, modifications, false);
    }

    #[test]
    fn reservation_within_limit_is_accepted() {
        let mut system_state = system_state(Cycles::new(1_000));
        system_state.set_reserved_balance_limit(Cycles::new(10));
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(10)),
            reserved_cycles: Cycles::new(10),
            ..Default::default()
        };

        assert_apply_changes(system_state, modifications, true);
    }

    #[test]
    fn reservation_above_limit_is_rejected() {
        let mut system_state = system_state(Cycles::new(1_000));
        system_state.set_reserved_balance_limit(Cycles::new(10));
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(11)),
            reserved_cycles: Cycles::new(11),
            ..Default::default()
        };

        assert_apply_changes(system_state, modifications, false);
    }

    #[test]
    fn unbacked_balance_increase_is_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::added(Cycles::new(100)),
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(10)), modifications, false);
    }

    #[test]
    fn overflowing_removed_cycles_are_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(u128::MAX)),
            requests: vec![
                output_request().payment(Cycles::new(u128::MAX)).build(),
                output_request().payment(Cycles::new(1)).build(),
            ],
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(u128::MAX)), modifications, false);
    }

    #[test]
    fn consumed_cycles_above_balance_are_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(100)),
            consumed_cycles_by_use_case: ConsumedCyclesDuringExecution {
                burned: Some(prepayment(100)),
                ..Default::default()
            },
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(10)), modifications, false);
    }

    #[test]
    fn reserved_balance_overflow_is_rejected() {
        let mut system_state = system_state(Cycles::new(u128::MAX));
        system_state.set_reserved_balance_limit(Cycles::new(u128::MAX));
        system_state.reserve_cycles(Cycles::new(u128::MAX)).unwrap();
        system_state.add_cycles(Cycles::new(1));
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(1)),
            reserved_cycles: Cycles::new(1),
            ..Default::default()
        };

        assert_apply_changes(system_state, modifications, false);
    }

    #[test]
    fn reservation_above_balance_is_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(100)),
            reserved_cycles: Cycles::new(100),
            ..Default::default()
        };

        assert_apply_changes(system_state(Cycles::new(10)), modifications, false);
    }

    #[test]
    fn cycles_minting_canister_can_mint_cycles() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::added(Cycles::new(100)),
            ..Default::default()
        };

        assert_apply_changes(
            system_state_with_id(CYCLES_MINTING_CANISTER_ID, Cycles::new(10)),
            modifications,
            true,
        );
    }

    #[test]
    fn cycles_minting_canister_balance_overflow_is_rejected() {
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::added(Cycles::new(1)),
            ..Default::default()
        };

        assert_apply_changes(
            system_state_with_id(CYCLES_MINTING_CANISTER_ID, Cycles::new(u128::MAX)),
            modifications,
            false,
        );
    }

    #[test]
    fn cycles_minting_canister_reservation_above_limit_is_rejected() {
        let mut system_state = system_state_with_id(CYCLES_MINTING_CANISTER_ID, Cycles::new(1_000));
        system_state.set_reserved_balance_limit(Cycles::new(10));
        let modifications = SystemStateModifications {
            cycles_balance_change: CyclesBalanceChange::removed(Cycles::new(11)),
            reserved_cycles: Cycles::new(11),
            ..Default::default()
        };

        assert_apply_changes(system_state, modifications, false);
    }

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
        let cost_schedule = CanisterCyclesCostSchedule::Normal;
        let system_state_modifications = SystemStateModifications::default_with_cycles_changes(
            CyclesBalanceChange::Removed(removed),
            ConsumedCyclesDuringExecution {
                request_and_response_transmission: Some(CompoundCycles::new(
                    consumed,
                    cost_schedule,
                )),
                ..Default::default()
            },
        );

        system_state_modifications.apply_balance_changes(&mut system_state);

        assert_eq!(initial_cycles_balance - removed, system_state.balance());

        let initial_cycles_balance = system_state.balance();

        let removed = Cycles::new(500_000);
        let consumed = Cycles::new(600_000);
        let system_state_modifications = SystemStateModifications::default_with_cycles_changes(
            CyclesBalanceChange::Removed(removed),
            ConsumedCyclesDuringExecution {
                request_and_response_transmission: Some(CompoundCycles::new(
                    consumed,
                    cost_schedule,
                )),
                ..Default::default()
            },
        );

        system_state_modifications.apply_balance_changes(&mut system_state);

        assert_eq!(initial_cycles_balance - removed, system_state.balance());

        let initial_cycles_balance = system_state.balance();

        let added = Cycles::new(500_000);
        let consumed = Cycles::new(100_000);
        let system_state_modifications = SystemStateModifications::default_with_cycles_changes(
            CyclesBalanceChange::Added(added),
            ConsumedCyclesDuringExecution {
                request_and_response_transmission: Some(CompoundCycles::new(
                    consumed,
                    cost_schedule,
                )),
                ..Default::default()
            },
        );

        system_state_modifications.apply_balance_changes(&mut system_state);

        assert_eq!(initial_cycles_balance + added, system_state.balance());

        let initial_cycles_balance = system_state.balance();

        let added = Cycles::new(500_000);
        let consumed = Cycles::new(600_000);
        let system_state_modifications = SystemStateModifications::default_with_cycles_changes(
            CyclesBalanceChange::Added(added),
            ConsumedCyclesDuringExecution {
                request_and_response_transmission: Some(CompoundCycles::new(
                    consumed,
                    cost_schedule,
                )),
                ..Default::default()
            },
        );

        system_state_modifications.apply_balance_changes(&mut system_state);

        assert_eq!(initial_cycles_balance + added, system_state.balance());
    }

    fn helper_msg_deadline(call_context_deadline: Option<CoarseTime>) -> CoarseTime {
        let sandbox_state = SandboxSafeSystemState::new_internal(
            canister_test_id(0),
            CanisterStatusView::Running,
            NumSeconds::from(3600),
            MemoryAllocation::default(),
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
            0,
            BTreeMap::new(),
            0,
            BTreeSet::new(),
            CyclesAccountManagerSubnetConfig::new(
                SMALL_APP_SUBNET_MAX_SIZE,
                CanisterCyclesCostSchedule::Normal,
                ic_config::subnet_config::DEFAULT_REFERENCE_SUBNET_SIZE,
            ),
            CanisterTimer::Inactive,
            0,
            BTreeSet::new(),
            RequestMetadata::new(0, Time::from_nanos_since_unix_epoch(0)),
            None,
            0,
            MAX_DELTA_LOG_MEMORY_LIMIT,
            // Wasm32 execution environment. Sufficient in testing.
            false,
            std::sync::Arc::new(NetworkTopology::default()),
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

    fn generate_inputs_expectations_for_use_case_both_some(
        first: Cycles,
        second: Cycles,
        use_case: CyclesUseCase,
    ) -> (
        ConsumedCyclesDuringExecution,
        ConsumedCyclesDuringExecution,
        ConsumedCyclesDuringExecution,
    ) {
        let cost_schedule = CanisterCyclesCostSchedule::Normal;
        match use_case {
            CyclesUseCase::BurnedCycles => {
                let consumed_cycles = ConsumedCyclesDuringExecution {
                    burned: Some(CompoundCycles::new(first, cost_schedule)),
                    ..Default::default()
                };
                let other_consumed_cycles = ConsumedCyclesDuringExecution {
                    burned: Some(CompoundCycles::new(second, cost_schedule)),
                    ..Default::default()
                };

                let expected = ConsumedCyclesDuringExecution {
                    burned: Some(CompoundCycles::new(first + second, cost_schedule)),
                    ..Default::default()
                };
                (consumed_cycles, other_consumed_cycles, expected)
            }
            CyclesUseCase::Instructions => {
                let consumed_cycles = ConsumedCyclesDuringExecution {
                    instructions: Some(CompoundCycles::new(first, cost_schedule)),
                    ..Default::default()
                };
                let other_consumed_cycles = ConsumedCyclesDuringExecution {
                    instructions: Some(CompoundCycles::new(second, cost_schedule)),
                    ..Default::default()
                };

                let expected = ConsumedCyclesDuringExecution {
                    instructions: Some(CompoundCycles::new(first + second, cost_schedule)),
                    ..Default::default()
                };
                (consumed_cycles, other_consumed_cycles, expected)
            }
            CyclesUseCase::RequestAndResponseTransmission => {
                let consumed_cycles = ConsumedCyclesDuringExecution {
                    request_and_response_transmission: Some(CompoundCycles::new(
                        first,
                        cost_schedule,
                    )),
                    ..Default::default()
                };
                let other_consumed_cycles = ConsumedCyclesDuringExecution {
                    request_and_response_transmission: Some(CompoundCycles::new(
                        second,
                        cost_schedule,
                    )),
                    ..Default::default()
                };

                let expected = ConsumedCyclesDuringExecution {
                    request_and_response_transmission: Some(CompoundCycles::new(
                        first + second,
                        cost_schedule,
                    )),
                    ..Default::default()
                };
                (consumed_cycles, other_consumed_cycles, expected)
            }
            _ => panic!(
                "Expected one of BurnedCycles|Instructions|RequestAndResponseTransmission, got {use_case:?}"
            ),
        }
    }

    fn generate_inputs_expectations_for_use_case_first_some(
        first: Cycles,
        use_case: CyclesUseCase,
    ) -> (
        ConsumedCyclesDuringExecution,
        ConsumedCyclesDuringExecution,
        ConsumedCyclesDuringExecution,
    ) {
        let cost_schedule = CanisterCyclesCostSchedule::Normal;
        let other_consumed_cycles = ConsumedCyclesDuringExecution::default();
        match use_case {
            CyclesUseCase::BurnedCycles => {
                let consumed_cycles = ConsumedCyclesDuringExecution {
                    burned: Some(CompoundCycles::new(first, cost_schedule)),
                    ..Default::default()
                };
                (consumed_cycles, other_consumed_cycles, consumed_cycles)
            }
            CyclesUseCase::Instructions => {
                let consumed_cycles = ConsumedCyclesDuringExecution {
                    instructions: Some(CompoundCycles::new(first, cost_schedule)),
                    ..Default::default()
                };
                (consumed_cycles, other_consumed_cycles, consumed_cycles)
            }
            CyclesUseCase::RequestAndResponseTransmission => {
                let consumed_cycles = ConsumedCyclesDuringExecution {
                    request_and_response_transmission: Some(CompoundCycles::new(
                        first,
                        cost_schedule,
                    )),
                    ..Default::default()
                };
                (consumed_cycles, other_consumed_cycles, consumed_cycles)
            }
            _ => panic!(
                "Expected one of BurnedCycles|Instructions|RequestAndResponseTransmission, got {use_case:?}"
            ),
        }
    }

    fn generate_inputs_expectations_for_use_case_second_some(
        second: Cycles,
        use_case: CyclesUseCase,
    ) -> (
        ConsumedCyclesDuringExecution,
        ConsumedCyclesDuringExecution,
        ConsumedCyclesDuringExecution,
    ) {
        let cost_schedule = CanisterCyclesCostSchedule::Normal;
        let consumed_cycles = ConsumedCyclesDuringExecution::default();
        match use_case {
            CyclesUseCase::BurnedCycles => {
                let other_consumed_cycles = ConsumedCyclesDuringExecution {
                    burned: Some(CompoundCycles::new(second, cost_schedule)),
                    ..Default::default()
                };

                (
                    consumed_cycles,
                    other_consumed_cycles,
                    other_consumed_cycles,
                )
            }
            CyclesUseCase::Instructions => {
                let other_consumed_cycles = ConsumedCyclesDuringExecution {
                    instructions: Some(CompoundCycles::new(second, cost_schedule)),
                    ..Default::default()
                };

                (
                    consumed_cycles,
                    other_consumed_cycles,
                    other_consumed_cycles,
                )
            }
            CyclesUseCase::RequestAndResponseTransmission => {
                let other_consumed_cycles = ConsumedCyclesDuringExecution {
                    request_and_response_transmission: Some(CompoundCycles::new(
                        second,
                        cost_schedule,
                    )),
                    ..Default::default()
                };

                (
                    consumed_cycles,
                    other_consumed_cycles,
                    other_consumed_cycles,
                )
            }
            _ => panic!(
                "Expected one of BurnedCycles|Instructions|RequestAndResponseTransmission, got {use_case:?}"
            ),
        }
    }

    fn assert_consumed_cycles_during_execution<T: CyclesUseCaseKind>(
        first: Cycles,
        second: Cycles,
    ) {
        let use_case = T::cycles_use_case();

        let (mut consumed_cycles, other_consumed_cycles, expected_consumed_cycles) =
            generate_inputs_expectations_for_use_case_both_some(first, second, use_case);

        consumed_cycles.merge(other_consumed_cycles);
        assert_eq!(consumed_cycles, expected_consumed_cycles);

        let (mut consumed_cycles, other_consumed_cycles, expected_consumed_cycles) =
            generate_inputs_expectations_for_use_case_first_some(first, use_case);

        consumed_cycles.merge(other_consumed_cycles);
        assert_eq!(consumed_cycles, expected_consumed_cycles);

        let (mut consumed_cycles, other_consumed_cycles, expected_consumed_cycles) =
            generate_inputs_expectations_for_use_case_second_some(second, use_case);

        consumed_cycles.merge(other_consumed_cycles);
        assert_eq!(consumed_cycles, expected_consumed_cycles);

        let mut consumed_cycles = ConsumedCyclesDuringExecution::default();
        let other_consumed_cycles = ConsumedCyclesDuringExecution::default();

        consumed_cycles.merge(other_consumed_cycles);
        assert_eq!(consumed_cycles, ConsumedCyclesDuringExecution::default());
    }

    #[test]
    fn can_merge_consumed_cycles_during_execution() {
        assert_consumed_cycles_during_execution::<BurnedCycles>(Cycles::new(10), Cycles::new(20));
        assert_consumed_cycles_during_execution::<Instructions>(Cycles::new(11), Cycles::new(21));
        assert_consumed_cycles_during_execution::<RequestAndResponseTransmission>(
            Cycles::new(12),
            Cycles::new(22),
        );
    }
}
