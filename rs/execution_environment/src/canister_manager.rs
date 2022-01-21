use crate::{
    canister_settings::CanisterSettings,
    hypervisor::Hypervisor,
    types::{IngressResponse, Response},
    util::GOVERNANCE_CANISTER_ID,
};
use candid::Decode;
use ic_base_types::NumSeconds;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_ic00_types::{
    CanisterIdRecord, CanisterStatusResultV2, InstallCodeArgs, Method as Ic00Method,
    SetControllerArgs, UpdateSettingsArgs,
};
use ic_interfaces::execution_environment::{
    CanisterOutOfCyclesError, ExecutionParameters, HypervisorError, IngressHistoryWriter,
};
use ic_logger::{error, fatal, info, ReplicaLogger};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallOrigin, CanisterState, CanisterStatus, Memory, ReplicatedState, SchedulerState, SystemState,
};
use ic_state_layout::{CanisterLayout, CheckpointLayout, RwPolicy};
use ic_types::{
    canonical_error::{not_found_error, permission_denied_error, CanonicalError},
    ingress::IngressStatus,
    messages::{
        CanisterInstallMode, Payload, RejectContext, Response as CanisterResponse,
        StopCanisterContext,
    },
    user_error::{ErrorCode, RejectCode, UserError},
    CanisterId, CanisterStatusType, ComputeAllocation, Cycles, Height, InstallCodeContext,
    MemoryAllocation, NumBytes, NumInstructions, PrincipalId, SubnetId, Time, UserId,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{collections::BTreeSet, convert::TryFrom, str::FromStr, sync::Arc};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InstallCodeResult {
    pub heap_delta: NumBytes,
    pub old_wasm_hash: Option<[u8; 32]>,
    pub new_wasm_hash: Option<[u8; 32]>,
}

/// The different return types from `stop_canister()` function below.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StopCanisterResult {
    /// The call failed.  The error and the unconsumed cycles are returned.
    Failure {
        error: CanisterManagerError,
        cycles_to_return: Cycles,
    },
    /// The canister is already stopped.  The unconsumed cycles are returned.
    AlreadyStopped { cycles_to_return: Cycles },
    /// The request was successfully accepted.  A response will follow
    /// eventually when the canister does stop.
    RequestAccepted,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct CanisterMgrConfig {
    pub(crate) subnet_memory_capacity: NumBytes,
    pub(crate) max_cycles_per_canister: Option<Cycles>,
    pub(crate) default_provisional_cycles_balance: Cycles,
    pub(crate) default_freeze_threshold: NumSeconds,
    pub(crate) compute_capacity: u64,
    pub(crate) own_subnet_id: SubnetId,
    pub(crate) own_subnet_type: SubnetType,
    pub(crate) max_controllers: usize,
}

impl CanisterMgrConfig {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        subnet_memory_capacity: NumBytes,
        max_cycles_per_canister: Option<Cycles>,
        default_provisional_cycles_balance: Cycles,
        default_freeze_threshold: NumSeconds,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        max_controllers: usize,
        num_cores: usize,
    ) -> Self {
        Self {
            subnet_memory_capacity,
            max_cycles_per_canister,
            default_provisional_cycles_balance,
            default_freeze_threshold,
            own_subnet_id,
            own_subnet_type,
            max_controllers,
            compute_capacity: 100 * num_cores as u64,
        }
    }
}

/// The entity responsible for managing canisters (creation, installing, etc.)
pub(crate) struct CanisterManager {
    hypervisor: Arc<Hypervisor>,
    log: ReplicaLogger,
    config: CanisterMgrConfig,
    cycles_account_manager: Arc<CyclesAccountManager>,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
}

impl CanisterManager {
    pub(crate) fn new(
        hypervisor: Arc<Hypervisor>,
        log: ReplicaLogger,
        config: CanisterMgrConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    ) -> Self {
        CanisterManager {
            hypervisor,
            log,
            config,
            cycles_account_manager,
            ingress_history_writer,
        }
    }

    /// Checks if a given ingress message directed to the management canister
    /// should be accepted or not.
    pub(crate) fn should_accept_ingress_message(
        &self,
        state: Arc<ReplicatedState>,
        provisional_whitelist: &ProvisionalWhitelist,
        sender: UserId,
        method_name: &str,
        payload: &[u8],
    ) -> Result<(), CanonicalError> {
        fn is_sender_controller(
            canister_id: CanisterId,
            sender: UserId,
            state: Arc<ReplicatedState>,
        ) -> Result<(), CanonicalError> {
            match state.canister_state(&canister_id) {
                Some(canister) => {
                    if !canister.controllers().contains(&sender.get()) {
                        Err(permission_denied_error(
                            "Requested canister rejected the message".to_string(),
                        ))
                    } else {
                        Ok(())
                    }
                }
                None => Err(not_found_error(
                    "Requested canister does not exist".to_string(),
                )),
            }
        }

        let rejected_canister_err = Err(permission_denied_error(
            "Requested canister rejected the message".to_string(),
        ));
        // The message is targeted towards the management canister. The
        // actual type of the method will determine if the message should be
        // accepted or not.
        match Ic00Method::from_str(method_name) {
            // The method is either invalid or it is of a type that users
            // are not allowed to send.
            Err(_)
            | Ok(Ic00Method::CreateCanister)
            | Ok(Ic00Method::SetupInitialDKG)
            | Ok(Ic00Method::SignWithECDSA)
            | Ok(Ic00Method::GetMockECDSAPublicKey)
            | Ok(Ic00Method::SignWithMockECDSA)
            // "DepositCycles" can be called by anyone however as ingress message
            // cannot carry cycles, it does not make sense to allow them from users.
            | Ok(Ic00Method::DepositCycles) => rejected_canister_err,

            // These methods are only valid if they are sent by the controller
            // of the canister. We assume that the canister always wants to
            // accept messages from its controller.
            Ok(Ic00Method::CanisterStatus)
            | Ok(Ic00Method::StartCanister)
            | Ok(Ic00Method::UninstallCode)
            | Ok(Ic00Method::StopCanister)
            | Ok(Ic00Method::DeleteCanister) => match Decode!(payload, CanisterIdRecord) {
                Err(_) => rejected_canister_err,
                Ok(args) => is_sender_controller(args.get_canister_id(), sender, state),
            },
            Ok(Ic00Method::UpdateSettings) => match Decode!(payload, UpdateSettingsArgs) {
                Err(_) => rejected_canister_err,
                Ok(args) => is_sender_controller(args.get_canister_id(), sender, state),
            },
            Ok(Ic00Method::InstallCode) => match Decode!(payload, InstallCodeArgs) {
                Err(_) => rejected_canister_err,
                Ok(args) => is_sender_controller(args.get_canister_id(), sender, state),
            },
            Ok(Ic00Method::SetController) => match Decode!(payload, SetControllerArgs) {
                Err(_) => rejected_canister_err,
                Ok(args) => is_sender_controller(args.get_canister_id(), sender, state),
            },

            // Nobody pays for `raw_rand`, so this cannot be used via ingress messages
            Ok(Ic00Method::RawRand) => rejected_canister_err,

            Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
            | Ok(Ic00Method::ProvisionalTopUpCanister) => {
                if provisional_whitelist.contains(sender.get_ref()) {
                    Ok(())
                } else {
                    rejected_canister_err
                }
            }
        }
    }

    fn validate_settings(
        &self,
        settings: CanisterSettings,
        total_subnet_compute_allocation_used: u64,
        total_subnet_memory_taken: NumBytes,
    ) -> Result<ValidatedCanisterSettings, CanisterManagerError> {
        if let Some(memory_allocation) = settings.memory_allocation() {
            let requested_allocation: NumBytes = memory_allocation.bytes();
            if requested_allocation + total_subnet_memory_taken > self.config.subnet_memory_capacity
            {
                return Err(CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                    requested: requested_allocation,
                    available: self.config.subnet_memory_capacity - total_subnet_memory_taken,
                });
            }
        }

        if let Some(compute_allocation) = settings.compute_allocation() {
            let compute_allocation = compute_allocation;
            if compute_allocation.as_percent() + total_subnet_compute_allocation_used
                >= self.config.compute_capacity
            {
                return Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: compute_allocation,
                    available: self.config.compute_capacity
                        - total_subnet_compute_allocation_used
                        - 1,
                });
            }
        }

        ValidatedCanisterSettings::try_from((settings, self.config.max_controllers))
    }

    /// Applies the requested settings on the canister.
    /// Note: Called only after validating the settings.
    fn do_update_settings(
        &self,
        settings: ValidatedCanisterSettings,
        canister: &mut CanisterState,
    ) {
        // Note: At this point, the settings are validated.
        if let Some(controller) = settings.controller {
            // Remove all the other controllers and add the new one.
            canister.system_state.controllers.clear();
            canister.system_state.controllers.insert(controller);
        }
        if let Some(controllers) = settings.controllers {
            canister.system_state.controllers.clear();
            for principal in controllers {
                canister.system_state.controllers.insert(principal);
            }
        }
        if let Some(compute_allocation) = settings.compute_allocation {
            canister.scheduler_state.compute_allocation = compute_allocation;
        }
        if let Some(memory_allocation) = settings.memory_allocation {
            // This should not happen normally because:
            //   1. `do_update_settings` is called during canister creation when the
            //       canister is empty and it should hold that memory usage of the
            //       canister is 0 and thus any number for memory allocation is bigger.
            //   2. When updating settings we have validated this holds.
            //
            // However, log an error in case it happens for visibility.
            if let MemoryAllocation::Reserved(bytes) = memory_allocation {
                if bytes < canister.memory_usage(self.config.own_subnet_type) {
                    error!(
                        self.log,
                        "Requested memory allocation of {} which is smaller than current canister memory usage {}",
                        bytes,
                        canister.memory_usage(self.config.own_subnet_type),
                    );
                }
            }
            canister.system_state.memory_allocation = memory_allocation;
        }
        if let Some(freezing_threshold) = settings.freezing_threshold {
            canister.system_state.freeze_threshold = freezing_threshold;
        }
    }

    /// Tries to apply the requested settings on the canister identified by
    /// `canister_id`.
    pub(crate) fn update_settings(
        &self,
        sender: PrincipalId,
        settings: CanisterSettings,
        canister: &mut CanisterState,
        total_subnet_compute_allocation_used: u64,
        total_subnet_memory_taken: NumBytes,
    ) -> Result<(), CanisterManagerError> {
        // Verify controller.
        self.validate_controller(canister, &sender)?;
        self.validate_compute_allocation(
            total_subnet_compute_allocation_used,
            canister,
            settings.compute_allocation(),
        )?;
        self.validate_memory_allocation(
            total_subnet_memory_taken,
            canister,
            settings.memory_allocation(),
        )?;

        let validated_settings =
            ValidatedCanisterSettings::try_from((settings, self.config.max_controllers))?;
        self.do_update_settings(validated_settings, canister);

        Ok(())
    }

    /// Creates a new canister and inserts it into `ReplicatedState`.
    ///
    /// Returns the auto-generated id the new canister that has been created.
    pub(crate) fn create_canister(
        &self,
        sender: PrincipalId,
        sender_subnet_id: SubnetId,
        cycles: Cycles,
        settings: CanisterSettings,
        max_number_of_canisters: u64,
        state: &mut ReplicatedState,
    ) -> (Result<CanisterId, CanisterManagerError>, Cycles) {
        // Creating a canister is possible only in the following cases:
        // 1. sender is on NNS => it can create canister on any subnet
        // 2. sender is not NNS => can create canister only if sender is on
        // same subnet.
        if sender_subnet_id != state.metadata.network_topology.nns_subnet_id
            && sender_subnet_id != self.config.own_subnet_id
        {
            return (
                Err(CanisterManagerError::InvalidSenderSubnet(sender_subnet_id)),
                cycles,
            );
        }

        if cycles < self.cycles_account_manager.canister_creation_fee() {
            return (
                Err(CanisterManagerError::CreateCanisterNotEnoughCycles {
                    sent: cycles,
                    required: self.cycles_account_manager.canister_creation_fee(),
                }),
                cycles,
            );
        }

        // Validate settings before `create_canister_helper` applies them
        match self.validate_settings(
            settings,
            state.total_compute_allocation(),
            state.total_memory_taken(),
        ) {
            Err(err) => (Err(err), cycles),
            Ok(validate_settings) => {
                let canister_id = match self.create_canister_helper(
                    sender,
                    cycles,
                    self.cycles_account_manager.canister_creation_fee(),
                    validate_settings,
                    max_number_of_canisters,
                    state,
                ) {
                    Ok(canister_id) => canister_id,
                    Err(err) => return (Err(err), cycles),
                };
                (Ok(canister_id), Cycles::zero())
            }
        }
    }

    /// Installs code to a canister.
    ///
    /// Only the controller of the canister can install code.
    ///
    /// There are three modes of installation that are supported:
    ///
    /// 1. `CanisterInstallMode::Install`
    ///    Used for installing code on an empty canister.
    ///
    /// 2. `CanisterInstallMode::Reinstall`
    ///    Used for installing code on a _non-empty_ canister. All existing
    ///    state in the canister is cleared.
    ///
    /// 3. `CanisterInstallMode::Upgrade`
    ///    Used for upgrading a canister while providing a mechanism to
    ///    preserve its state.
    ///
    /// This function is atomic. In case an error is thrown, the state is
    /// unmodified.
    pub(crate) fn install_code(
        &self,
        context: InstallCodeContext,
        state: &mut ReplicatedState,
        mut execution_parameters: ExecutionParameters,
    ) -> (
        NumInstructions,
        Result<InstallCodeResult, CanisterManagerError>,
    ) {
        // Copy necessary bits out of the `ReplicatedState`. This is because further
        // below, we take a mutable reference to the old canister state while it
        // is held inside state. Then Rust's borrow checker prevents us from
        // calling further methods on the state.
        let time = state.time();
        let canister_layout_path = state.path().to_path_buf();
        let compute_allocation_used = state.total_compute_allocation();
        let memory_taken = state.total_memory_taken();

        // Perform a battery of validation checks.
        let old_canister = match state.canister_state_mut(&context.canister_id) {
            None => {
                return (
                    execution_parameters.instruction_limit,
                    Err(CanisterManagerError::CanisterNotFound(context.canister_id)),
                );
            }
            Some(canister) => canister,
        };
        if let Err(err) = self.validate_compute_allocation(
            compute_allocation_used,
            old_canister,
            context.compute_allocation,
        ) {
            return (execution_parameters.instruction_limit, Err(err));
        }
        if let Err(err) =
            self.validate_memory_allocation(memory_taken, old_canister, context.memory_allocation)
        {
            return (execution_parameters.instruction_limit, Err(err));
        }
        if let Err(err) = self.validate_controller(old_canister, &context.sender) {
            return (execution_parameters.instruction_limit, Err(err));
        }
        match context.mode {
            CanisterInstallMode::Install => {
                if old_canister.execution_state.is_some() {
                    return (
                        execution_parameters.instruction_limit,
                        Err(CanisterManagerError::CanisterNonEmpty(context.canister_id)),
                    );
                }
            }
            CanisterInstallMode::Reinstall | CanisterInstallMode::Upgrade => {}
        }

        // All validation checks have passed. Reserve cycles on the old canister
        // for executing the various hooks such as `start`, `pre_upgrade`,
        // `post_upgrade`.
        let memory_usage = old_canister.memory_usage(self.config.own_subnet_type);
        let compute_allocation = old_canister.scheduler_state.compute_allocation;
        if let MemoryAllocation::Reserved(bytes) = old_canister.memory_allocation() {
            execution_parameters.canister_memory_limit = bytes;
        }
        execution_parameters.compute_allocation = compute_allocation;

        if let Err(err) = self.cycles_account_manager.withdraw_execution_cycles(
            &mut old_canister.system_state,
            memory_usage,
            compute_allocation,
            execution_parameters.instruction_limit,
        ) {
            return (
                execution_parameters.instruction_limit,
                Err(CanisterManagerError::InstallCodeNotEnoughCycles(err)),
            );
        }

        // Copy bits out of context as the calls below are going to consume it.
        let canister_id = context.canister_id;
        let mode = context.mode;

        let (instructions_left, result) = match context.mode {
            CanisterInstallMode::Install | CanisterInstallMode::Reinstall => self.install(
                context,
                old_canister,
                time,
                canister_layout_path,
                execution_parameters,
            ),
            CanisterInstallMode::Upgrade => self.upgrade(
                context,
                old_canister,
                time,
                canister_layout_path,
                execution_parameters,
            ),
        };

        let result = match result {
            Ok((heap_delta, mut new_canister)) => {
                // Refund the left over execution cycles to the new canister and
                // replace the old canister with the new one.

                let old_wasm_hash = self.get_wasm_hash(old_canister);
                let new_wasm_hash = self.get_wasm_hash(&new_canister);
                self.cycles_account_manager
                    .refund_execution_cycles(&mut new_canister.system_state, instructions_left);
                state.put_canister_state(new_canister);
                // We managed to create a new canister and will be dropping the
                // older one. So we get rid of the previous heap to make sure it
                // doesn't interfere with the new deltas and replace the old
                // canister with the new one.
                truncate_canister_heap(&self.log, state.path(), canister_id);
                if mode != CanisterInstallMode::Upgrade {
                    truncate_canister_stable_memory(&self.log, state.path(), canister_id);
                }

                Ok(InstallCodeResult {
                    heap_delta,
                    old_wasm_hash,
                    new_wasm_hash,
                })
            }
            Err(err) => {
                // the install / upgrade failed. Refund the left over cycles to
                // the old canister and leave it in the state.

                self.cycles_account_manager
                    .refund_execution_cycles(&mut old_canister.system_state, instructions_left);
                Err(err)
            }
        };
        (instructions_left, result)
    }

    /// Uninstalls code from a canister.
    ///
    /// See https://sdk.dfinity.org/docs/interface-spec/index.html#ic-uninstall_code
    pub(crate) fn uninstall_code(
        &self,
        canister_id: CanisterId,
        sender: PrincipalId,
        state: &mut ReplicatedState,
    ) -> Result<(), CanisterManagerError> {
        let time = state.time();
        let path = state.path().to_owned();
        let canister = match state.canister_state_mut(&canister_id) {
            Some(canister) => canister,
            None => return Err(CanisterManagerError::CanisterNotFound(canister_id)),
        };

        // Skip the controller validation if the sender is the governance
        // canister. The governance canister can forcefully
        // uninstall the code of any canister.
        if sender != GOVERNANCE_CANISTER_ID.get() {
            if let Err(err) = self.validate_controller(canister, &sender) {
                return Err(err);
            }
        }

        let rejects = uninstall_canister(&self.log, canister, &path, time);
        crate::util::process_responses(
            rejects,
            state,
            Arc::clone(&self.ingress_history_writer),
            self.log.clone(),
        );
        Ok(())
    }

    /// Signals a canister to stop.
    ///
    /// If the canister is running, then the canister is marked as "stopping".
    /// Stopping is meant to be an ephemeral state where the canister has the
    /// opportunity to close its call contexts before fully stopping. The stop
    /// message is saved in the canister's status so that, at a later point, the
    /// scheduler can respond to that message when the canister is fully
    /// stopped.
    ///
    /// If the canister is in the stopping state, then the stop message is
    /// appended to the canister's status. At a later point when the canister is
    /// ready to be fully stopped, the scheduler will respond to this message.
    ///
    /// If the canister is already stopped, then this function is a no-op.
    pub(crate) fn stop_canister(
        &self,
        canister_id: CanisterId,
        mut stop_context: StopCanisterContext,
        state: &mut ReplicatedState,
    ) -> StopCanisterResult {
        let mut canister = match state.take_canister_state(&canister_id) {
            None => {
                return StopCanisterResult::Failure {
                    error: CanisterManagerError::CanisterNotFound(canister_id),
                    cycles_to_return: stop_context.take_cycles(),
                }
            }
            Some(canister) => canister,
        };

        let result = match self.validate_controller(&canister, stop_context.sender()) {
            Err(err) => StopCanisterResult::Failure {
                error: err,
                cycles_to_return: stop_context.take_cycles(),
            },
            Ok(()) => {
                match &mut canister.system_state.status {
                    CanisterStatus::Stopped => StopCanisterResult::AlreadyStopped {
                        cycles_to_return: stop_context.take_cycles(),
                    },

                    CanisterStatus::Stopping { stop_contexts, .. } => {
                        // Canister is already stopping. Add the message to it
                        // so that we can respond to the message once the
                        // canister has fully stopped.
                        stop_contexts.push(stop_context);
                        StopCanisterResult::RequestAccepted
                    }

                    CanisterStatus::Running {
                        call_context_manager,
                    } => {
                        // Transition the canister into the stopping state.
                        canister.system_state.status = CanisterStatus::Stopping {
                            call_context_manager: call_context_manager.clone(),
                            // Track the stop message to later respond to it once the
                            // canister is fully stopped.
                            stop_contexts: vec![stop_context],
                        };
                        StopCanisterResult::RequestAccepted
                    }
                }
            }
        };
        state.put_canister_state(canister);
        result
    }

    /// Signals a canister to start.
    ///
    /// If the canister is stopped, then the canister is immediately
    /// transitioned into the "running" state.
    ///
    /// If the canister is already running, this operation is a no-op.
    ///
    /// If the canister is in the process of being stopped (i.e stopping), then
    /// the canister is transitioned back into a running state and the
    /// `stop_contexts` that were used for stopping the canister are
    /// returned.
    pub(crate) fn start_canister(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
    ) -> Result<Vec<StopCanisterContext>, CanisterManagerError> {
        self.validate_controller(canister, &sender)?;

        let stop_contexts = match &mut canister.system_state.status {
            CanisterStatus::Stopping { stop_contexts, .. } => std::mem::take(stop_contexts),
            CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
                Vec::new() // No stop contexts to return.
            }
        };

        // Transition the canister into "running".
        let status = match &canister.system_state.status {
            CanisterStatus::Running {
                call_context_manager,
            }
            | CanisterStatus::Stopping {
                call_context_manager,
                ..
            } => CanisterStatus::Running {
                call_context_manager: call_context_manager.clone(),
            },
            CanisterStatus::Stopped => CanisterStatus::new_running(),
        };
        canister.system_state.status = status;

        Ok(stop_contexts)
    }

    /// Fetches the current status of the canister.
    pub(crate) fn get_canister_status(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
    ) -> Result<CanisterStatusResultV2, CanisterManagerError> {
        self.validate_controller(canister, &sender)?;

        let controller = canister.system_state.controller();
        let controllers = canister
            .controllers()
            .iter()
            .copied()
            .collect::<Vec<PrincipalId>>();

        Ok(CanisterStatusResultV2::new(
            canister.status(),
            canister
                .execution_state
                .as_ref()
                .map(|es| es.wasm_binary.binary.hash_sha256().to_vec()),
            *controller,
            controllers,
            canister.memory_usage(self.config.own_subnet_type),
            canister.system_state.cycles_balance.get(),
            canister.scheduler_state.compute_allocation.as_percent(),
            Some(canister.memory_allocation().bytes().get()),
            canister.system_state.freeze_threshold.get(),
        ))
    }

    /// Sets a new controller for a canister. Only the current controller of
    /// the canister is able to run this, otherwise an error is returned.
    pub(crate) fn set_controller(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        new_controller: PrincipalId,
        state: &mut ReplicatedState,
    ) -> Result<(), CanisterManagerError> {
        let compute_allocation_used = state.total_compute_allocation();
        let memory_taken = state.total_memory_taken();
        let canister = state
            .canister_state_mut(&canister_id)
            .ok_or(CanisterManagerError::CanisterNotFound(canister_id))?;

        let settings = CanisterSettings::new(Some(new_controller), None, None, None, None);
        self.update_settings(
            sender,
            settings,
            canister,
            compute_allocation_used,
            memory_taken,
        )
    }

    /// Permanently deletes a canister from `ReplicatedState`.
    ///
    /// The canister must be `Stopped` and only the controller of the canister
    /// can delete it. The controller must be a canister and the canister
    /// cannot be its own controller.
    ///
    /// Any remaining cycles in the canister are discarded.
    ///
    /// #Errors
    /// CanisterManagerError::DeleteCanisterSelf is the canister attempts to
    /// delete itself.
    pub(crate) fn delete_canister(
        &self,
        sender: PrincipalId,
        canister_id_to_delete: CanisterId,
        state: &mut ReplicatedState,
    ) -> Result<(), CanisterManagerError> {
        if let Ok(canister_id) = CanisterId::try_from(sender) {
            if canister_id == canister_id_to_delete {
                // A canister cannot delete itself.
                return Err(CanisterManagerError::DeleteCanisterSelf(canister_id));
            }
        }

        let canister_to_delete = self.validate_canister_exists(state, canister_id_to_delete)?;

        // Validate the request is from the controller.
        self.validate_controller(canister_to_delete, &sender)?;

        self.validate_canister_is_stopped(canister_to_delete)?;

        // Once a canister is stopped, it stops accepting new messages, so this should
        // never happen.
        if canister_to_delete.has_input() {
            fatal!(
                self.log,
                "[EXC-BUG] Trying to delete canister {} while having messages in its input queue.",
                canister_to_delete.canister_id()
            );
        }

        // This scenario should be impossible because:
        //
        // 1) A stopped canister does not accept new messages.
        //
        // 2) A canister is transitioned to a stopped state at the end of a round.
        //
        // 3) All output messages are cleared by the `StreamBuilder` at the end of
        //    every round.
        //
        // Because the canister is already stopped, it must have been stopped in a
        // previous round (2), had its output queued emptied in a previous round (3),
        // and the output queue is still empty because it didn't accept any new
        // messages (1).
        if canister_to_delete.has_output() {
            fatal!(
                self.log,
                "[EXC-BUG] Trying to delete canister {} while having messages in its output queue.",
                canister_to_delete.canister_id()
            );
        }

        // When a canister is deleted:
        // - its state is permanently deleted, and
        // - its cycles are discarded.

        // Take out the canister from `ReplicatedState`.
        let _canister_to_delete = state.take_canister_state(&canister_id_to_delete).unwrap();

        let layout = canister_layout(state.path(), &canister_id_to_delete);
        layout
            .mark_deleted()
            .expect("failed to mark canister as deleted on the filesystem");

        // The canister has now been removed from `ReplicatedState` and is dropped
        // once the function is out of scope.
        Ok(())
    }

    /// Deposits the amount of cycles specified from the sender to the target
    /// `canister_id`.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterManagerError` in case the canister does not exist
    pub(crate) fn deposit_cycles(&self, canister: &mut CanisterState, cycles: Cycles) -> Cycles {
        self.cycles_account_manager
            .add_cycles(&mut canister.system_state, cycles)
    }

    #[allow(clippy::too_many_arguments)]
    fn install(
        &self,
        context: InstallCodeContext,
        old_canister: &CanisterState,
        time: Time,
        canister_layout_path: PathBuf,
        mut execution_parameters: ExecutionParameters,
    ) -> (
        NumInstructions,
        Result<(NumBytes, CanisterState), CanisterManagerError>,
    ) {
        let canister_id = context.canister_id;
        let layout = canister_layout(&canister_layout_path, &canister_id);

        let system_state = old_canister.system_state.clone();
        let execution_state = match self.hypervisor.create_execution_state(
            context.wasm_module,
            layout.raw_path(),
            canister_id,
        ) {
            Ok(execution_state) => Some(execution_state),
            Err(err) => {
                return (
                    execution_parameters.instruction_limit,
                    Err((canister_id, err).into()),
                );
            }
        };

        let scheduler_state = old_canister.scheduler_state.clone();
        let mut new_canister = CanisterState::new(system_state, execution_state, scheduler_state);

        // Update allocations.  This must happen after we have created the new
        // execution state so that we fairly account for the memory requirements
        // of the new wasm module.
        if let Some(compute_allocation) = context.compute_allocation {
            new_canister.scheduler_state.compute_allocation = compute_allocation;
            execution_parameters.compute_allocation = compute_allocation;
        }

        // While the memory allocation can still be included in the context, we need to
        // try to take it from there. Otherwise, we should use the current memory
        // allocation of the canister.
        let desired_memory_allocation = match context.memory_allocation {
            Some(allocation) => allocation,
            None => new_canister.system_state.memory_allocation,
        };
        if let MemoryAllocation::Reserved(bytes) = desired_memory_allocation {
            if bytes < new_canister.memory_usage(self.config.own_subnet_type) {
                return (
                    execution_parameters.instruction_limit,
                    Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                        canister_id,
                        memory_allocation_given: desired_memory_allocation,
                        memory_usage_needed: new_canister.memory_usage(self.config.own_subnet_type),
                    }),
                );
            }
            execution_parameters.canister_memory_limit = bytes;
        }
        new_canister.system_state.memory_allocation = desired_memory_allocation;

        let mut total_heap_delta = NumBytes::from(0);

        // Run (start)
        let (new_canister, instruction_limit, result) = self
            .hypervisor
            .execute_canister_start(new_canister, execution_parameters.clone());
        info!(
            self.log,
            "Executing (start) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.instruction_limit - instruction_limit,
            instruction_limit
        );
        match result {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
            }
            Err(err) => return (instruction_limit, Err((canister_id, err).into())),
        }

        execution_parameters.instruction_limit = instruction_limit;

        // Run canister_init
        let (new_canister, instruction_limit, result) = self.hypervisor.execute_canister_init(
            new_canister,
            context.sender,
            context.arg.as_slice(),
            time,
            execution_parameters.clone(),
        );
        info!(
            self.log,
            "Executing (canister_init) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.instruction_limit - instruction_limit,
            instruction_limit
        );
        match result {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
                (instruction_limit, Ok((total_heap_delta, new_canister)))
            }
            Err(err) => (instruction_limit, Err((canister_id, err).into())),
        }
    }

    fn upgrade(
        &self,
        context: InstallCodeContext,
        old_canister: &CanisterState,
        time: Time,
        canister_layout_path: PathBuf,
        mut execution_parameters: ExecutionParameters,
    ) -> (
        NumInstructions,
        Result<(NumBytes, CanisterState), CanisterManagerError>,
    ) {
        let canister_id = context.canister_id;
        let new_canister = old_canister.clone();
        let mut total_heap_delta = NumBytes::from(0);
        // Call pre-upgrade hook on the canister.
        let (mut new_canister, instructions_limit, res) =
            self.hypervisor.execute_canister_pre_upgrade(
                new_canister,
                context.sender,
                time,
                execution_parameters.clone(),
            );
        info!(
            self.log,
            "Executing (canister_pre_upgrade) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.instruction_limit - instructions_limit,
            instructions_limit
        );
        execution_parameters.instruction_limit = instructions_limit;
        match res {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
            }
            Err(err) => return (instructions_limit, Err((canister_id, err).into())),
        }

        // Replace the execution state of the canister with a new execution state, but
        // persist the stable memory (if it exists).
        let layout = canister_layout(&canister_layout_path, &canister_id);
        new_canister.execution_state = match self.hypervisor.create_execution_state(
            context.wasm_module,
            layout.raw_path(),
            canister_id,
        ) {
            Err(err) => return (instructions_limit, Err((canister_id, err).into())),
            Ok(mut execution_state) => {
                let stable_memory = match new_canister.execution_state {
                    Some(es) => es.stable_memory,
                    None => Memory::default(),
                };
                execution_state.stable_memory = stable_memory;
                Some(execution_state)
            }
        };

        // Update allocations.  This must happen after we have created the new
        // execution state so that we fairly account for the memory requirements
        // of the new wasm module.
        if let Some(compute_allocation) = context.compute_allocation {
            new_canister.scheduler_state.compute_allocation = compute_allocation;
            execution_parameters.compute_allocation = compute_allocation;
        }

        // While the memory allocation can still be included in the context, we need to
        // try to take it from there. Otherwise, we should use the current memory
        // allocation of the canister.
        let desired_memory_allocation = match context.memory_allocation {
            Some(allocation) => allocation,
            None => new_canister.system_state.memory_allocation,
        };
        if let MemoryAllocation::Reserved(bytes) = desired_memory_allocation {
            if bytes < new_canister.memory_usage(self.config.own_subnet_type) {
                return (
                    instructions_limit,
                    Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                        canister_id,
                        memory_allocation_given: desired_memory_allocation,
                        memory_usage_needed: new_canister.memory_usage(self.config.own_subnet_type),
                    }),
                );
            }
            execution_parameters.canister_memory_limit = bytes;
        }
        new_canister.system_state.memory_allocation = desired_memory_allocation;

        // Run (start)
        let (new_canister, instructions_limit, result) = self
            .hypervisor
            .execute_canister_start(new_canister, execution_parameters.clone());
        info!(
            self.log,
            "Executing (start) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.instruction_limit - instructions_limit,
            instructions_limit
        );
        execution_parameters.instruction_limit = instructions_limit;
        match result {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
            }
            Err(err) => return (instructions_limit, Err((context.canister_id, err).into())),
        }

        // Call post-upgrade hook on the upgraded canister.
        let (new_canister, instructions_left, result) =
            self.hypervisor.execute_canister_post_upgrade(
                new_canister,
                context.sender,
                context.arg.as_slice(),
                time,
                execution_parameters.clone(),
            );
        info!(
            self.log,
            "Executing (canister_post_upgrade) on canister {} consumed {} instructions.  {} instructions are left.",
            canister_id,
            execution_parameters.instruction_limit - instructions_limit,
            instructions_limit
        );
        match result {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
            }
            Err(err) => return (instructions_left, Err((canister_id, err).into())),
        }

        (instructions_left, Ok((total_heap_delta, new_canister)))
    }

    /// Creates a new canister with the cycles amount specified and inserts it
    /// into `ReplicatedState`.
    ///
    /// Note that this method is meant to only be invoked in local development
    /// by a list of whitelisted principals.
    ///
    /// Returns the auto-generated id the new canister that has been created.
    pub(crate) fn create_canister_with_cycles(
        &self,
        sender: PrincipalId,
        cycles_amount: Option<u64>,
        settings: CanisterSettings,
        state: &mut ReplicatedState,
        provisional_whitelist: &ProvisionalWhitelist,
        max_number_of_canisters: u64,
    ) -> Result<CanisterId, CanisterManagerError> {
        if !provisional_whitelist.contains(&sender) {
            return Err(CanisterManagerError::SenderNotInWhitelist(sender));
        }

        let cycles = match cycles_amount {
            Some(cycles_amount) => Cycles::from(cycles_amount),
            None => self.config.default_provisional_cycles_balance,
        };

        // Validate settings before `create_canister_helper` applies them
        // No creation fee applied.
        match self.validate_settings(
            settings,
            state.total_compute_allocation(),
            state.total_memory_taken(),
        ) {
            Err(err) => Err(err),
            Ok(validated_settings) => self.create_canister_helper(
                sender,
                cycles,
                Cycles::new(0),
                validated_settings,
                max_number_of_canisters,
                state,
            ),
        }
    }

    fn create_canister_helper(
        &self,
        sender: PrincipalId,
        cycles: Cycles,
        creation_fee: Cycles,
        settings: ValidatedCanisterSettings,
        max_number_of_canisters: u64,
        state: &mut ReplicatedState,
    ) -> Result<CanisterId, CanisterManagerError> {
        // A value of 0 is equivalent to setting no limit.
        // See documentation of `SubnetRecord` for the semantics of `max_number_of_canisters`.
        if max_number_of_canisters > 0 && state.num_canisters() as u64 >= max_number_of_canisters {
            return Err(CanisterManagerError::MaxNumberOfCanistersReached {
                subnet_id: self.config.own_subnet_id,
                max_number_of_canisters,
            });
        }

        let new_canister_id = self.generate_new_canister_id(state)?;
        self.validate_canister_id_available(state, &new_canister_id)?;

        // Take the fee out of the cycles that are going to be added as the canister's
        // initial balance.
        let mut cycles = cycles - creation_fee;
        cycles = self
            .cycles_account_manager
            .check_max_cycles_can_add(Cycles::from(0), cycles);

        // Canister id available. Create the new canister.
        let mut system_state = SystemState::new_running(
            new_canister_id,
            sender,
            cycles,
            self.config.default_freeze_threshold,
        );

        self.cycles_account_manager
            .observe_consumed_cycles(&mut system_state, creation_fee);
        let scheduler_state = SchedulerState::default();
        let mut new_canister = CanisterState::new(system_state, None, scheduler_state);

        self.do_update_settings(settings, &mut new_canister);

        // Add new canister to the replicated state.
        state.put_canister_state(new_canister);

        info!(
            self.log,
            "Successfully created canister, canister_id: {}, subnet_id: {}",
            new_canister_id.to_string(),
            self.config.own_subnet_id.get()
        );

        Ok(new_canister_id)
    }

    /// Adds cycles to the canister.
    pub(crate) fn add_cycles(
        &self,
        sender: PrincipalId,
        cycles_amount: Option<u64>,
        canister: &mut CanisterState,
        provisional_whitelist: &ProvisionalWhitelist,
    ) -> Result<(), CanisterManagerError> {
        if !provisional_whitelist.contains(&sender) {
            return Err(CanisterManagerError::SenderNotInWhitelist(sender));
        }

        let cycles_amount = match cycles_amount {
            Some(cycles_amount) => Cycles::from(cycles_amount),
            None => self.config.default_provisional_cycles_balance,
        };

        self.cycles_account_manager
            .add_cycles(&mut canister.system_state, cycles_amount);

        Ok(())
    }

    fn validate_controller(
        &self,
        canister: &CanisterState,
        controller: &PrincipalId,
    ) -> Result<(), CanisterManagerError> {
        if !canister.controllers().contains(controller) {
            return Err(CanisterManagerError::CanisterInvalidController {
                canister_id: canister.canister_id(),
                controllers_expected: canister.system_state.controllers.clone(),
                controller_provided: *controller,
            });
        }
        Ok(())
    }

    fn validate_canister_id_available(
        &self,
        state: &ReplicatedState,
        canister_id: &CanisterId,
    ) -> Result<(), CanisterManagerError> {
        match state.canister_state(canister_id) {
            Some(_) => Err(CanisterManagerError::CanisterAlreadyExists(*canister_id)),
            _ => Ok(()),
        }
    }

    fn validate_compute_allocation(
        &self,
        total_subnet_compute_allocation_used: u64,
        canister: &CanisterState,
        compute_allocation: Option<ComputeAllocation>,
    ) -> Result<(), CanisterManagerError> {
        if let Some(compute_allocation) = compute_allocation {
            let canister_current_allocation =
                canister.scheduler_state.compute_allocation.as_percent();

            // current_compute_allocation of this canister will be subtracted from the
            // total_compute_allocation() of the subnet if the canister's compute_allocation
            // is changed to the requested_compute_allocation
            if compute_allocation.as_percent() + total_subnet_compute_allocation_used
                - canister_current_allocation
                >= self.config.compute_capacity
            {
                return Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: compute_allocation,
                    available: self.config.compute_capacity + canister_current_allocation
                        - total_subnet_compute_allocation_used
                        - 1,
                });
            }
        }

        Ok(())
    }

    // Ensures that the subnet has enough memory capacity left to install the
    // canister.
    fn validate_memory_allocation(
        &self,
        total_subnet_memory_taken: NumBytes,
        canister: &CanisterState,
        memory_allocation: Option<MemoryAllocation>,
    ) -> Result<(), CanisterManagerError> {
        if let Some(memory_allocation) = memory_allocation {
            if let MemoryAllocation::Reserved(requested_allocation) = memory_allocation {
                if requested_allocation < canister.memory_usage(self.config.own_subnet_type) {
                    return Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                        canister_id: canister.canister_id(),
                        memory_allocation_given: memory_allocation,
                        memory_usage_needed: canister.memory_usage(self.config.own_subnet_type),
                    });
                }
            }
            let canister_current_allocation = match canister.memory_allocation() {
                MemoryAllocation::Reserved(bytes) => bytes,
                MemoryAllocation::BestEffort => canister.memory_usage(self.config.own_subnet_type),
            };
            if memory_allocation.bytes() + total_subnet_memory_taken - canister_current_allocation
                > self.config.subnet_memory_capacity
            {
                return Err(CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                    requested: memory_allocation.bytes(),
                    available: self.config.subnet_memory_capacity
                        - total_subnet_memory_taken
                        - canister_current_allocation,
                });
            }
        }
        Ok(())
    }

    fn validate_canister_is_stopped(
        &self,
        canister: &CanisterState,
    ) -> Result<(), CanisterManagerError> {
        if canister.status() != CanisterStatusType::Stopped {
            return Err(CanisterManagerError::DeleteCanisterNotStopped(
                canister.canister_id(),
            ));
        }
        Ok(())
    }

    // WARNING!!! If you change the logic here, please ensure that the sequence
    // of NNS canister ids as defined in nns/constants/src/constants.rs are also
    // updated.
    fn generate_new_canister_id(
        &self,
        state: &mut ReplicatedState,
    ) -> Result<CanisterId, CanisterManagerError> {
        let canister_id_ranges = state
            .metadata
            .network_topology
            .routing_table
            .ranges(self.config.own_subnet_id);
        if state.metadata.generated_id_counter as u128 >= canister_id_ranges.total_count() {
            error!(
                self.log,
                "Subnet is full.  Total allowed is {} and generated_count is {}",
                canister_id_ranges.total_count(),
                state.metadata.generated_id_counter
            );
            return Err(CanisterManagerError::SubnetOutOfCanisterIds {
                allowed: canister_id_ranges.total_count(),
            });
        }
        let canister_id = canister_id_ranges.locate(state.metadata.generated_id_counter);
        state.metadata.generated_id_counter += 1;
        Ok(canister_id)
    }

    fn validate_canister_exists<'a>(
        &self,
        state: &'a ReplicatedState,
        canister_id: CanisterId,
    ) -> Result<&'a CanisterState, CanisterManagerError> {
        state
            .canister_state(&canister_id)
            .ok_or(CanisterManagerError::CanisterNotFound(canister_id))
    }

    pub(crate) fn get_wasm_hash(&self, canister: &CanisterState) -> Option<[u8; 32]> {
        canister
            .execution_state
            .as_ref()
            .map(|execution_state| execution_state.wasm_binary.binary.hash_sha256())
    }
}
#[doc(hidden)] // pub for usage in tests
pub(crate) fn canister_layout(
    state_path: &Path,
    canister_id: &CanisterId,
) -> CanisterLayout<RwPolicy> {
    CheckpointLayout::<RwPolicy>::new(state_path.into(), Height::from(0))
        .and_then(|layout| layout.canister(canister_id))
        .expect("failed to obtain canister layout")
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CanisterManagerError {
    CanisterInvalidController {
        canister_id: CanisterId,
        controllers_expected: BTreeSet<PrincipalId>,
        controller_provided: PrincipalId,
    },
    CanisterAlreadyExists(CanisterId),
    CanisterNotFound(CanisterId),
    CanisterNonEmpty(CanisterId),
    InvalidSenderSubnet(SubnetId),
    SubnetComputeCapacityOverSubscribed {
        requested: ComputeAllocation,
        available: u64,
    },
    SubnetMemoryCapacityOverSubscribed {
        requested: NumBytes,
        available: NumBytes,
    },
    Hypervisor(CanisterId, HypervisorError),
    DeleteCanisterNotStopped(CanisterId),
    DeleteCanisterSelf(CanisterId),
    SenderNotInWhitelist(PrincipalId),
    NotEnoughMemoryAllocationGiven {
        canister_id: CanisterId,
        memory_allocation_given: MemoryAllocation,
        memory_usage_needed: NumBytes,
    },
    CreateCanisterNotEnoughCycles {
        sent: Cycles,
        required: Cycles,
    },
    InstallCodeNotEnoughCycles(CanisterOutOfCyclesError),
    SubnetOutOfCanisterIds {
        allowed: u128,
    },

    InvalidSettings {
        message: String,
    },
    MaxNumberOfCanistersReached {
        subnet_id: SubnetId,
        max_number_of_canisters: u64,
    },
}

impl From<CanisterManagerError> for UserError {
    fn from(err: CanisterManagerError) -> Self {
        use CanisterManagerError::*;

        match err {
            CanisterAlreadyExists(canister_id) => {
                Self::new(
                    ErrorCode::CanisterAlreadyInstalled,
                    format!("Canister {} is already installed", canister_id))
            },
            SubnetComputeCapacityOverSubscribed {requested , available } => {
                Self::new(
                    ErrorCode::SubnetOversubscribed,
                    format!(
                        "Canister requested a compute allocation of {} which cannot be satisfied because the Subnet's remaining compute capacity is {}%",
                        requested,
                        available
                    ))
            }
            CanisterNotFound(canister_id) => {
                Self::new(
                    ErrorCode::CanisterNotFound,
                    format!("Canister {} not found.", &canister_id),
                )
            }
            Hypervisor(canister_id, err) => err.into_user_error(&canister_id),
            SubnetMemoryCapacityOverSubscribed {requested, available } => {
                Self::new(
                    ErrorCode::SubnetOversubscribed,
                    format!(
                        "Canister with memory allocation {}MiB cannot be installed because the Subnet's remaining memory capacity is {}MiB",
                        requested.get() / (1024 * 1024),
                        available.get() / (1024 * 1024),
                    )
                )
            }
            CanisterNonEmpty(canister_id) => {
                Self::new(
                    ErrorCode::CanisterNonEmpty,
                    format!("Canister {} cannot be installed because the canister is not empty. Try installing with mode='reinstall' instead.",
                            canister_id),
                )
            }
            CanisterInvalidController {
                canister_id,
                controllers_expected,
                controller_provided } => {
                let controllers_expected = controllers_expected.iter().map(|id| format!("{}", id)).collect::<Vec<String>>().join(" ");
                Self::new(
                    ErrorCode::CanisterInvalidController,
                    format!(
                        "Only the controllers of the canister {} can control it.\n\
                        Canister's controllers: {}\n\
                        Sender's ID: {}",
                        canister_id, controllers_expected, controller_provided
                    )
                )
            }
            DeleteCanisterNotStopped(canister_id) => {
                Self::new(
                    ErrorCode::CanisterNotStopped,
                    format!(
                        "Canister {} must be stopped before it is deleted.",
                        canister_id,
                    )
                )
            }
            DeleteCanisterSelf(canister_id) => {
                Self::new(
                    ErrorCode::CanisterInvalidController,
                    format!(
                        "Canister {} cannot delete itself.",
                        canister_id,
                    )
                )
            }
            SenderNotInWhitelist(_) => {
                // Methods that are whitelisted are private and should be invisible to users
                // outside of the whitelist. Therefore, not finding the sender in the whitelist is
                // concealed as a "method not found" error.
                Self::new(
                    ErrorCode::CanisterMethodNotFound,
                    String::from("Sender not authorized to use method.")
                )
            }
            NotEnoughMemoryAllocationGiven { canister_id, memory_allocation_given, memory_usage_needed} => {
                Self::new(
                    ErrorCode::InsufficientMemoryAllocation,
                    format!(
                        "Canister {} was given {} memory allocation but at least {} of memory is needed.",
                        canister_id, memory_allocation_given, memory_usage_needed,
                    )
                )
            }
            CreateCanisterNotEnoughCycles {sent, required} => {
                Self::new(
                    ErrorCode::InsufficientCyclesForCreateCanister,
                    format!(
                        "Creating a canister requires a fee of {} that is deducted from the canister's initial balance but only {} cycles were received with the create_canister request.",
                        required, sent,
                    ),
                )
            }
            InvalidSenderSubnet(_subnet_id) => {
                Self::new(
                    ErrorCode::CanisterContractViolation,
                        "Cannot create canister. Sender should be on the same subnet or on the NNS subnet.".to_string(),
                )
            }
            InstallCodeNotEnoughCycles(err) => {
                Self::new(
                ErrorCode::CanisterOutOfCycles,
                    format!("Canister installation failed with `{}`", err),
                )
            }
            SubnetOutOfCanisterIds{ allowed } => {
                Self::new(
                    ErrorCode::SubnetOversubscribed,
                    format!(
                        "Could not create canister.  Subnet has surpassed its limit {} of canister ids",
                        allowed,
                    ),
                )
            }
            InvalidSettings { message } => {
                Self::new(ErrorCode::CanisterContractViolation,
                          format!("Could not validate the settings: {} ", message),
                )
            }
            MaxNumberOfCanistersReached { subnet_id, max_number_of_canisters } => {
                Self::new(
                    ErrorCode::MaxNumberOfCanistersReached,
                    format!("Subnet {} has reached the allowed canister limit of {} canisters. Retry creating the canister.", subnet_id, max_number_of_canisters),
                )
            }
        }
    }
}

impl From<(CanisterId, HypervisorError)> for CanisterManagerError {
    fn from(val: (CanisterId, HypervisorError)) -> Self {
        CanisterManagerError::Hypervisor(val.0, val.1)
    }
}

impl From<CanisterManagerError> for RejectContext {
    fn from(error: CanisterManagerError) -> Self {
        let error = UserError::from(error);
        Self::from(error)
    }
}

pub(crate) fn truncate_canister_heap(
    log: &ReplicaLogger,
    state_path: &Path,
    canister_id: CanisterId,
) {
    let layout = canister_layout(state_path, &canister_id);
    let heap_file = layout.vmemory_0();
    if let Err(err) = nix::unistd::truncate(&heap_file, 0) {
        // It's OK if the file doesn't exist, everything else is a fatal error.
        if err != nix::errno::Errno::ENOENT {
            fatal!(
                log,
                "failed to truncate heap of canister {} stored at {}: {}",
                canister_id,
                heap_file.display(),
                err
            )
        }
    }
}

pub(crate) fn truncate_canister_stable_memory(
    log: &ReplicaLogger,
    state_path: &Path,
    canister_id: CanisterId,
) {
    let layout = canister_layout(state_path, &canister_id);
    let stable_memory_file = layout.stable_memory_blob();
    if let Err(err) = nix::unistd::truncate(&stable_memory_file, 0) {
        // It's OK if the file doesn't exist, everything else is a fatal error.
        if err != nix::errno::Errno::ENOENT {
            fatal!(
                log,
                "failed to truncate stable memory of canister {} stored at {}: {}",
                canister_id,
                stable_memory_file.display(),
                err
            )
        }
    }
}

/// Uninstalls a canister.
///
/// See https://sdk.dfinity.org/docs/interface-spec/index.html#ic-uninstall_code
///
/// Returns a list of rejects that need to be sent out to their callers.
#[doc(hidden)]
pub fn uninstall_canister(
    log: &ReplicaLogger,
    canister: &mut CanisterState,
    state_path: &Path,
    time: Time,
) -> Vec<Response> {
    // Drop the canister's execution state.
    canister.execution_state = None;

    // Drop its certified data.
    canister.system_state.certified_data = Vec::new();

    truncate_canister_heap(log, state_path, canister.canister_id());
    truncate_canister_stable_memory(log, state_path, canister.canister_id());

    let mut rejects = Vec::new();
    let canister_id = canister.canister_id();
    if let Some(call_context_manager) = canister.system_state.call_context_manager_mut() {
        // Mark all call contexts as deleted and prepare reject responses.
        // Note that callbacks will be unregistered at a later point once they are
        // received.
        for call_context in call_context_manager.call_contexts_mut().values_mut() {
            // Mark the call context as deleted.
            call_context.mark_deleted();

            if call_context.has_responded() {
                // Call context has already been responded to. Nothing to do.
                continue;
            }

            // Generate a reject response.
            match call_context.call_origin() {
                CallOrigin::Ingress(user_id, message_id) => {
                    rejects.push(Response::Ingress(IngressResponse {
                        message_id: message_id.clone(),
                        status: IngressStatus::Failed {
                            receiver: canister_id.get(),
                            user_id: *user_id,
                            error: UserError::new(
                                ErrorCode::CanisterRejectedMessage,
                                "Canister has been uninstalled.",
                            ),
                            time,
                        },
                    }));
                }
                CallOrigin::CanisterUpdate(caller_canister_id, callback_id) => {
                    rejects.push(Response::Canister(CanisterResponse {
                        originator: *caller_canister_id,
                        respondent: canister_id,
                        originator_reply_callback: *callback_id,
                        refund: call_context.available_cycles(),
                        response_payload: Payload::Reject(RejectContext {
                            code: RejectCode::CanisterReject,
                            message: String::from("Canister has been uninstalled."),
                        }),
                    }));
                }
                CallOrigin::CanisterQuery(_, _) | CallOrigin::Query(_) => fatal!(
                    log,
                    "No callbacks with a query origin should be found when uninstalling"
                ),
                CallOrigin::Heartbeat => {
                    // Cannot respond to heartbeat messages. Nothing to do.
                }
            }

            // Mark the call context as responded to.
            call_context.mark_responded();
        }
    }

    rejects
}

struct ValidatedCanisterSettings {
    pub controller: Option<PrincipalId>,
    pub controllers: Option<Vec<PrincipalId>>,
    pub compute_allocation: Option<ComputeAllocation>,
    pub memory_allocation: Option<MemoryAllocation>,
    pub freezing_threshold: Option<NumSeconds>,
}

impl TryFrom<(CanisterSettings, usize)> for ValidatedCanisterSettings {
    type Error = CanisterManagerError;

    fn try_from(input: (CanisterSettings, usize)) -> Result<Self, Self::Error> {
        let (settings, max_controllers) = input;
        // Field `controller` is kept for backward compatibility. However, specifying
        // both `controller` and `controllers` fields in the same request results in an
        // error.
        let controllers = settings.controllers();
        if let (Some(_), Some(_)) = (settings.controller(), &controllers) {
            return Err(CanisterManagerError::InvalidSettings {
                message: "Invalid settings: 'controller' and 'controllers' fields cannot be set simultaneously".to_string(),
            });
        }
        match &controllers {
            Some(controllers) => {
                if controllers.len() > max_controllers {
                    return Err(CanisterManagerError::InvalidSettings {
                        message:
                            "Invalid settings: 'controllers' length exceeds maximum size allowed"
                                .to_string(),
                    });
                }
            }
            None => {}
        }

        Ok(Self {
            controller: settings.controller(),
            controllers: settings.controllers(),
            compute_allocation: settings.compute_allocation(),
            memory_allocation: settings.memory_allocation(),
            freezing_threshold: settings.freezing_threshold(),
        })
    }
}

#[cfg(test)]
mod tests;
