use crate::{
    canister_settings::CanisterSettings,
    hypervisor::Hypervisor,
    types::{IngressResponse, Response},
};
use candid::Decode;
use ic_base_types::NumSeconds;
use ic_cow_state::CowMemoryManager;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_ic00_types::{
    CanisterIdRecord, CanisterStatusResultV2, InstallCodeArgs, Method as Ic00Method,
    SetControllerArgs, UpdateSettingsArgs,
};
use ic_interfaces::execution_environment::{
    HypervisorError, IngressHistoryWriter, MessageAcceptanceError, SubnetAvailableMemory,
};
use ic_logger::{error, fatal, info, ReplicaLogger};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallOrigin, CanisterState, CanisterStatus, CyclesAccountError, ExecutionState, ReplicatedState,
    SchedulerState, SystemState,
};
use ic_state_layout::{CanisterLayout, CheckpointLayout, RwPolicy};
use ic_types::{
    ingress::IngressStatus,
    messages::{
        CanisterInstallMode, Payload, RejectContext, Response as CanisterResponse,
        StopCanisterContext,
    },
    methods::SystemMethod,
    user_error::{ErrorCode, RejectCode, UserError},
    CanisterId, CanisterStatusType, ComputeAllocation, Cycles, Funds, Height, InstallCodeContext,
    MemoryAllocation, NumBytes, NumInstructions, PrincipalId, SubnetId, Time, UserId,
};
use ic_utils::ic_features::cow_state_feature;
use ic_wasm_utils::validation::WasmValidationLimits;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{convert::TryFrom, mem, str::FromStr, sync::Arc};

/// The different return types from `stop_canister()` function below.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StopCanisterResult {
    /// The call failed.  The error and the unconsumed funds are returned.
    Failure {
        error: CanisterManagerError,
        funds_to_return: Funds,
    },
    /// The canister is already stopped.  The unconsumed funds are returned.
    AlreadyStopped { funds_to_return: Funds },
    /// The request was successfully accepted.  A response will follow
    /// eventually when the canister does stop.
    RequestAccepted,
}

/// Returns true if the canister is empty, false otherwise.
fn canister_is_empty(canister: &CanisterState) -> bool {
    canister.execution_state.is_none() && canister.system_state.stable_memory_size.get() == 0
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct CanisterMgrConfig {
    pub(crate) subnet_memory_capacity: NumBytes,
    pub(crate) max_cycles_per_canister: Option<Cycles>,
    pub(crate) default_provisional_cycles_balance: Cycles,
    pub(crate) default_freeze_threshold: NumSeconds,
    pub(crate) max_globals: usize,
    pub(crate) max_functions: usize,
}

impl CanisterMgrConfig {
    pub(crate) fn new(
        subnet_memory_capacity: NumBytes,
        max_cycles_per_canister: Option<Cycles>,
        default_provisional_cycles_balance: Cycles,
        default_freeze_threshold: NumSeconds,
        max_globals: usize,
        max_functions: usize,
    ) -> Self {
        Self {
            subnet_memory_capacity,
            max_cycles_per_canister,
            default_provisional_cycles_balance,
            default_freeze_threshold,
            max_globals,
            max_functions,
        }
    }
}

/// The entity responsible for managing canisters (creation, installing, etc.)
pub(crate) struct CanisterManager {
    hypervisor: Arc<Hypervisor>,
    compute_capacity: u64,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    log: ReplicaLogger,
    config: CanisterMgrConfig,
    cycles_account_manager: Arc<CyclesAccountManager>,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
}

impl CanisterManager {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        hypervisor: Arc<Hypervisor>,
        cores: usize,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        log: ReplicaLogger,
        config: CanisterMgrConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    ) -> Self {
        CanisterManager {
            hypervisor,
            compute_capacity: 100 * cores as u64,
            own_subnet_id,
            own_subnet_type,
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
    ) -> Result<(), MessageAcceptanceError> {
        fn is_sender_controller(
            canister_id: CanisterId,
            sender: UserId,
            state: Arc<ReplicatedState>,
        ) -> Result<(), MessageAcceptanceError> {
            match state.canister_state(&canister_id) {
                Some(canister) => {
                    if sender.get() != canister.controller() {
                        Err(MessageAcceptanceError::CanisterRejected)
                    } else {
                        Ok(())
                    }
                }
                None => Err(MessageAcceptanceError::CanisterNotFound),
            }
        }

        // The message is targetted towards the management canister. The
        // actual type of the method will determine if the message should be
        // accepted or not.
        match Ic00Method::from_str(method_name) {
            // The method is either invalid or it is of a type that users
            // are not allowed to send.
            Err(_)
            | Ok(Ic00Method::CreateCanister)
                | Ok(Ic00Method::SetupInitialDKG)
                // This method is deprecated
                | Ok(Ic00Method::DepositFunds)
                // This can be called by anyone however as ingress message
                // cannot carry cycles, it does not make sense to allow them from users.
            | Ok(Ic00Method::DepositCycles) => Err(MessageAcceptanceError::CanisterRejected),

            // These methods are only valid if they are sent by the controller
            // of the canister. We assume that the canister always wants to
            // accept messages from its controller.
            Ok(Ic00Method::CanisterStatus)
            | Ok(Ic00Method::StartCanister)
            | Ok(Ic00Method::UninstallCode)
            | Ok(Ic00Method::StopCanister)
            | Ok(Ic00Method::DeleteCanister) => match Decode!(&payload, CanisterIdRecord) {
                Err(_) => Err(MessageAcceptanceError::CanisterRejected),
                Ok(args) => is_sender_controller(args.get_canister_id(), sender, state),
            },
            Ok(Ic00Method::UpdateSettings) => match Decode!(&payload, UpdateSettingsArgs) {
                Err(_) => Err(MessageAcceptanceError::CanisterRejected),
                Ok(args) => is_sender_controller(args.get_canister_id(), sender, state),
            },
            Ok(Ic00Method::InstallCode) => match Decode!(&payload, InstallCodeArgs) {
                Err(_) => Err(MessageAcceptanceError::CanisterRejected),
                Ok(args) => is_sender_controller(args.get_canister_id(), sender, state),
            },
            Ok(Ic00Method::SetController) => match Decode!(&payload, SetControllerArgs) {
                Err(_) => Err(MessageAcceptanceError::CanisterRejected),
                Ok(args) => is_sender_controller(args.get_canister_id(), sender, state),
            },

            // Nobody pays for `raw_rand`, so this cannot be used via ingress messages
            Ok(Ic00Method::RawRand) => Err(MessageAcceptanceError::CanisterRejected),

            Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
                | Ok(Ic00Method::ProvisionalTopUpCanister) => {
                    if provisional_whitelist.contains(sender.get_ref()) {
                        Ok(())
                    } else {
                        Err(MessageAcceptanceError::CanisterRejected)
                    }
                }
        }
    }

    fn validate_settings(
        &self,
        settings: CanisterSettings,
        state: &ReplicatedState,
    ) -> Result<ValidatedCanisterSettings, CanisterManagerError> {
        let memory_allocation_used = state.total_memory_allocation_used();
        let compute_allocation_used = state.total_compute_allocation();

        if let Some(memory_allocation) = settings.memory_allocation() {
            let requested_allocation: NumBytes = memory_allocation.get();
            if requested_allocation + memory_allocation_used > self.config.subnet_memory_capacity {
                return Err(CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                    requested: requested_allocation,
                    available: self.config.subnet_memory_capacity - memory_allocation_used,
                });
            }
        }

        if let Some(compute_allocation) = settings.compute_allocation() {
            let compute_allocation = compute_allocation;
            if compute_allocation.as_percent() + compute_allocation_used >= self.compute_capacity {
                return Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: compute_allocation,
                    available: self.compute_capacity - compute_allocation_used - 1,
                });
            }
        }

        Ok(ValidatedCanisterSettings::from(settings))
    }

    /// Applies the requested settings on the canister.
    /// Note: Called only after validating the settings.
    fn do_update_settings(
        &self,
        settings: ValidatedCanisterSettings,
        canister: &mut CanisterState,
    ) {
        if let Some(controller_id) = settings.controller {
            canister.system_state.controller = controller_id;
        }
        if let Some(compute_allocation) = settings.compute_allocation {
            canister.scheduler_state.compute_allocation = compute_allocation;
        }
        if let Some(memory_allocation) = settings.memory_allocation {
            canister.system_state.memory_allocation = Some(memory_allocation);
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
        canister_id: CanisterId,
        settings: CanisterSettings,
        state: &mut ReplicatedState,
    ) -> Result<(), CanisterManagerError> {
        let compute_allocation_used = state.total_compute_allocation();
        let memory_allocation_used = state.total_memory_allocation_used();
        let canister = state
            .canister_state_mut(&canister_id)
            .ok_or_else(|| CanisterManagerError::CanisterNotFound(canister_id))?;

        // Verify controller.
        self.validate_controller(&canister, &sender)?;
        self.validate_compute_allocation(
            compute_allocation_used,
            &canister,
            settings.compute_allocation(),
        )?;
        self.validate_memory_allocation(
            memory_allocation_used,
            &canister,
            settings.memory_allocation(),
        )?;

        let validated_settings = ValidatedCanisterSettings::from(settings);
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
        funds: Funds,
        settings: CanisterSettings,
        state: &mut ReplicatedState,
    ) -> (Result<CanisterId, CanisterManagerError>, Funds) {
        // Creating a canister is possible only in the following cases:
        // 1. sender is on NNS => it can create canister on any subnet
        // 2. sender is not NNS => can create canister only if sender is on
        // same subnet.
        if sender_subnet_id != state.metadata.network_topology.nns_subnet_id
            && sender_subnet_id != state.metadata.own_subnet_id
        {
            return (
                Err(CanisterManagerError::InvalidSenderSubnet(sender_subnet_id)),
                funds,
            );
        }

        let cycles = funds.cycles();
        if cycles < self.cycles_account_manager.canister_creation_fee() {
            return (
                Err(CanisterManagerError::CreateCanisterNotEnoughCycles {
                    sent: cycles,
                    required: self.cycles_account_manager.canister_creation_fee(),
                }),
                funds,
            );
        }

        // Validate settings before `create_canister_helper` applies them
        match self.validate_settings(settings, state) {
            Err(err) => (Err(err), funds),
            Ok(validate_settings) => {
                // Take the fee out of the cycles that are going to be added as the canister's
                // initial balance.
                let cycles = funds.cycles() - self.cycles_account_manager.canister_creation_fee();
                let canister_id =
                    match self.create_canister_helper(sender, cycles, validate_settings, state) {
                        Ok(canister_id) => canister_id,
                        Err(err) => return (Err(err), funds),
                    };
                (Ok(canister_id), Funds::zero())
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
        instructions_limit: NumInstructions,
        subnet_available_memory: SubnetAvailableMemory,
    ) -> (NumInstructions, Result<NumBytes, CanisterManagerError>) {
        // Copy necessary bits out of the `ReplicatedState`. This is because further
        // below, we take a mutable reference to the old canister state while it
        // is held inside state. Then Rust's borrow checker prevents us from
        // calling further methods on the state.
        let time = state.time();
        let canister_layout_path = state.path().to_path_buf();
        let compute_allocation_used = state.total_compute_allocation();
        let memory_allocation_used = state.total_memory_allocation_used();

        // Perform a battery of validation checks.
        let old_canister = match state.canister_state_mut(&context.canister_id) {
            None => {
                return (
                    instructions_limit,
                    Err(CanisterManagerError::CanisterNotFound(context.canister_id)),
                );
            }
            Some(canister) => canister,
        };
        if let Err(err) = self.validate_compute_allocation(
            compute_allocation_used,
            &old_canister,
            context.compute_allocation,
        ) {
            return (instructions_limit, Err(err));
        }
        if let Err(err) = self.validate_memory_allocation(
            memory_allocation_used,
            &old_canister,
            context.memory_allocation,
        ) {
            return (instructions_limit, Err(err));
        }
        if old_canister.system_state.controller != context.sender {
            return (
                instructions_limit,
                Err(CanisterManagerError::CanisterInvalidController {
                    canister_id: context.canister_id,
                    controller_expected: old_canister.system_state.controller,
                    controller_provided: context.sender,
                }),
            );
        }
        match context.mode {
            CanisterInstallMode::Install => {
                if !canister_is_empty(old_canister) {
                    return (
                        instructions_limit,
                        Err(CanisterManagerError::CanisterNonEmpty(context.canister_id)),
                    );
                }
            }
            CanisterInstallMode::Reinstall | CanisterInstallMode::Upgrade => {}
        }

        // All validation checks have passed. Reserve cycles on the old canister
        // for executing the various hooks such as `start`, `pre_upgrade`,
        // `post_upgrade`.
        let memory_usage = old_canister.memory_usage();
        let compute_allocation = old_canister.scheduler_state.compute_allocation;
        if let Err(err) = self.cycles_account_manager.withdraw_execution_cycles(
            &mut old_canister.system_state,
            memory_usage,
            compute_allocation,
            instructions_limit,
        ) {
            return (instructions_limit, Err((context.canister_id, err).into()));
        }

        // Copy bits out of context as the calls below are going to consume it.
        let canister_id = context.canister_id;
        let mode = context.mode;

        let (instructions_left, result) = match context.mode {
            CanisterInstallMode::Install | CanisterInstallMode::Reinstall => self.install(
                context,
                old_canister,
                instructions_limit,
                subnet_available_memory,
                time,
                canister_layout_path,
            ),
            CanisterInstallMode::Upgrade => self.upgrade(
                context,
                old_canister,
                instructions_limit,
                subnet_available_memory,
                time,
                canister_layout_path,
            ),
        };

        let result = match result {
            Ok((heap_delta, mut new_canister)) => {
                // Refund the left over execution cycles to the new canister and
                // replace the old canister with the new one.

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
                Ok(heap_delta)
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

        if canister.controller() != sender {
            return Err(CanisterManagerError::CanisterInvalidController {
                canister_id,
                controller_expected: canister.controller(),
                controller_provided: sender,
            });
        }

        let rejects = uninstall_canister(&self.log, canister, &path, time);
        crate::util::process_responses(rejects, state, Arc::clone(&self.ingress_history_writer));
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
                    funds_to_return: stop_context.take_funds(),
                }
            }
            Some(canister) => canister,
        };

        let result = match self.validate_controller(&canister, stop_context.sender()) {
            Err(err) => StopCanisterResult::Failure {
                error: err,
                funds_to_return: stop_context.take_funds(),
            },
            Ok(()) => {
                match &mut canister.system_state.status {
                    CanisterStatus::Stopped => StopCanisterResult::AlreadyStopped {
                        funds_to_return: stop_context.take_funds(),
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
        canister_id: CanisterId,
        sender: PrincipalId,
        state: &mut ReplicatedState,
    ) -> Result<Vec<StopCanisterContext>, CanisterManagerError> {
        let canister = state
            .canister_state(&canister_id)
            .ok_or_else(|| CanisterManagerError::CanisterNotFound(canister_id))?;

        self.validate_controller(&canister, &sender)?;

        let mut canister = state.take_canister_state(&canister_id).unwrap();

        let stop_contexts = match &mut canister.system_state.status {
            CanisterStatus::Stopping { stop_contexts, .. } => mem::replace(stop_contexts, vec![]),
            CanisterStatus::Running { .. } | CanisterStatus::Stopped => {
                Vec::new() // No stop contexts to return.
            }
        };

        // Transition the canister into "running".
        canister.system_state.status = match canister.system_state.status {
            CanisterStatus::Running {
                call_context_manager,
            }
            | CanisterStatus::Stopping {
                call_context_manager,
                ..
            } => CanisterStatus::Running {
                call_context_manager,
            },
            CanisterStatus::Stopped => CanisterStatus::new_running(),
        };

        state.put_canister_state(canister);
        Ok(stop_contexts)
    }

    /// Fetches the current status of the canister.
    pub(crate) fn get_canister_status(
        &self,
        canister_id: CanisterId,
        sender: PrincipalId,
        state: &mut ReplicatedState,
    ) -> Result<CanisterStatusResultV2, CanisterManagerError> {
        let canister = state
            .canister_state(&canister_id)
            .ok_or_else(|| CanisterManagerError::CanisterNotFound(canister_id))?;

        self.validate_controller(&canister, &sender)?;

        Ok(CanisterStatusResultV2::new(
            canister.status(),
            canister
                .execution_state
                .as_ref()
                .map(|es| es.wasm_binary.hash_sha256().to_vec()),
            canister.controller(),
            canister.memory_usage(),
            canister.system_state.cycles_account.cycles_balance().get(),
            canister.scheduler_state.compute_allocation.as_percent(),
            canister
                .system_state
                .memory_allocation
                .map(|allocation| allocation.get().get()),
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
        let settings = CanisterSettings::new(Some(new_controller), None, None, None);
        self.update_settings(sender, canister_id, settings, state)
    }

    /// Permanently deletes a canister from `ReplicatedState`.
    ///
    /// The canister must be `Stopped` and only the controller of the canister
    /// can delete it. The controller must be a canister and the canister
    /// cannot be its own controller.
    ///
    /// Any remaining funds in the canister are transferred to its controller.
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
        self.validate_controller(&canister_to_delete, &sender)?;

        self.validate_canister_is_stopped(&canister_to_delete)?;

        // Once a canister is stopped, it stops accepting new messages, so this should
        // never happen.
        assert!(
            !canister_to_delete.has_input(),
            format!(
                "Trying to delete canister {} while having messages in its input queue.",
                canister_to_delete.canister_id()
            )
        );

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
        assert!(
            !canister_to_delete.has_output(),
            format!(
                "Trying to delete canister {} while having messages in its output queue.",
                canister_to_delete.canister_id()
            )
        );

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

    /// Deposits the amount of funds specified from the sender to the target
    /// `canister_id`.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterManagerError` in case the canister does not exist or
    /// this was invoked not by the controller or the receiving canister did not
    /// have enough cycles to cover the cost.
    pub(crate) fn deposit_funds(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        mut funds: Funds,
        state: &mut ReplicatedState,
    ) -> (Funds, Result<(), CanisterManagerError>) {
        match self.validate_canister_exists(state, canister_id) {
            Err(err) => (funds, Err(err)),
            Ok(canister) => {
                if let Err(err) = self.validate_controller(&canister, &sender) {
                    return (funds, Err(err));
                }
                let canister = state.canister_state_mut(&canister_id).unwrap();
                self.cycles_account_manager
                    .add_cycles(&mut canister.system_state, funds.take_cycles());
                (Funds::zero(), Ok(()))
            }
        }
    }

    /// Deposits the amount of cycles specified from the sender to the target
    /// `canister_id`.
    ///
    /// # Errors
    ///
    /// Returns a `CanisterManagerError` in case the canister does not exist
    pub(crate) fn deposit_cycles(
        &self,
        canister_id: CanisterId,
        cycles: Cycles,
        state: &mut ReplicatedState,
    ) -> (Cycles, Result<(), CanisterManagerError>) {
        match state.canister_state_mut(&canister_id) {
            None => (
                cycles,
                Err(CanisterManagerError::CanisterNotFound(canister_id)),
            ),
            Some(canister) => {
                self.cycles_account_manager
                    .add_cycles(&mut canister.system_state, cycles);

                // Take out the cost of the operation.
                (Cycles::from(0), Ok(()))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn install(
        &self,
        context: InstallCodeContext,
        old_canister: &CanisterState,
        instructions_limit: NumInstructions,
        subnet_available_memory: SubnetAvailableMemory,
        time: Time,
        canister_layout_path: PathBuf,
    ) -> (
        NumInstructions,
        Result<(NumBytes, CanisterState), CanisterManagerError>,
    ) {
        let canister_id = context.canister_id;
        let layout = canister_layout(&canister_layout_path, &canister_id);
        let execution_state = match ExecutionState::new(
            context.wasm_module,
            layout.raw_path(),
            WasmValidationLimits {
                max_globals: self.config.max_globals,
                max_functions: self.config.max_functions,
            },
        ) {
            Ok(execution_state) => Some(execution_state),
            Err(err) => {
                return (instructions_limit, Err((canister_id, err).into()));
            }
        };

        let mut system_state = old_canister.system_state.clone();
        // According to spec, we must clear stable memory on install and reinstall.
        system_state.clear_stable_memory();
        let scheduler_state = old_canister.scheduler_state.clone();
        let new_canister = CanisterState::new(system_state, execution_state, scheduler_state);

        let (mut new_canister, result) = self.hypervisor.execute_empty(new_canister).get_no_pause();
        match result {
            Ok(()) => (),
            Err(err) => return (instructions_limit, Err((canister_id, err).into())),
        }

        // Update allocations.  This must happen after we have created the new
        // execution state so that we fairly account for the memory requirements
        // of the new wasm module.
        new_canister.scheduler_state.query_allocation = context.query_allocation;
        if let Some(compute_allocation) = context.compute_allocation {
            new_canister.scheduler_state.compute_allocation = compute_allocation;
        }
        if let Some(desired_memory_allocation) = context.memory_allocation {
            if desired_memory_allocation.get() < new_canister.memory_usage() {
                return (
                    instructions_limit,
                    Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                        canister_id,
                        memory_allocation_given: desired_memory_allocation,
                        memory_usage_needed: new_canister.memory_usage(),
                    }),
                );
            }
            new_canister.system_state.memory_allocation = Some(desired_memory_allocation);
        }

        let mut total_heap_delta = NumBytes::from(0);

        // Run (start)
        let (new_canister, instructions_limit, result) = self
            .hypervisor
            .execute_canister_start(
                new_canister,
                instructions_limit,
                subnet_available_memory.clone(),
            )
            .get_no_pause();
        match result {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
            }
            Err(err) => return (instructions_limit, Err((canister_id, err).into())),
        }

        // Run canister_init
        let (new_canister, instructions_limit, result) = self
            .hypervisor
            .execute_system(
                new_canister,
                SystemMethod::CanisterInit,
                context.sender,
                context.arg.as_slice(),
                instructions_limit,
                time,
                subnet_available_memory,
            )
            .get_no_pause();
        match result {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
                (instructions_limit, Ok((total_heap_delta, new_canister)))
            }
            Err(err) => (instructions_limit, Err((canister_id, err).into())),
        }
    }

    fn upgrade(
        &self,
        context: InstallCodeContext,
        old_canister: &CanisterState,
        instructions_limit: NumInstructions,
        subnet_available_memory: SubnetAvailableMemory,
        time: Time,
        canister_layout_path: PathBuf,
    ) -> (
        NumInstructions,
        Result<(NumBytes, CanisterState), CanisterManagerError>,
    ) {
        let canister_id = context.canister_id;
        let new_canister = old_canister.clone();
        let mut total_heap_delta = NumBytes::from(0);
        // Call pre-upgrade hook on the canister.
        let (mut new_canister, instructions_limit, res) = self
            .hypervisor
            .execute_system(
                new_canister,
                SystemMethod::CanisterPreUpgrade,
                context.sender,
                &[],
                instructions_limit,
                time,
                subnet_available_memory.clone(),
            )
            .get_no_pause();
        match res {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
            }
            Err(err) => return (instructions_limit, Err((canister_id, err).into())),
        }

        // Wipe the heap first
        if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            new_canister
                .execution_state
                .as_ref()
                .unwrap()
                .cow_mem_mgr
                .upgrade();
        }

        // Replace the execution state of the canister with a new execution state.
        let layout = canister_layout(&canister_layout_path, &canister_id);
        new_canister.execution_state = match ExecutionState::new(
            context.wasm_module,
            layout.raw_path(),
            WasmValidationLimits {
                max_globals: self.config.max_globals,
                max_functions: self.config.max_functions,
            },
        ) {
            Err(err) => return (instructions_limit, Err((canister_id, err).into())),
            Ok(execution_state) => Some(execution_state),
        };

        let (mut new_canister, result) = self.hypervisor.execute_empty(new_canister).get_no_pause();
        match result {
            Ok(()) => (),
            Err(err) => return (instructions_limit, Err((canister_id, err).into())),
        }

        // Update allocations.  This must happen after we have created the new
        // execution state so that we fairly account for the memory requirements
        // of the new wasm module.
        new_canister.scheduler_state.query_allocation = context.query_allocation;
        if let Some(compute_allocation) = context.compute_allocation {
            new_canister.scheduler_state.compute_allocation = compute_allocation;
        }
        if let Some(desired_memory_allocation) = context.memory_allocation {
            if desired_memory_allocation.get() < new_canister.memory_usage() {
                return (
                    instructions_limit,
                    Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                        canister_id,
                        memory_allocation_given: desired_memory_allocation,
                        memory_usage_needed: new_canister.memory_usage(),
                    }),
                );
            }
            new_canister.system_state.memory_allocation = Some(desired_memory_allocation);
        }

        // Run (start)
        let (new_canister, instructions_limit, result) = self
            .hypervisor
            .execute_canister_start(
                new_canister,
                instructions_limit,
                subnet_available_memory.clone(),
            )
            .get_no_pause();
        match result {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
            }
            Err(err) => return (instructions_limit, Err((context.canister_id, err).into())),
        }

        // Call post-upgrade hook on the upgraded canister.
        let (new_canister, instructions_left, result) = self
            .hypervisor
            .execute_system(
                new_canister,
                SystemMethod::CanisterPostUpgrade,
                context.sender,
                context.arg.as_slice(),
                instructions_limit,
                time,
                subnet_available_memory,
            )
            .get_no_pause();
        match result {
            Ok(heap_delta) => {
                total_heap_delta += heap_delta;
            }
            Err(err) => return (instructions_left, Err((canister_id, err).into())),
        }

        (instructions_left, Ok((total_heap_delta, new_canister)))
    }

    /// Creates a new canister with the fund amounts specified and inserts it
    /// into `ReplicatedState`.
    ///
    /// Note that this method is meant to only be invoked in local development
    /// or, for Sodium, by a list of whitelisted principals.
    ///
    /// Returns the auto-generated id the new canister that has been created.
    pub(crate) fn create_canister_with_funds(
        &self,
        sender: PrincipalId,
        cycles_amount: Option<u64>,
        _icp_amount: u64,
        settings: CanisterSettings,
        state: &mut ReplicatedState,
        provisional_whitelist: &ProvisionalWhitelist,
    ) -> Result<CanisterId, CanisterManagerError> {
        if !provisional_whitelist.contains(&sender) {
            return Err(CanisterManagerError::SenderNotInWhitelist(sender));
        }

        let cycles = match cycles_amount {
            Some(cycles_amount) => Cycles::from(cycles_amount),
            None => self.config.default_provisional_cycles_balance,
        };

        // Validate settings before `create_canister_helper` applies them
        match self.validate_settings(settings, state) {
            Err(err) => Err(err),
            Ok(validated_settings) => {
                self.create_canister_helper(sender, cycles, validated_settings, state)
            }
        }
    }

    fn create_canister_helper(
        &self,
        sender: PrincipalId,
        cycles: Cycles,
        settings: ValidatedCanisterSettings,
        state: &mut ReplicatedState,
    ) -> Result<CanisterId, CanisterManagerError> {
        let new_canister_id = self.generate_new_canister_id(state)?;
        self.validate_canister_id_available(&state, &new_canister_id)?;

        let cycles = match self.own_subnet_type {
            // Canisters on the System subnet can hold any amount of cycles
            SubnetType::System => cycles,
            SubnetType::Application | SubnetType::VerifiedApplication => {
                match self.config.max_cycles_per_canister {
                    None => cycles,
                    Some(max_cycles_per_canister) => {
                        if cycles > max_cycles_per_canister {
                            info!(
                                self.log,
                                "Attempted to set {} cycles for canister_id: {}, saturating instead at: {}",
                                cycles,
                                new_canister_id,
                                max_cycles_per_canister
                            );
                            max_cycles_per_canister
                        } else {
                            cycles
                        }
                    }
                }
            }
        };

        // Canister id available. Create the new canister.
        let system_state = SystemState::new_running(
            new_canister_id,
            sender,
            cycles,
            self.config.default_freeze_threshold,
        );
        let scheduler_state = SchedulerState::default();
        let mut new_canister = CanisterState::new(system_state, None, scheduler_state);

        self.do_update_settings(settings, &mut new_canister);

        // Add new canister to the replicated state.
        state.put_canister_state(new_canister);

        info!(
            self.log,
            "Successfully created canister, canister_id: {}, subnet_id: {}",
            new_canister_id.to_string(),
            self.own_subnet_id.get()
        );

        Ok(new_canister_id)
    }

    /// Adds cycles to the canister.
    pub(crate) fn add_cycles(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        cycles_amount: Option<u64>,
        state: &mut ReplicatedState,
        provisional_whitelist: &ProvisionalWhitelist,
    ) -> Result<(), CanisterManagerError> {
        if !provisional_whitelist.contains(&sender) {
            return Err(CanisterManagerError::SenderNotInWhitelist(sender));
        }

        self.validate_canister_exists(state, canister_id)?;
        let cycles_amount = match cycles_amount {
            Some(cycles_amount) => Cycles::from(cycles_amount),
            None => self.config.default_provisional_cycles_balance,
        };

        let canister = state.canister_state_mut(&canister_id).unwrap();
        self.cycles_account_manager
            .add_cycles(&mut canister.system_state, cycles_amount);

        Ok(())
    }

    fn validate_controller(
        &self,
        canister: &CanisterState,
        controller: &PrincipalId,
    ) -> Result<(), CanisterManagerError> {
        if canister.controller() != *controller {
            return Err(CanisterManagerError::CanisterInvalidController {
                canister_id: canister.canister_id(),
                controller_expected: canister.controller(),
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
        compute_allocation_used: u64,
        canister: &CanisterState,
        compute_allocation: Option<ComputeAllocation>,
    ) -> Result<(), CanisterManagerError> {
        if let Some(compute_allocation) = compute_allocation {
            let canister_current_allocation =
                canister.scheduler_state.compute_allocation.as_percent();

            // current_compute_allocation of this canister will be subtracted from the
            // total_compute_allocation() of the subnet if the canister's compute_allocation
            // is changed to the requested_compute_allocation
            if compute_allocation.as_percent() + compute_allocation_used
                - canister_current_allocation
                >= self.compute_capacity
            {
                return Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: compute_allocation,
                    available: self.compute_capacity + canister_current_allocation
                        - compute_allocation_used
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
        memory_allocation_used: NumBytes,
        canister: &CanisterState,
        memory_allocation: Option<MemoryAllocation>,
    ) -> Result<(), CanisterManagerError> {
        if let Some(memory_allocation) = memory_allocation {
            let requested_allocation: NumBytes = memory_allocation.get();
            let canister_current_allocation = canister
                .memory_allocation()
                .unwrap_or_else(|| canister.memory_usage());
            if requested_allocation + memory_allocation_used - canister_current_allocation
                > self.config.subnet_memory_capacity
            {
                return Err(CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                    requested: requested_allocation,
                    available: self.config.subnet_memory_capacity
                        - memory_allocation_used
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
            .ranges(self.own_subnet_id);
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
            .ok_or_else(|| CanisterManagerError::CanisterNotFound(canister_id))
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
        controller_expected: PrincipalId,
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
    CanisterOutOfCycles {
        canister_id: CanisterId,
        available: Cycles,
        required: Cycles,
    },
    SubnetOutOfCanisterIds {
        allowed: u128,
    },
}

impl From<(CanisterId, CyclesAccountError)> for CanisterManagerError {
    fn from(input: (CanisterId, CyclesAccountError)) -> Self {
        let (canister_id, err) = input;
        match err {
            CyclesAccountError::CanisterOutOfCycles {
                available,
                requested,
            } => Self::CanisterOutOfCycles {
                canister_id,
                available,
                required: requested,
            },
        }
    }
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
                controller_expected,
                controller_provided } => {
                Self::new(
                    ErrorCode::CanisterInvalidController,
                    format!(
                        "Only the controller of canister {} can control it.\n\
                        Canister's controller: {}\n\
                        Sender's ID: {}",
                        canister_id, controller_expected, controller_provided
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
            CanisterOutOfCycles { canister_id, available, required } => {
                Self::new(
                ErrorCode::CanisterOutOfCycles,
                    format!(
                        "Could not install canister {} as it has only {} cycles but {} are required.",
                        canister_id, available, required
                    ),
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
        if err.as_errno() != Some(nix::errno::Errno::ENOENT) {
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
        if err.as_errno() != Some(nix::errno::Errno::ENOENT) {
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

    // Drop its stable memory
    canister.system_state.clear_stable_memory();

    // Drop its certified data.
    canister.system_state.certified_data = Vec::new();

    truncate_canister_heap(&log, state_path, canister.canister_id());
    truncate_canister_stable_memory(&log, state_path, canister.canister_id());

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
                        refund: Funds::from(call_context.available_cycles()),
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
    pub compute_allocation: Option<ComputeAllocation>,
    pub memory_allocation: Option<MemoryAllocation>,
    pub freezing_threshold: Option<NumSeconds>,
}

impl From<CanisterSettings> for ValidatedCanisterSettings {
    fn from(settings: CanisterSettings) -> Self {
        Self {
            controller: settings.controller(),
            compute_allocation: settings.compute_allocation(),
            memory_allocation: settings.memory_allocation(),
            freezing_threshold: settings.freezing_threshold(),
        }
    }
}

#[cfg(test)]
mod tests;
