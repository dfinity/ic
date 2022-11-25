use crate::execution::install_code::{
    validate_compute_allocation, validate_controller, validate_memory_allocation, OriginalContext,
};
use crate::execution::{install::execute_install, upgrade::execute_upgrade};
use crate::execution_environment::{CompilationCostHandling, RoundContext, RoundLimits};
use crate::{
    canister_settings::CanisterSettings,
    hypervisor::Hypervisor,
    types::{IngressResponse, Response},
    util::GOVERNANCE_CANISTER_ID,
};
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_ic00_types::{
    CanisterInstallMode, CanisterStatusResultV2, CanisterStatusType, InstallCodeArgs,
    Method as Ic00Method,
};
use ic_interfaces::execution_environment::{
    CanisterOutOfCyclesError, HypervisorError, IngressHistoryWriter, SubnetAvailableMemory,
};
use ic_interfaces::messages::RequestOrIngress;
use ic_logger::{error, fatal, info, ReplicaLogger};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CallOrigin, CanisterState, CanisterStatus, NetworkTopology, ReplicatedState, SchedulerState,
    SystemState,
};
use ic_system_api::ExecutionParameters;
use ic_types::messages::{MessageId, SignedIngressContent};
use ic_types::nominal_cycles::NominalCycles;
use ic_types::NumInstructions;
use ic_types::{
    ingress::{IngressState, IngressStatus},
    messages::{Payload, RejectContext, Response as CanisterResponse, StopCanisterContext},
    CanisterId, CanisterTimer, ComputeAllocation, Cycles, InvalidComputeAllocationError,
    InvalidMemoryAllocationError, InvalidQueryAllocationError, MemoryAllocation, NumBytes,
    PrincipalId, QueryAllocation, SubnetId, Time,
};
use ic_wasm_types::CanisterModule;
use num_traits::cast::ToPrimitive;
use prometheus::IntCounter;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{collections::BTreeSet, convert::TryFrom, str::FromStr, sync::Arc};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InstallCodeResult {
    pub heap_delta: NumBytes,
    pub old_wasm_hash: Option<[u8; 32]>,
    pub new_wasm_hash: Option<[u8; 32]>,
}

/// The result of executing a single slice of `install_code` message (i.e
/// install, re-install, upgrade).
/// * If execution has finished successfully, then the result contains the new
///   canister state with all the changes done during execution.
/// * If execution has failed, then the result contains the old canister state
///   with some changes such charging of execution cycles.
/// * If exection did not complete, then the result contains the old canister state,
///   with some changes such reservation of execution cycles and a continuation.
#[derive(Debug)]
pub(crate) enum DtsInstallCodeResult {
    Finished {
        canister: CanisterState,
        message: RequestOrIngress,
        instructions_used: NumInstructions,
        result: Result<InstallCodeResult, CanisterManagerError>,
    },
    Paused {
        canister: CanisterState,
        paused_execution: Box<dyn PausedInstallCodeExecution>,
        ingress_status: Option<(MessageId, IngressStatus)>,
    },
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
    pub(crate) default_provisional_cycles_balance: Cycles,
    pub(crate) default_freeze_threshold: NumSeconds,
    pub(crate) compute_capacity: u64,
    pub(crate) own_subnet_id: SubnetId,
    pub(crate) own_subnet_type: SubnetType,
    pub(crate) max_controllers: usize,
    pub(crate) rate_limiting_of_instructions: FlagStatus,
}

impl CanisterMgrConfig {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        subnet_memory_capacity: NumBytes,
        default_provisional_cycles_balance: Cycles,
        default_freeze_threshold: NumSeconds,
        own_subnet_id: SubnetId,
        own_subnet_type: SubnetType,
        max_controllers: usize,
        compute_capacity: usize,
        rate_limiting_of_instructions: FlagStatus,
        allocatable_capacity_in_percent: usize,
    ) -> Self {
        Self {
            subnet_memory_capacity,
            default_provisional_cycles_balance,
            default_freeze_threshold,
            own_subnet_id,
            own_subnet_type,
            max_controllers,
            compute_capacity: (compute_capacity * allocatable_capacity_in_percent.min(100) / 100)
                as u64,
            rate_limiting_of_instructions,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InstallCodeContext {
    pub sender: PrincipalId,
    pub mode: CanisterInstallMode,
    pub canister_id: CanisterId,
    pub wasm_module: CanisterModule,
    pub arg: Vec<u8>,
    pub compute_allocation: Option<ComputeAllocation>,
    pub memory_allocation: Option<MemoryAllocation>,
    pub query_allocation: QueryAllocation,
}

/// Errors that can occur when converting from (sender, [`InstallCodeArgs`]) to
/// an [`InstallCodeContext`].
#[derive(Debug)]
pub enum InstallCodeContextError {
    ComputeAllocation(InvalidComputeAllocationError),
    MemoryAllocation(InvalidMemoryAllocationError),
    QueryAllocation(InvalidQueryAllocationError),
    InvalidCanisterId(String),
}

impl From<InstallCodeContextError> for UserError {
    fn from(err: InstallCodeContextError) -> Self {
        match err {
            InstallCodeContextError::ComputeAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "ComputeAllocation expected to be in the range [{}..{}], got {}",
                    err.min(),
                    err.max(),
                    err.given()
                ),
            ),
            InstallCodeContextError::QueryAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "QueryAllocation expected to be in the range [{}..{}], got {}",
                    err.min, err.max, err.given
                ),
            ),
            InstallCodeContextError::MemoryAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "MemoryAllocation expected to be in the range [{}..{}], got {}",
                    err.min, err.max, err.given
                ),
            ),
            InstallCodeContextError::InvalidCanisterId(bytes) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Specified canister id is not a valid principal id {}",
                    hex::encode(&bytes[..])
                ),
            ),
        }
    }
}

impl From<InvalidComputeAllocationError> for InstallCodeContextError {
    fn from(err: InvalidComputeAllocationError) -> Self {
        Self::ComputeAllocation(err)
    }
}

impl From<InvalidQueryAllocationError> for InstallCodeContextError {
    fn from(err: InvalidQueryAllocationError) -> Self {
        Self::QueryAllocation(err)
    }
}

impl From<InvalidMemoryAllocationError> for InstallCodeContextError {
    fn from(err: InvalidMemoryAllocationError) -> Self {
        Self::MemoryAllocation(err)
    }
}

impl TryFrom<(PrincipalId, InstallCodeArgs)> for InstallCodeContext {
    type Error = InstallCodeContextError;

    fn try_from(input: (PrincipalId, InstallCodeArgs)) -> Result<Self, Self::Error> {
        let (sender, args) = input;
        let canister_id = CanisterId::new(args.canister_id).map_err(|err| {
            InstallCodeContextError::InvalidCanisterId(format!(
                "Converting canister id {} failed with {}",
                args.canister_id, err
            ))
        })?;
        let compute_allocation = match args.compute_allocation {
            Some(ca) => Some(ComputeAllocation::try_from(ca.0.to_u64().ok_or_else(
                || {
                    InstallCodeContextError::ComputeAllocation(InvalidComputeAllocationError::new(
                        ca,
                    ))
                },
            )?)?),
            None => None,
        };
        let memory_allocation = match args.memory_allocation {
            Some(ma) => Some(MemoryAllocation::try_from(NumBytes::from(
                ma.0.to_u64().ok_or_else(|| {
                    InstallCodeContextError::MemoryAllocation(InvalidMemoryAllocationError::new(ma))
                })?,
            ))?),
            None => None,
        };

        // TODO(EXE-294): Query allocations are not supported and should be deleted.
        let query_allocation = QueryAllocation::default();

        Ok(InstallCodeContext {
            sender,
            mode: args.mode,
            canister_id,
            wasm_module: CanisterModule::new(args.wasm_module),
            arg: args.arg,
            compute_allocation,
            memory_allocation,
            query_allocation,
        })
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
        ingress: &SignedIngressContent,
        effective_canister_id: Option<CanisterId>,
    ) -> Result<(), UserError> {
        let method_name = ingress.method_name();
        let sender = ingress.sender();
        // The message is targeted towards the management canister. The
        // actual type of the method will determine if the message should be
        // accepted or not.
        match Ic00Method::from_str(ingress.method_name()) {
            // The method is either invalid or it is of a type that users
            // are not allowed to send.
            Err(_)
            | Ok(Ic00Method::CreateCanister)
            | Ok(Ic00Method::ECDSAPublicKey)
            | Ok(Ic00Method::SetupInitialDKG)
            | Ok(Ic00Method::SignWithECDSA)
            | Ok(Ic00Method::ComputeInitialEcdsaDealings)
            // "DepositCycles" can be called by anyone however as ingress message
            // cannot carry cycles, it does not make sense to allow them from users.
            | Ok(Ic00Method::DepositCycles)
            | Ok(Ic00Method::HttpRequest)
            // Nobody pays for `raw_rand`, so this cannot be used via ingress messages
            | Ok(Ic00Method::RawRand)
            // Bitcoin messages require cycles, so we reject all ingress messages.
            | Ok(Ic00Method::BitcoinGetBalance)
            | Ok(Ic00Method::BitcoinGetUtxos)
            | Ok(Ic00Method::BitcoinSendTransaction)
            | Ok(Ic00Method::BitcoinSendTransactionInternal)
            | Ok(Ic00Method::BitcoinGetCurrentFeePercentiles) => Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!("Only canisters can call ic00 method {}", method_name),
            )),


            // These methods are only valid if they are sent by the controller
            // of the canister. We assume that the canister always wants to
            // accept messages from its controller.
            Ok(Ic00Method::CanisterStatus)
            | Ok(Ic00Method::StartCanister)
            | Ok(Ic00Method::UninstallCode)
            | Ok(Ic00Method::StopCanister)
            | Ok(Ic00Method::DeleteCanister) |
            Ok(Ic00Method::UpdateSettings)|
            Ok(Ic00Method::InstallCode) |
            Ok(Ic00Method::SetController) => {
                match effective_canister_id {
                    Some(canister_id) => {
                        let canister = state.canister_state(&canister_id).ok_or_else(|| UserError::new(
                            ErrorCode::CanisterNotFound,
                            format!("Canister {} not found", canister_id),
                        ))?;
                        match canister.controllers().contains(&sender.get()) {
                            true => Ok(()),
                            false => Err(UserError::new(
                                ErrorCode::CanisterInvalidController,
                                format!(
                                    "Only controllers of canister {} can call ic00 method {}",
                                    canister_id, method_name,
                                ),
                            )),
                        }
                    },
                    None =>  Err(UserError::new(
                        ErrorCode::InvalidManagementPayload,
                        format!("Failed to decode payload for ic00 method: {}", method_name),
                    )),
                }
            },

            Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
            | Ok(Ic00Method::BitcoinGetSuccessors)
            | Ok(Ic00Method::ProvisionalTopUpCanister) => {
                if provisional_whitelist.contains(sender.get_ref()) {
                    Ok(())
                } else {
                    Err(UserError::new(
                        ErrorCode::CanisterRejectedMessage,
                        format!("Caller {} is not allowed to call ic00 method {}", sender, method_name)
                    ))
                }
            }
        }
    }

    fn validate_settings(
        &self,
        settings: CanisterSettings,
        total_subnet_compute_allocation_used: u64,
        available_memory: &SubnetAvailableMemory,
    ) -> Result<ValidatedCanisterSettings, CanisterManagerError> {
        if let Some(memory_allocation) = settings.memory_allocation() {
            let requested_allocation: NumBytes = memory_allocation.bytes();
            if requested_allocation.get() as i64 > available_memory.get_total_memory() {
                return Err(CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                    requested: requested_allocation,
                    available: NumBytes::from(available_memory.get_total_memory().max(0) as u64),
                });
            }
        }

        if let Some(compute_allocation) = settings.compute_allocation() {
            let compute_allocation = compute_allocation;
            if compute_allocation.as_percent() > 0
                && compute_allocation.as_percent() + total_subnet_compute_allocation_used
                    >= self.config.compute_capacity
            {
                let capped_usage = std::cmp::min(
                    self.config.compute_capacity,
                    total_subnet_compute_allocation_used + 1,
                );
                return Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: compute_allocation,
                    available: self.config.compute_capacity - capped_usage,
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
        round_limits: &mut RoundLimits,
    ) -> Result<(), CanisterManagerError> {
        // Verify controller.
        validate_controller(canister, &sender)?;
        validate_compute_allocation(
            round_limits.compute_allocation_used,
            canister,
            settings.compute_allocation(),
            &self.config,
        )?;
        validate_memory_allocation(
            &round_limits.subnet_available_memory,
            canister,
            settings.memory_allocation(),
            &self.config,
        )?;

        let validated_settings =
            ValidatedCanisterSettings::try_from((settings, self.config.max_controllers))?;

        let old_usage = canister.memory_usage(self.config.own_subnet_type);
        let old_mem = canister
            .system_state
            .memory_allocation
            .bytes()
            .max(old_usage);
        let old_compute_allocation = canister.scheduler_state.compute_allocation.as_percent();

        self.do_update_settings(validated_settings, canister);

        let new_compute_allocation = canister.scheduler_state.compute_allocation.as_percent();
        if old_compute_allocation < new_compute_allocation {
            round_limits.compute_allocation_used = round_limits
                .compute_allocation_used
                .saturating_add(new_compute_allocation - old_compute_allocation);
        } else {
            round_limits.compute_allocation_used = round_limits
                .compute_allocation_used
                .saturating_sub(old_compute_allocation - new_compute_allocation);
        }

        let new_usage = old_usage;
        let new_mem = canister
            .system_state
            .memory_allocation
            .bytes()
            .max(new_usage);

        if new_mem >= old_mem {
            // settings were validated before so this should always succeed
            round_limits
                .subnet_available_memory
                .try_decrement(new_mem - old_mem, NumBytes::from(0))
                .ok();
        } else {
            round_limits
                .subnet_available_memory
                .increment(old_mem - new_mem, NumBytes::from(0));
        }

        canister.system_state.canister_version += 1;

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
        subnet_size: usize,
        round_limits: &mut RoundLimits,
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

        let fee = self
            .cycles_account_manager
            .canister_creation_fee(subnet_size);
        if cycles < fee {
            return (
                Err(CanisterManagerError::CreateCanisterNotEnoughCycles {
                    sent: cycles,
                    required: fee,
                }),
                cycles,
            );
        }

        // Validate settings before `create_canister_helper` applies them
        match self.validate_settings(
            settings,
            round_limits.compute_allocation_used,
            &round_limits.subnet_available_memory,
        ) {
            Err(err) => (Err(err), cycles),
            Ok(validate_settings) => {
                let canister_id = match self.create_canister_helper(
                    sender,
                    cycles,
                    fee,
                    validate_settings,
                    max_number_of_canisters,
                    state,
                    round_limits,
                    None,
                ) {
                    Ok(canister_id) => canister_id,
                    Err(err) => return (Err(err), cycles),
                };
                (Ok(canister_id), Cycles::zero())
            }
        }
    }

    #[doc(hidden)]
    /// This function is a wrapper on install_code_dts, which allows to perform
    /// canister installation or upgrade with an assumption that Pause doesn't happen.
    /// Currently CanisterManager tests use it extensively.
    #[cfg(test)]
    pub(crate) fn install_code(
        &self,
        context: InstallCodeContext,
        message: RequestOrIngress,
        state: &mut ReplicatedState,
        mut execution_parameters: ExecutionParameters,
        round_limits: &mut RoundLimits,
        execution_refund_error_counter: &IntCounter,
        subnet_size: usize,
    ) -> (
        Result<InstallCodeResult, CanisterManagerError>,
        NumInstructions,
        Option<CanisterState>,
    ) {
        let time = state.time();
        let network_topology = state.metadata.network_topology.clone();

        let old_canister = match state.take_canister_state(&context.canister_id) {
            None => {
                return (
                    Err(CanisterManagerError::CanisterNotFound(context.canister_id)),
                    NumInstructions::from(0),
                    None,
                );
            }
            Some(canister) => canister,
        };
        execution_parameters.compute_allocation = old_canister.scheduler_state.compute_allocation;
        execution_parameters.canister_memory_limit = match old_canister.memory_allocation() {
            MemoryAllocation::Reserved(bytes) => bytes,
            MemoryAllocation::BestEffort => execution_parameters.canister_memory_limit,
        };
        let dts_result = self.install_code_dts(
            context,
            message,
            None,
            old_canister,
            time,
            "NOT_USED".into(),
            &network_topology,
            execution_parameters,
            round_limits,
            CompilationCostHandling::CountFullAmount,
            execution_refund_error_counter,
            subnet_size,
        );
        match dts_result {
            DtsInstallCodeResult::Finished {
                canister,
                message: _,
                instructions_used,
                result,
            } => (result, instructions_used, Some(canister)),
            DtsInstallCodeResult::Paused {
                canister: _,
                paused_execution,
                ingress_status: _,
            } => {
                unreachable!(
                    "Unexpected paused execution in canister manager tests: {:?}",
                    paused_execution
                );
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
    /// This function is atomic. Either all of its subroutines succeed,
    /// or the changes made to old_canister are reverted to the state
    /// from before execution of the first one.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn install_code_dts(
        &self,
        context: InstallCodeContext,
        message: RequestOrIngress,
        prepaid_execution_cycles: Option<Cycles>,
        mut canister: CanisterState,
        time: Time,
        canister_layout_path: PathBuf,
        network_topology: &NetworkTopology,
        execution_parameters: ExecutionParameters,
        round_limits: &mut RoundLimits,
        compilation_cost_handling: CompilationCostHandling,
        execution_refund_error_counter: &IntCounter,
        subnet_size: usize,
    ) -> DtsInstallCodeResult {
        if let Err(err) = validate_controller(&canister, &context.sender) {
            return DtsInstallCodeResult::Finished {
                canister,
                message,
                instructions_used: NumInstructions::from(0),
                result: Err(err),
            };
        }

        let prepaid_execution_cycles = match prepaid_execution_cycles {
            Some(prepaid_execution_cycles) => prepaid_execution_cycles,
            None => {
                let memory_usage = canister.memory_usage(execution_parameters.subnet_type);
                match self.cycles_account_manager.prepay_execution_cycles(
                    &mut canister.system_state,
                    memory_usage,
                    execution_parameters.compute_allocation,
                    execution_parameters.instruction_limits.message(),
                    subnet_size,
                ) {
                    Ok(cycles) => cycles,
                    Err(err) => {
                        return DtsInstallCodeResult::Finished {
                            canister,
                            message,
                            instructions_used: NumInstructions::from(0),
                            result: Err(CanisterManagerError::InstallCodeNotEnoughCycles(err)),
                        };
                    }
                }
            }
        };

        let original = OriginalContext {
            execution_parameters,
            mode: context.mode,
            canister_layout_path,
            config: self.config.clone(),
            message,
            prepaid_execution_cycles,
            time,
            compilation_cost_handling,
            subnet_size,
            requested_compute_allocation: context.compute_allocation,
            requested_memory_allocation: context.memory_allocation,
            sender: context.sender,
            canister_id: canister.canister_id(),
        };

        let round = RoundContext {
            network_topology,
            hypervisor: &self.hypervisor,
            cycles_account_manager: &self.cycles_account_manager,
            execution_refund_error_counter,
            log: &self.log,
            time,
        };

        match context.mode {
            CanisterInstallMode::Install | CanisterInstallMode::Reinstall => {
                execute_install(context, canister, original, round.clone(), round_limits)
            }
            CanisterInstallMode::Upgrade => {
                execute_upgrade(context, canister, original, round.clone(), round_limits)
            }
        }
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
        let canister = match state.canister_state_mut(&canister_id) {
            Some(canister) => canister,
            None => return Err(CanisterManagerError::CanisterNotFound(canister_id)),
        };

        // Skip the controller validation if the sender is the governance
        // canister. The governance canister can forcefully
        // uninstall the code of any canister.
        if sender != GOVERNANCE_CANISTER_ID.get() {
            if let Err(err) = validate_controller(canister, &sender) {
                return Err(err);
            }
        }

        let rejects = uninstall_canister(&self.log, canister, time);
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

        let result = match validate_controller(&canister, stop_context.sender()) {
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
        validate_controller(canister, &sender)?;

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
        subnet_size: usize,
    ) -> Result<CanisterStatusResultV2, CanisterManagerError> {
        // Skip the controller check if the canister itself is requesting its
        // own status, as the canister is considered in the same trust domain.
        if sender != canister.canister_id().get() {
            if let Err(err) = validate_controller(canister, &sender) {
                return Err(err);
            }
        }

        let controller = canister.system_state.controller();
        let controllers = canister
            .controllers()
            .iter()
            .copied()
            .collect::<Vec<PrincipalId>>();

        let canister_memory_usage = canister.memory_usage(self.config.own_subnet_type);
        let compute_allocation = canister.scheduler_state.compute_allocation;
        let memory_allocation = canister.memory_allocation();
        let freeze_threshold = canister.system_state.freeze_threshold;

        Ok(CanisterStatusResultV2::new(
            canister.status(),
            canister
                .execution_state
                .as_ref()
                .map(|es| es.wasm_binary.binary.module_hash().to_vec()),
            *controller,
            controllers,
            canister_memory_usage,
            canister.system_state.balance().get(),
            compute_allocation.as_percent(),
            Some(memory_allocation.bytes().get()),
            freeze_threshold.get(),
            self.cycles_account_manager
                .idle_cycles_burned_rate(
                    memory_allocation,
                    canister_memory_usage,
                    compute_allocation,
                    subnet_size,
                )
                .get(),
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
        round_limits: &mut RoundLimits,
    ) -> Result<(), CanisterManagerError> {
        let canister = state
            .canister_state_mut(&canister_id)
            .ok_or(CanisterManagerError::CanisterNotFound(canister_id))?;

        let settings = CanisterSettings::new(Some(new_controller), None, None, None, None);
        self.update_settings(sender, settings, canister, round_limits)
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
        validate_controller(canister_to_delete, &sender)?;

        self.validate_canister_is_stopped(canister_to_delete)?;

        if canister_to_delete.has_input() || canister_to_delete.has_output() {
            return Err(CanisterManagerError::DeleteCanisterQueueNotEmpty(
                canister_id_to_delete,
            ));
        }

        // When a canister is deleted:
        // - its state is permanently deleted, and
        // - its cycles are discarded.

        // Take out the canister from `ReplicatedState`.
        let canister_to_delete = state.take_canister_state(&canister_id_to_delete).unwrap();
        // Leftover cycles in the balance are considered `consumed`.
        let consumed_cycles_by_canister_to_delete =
            NominalCycles::from(canister_to_delete.system_state.balance())
                + canister_to_delete
                    .system_state
                    .canister_metrics
                    .consumed_cycles_since_replica_started;

        state
            .metadata
            .subnet_metrics
            .consumed_cycles_by_deleted_canisters += consumed_cycles_by_canister_to_delete;

        // The canister has now been removed from `ReplicatedState` and is dropped
        // once the function is out of scope.
        Ok(())
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
        cycles_amount: Option<u128>,
        settings: CanisterSettings,
        specified_id: Option<PrincipalId>,
        state: &mut ReplicatedState,
        provisional_whitelist: &ProvisionalWhitelist,
        max_number_of_canisters: u64,
        round_limits: &mut RoundLimits,
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
            round_limits.compute_allocation_used,
            &round_limits.subnet_available_memory,
        ) {
            Err(err) => Err(err),
            Ok(validated_settings) => self.create_canister_helper(
                sender,
                cycles,
                Cycles::new(0),
                validated_settings,
                max_number_of_canisters,
                state,
                round_limits,
                specified_id,
            ),
        }
    }

    /// Validates specified ID is available for use.
    ///
    /// It must be used in in the context of provisional create canister flow when a specified ID is provided.
    ///
    /// Returns `Err` iff the `specified_id` is not valid.
    fn validate_specified_id(
        &self,
        state: &mut ReplicatedState,
        specified_id: PrincipalId,
    ) -> Result<CanisterId, CanisterManagerError> {
        let new_canister_id = CanisterId::new(specified_id).unwrap();

        if state.canister_states.get(&new_canister_id).is_some() {
            return Err(CanisterManagerError::CanisterAlreadyExists(new_canister_id));
        }

        if state
            .metadata
            .network_topology
            .routing_table
            .route(specified_id)
            == Some(state.metadata.own_subnet_id)
        {
            Ok(new_canister_id)
        } else {
            Err(CanisterManagerError::CanisterNotHostedBySubnet {
                message: format!(
                    "Specified CanisterId {} is not hosted by subnet {}.",
                    specified_id, state.metadata.own_subnet_id
                ),
            })
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
        round_limits: &mut RoundLimits,
        specified_id: Option<PrincipalId>,
    ) -> Result<CanisterId, CanisterManagerError> {
        // A value of 0 is equivalent to setting no limit.
        // See documentation of `SubnetRecord` for the semantics of `max_number_of_canisters`.
        if max_number_of_canisters > 0 && state.num_canisters() as u64 >= max_number_of_canisters {
            return Err(CanisterManagerError::MaxNumberOfCanistersReached {
                subnet_id: self.config.own_subnet_id,
                max_number_of_canisters,
            });
        }

        let new_canister_id = match specified_id {
            Some(spec_id) => self.validate_specified_id(state, spec_id)?,

            None => self.generate_new_canister_id(state)?,
        };

        // Take the fee out of the cycles that are going to be added as the canister's
        // initial balance.
        let cycles = cycles - creation_fee;

        // Canister id available. Create the new canister.
        let mut system_state = SystemState::new_running(
            new_canister_id,
            sender,
            cycles,
            self.config.default_freeze_threshold,
        );

        self.cycles_account_manager
            .observe_consumed_cycles(&mut system_state, creation_fee);
        let scheduler_state = SchedulerState::new(state.metadata.batch_time);
        let mut new_canister = CanisterState::new(system_state, None, scheduler_state);

        self.do_update_settings(settings, &mut new_canister);
        let new_usage = new_canister.memory_usage(self.config.own_subnet_type);
        let new_mem = new_canister
            .system_state
            .memory_allocation
            .bytes()
            .max(new_usage);

        // settings were validated before so this should always succeed
        round_limits
            .subnet_available_memory
            .try_decrement(new_mem, NumBytes::from(0))
            .ok();

        round_limits.compute_allocation_used = round_limits
            .compute_allocation_used
            .saturating_add(new_canister.scheduler_state.compute_allocation.as_percent());
        // Add new canister to the replicated state.
        state.put_canister_state(new_canister);

        info!(
            self.log,
            "Canister {} created canister {} with {} initial balance on subnet {}.",
            sender,
            new_canister_id.get(),
            cycles,
            self.config.own_subnet_id.get()
        );

        Ok(new_canister_id)
    }

    /// Adds cycles to the canister.
    pub(crate) fn add_cycles(
        &self,
        sender: PrincipalId,
        cycles_amount: Option<u128>,
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
            .add_cycles(canister.system_state.balance_mut(), cycles_amount);

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

    /// Generates a new canister ID.
    ///
    /// Returns `Err` if the subnet can generate no more canister IDs; or a canister
    /// with the newly generated ID already exists.
    //
    // WARNING!!! If you change the logic here, please ensure that the sequence
    // of NNS canister ids as defined in nns/constants/src/constants.rs are also
    // updated.
    fn generate_new_canister_id(
        &self,
        state: &mut ReplicatedState,
    ) -> Result<CanisterId, CanisterManagerError> {
        let canister_id = state.metadata.generate_new_canister_id().map_err(|err| {
            error!(self.log, "Unable to generate new canister IDs: {}", err);
            CanisterManagerError::SubnetOutOfCanisterIds
        })?;

        // Sanity check: ensure that no canister with this ID exists already.
        if state.canister_state(&canister_id).is_some() {
            return Err(CanisterManagerError::CanisterAlreadyExists(canister_id));
        }

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
    DeleteCanisterQueueNotEmpty(CanisterId),
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
    InstallCodeRateLimited(CanisterId),
    SubnetOutOfCanisterIds,

    InvalidSettings {
        message: String,
    },
    MaxNumberOfCanistersReached {
        subnet_id: SubnetId,
        max_number_of_canisters: u64,
    },
    CanisterNotHostedBySubnet {
        message: String,
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
            DeleteCanisterQueueNotEmpty(canister_id) => {
                Self::new(
                    ErrorCode::CanisterQueueNotEmpty,
                    format!(
                        "Canister {} has messages in its queues and cannot be \
                        deleted now. Please retry after some time",
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
            InstallCodeRateLimited(canister_id) => {
                Self::new(
                ErrorCode::CanisterInstallCodeRateLimited,
                    format!("Canister {} is rate limited because it executed too many instructions in the previous install_code messages. Please retry installation after several minutes.", canister_id),
                )
            }
            SubnetOutOfCanisterIds => {
                Self::new(
                    ErrorCode::SubnetOversubscribed,
                    "Could not create canister. Subnet has surpassed its canister ID allocation.",
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
            CanisterNotHostedBySubnet {message} => {
                Self::new(
                    ErrorCode::CanisterNotHostedBySubnet,
                    format!("Unsuccessful validation of specified ID: {}", message),
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

/// Uninstalls a canister.
///
/// See https://sdk.dfinity.org/docs/interface-spec/index.html#ic-uninstall_code
///
/// Returns a list of rejects that need to be sent out to their callers.
#[doc(hidden)]
pub fn uninstall_canister(
    log: &ReplicaLogger,
    canister: &mut CanisterState,
    time: Time,
) -> Vec<Response> {
    // Drop the canister's execution state.
    canister.execution_state = None;

    // Drop its certified data.
    canister.system_state.certified_data = Vec::new();

    // Deactivate global timer.
    canister.system_state.global_timer = CanisterTimer::Inactive;
    // Increment canister version.
    canister.system_state.canister_version += 1;

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
                        status: IngressStatus::Known {
                            receiver: canister_id.get(),
                            user_id: *user_id,
                            time,
                            state: IngressState::Failed(UserError::new(
                                ErrorCode::CanisterRejectedMessage,
                                "Canister has been uninstalled.",
                            )),
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
                CallOrigin::SystemTask => {
                    // Cannot respond to system tasks. Nothing to do.
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

/// Holds necessary information for the deterministic time slicing execution of
/// install code. Install code can be executed in three modes - install,
/// reinstall and upgrade.
pub(crate) trait PausedInstallCodeExecution: Send + std::fmt::Debug {
    fn resume(
        self: Box<Self>,
        canister: CanisterState,
        round: RoundContext,
        round_limits: &mut RoundLimits,
    ) -> DtsInstallCodeResult;

    /// Aborts the paused execution.
    /// Returns the original message and the cycles prepaid for execution.
    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (RequestOrIngress, Cycles);
}

#[cfg(test)]
pub(crate) mod tests;
