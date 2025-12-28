use crate::as_round_instructions;
use crate::execution::install_code::{OriginalContext, validate_controller};
use crate::execution::{install::execute_install, upgrade::execute_upgrade};
use crate::execution_environment::{
    CompilationCostHandling, RoundContext, RoundCounters, RoundLimits,
};
use crate::util::MIGRATION_CANISTER_ID;
use crate::{
    canister_settings::{CanisterSettings, ValidatedCanisterSettings},
    hypervisor::Hypervisor,
    types::{IngressResponse, Response},
    util::GOVERNANCE_CANISTER_ID,
};
use ic_base_types::NumSeconds;
use ic_config::embedders::Config as EmbeddersConfig;
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::{CyclesAccountManager, ResourceSaturation};
use ic_embedders::{
    wasm_utils::decoding::decode_wasm, wasmtime_embedder::system_api::ExecutionParameters,
};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_interfaces::execution_environment::{
    IngressHistoryWriter, MessageMemoryUsage, SubnetAvailableMemory,
};
use ic_logger::{ReplicaLogger, error, fatal, info};
use ic_management_canister_types_private::{
    CanisterChangeDetails, CanisterChangeOrigin, CanisterInstallModeV2, CanisterMetadataResponse,
    CanisterSnapshotDataKind, CanisterSnapshotDataOffset, CanisterSnapshotResponse,
    CanisterStatusResultV2, CanisterStatusType, ChunkHash, Global, GlobalTimer,
    Method as Ic00Method, ReadCanisterSnapshotDataResponse, ReadCanisterSnapshotMetadataResponse,
    SnapshotSource, StoredChunksReply, UploadCanisterSnapshotDataArgs,
    UploadCanisterSnapshotMetadataArgs, UploadChunkReply,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_replicated_state::canister_snapshots::ValidatedSnapshotMetadata;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_replicated_state::canister_state::execution_state::{CustomSectionType, SandboxMemory};
use ic_replicated_state::canister_state::system_state::wasm_chunk_store::{
    CHUNK_SIZE, ChunkValidationResult, WasmChunkHash,
};
use ic_replicated_state::page_map::Buffer;
use ic_replicated_state::{
    CallOrigin, CanisterState, NetworkTopology, ReplicatedState, SchedulerState, SystemState,
    canister_snapshots::CanisterSnapshot,
    canister_state::{
        NextExecution,
        execution_state::Memory,
        execution_state::WasmExecutionMode,
        system_state::{
            CyclesUseCase, ReservationError,
            wasm_chunk_store::{self, WasmChunkStore},
        },
    },
    metadata_state::subnet_call_context_manager::InstallCodeCallId,
    page_map::PageAllocatorFileDescriptor,
};
use ic_types::batch::CanisterCyclesCostSchedule;
use ic_types::{
    CanisterId, CanisterTimer, ComputeAllocation, Cycles, DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT,
    MAX_AGGREGATE_LOG_MEMORY_LIMIT, MIN_AGGREGATE_LOG_MEMORY_LIMIT, MemoryAllocation, NumBytes,
    NumInstructions, PrincipalId, SnapshotId, SubnetId, Time,
    ingress::{IngressState, IngressStatus},
    messages::{
        CanisterCall, Payload, RejectContext, Response as CanisterResponse, SignedIngressContent,
        StopCanisterContext,
    },
    nominal_cycles::NominalCycles,
};
use ic_wasm_types::WasmHash;
use num_traits::{SaturatingAdd, SaturatingSub};
use prometheus::IntCounter;
use std::iter::zip;
use std::path::PathBuf;
use std::{convert::TryFrom, str::FromStr, sync::Arc};

use types::*;
pub(crate) mod types;

/// Maximum binary slice size allowed per single message download.
const MAX_SLICE_SIZE_BYTES: u64 = 2_000_000;

/// Contains validated cycles and memory usage:
/// - cycles for instructions that can be consumed safely;
/// - new memory usage (to compute the new freezing threshold);
/// - allocated and deallocated bytes that can be safely applied to subnet available memory;
/// - new storage reservation cycles that can be safely moved from the canister's main balance
///   to its reserved balance.
struct ValidatedCyclesAndMemoryUsage {
    cycles_for_instructions: Cycles,
    new_memory_usage: NumBytes,
    allocated_bytes: NumBytes,
    deallocated_bytes: NumBytes,
    new_storage_reservation_cycles: Cycles,
}

/// The entity responsible for managing canisters (creation, installing, etc.)
pub(crate) struct CanisterManager {
    hypervisor: Arc<Hypervisor>,
    log: ReplicaLogger,
    config: CanisterMgrConfig,
    cycles_account_manager: Arc<CyclesAccountManager>,
    ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    environment_variables_flag: FlagStatus,
}

impl CanisterManager {
    pub(crate) fn new(
        hypervisor: Arc<Hypervisor>,
        log: ReplicaLogger,
        config: CanisterMgrConfig,
        cycles_account_manager: Arc<CyclesAccountManager>,
        ingress_history_writer: Arc<dyn IngressHistoryWriter<State = ReplicatedState>>,
        fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
        environment_variables_flag: FlagStatus,
    ) -> Self {
        CanisterManager {
            hypervisor,
            log,
            config,
            cycles_account_manager,
            ingress_history_writer,
            fd_factory,
            environment_variables_flag,
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
        let method = Ic00Method::from_str(ingress.method_name());
        // The message is targeted towards the management canister. The
        // actual type of the method will determine if the message should be
        // accepted or not.
        match method {
            // The method is either invalid or it is of a type that users
            // are not allowed to send.
            Err(_)
            | Ok(Ic00Method::CreateCanister)
            | Ok(Ic00Method::CanisterInfo)
            | Ok(Ic00Method::CanisterMetadata)
            | Ok(Ic00Method::ECDSAPublicKey)
            | Ok(Ic00Method::SetupInitialDKG)
            | Ok(Ic00Method::SignWithECDSA)
            | Ok(Ic00Method::ReshareChainKey)
            | Ok(Ic00Method::SchnorrPublicKey)
            | Ok(Ic00Method::SignWithSchnorr)
            | Ok(Ic00Method::VetKdPublicKey)
            | Ok(Ic00Method::VetKdDeriveKey)
            // "DepositCycles" can be called by anyone however as ingress message
            // cannot carry cycles, it does not make sense to allow them from users.
            | Ok(Ic00Method::DepositCycles)
            | Ok(Ic00Method::HttpRequest)
            // Nobody pays for `raw_rand`, so this cannot be used via ingress messages
            | Ok(Ic00Method::RawRand)
            // Bitcoin messages require cycles, so we reject all ingress messages.
            | Ok(Ic00Method::BitcoinGetBalance)
            | Ok(Ic00Method::BitcoinGetUtxos)
            | Ok(Ic00Method::BitcoinGetBlockHeaders)
            | Ok(Ic00Method::BitcoinSendTransaction)
            | Ok(Ic00Method::BitcoinSendTransactionInternal)
            | Ok(Ic00Method::BitcoinGetCurrentFeePercentiles)
            | Ok(Ic00Method::NodeMetricsHistory)
            | Ok(Ic00Method::SubnetInfo)
            // `RenameCanister` can only be called from the NNS subnet.
            | Ok(Ic00Method::RenameCanister) => Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!("Only canisters can call ic00 method {method_name}"),
            )),

            // These methods are only valid if they are sent by the controller
            // of the canister. We assume that the canister always wants to
            // accept messages from its controller.
            Ok(Ic00Method::CanisterStatus)
            | Ok(Ic00Method::StartCanister)
            | Ok(Ic00Method::UninstallCode)
            | Ok(Ic00Method::StopCanister)
            | Ok(Ic00Method::DeleteCanister)
            | Ok(Ic00Method::UpdateSettings)
            | Ok(Ic00Method::InstallCode)
            | Ok(Ic00Method::InstallChunkedCode)
            | Ok(Ic00Method::UploadChunk)
            | Ok(Ic00Method::StoredChunks)
            | Ok(Ic00Method::ClearChunkStore)
            | Ok(Ic00Method::TakeCanisterSnapshot)
            | Ok(Ic00Method::LoadCanisterSnapshot)
            | Ok(Ic00Method::ListCanisterSnapshots)
            | Ok(Ic00Method::DeleteCanisterSnapshot)
            | Ok(Ic00Method::ReadCanisterSnapshotMetadata)
            | Ok(Ic00Method::ReadCanisterSnapshotData)
            | Ok(Ic00Method::UploadCanisterSnapshotMetadata)
            | Ok(Ic00Method::UploadCanisterSnapshotData) => {
                match effective_canister_id {
                    Some(canister_id) => {
                        let canister = state.canister_state(&canister_id).ok_or_else(|| UserError::new(
                            ErrorCode::CanisterNotFound,
                            format!("Canister {canister_id} not found"),
                        ))?;
                        match canister.controllers().contains(&sender.get()) {
                            true => Ok(()),
                            false => Err(UserError::new(
                                ErrorCode::CanisterInvalidController,
                                format!(
                                    "Only controllers of canister {canister_id} can call ic00 method {method_name}",
                                ),
                            )),
                        }
                    },
                    None => Err(UserError::new(
                        ErrorCode::InvalidManagementPayload,
                        format!("Failed to decode payload for ic00 method: {method_name}"),
                    )),
                }
            },

            Ok(Ic00Method::FetchCanisterLogs) => Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "{} API is not accessible via ingress in replicated mode",
                    Ic00Method::FetchCanisterLogs
                ),
            )),

            Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
            | Ok(Ic00Method::BitcoinGetSuccessors)
            | Ok(Ic00Method::ProvisionalTopUpCanister) => {
                if provisional_whitelist.contains(sender.get_ref()) {
                    Ok(())
                } else {
                    Err(UserError::new(
                        ErrorCode::CanisterRejectedMessage,
                        format!("Caller {sender} is not allowed to call ic00 method {method_name}")
                    ))
                }
            },
        }
    }

    /// Validates the environment variables of the canister.
    /// - the number of environment variables cannot exceed the given maximum.
    /// - the key and value of each environment variable cannot exceed the given maximum length.
    fn validate_environment_variables(
        &self,
        settings: &CanisterSettings,
    ) -> Result<(), CanisterManagerError> {
        if let Some(environment_variables) = settings.environment_variables() {
            if environment_variables.len() > self.config.max_environment_variables {
                return Err(CanisterManagerError::EnvironmentVariablesTooMany {
                    max: self.config.max_environment_variables,
                    count: environment_variables.len(),
                });
            }
            for (name, value) in environment_variables.iter() {
                if name.len() > self.config.max_environment_variable_name_length {
                    return Err(CanisterManagerError::EnvironmentVariablesNameTooLong {
                        name: name.clone(),
                        max_name_length: self.config.max_environment_variable_name_length,
                    });
                }
                if value.len() > self.config.max_environment_variable_value_length {
                    return Err(CanisterManagerError::EnvironmentVariablesValueTooLong {
                        value: value.clone(),
                        max_value_length: self.config.max_environment_variable_value_length,
                    });
                }
            }
        }
        Ok(())
    }

    /// Validates the new canisters settings:
    /// - memory allocation:
    ///     - it cannot be lower than the current canister memory usage.
    ///     - there must be enough available subnet capacity for the change.
    ///     - there must be enough cycles for storage reservation.
    ///     - there must be enough cycles to avoid freezing the canister.
    /// - compute allocation:
    ///     - there must be enough available compute capacity for the change.
    ///     - there must be enough cycles to avoid freezing the canister.
    /// - controllers:
    ///     - the number of controllers cannot exceed the given maximum.
    /// - environment variables:
    ///     - the number of environment variables cannot exceed the given maximum.
    ///     - the key and value of each environment variable cannot exceed the given maximum length.
    /// - log memory limit:
    ///     - must be at least the specified minimum.
    ///     - must not exceed the specified maximum.
    ///
    /// Keep this function in sync with `do_update_settings()`.
    #[allow(clippy::too_many_arguments)]
    fn validate_canister_settings(
        &self,
        settings: CanisterSettings,
        canister_memory_usage: NumBytes,
        canister_message_memory_usage: MessageMemoryUsage,
        canister_memory_allocation: MemoryAllocation,
        subnet_available_memory: &SubnetAvailableMemory,
        subnet_memory_saturation: &ResourceSaturation,
        canister_compute_allocation: ComputeAllocation,
        subnet_compute_allocation_usage: u64,
        canister_freezing_threshold: NumSeconds,
        canister_cycles_balance: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        canister_reserved_balance: Cycles,
        canister_reserved_balance_limit: Option<Cycles>,
    ) -> Result<ValidatedCanisterSettings, CanisterManagerError> {
        self.validate_environment_variables(&settings)?;

        let old_memory_bytes = canister_memory_allocation.allocated_bytes(canister_memory_usage);
        let new_memory_bytes = settings
            .memory_allocation
            .unwrap_or(canister_memory_allocation)
            .allocated_bytes(canister_memory_usage);

        // If the available memory in the subnet is negative, then we must cap
        // it at zero such that the new memory allocation can change between
        // zero and the old memory allocation. Note that capping at zero also
        // makes conversion from `i64` to `u64` valid.
        let subnet_available_memory = subnet_available_memory.get_execution_memory().max(0) as u64;
        let subnet_available_memory =
            subnet_available_memory.saturating_add(old_memory_bytes.get());
        if new_memory_bytes.get() > subnet_available_memory {
            return Err(CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                requested: new_memory_bytes,
                available: NumBytes::from(subnet_available_memory),
            });
        }

        if let Some(new_compute_allocation) = settings.compute_allocation {
            // The saturating `u64` subtractions ensure that the available compute
            // capacity of the subnet never goes below zero. This means that even if
            // compute capacity is oversubscribed, the new compute allocation can
            // change between zero and the old compute allocation.
            let available_compute_allocation = self
                .config
                .compute_capacity
                .saturating_sub(subnet_compute_allocation_usage)
                // Minus 1 below guarantees there is always at least 1% of free compute
                // if the subnet was not already oversubscribed.
                .saturating_sub(1)
                .saturating_add(canister_compute_allocation.as_percent());
            if new_compute_allocation.as_percent() > available_compute_allocation {
                return Err(CanisterManagerError::SubnetComputeCapacityOverSubscribed {
                    requested: new_compute_allocation,
                    available: available_compute_allocation,
                });
            }
        }

        let controllers = settings.controllers();
        if let Some(controllers) = &controllers
            && controllers.len() > self.config.max_controllers
        {
            return Err(CanisterManagerError::InvalidSettings {
                message: format!(
                    "Invalid settings: 'controllers' length exceeds maximum size allowed of {}.",
                    self.config.max_controllers
                ),
            });
        }

        let new_memory_allocation = settings
            .memory_allocation
            .unwrap_or(canister_memory_allocation);

        let new_compute_allocation = settings
            .compute_allocation()
            .unwrap_or(canister_compute_allocation);

        let freezing_threshold = settings
            .freezing_threshold
            .unwrap_or(canister_freezing_threshold);

        let threshold = self.cycles_account_manager.freeze_threshold_cycles(
            freezing_threshold,
            new_memory_allocation,
            canister_memory_usage,
            canister_message_memory_usage,
            new_compute_allocation,
            subnet_size,
            cost_schedule,
            canister_reserved_balance,
        );

        if canister_cycles_balance < threshold {
            if new_compute_allocation > canister_compute_allocation {
                // Note that the error is produced only if allocation increases.
                // This is to allow increasing of the freezing threshold to make the
                // canister frozen.
                return Err(
                    CanisterManagerError::InsufficientCyclesInComputeAllocation {
                        compute_allocation: new_compute_allocation,
                        available: canister_cycles_balance,
                        threshold,
                    },
                );
            }
            if new_memory_allocation > canister_memory_allocation {
                // Note that the error is produced only if allocation increases.
                // This is to allow increasing of the freezing threshold to make the
                // canister frozen.
                return Err(CanisterManagerError::InsufficientCyclesInMemoryAllocation {
                    memory_allocation: new_memory_allocation,
                    available: canister_cycles_balance,
                    threshold,
                });
            }
        }

        let allocated_bytes = new_memory_bytes.saturating_sub(&old_memory_bytes);
        let reservation_cycles = self.cycles_account_manager.storage_reservation_cycles(
            allocated_bytes,
            subnet_memory_saturation,
            subnet_size,
            cost_schedule,
        );
        let reserved_balance_limit = settings
            .reserved_cycles_limit()
            .or(canister_reserved_balance_limit);

        if let Some(limit) = reserved_balance_limit {
            if canister_reserved_balance > limit {
                return Err(CanisterManagerError::ReservedCyclesLimitIsTooLow {
                    cycles: canister_reserved_balance,
                    limit,
                });
            } else if canister_reserved_balance + reservation_cycles > limit {
                return Err(
                    CanisterManagerError::ReservedCyclesLimitExceededInMemoryAllocation {
                        memory_allocation: new_memory_allocation,
                        requested: canister_reserved_balance + reservation_cycles,
                        limit,
                    },
                );
            }
        }

        // Note that this check does not include the freezing threshold to be
        // consistent with the `reserve_cycles()` function, which moves
        // cycles between the main and reserved balances without checking
        // the freezing threshold.
        if canister_cycles_balance < reservation_cycles {
            return Err(CanisterManagerError::InsufficientCyclesInMemoryAllocation {
                memory_allocation: new_memory_allocation,
                available: canister_cycles_balance,
                threshold: reservation_cycles,
            });
        }

        let log_memory_limit = settings.log_memory_limit().or(Some(NumBytes::new(
            DEFAULT_AGGREGATE_LOG_MEMORY_LIMIT as u64,
        )));
        let (min_limit, max_limit) = (
            NumBytes::new(MIN_AGGREGATE_LOG_MEMORY_LIMIT as u64),
            NumBytes::new(MAX_AGGREGATE_LOG_MEMORY_LIMIT as u64),
        );
        match log_memory_limit {
            Some(bytes) if bytes < min_limit => {
                return Err(CanisterManagerError::CanisterLogMemoryLimitIsTooLow {
                    bytes,
                    limit: min_limit,
                });
            }
            Some(bytes) if bytes > max_limit => {
                return Err(CanisterManagerError::CanisterLogMemoryLimitIsTooHigh {
                    bytes,
                    limit: max_limit,
                });
            }
            _ => {}
        }

        Ok(ValidatedCanisterSettings::new(
            settings.controllers(),
            settings.compute_allocation(),
            settings.memory_allocation(),
            settings.wasm_memory_threshold(),
            settings.freezing_threshold(),
            settings.reserved_cycles_limit(),
            reservation_cycles,
            settings.log_visibility().cloned(),
            log_memory_limit,
            settings.wasm_memory_limit(),
            settings.environment_variables().cloned(),
        ))
    }

    fn validate_settings_for_canister_creation(
        &self,
        settings: CanisterSettings,
        subnet_compute_allocation_usage: u64,
        subnet_available_memory: &SubnetAvailableMemory,
        subnet_memory_saturation: &ResourceSaturation,
        canister_cycles_balance: Cycles,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Result<ValidatedCanisterSettings, CanisterManagerError> {
        self.validate_canister_settings(
            settings,
            NumBytes::new(0),
            MessageMemoryUsage::ZERO,
            MemoryAllocation::default(),
            subnet_available_memory,
            subnet_memory_saturation,
            ComputeAllocation::zero(),
            subnet_compute_allocation_usage,
            self.config.default_freeze_threshold,
            canister_cycles_balance,
            subnet_size,
            cost_schedule,
            Cycles::zero(),
            None,
        )
    }

    /// Applies the requested settings on the canister.
    /// Note: Called only after validating the settings.
    /// Keep this function in sync with `validate_canister_settings()`.
    fn do_update_settings(
        &self,
        settings: &ValidatedCanisterSettings,
        canister: &mut CanisterState,
    ) {
        // Note: At this point, the settings are validated.
        if let Some(controllers) = settings.controllers() {
            canister.system_state.controllers.clear();
            for principal in controllers {
                canister.system_state.controllers.insert(principal);
            }
        }
        if let Some(compute_allocation) = settings.compute_allocation() {
            canister.scheduler_state.compute_allocation = compute_allocation;
        }
        if let Some(memory_allocation) = settings.memory_allocation() {
            canister.system_state.memory_allocation = memory_allocation;
        }
        if let Some(wasm_memory_threshold) = settings.wasm_memory_threshold() {
            canister.system_state.wasm_memory_threshold = wasm_memory_threshold;
        }
        if let Some(limit) = settings.reserved_cycles_limit() {
            canister.system_state.set_reserved_balance_limit(limit);
        }
        canister
            .system_state
            .reserve_cycles(settings.reservation_cycles())
            .expect(
                "Reserving cycles should succeed because \
                    the canister settings have been validated.",
            );
        if let Some(freezing_threshold) = settings.freezing_threshold() {
            canister.system_state.freeze_threshold = freezing_threshold;
        }
        if let Some(log_visibility) = settings.log_visibility() {
            canister.system_state.log_visibility = log_visibility.clone();
        }
        if let Some(log_memory_limit) = settings.log_memory_limit() {
            canister
                .system_state
                .log_memory_store
                .set_log_memory_limit(log_memory_limit.get() as usize);
        }
        if let Some(wasm_memory_limit) = settings.wasm_memory_limit() {
            canister.system_state.wasm_memory_limit = Some(wasm_memory_limit);
        }
        if let Some(environment_variables) = settings.environment_variables()
            && self.environment_variables_flag == FlagStatus::Enabled
        {
            canister.system_state.environment_variables = environment_variables.clone();
        }
    }

    /// Tries to apply the requested settings on the canister identified by
    /// `canister_id`.
    pub(crate) fn update_settings(
        &self,
        timestamp_nanos: Time,
        origin: CanisterChangeOrigin,
        settings: CanisterSettings,
        canister: &mut CanisterState,
        round_limits: &mut RoundLimits,
        subnet_memory_saturation: ResourceSaturation,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
    ) -> Result<(), CanisterManagerError> {
        let sender = origin.origin();

        validate_controller(canister, &sender)?;

        let validated_settings = self.validate_canister_settings(
            settings,
            canister.memory_usage(),
            canister.message_memory_usage(),
            canister.memory_allocation(),
            &round_limits.subnet_available_memory,
            &subnet_memory_saturation,
            canister.compute_allocation(),
            round_limits.compute_allocation_used,
            canister.system_state.freeze_threshold,
            canister.system_state.balance(),
            subnet_size,
            cost_schedule,
            canister.system_state.reserved_balance(),
            canister.system_state.reserved_balance_limit(),
        )?;

        let old_usage = canister.memory_usage();
        let old_mem = canister.memory_allocation().allocated_bytes(old_usage);
        let old_compute_allocation = canister.scheduler_state.compute_allocation.as_percent();

        self.do_update_settings(&validated_settings, canister);

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
        let new_mem = canister.memory_allocation().allocated_bytes(new_usage);
        if new_mem >= old_mem {
            // Settings were validated before so this should always succeed.
            round_limits
                .subnet_available_memory
                .try_decrement(new_mem - old_mem, NumBytes::from(0), NumBytes::from(0))
                .expect("Error: Cannot fail to decrement SubnetAvailableMemory after validating the canister's settings");
        } else {
            round_limits.subnet_available_memory.increment(
                old_mem - new_mem,
                NumBytes::from(0),
                NumBytes::from(0),
            );
        }

        canister.system_state.canister_version += 1;
        let new_controllers = match validated_settings.controllers() {
            Some(_) => Some(canister.system_state.controllers.iter().copied().collect()),
            None => None,
        };

        // For the sake of backward-compatibility, we do not record
        // changes to canister environment variables in canister history.
        // In particular, we never produce a canister history entry of the form `settings_change`.
        /*
        match self.environment_variables_flag {
            FlagStatus::Enabled => {
                let new_environment_variables_hash = validated_settings
                    .environment_variables()
                    .map(|environment_variables| environment_variables.hash());

                if new_environment_variables_hash.is_some() || new_controllers.is_some() {
                    let available_execution_memory_change = canister.add_canister_change(
                        timestamp_nanos,
                        origin,
                        CanisterChangeDetails::settings_change(
                            new_controllers,
                            new_environment_variables_hash,
                        ),
                    );
                    round_limits
                        .subnet_available_memory
                        .update_execution_memory_unchecked(available_execution_memory_change);
                }
            }
            FlagStatus::Disabled => {
        */
        if let Some(new_controllers) = new_controllers {
            let available_execution_memory_change = canister.add_canister_change(
                timestamp_nanos,
                origin,
                CanisterChangeDetails::controllers_change(new_controllers),
            );
            round_limits
                .subnet_available_memory
                .update_execution_memory_unchecked(available_execution_memory_change);
        }
        /*
            }
        }
        */

        Ok(())
    }

    /// Creates a new canister and inserts it into `ReplicatedState`.
    ///
    /// Returns the auto-generated id the new canister that has been created.
    pub(crate) fn create_canister(
        &self,
        origin: CanisterChangeOrigin,
        sender_subnet_id: SubnetId,
        cycles: Cycles,
        mut settings: CanisterSettings,
        max_number_of_canisters: u64,
        state: &mut ReplicatedState,
        subnet_size: usize,
        round_limits: &mut RoundLimits,
        subnet_memory_saturation: ResourceSaturation,
        canister_creation_error: &IntCounter,
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
            .canister_creation_fee(subnet_size, state.get_own_cost_schedule());
        if cycles < fee {
            return (
                Err(CanisterManagerError::CreateCanisterNotEnoughCycles {
                    sent: cycles,
                    required: fee,
                }),
                cycles,
            );
        }

        // Set the field to the default value if it is empty.
        settings
            .reserved_cycles_limit
            .get_or_insert_with(|| self.cycles_account_manager.default_reserved_balance_limit());

        settings
            .wasm_memory_limit
            .get_or_insert(self.config.default_wasm_memory_limit);

        // Validate settings before `create_canister_helper` applies them
        match self.validate_settings_for_canister_creation(
            settings,
            round_limits.compute_allocation_used,
            &round_limits.subnet_available_memory,
            &subnet_memory_saturation,
            cycles - fee,
            subnet_size,
            state.get_own_cost_schedule(),
        ) {
            Err(err) => (Err(err), cycles),
            Ok(validate_settings) => {
                // Test coverage relies on the fact that
                // the IC method `provisional_create_canister_with_cycles`
                // implemented by `CanisterManager::create_canister_with_cycles`
                // uses the same code (in `CanisterManager::create_canister_helper`)
                // as the production IC method `create_canister`
                // implemented by this function `CanisterManager::create_canister`.
                let canister_id = match self.create_canister_helper(
                    origin,
                    cycles,
                    fee,
                    validate_settings,
                    max_number_of_canisters,
                    state,
                    round_limits,
                    None,
                    canister_creation_error,
                ) {
                    Ok(canister_id) => canister_id,
                    Err(err) => return (Err(err), cycles),
                };
                (Ok(canister_id), Cycles::zero())
            }
        }
    }

    /// Checks if the given wasm module is a Wasm64 module.
    /// This is solely for the purpose of install code, when at the replica level
    /// we don't know yet if the module is Wasm32/64 and we need to prepay accordingly.
    /// In case of errors, we simply return false, assuming Wasm32.
    /// The errors will be caught and handled by the sandbox later.
    fn check_if_wasm64_module(&self, wasm_module_source: WasmSource) -> bool {
        let wasm_module = match wasm_module_source.into_canister_module() {
            Ok(wasm_module) => wasm_module,
            Err(_err) => {
                return false;
            }
        };

        let decoded_wasm_module = match decode_wasm(
            EmbeddersConfig::new().wasm_max_size,
            Arc::new(wasm_module.as_slice().to_vec()),
        ) {
            Ok(decoded_wasm_module) => decoded_wasm_module,
            Err(_err) => {
                return false;
            }
        };

        let parser = wasmparser::Parser::new(0);
        for section in parser.parse_all(decoded_wasm_module.as_slice()).flatten() {
            if let wasmparser::Payload::MemorySection(reader) = section
                && let Some(memory) = reader.into_iter().flatten().next()
            {
                return memory.memory64;
            }
        }
        false
    }

    /// Installs code to a canister.
    ///
    /// Only the controller of the canister can install code.
    ///
    /// There are three modes of installation that are supported:
    ///
    /// 1. `CanisterInstallModeV2::Install`
    ///    Used for installing code on an empty canister.
    ///
    /// 2. `CanisterInstallModeV2::Reinstall`
    ///    Used for installing code on a _non-empty_ canister. All existing
    ///    state in the canister is cleared.
    ///
    /// 3. `CanisterInstallModeV2::Upgrade`
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
        message: CanisterCall,
        call_id: InstallCodeCallId,
        prepaid_execution_cycles: Option<Cycles>,
        mut canister: CanisterState,
        time: Time,
        canister_layout_path: PathBuf,
        network_topology: &NetworkTopology,
        execution_parameters: ExecutionParameters,
        round_limits: &mut RoundLimits,
        compilation_cost_handling: CompilationCostHandling,
        round_counters: RoundCounters,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        log_dirty_pages: FlagStatus,
    ) -> DtsInstallCodeResult {
        if let Err(err) = validate_controller(&canister, &context.sender()) {
            return DtsInstallCodeResult::Finished {
                canister,
                message,
                call_id,
                instructions_used: NumInstructions::from(0),
                result: Err(err),
            };
        }

        let wasm_execution_mode = WasmExecutionMode::from_is_wasm64(
            self.check_if_wasm64_module(context.wasm_source.clone()),
        );

        let prepaid_execution_cycles = match prepaid_execution_cycles {
            Some(prepaid_execution_cycles) => prepaid_execution_cycles,
            None => {
                let memory_usage = canister.memory_usage();
                let message_memory_usage = canister.message_memory_usage();
                let reveal_top_up = canister.controllers().contains(message.sender());

                match self.cycles_account_manager.prepay_execution_cycles(
                    &mut canister.system_state,
                    memory_usage,
                    message_memory_usage,
                    execution_parameters.compute_allocation,
                    execution_parameters.instruction_limits.message(),
                    subnet_size,
                    cost_schedule,
                    reveal_top_up,
                    wasm_execution_mode,
                ) {
                    Ok(cycles) => cycles,
                    Err(err) => {
                        return DtsInstallCodeResult::Finished {
                            canister,
                            message,
                            call_id,
                            instructions_used: NumInstructions::from(0),
                            result: Err(CanisterManagerError::InstallCodeNotEnoughCycles(err)),
                        };
                    }
                }
            }
        };

        let original: OriginalContext = OriginalContext {
            execution_parameters,
            mode: context.mode,
            canister_layout_path,
            config: self.config.clone(),
            message,
            call_id,
            prepaid_execution_cycles,
            time,
            compilation_cost_handling,
            subnet_size,
            sender: context.sender(),
            canister_id: canister.canister_id(),
            log_dirty_pages,
            wasm_execution_mode,
        };

        let round = RoundContext {
            network_topology,
            hypervisor: &self.hypervisor,
            cycles_account_manager: &self.cycles_account_manager,
            counters: round_counters,
            log: &self.log,
            time,
            cost_schedule,
        };

        match context.mode {
            CanisterInstallModeV2::Install | CanisterInstallModeV2::Reinstall => {
                execute_install(context, canister, original, round.clone(), round_limits)
            }
            CanisterInstallModeV2::Upgrade(..) => {
                execute_upgrade(context, canister, original, round.clone(), round_limits)
            }
        }
    }

    /// Uninstalls code from a canister.
    ///
    /// See https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-uninstall_code
    pub(crate) fn uninstall_code(
        &self,
        origin: CanisterChangeOrigin,
        canister_id: CanisterId,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
        canister_not_found_error: &IntCounter,
    ) -> Result<(), CanisterManagerError> {
        let sender = origin.origin();
        let time = state.time();
        let canister = match state.canister_state_mut(&canister_id) {
            Some(canister) => canister,
            None => return Err(CanisterManagerError::CanisterNotFound(canister_id)),
        };

        // Skip the controller validation if the sender is the governance
        // canister. The governance canister can forcefully
        // uninstall the code of any canister.
        if sender != GOVERNANCE_CANISTER_ID.get() {
            validate_controller(canister, &sender)?
        }

        let rejects = uninstall_canister(
            &self.log,
            canister,
            Some(round_limits),
            time,
            Arc::clone(&self.fd_factory),
        );

        let available_execution_memory_change = canister.add_canister_change(
            time,
            origin,
            CanisterChangeDetails::CanisterCodeUninstall,
        );
        round_limits
            .subnet_available_memory
            .update_execution_memory_unchecked(available_execution_memory_change);

        crate::util::process_responses(
            rejects,
            state,
            Arc::clone(&self.ingress_history_writer),
            self.log.clone(),
            canister_not_found_error,
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
        let canister = match state.canister_state_mut(&canister_id) {
            None => {
                return StopCanisterResult::Failure {
                    error: CanisterManagerError::CanisterNotFound(canister_id),
                    cycles_to_return: stop_context.take_cycles(),
                };
            }
            Some(canister) => canister,
        };

        if let Err(err) = validate_controller(canister, stop_context.sender()) {
            return StopCanisterResult::Failure {
                error: err,
                cycles_to_return: stop_context.take_cycles(),
            };
        }

        let result = match canister.system_state.begin_stopping(stop_context) {
            Some(mut stop_context) => StopCanisterResult::AlreadyStopped {
                cycles_to_return: stop_context.take_cycles(),
            },
            None => StopCanisterResult::RequestAccepted,
        };
        canister.system_state.canister_version += 1;
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

        let stop_contexts = canister.system_state.start_canister();
        canister.system_state.canister_version += 1;

        Ok(stop_contexts)
    }

    /// Fetches the current status of the canister.
    pub(crate) fn get_canister_status(
        &self,
        sender: PrincipalId,
        canister: &CanisterState,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        ready_for_migration: bool,
    ) -> Result<CanisterStatusResultV2, CanisterManagerError> {
        // Skip the controller check if the canister itself is requesting its
        // own status, as the canister is considered in the same trust domain.
        if sender != canister.canister_id().get() {
            validate_controller(canister, &sender)?
        }

        let controller = canister.system_state.controller();
        let controllers = canister
            .controllers()
            .iter()
            .copied()
            .collect::<Vec<PrincipalId>>();

        let version = canister.system_state.canister_version;

        let canister_memory_usage = canister.memory_usage();
        let canister_wasm_memory_usage = canister.wasm_memory_usage();
        let canister_stable_memory_usage = canister.stable_memory_usage();
        let canister_global_memory_usage = canister.global_memory_usage();
        let canister_wasm_binary_memory_usage = canister.wasm_binary_memory_usage();
        let canister_custom_sections_memory_usage = canister.wasm_custom_sections_memory_usage();
        let canister_history_memory_usage = canister.canister_history_memory_usage();
        let canister_wasm_chunk_store_memory_usage = canister.wasm_chunk_store_memory_usage();
        let canister_snapshots_memory_usage = canister.snapshots_memory_usage();
        let canister_log_memory_usage = canister.log_memory_store_memory_usage();
        let canister_message_memory_usage = canister.message_memory_usage();
        let compute_allocation = canister.scheduler_state.compute_allocation;
        let memory_allocation = canister.memory_allocation();
        let freeze_threshold = canister.system_state.freeze_threshold;
        let reserved_cycles_limit = canister.system_state.reserved_balance_limit();
        let log_visibility = canister.system_state.log_visibility.clone();
        let log_memory_limit = canister.system_state.log_memory_store.log_memory_limit();
        let wasm_memory_limit = canister.system_state.wasm_memory_limit;
        let wasm_memory_threshold = canister.system_state.wasm_memory_threshold;

        Ok(CanisterStatusResultV2::new(
            canister.status(),
            ready_for_migration,
            version,
            canister
                .execution_state
                .as_ref()
                .map(|es| es.wasm_binary.binary.module_hash().to_vec()),
            *controller,
            controllers,
            canister_memory_usage,
            canister_wasm_memory_usage,
            canister_stable_memory_usage,
            canister_global_memory_usage,
            canister_wasm_binary_memory_usage,
            canister_custom_sections_memory_usage,
            canister_history_memory_usage,
            canister_wasm_chunk_store_memory_usage,
            canister_snapshots_memory_usage,
            canister_log_memory_usage,
            canister.system_state.balance().get(),
            compute_allocation.as_percent(),
            Some(memory_allocation.pre_allocated_bytes().get()),
            freeze_threshold.get(),
            reserved_cycles_limit.map(|x| x.get()),
            log_visibility,
            log_memory_limit as u64,
            self.cycles_account_manager
                .idle_cycles_burned_rate(
                    memory_allocation,
                    canister_memory_usage,
                    canister_message_memory_usage,
                    compute_allocation,
                    subnet_size,
                    cost_schedule,
                )
                .get(),
            canister.system_state.reserved_balance().get(),
            canister.scheduler_state.total_query_stats.num_calls,
            canister.scheduler_state.total_query_stats.num_instructions,
            canister
                .scheduler_state
                .total_query_stats
                .ingress_payload_size,
            canister
                .scheduler_state
                .total_query_stats
                .egress_payload_size,
            wasm_memory_limit.map(|x| x.get()),
            wasm_memory_threshold.get(),
            canister.system_state.environment_variables.clone(),
        ))
    }

    /// Gets the metadata of the canister.
    pub(crate) fn get_canister_metadata(
        &self,
        sender: PrincipalId,
        canister: &CanisterState,
        section_name: &str,
    ) -> Result<CanisterMetadataResponse, CanisterManagerError> {
        let execution_state = canister.execution_state.as_ref().ok_or(
            CanisterManagerError::CanisterMetadataNoWasmModule {
                canister_id: canister.canister_id(),
            },
        )?;
        let custom_section = execution_state
            .metadata
            .get_custom_section(section_name)
            .ok_or(CanisterManagerError::CanisterMetadataSectionNotFound {
                canister_id: canister.canister_id(),
                section_name: section_name.to_string(),
            })?;

        let is_sender_controller = canister.controllers().contains(&sender);
        let can_non_controller_read_section = match custom_section.visibility() {
            CustomSectionType::Public => true,
            CustomSectionType::Private => false,
        };
        if is_sender_controller || can_non_controller_read_section {
            Ok(CanisterMetadataResponse::new(
                custom_section.content().to_vec(),
            ))
        } else {
            Err(CanisterManagerError::CanisterMetadataSectionNotFound {
                canister_id: canister.canister_id(),
                section_name: section_name.to_string(),
            })
        }
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
        round_limits: &mut RoundLimits,
    ) -> Result<(), CanisterManagerError> {
        if let Ok(canister_id) = CanisterId::try_from(sender)
            && canister_id == canister_id_to_delete
        {
            // A canister cannot delete itself.
            return Err(CanisterManagerError::DeleteCanisterSelf(canister_id));
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
        let canister_memory_allocated_bytes = canister_to_delete.memory_allocated_bytes();

        // Delete canister snapshots that are stored separately in `ReplicatedState`.
        state
            .canister_snapshots
            .delete_snapshots(canister_to_delete.canister_id());

        round_limits.subnet_available_memory.increment(
            canister_memory_allocated_bytes,
            NumBytes::from(0),
            NumBytes::from(0),
        );

        // Leftover cycles in the balance are considered `consumed`.
        let leftover_cycles = NominalCycles::from(canister_to_delete.system_state.balance());
        let consumed_cycles_by_canister_to_delete = leftover_cycles
            + canister_to_delete
                .system_state
                .canister_metrics
                .consumed_cycles;

        state
            .metadata
            .subnet_metrics
            .observe_consumed_cycles_with_use_case(
                CyclesUseCase::DeletedCanisters,
                leftover_cycles,
            );

        state
            .metadata
            .subnet_metrics
            .consumed_cycles_by_deleted_canisters += consumed_cycles_by_canister_to_delete;

        for (use_case, cycles) in canister_to_delete
            .system_state
            .canister_metrics
            .get_consumed_cycles_by_use_cases()
            .iter()
        {
            state
                .metadata
                .subnet_metrics
                .observe_consumed_cycles_with_use_case(*use_case, *cycles);
        }

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
        origin: CanisterChangeOrigin,
        cycles_amount: Option<u128>,
        mut settings: CanisterSettings,
        specified_id: Option<PrincipalId>,
        state: &mut ReplicatedState,
        provisional_whitelist: &ProvisionalWhitelist,
        max_number_of_canisters: u64,
        round_limits: &mut RoundLimits,
        subnet_memory_saturation: ResourceSaturation,
        subnet_size: usize,
        canister_creation_error: &IntCounter,
    ) -> Result<CanisterId, CanisterManagerError> {
        let sender = origin.origin();

        if !provisional_whitelist.contains(&sender) {
            return Err(CanisterManagerError::SenderNotInWhitelist(sender));
        }

        let cycles = match cycles_amount {
            Some(cycles_amount) => Cycles::from(cycles_amount),
            None => self.config.default_provisional_cycles_balance,
        };

        // Set the field to the default value if it is empty.
        settings
            .reserved_cycles_limit
            .get_or_insert_with(|| self.cycles_account_manager.default_reserved_balance_limit());

        // Validate settings before `create_canister_helper` applies them
        // No creation fee applied.
        //
        // Test coverage relies on the fact that
        // the IC method `provisional_create_canister_with_cycles`
        // implemented by this function `CanisterManager::create_canister_with_cycles`
        // uses the same code (in `CanisterManager::create_canister_helper`)
        // as the production IC method `create_canister`
        // implemented by `CanisterManager::create_canister`.
        match self.validate_settings_for_canister_creation(
            settings,
            round_limits.compute_allocation_used,
            &round_limits.subnet_available_memory,
            &subnet_memory_saturation,
            cycles,
            subnet_size,
            state.get_own_cost_schedule(),
        ) {
            Err(err) => Err(err),
            Ok(validated_settings) => self.create_canister_helper(
                origin,
                cycles,
                Cycles::new(0),
                validated_settings,
                max_number_of_canisters,
                state,
                round_limits,
                specified_id,
                canister_creation_error,
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
        let new_canister_id = CanisterId::unchecked_from_principal(specified_id);

        if !state.metadata.validate_specified_id(&new_canister_id) {
            return Err(CanisterManagerError::InvalidSpecifiedId {
                specified_id: new_canister_id,
            });
        }

        if state.canister_states.contains_key(&new_canister_id) {
            return Err(CanisterManagerError::CanisterAlreadyExists(new_canister_id));
        }

        if state.metadata.network_topology.route(specified_id) == Some(state.metadata.own_subnet_id)
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
        origin: CanisterChangeOrigin,
        cycles: Cycles,
        creation_fee: Cycles,
        settings: ValidatedCanisterSettings,
        max_number_of_canisters: u64,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
        specified_id: Option<PrincipalId>,
        canister_creation_error: &IntCounter,
    ) -> Result<CanisterId, CanisterManagerError> {
        let sender = origin.origin();

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

            None => self.generate_new_canister_id(state, canister_creation_error)?,
        };

        // Canister id available. Create the new canister.
        let mut system_state = SystemState::new_running(
            new_canister_id,
            sender,
            cycles,
            self.config.default_freeze_threshold,
            Arc::clone(&self.fd_factory),
        );

        system_state.remove_cycles(creation_fee, CyclesUseCase::CanisterCreation);
        let scheduler_state = SchedulerState::new(state.metadata.batch_time);
        let mut new_canister = CanisterState::new(system_state, None, scheduler_state);

        self.do_update_settings(&settings, &mut new_canister);
        let new_usage = new_canister.memory_usage();
        let new_mem = new_canister
            .system_state
            .memory_allocation
            .allocated_bytes(new_usage);

        // settings were validated before so this should always succeed
        round_limits
            .subnet_available_memory
            .try_decrement(new_mem, NumBytes::from(0), NumBytes::from(0))
            .expect("Error: Cannot fail to decrement SubnetAvailableMemory after validating canister's settings");

        round_limits.compute_allocation_used = round_limits
            .compute_allocation_used
            .saturating_add(new_canister.scheduler_state.compute_allocation.as_percent());

        let controllers = new_canister
            .system_state
            .controllers
            .iter()
            .copied()
            .collect();

        let available_execution_memory_change = match self.environment_variables_flag {
            FlagStatus::Enabled => {
                let environment_variables_hash = settings
                    .environment_variables()
                    .map(|env_vars| env_vars.hash());
                new_canister.add_canister_change(
                    state.time(),
                    origin,
                    CanisterChangeDetails::canister_creation(
                        controllers,
                        environment_variables_hash,
                    ),
                )
            }
            FlagStatus::Disabled => new_canister.add_canister_change(
                state.time(),
                origin,
                CanisterChangeDetails::canister_creation(controllers, None),
            ),
        };
        round_limits
            .subnet_available_memory
            .update_execution_memory_unchecked(available_execution_memory_change);

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

        canister
            .system_state
            .add_cycles(cycles_amount, CyclesUseCase::NonConsumed);

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
    // of NNS canister ids as defined in nns/constants/src/lib.rs are also
    // updated.
    fn generate_new_canister_id(
        &self,
        state: &mut ReplicatedState,
        canister_creation_error: &IntCounter,
    ) -> Result<CanisterId, CanisterManagerError> {
        let canister_id = state.metadata.generate_new_canister_id().map_err(|err| {
            error!(self.log, "Unable to generate new canister IDs: {}", err);
            CanisterManagerError::SubnetOutOfCanisterIds
        })?;

        // Sanity check: ensure that no canister with this ID exists already.
        debug_assert!(state.canister_state(&canister_id).is_none());
        if state.canister_state(&canister_id).is_some() {
            canister_creation_error.inc();
            error!(
                self.log,
                "[EXC-BUG] New canister id {} already exists.", canister_id
            );
            return Err(CanisterManagerError::CanisterIdAlreadyExists(canister_id));
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

    pub(crate) fn upload_chunk(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
        chunk: Vec<u8>,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        resource_saturation: &ResourceSaturation,
    ) -> Result<UploadChunkResult, CanisterManagerError> {
        // Allow the canister itself to perform this operation.
        if sender != canister.system_state.canister_id.into() {
            validate_controller(canister, &sender)?
        }

        // Charge for the upload. We charge before checking if the chunk has already been uploaded
        // since that check involves hash computation that we also want to charge for.
        let instructions = self.config.upload_wasm_chunk_instructions;
        self.cycles_account_manager
            .consume_cycles_for_instructions(
                &sender,
                canister,
                instructions,
                subnet_size,
                cost_schedule,
                // For the `upload_chunk` operation, it does not matter if this is a Wasm64 or Wasm32 module
                // since the number of instructions charged depends on a constant fee
                // and Wasm64 does not bring any additional overhead for this operation.
                // The only overhead is during execution time.
                WasmExecutionMode::Wasm32,
            )
            .map_err(|err| CanisterManagerError::WasmChunkStoreError {
                message: format!("Error charging for 'upload_chunk': {err}"),
            })?;

        let validated_chunk = match canister
            .system_state
            .wasm_chunk_store
            .can_insert_chunk(self.config.wasm_chunk_store_max_size, chunk)
        {
            ChunkValidationResult::Insert(validated_chunk) => validated_chunk,
            ChunkValidationResult::AlreadyExists(hash) => {
                return Ok(UploadChunkResult {
                    reply: UploadChunkReply {
                        hash: hash.to_vec(),
                    },
                    heap_delta_increase: NumBytes::new(0),
                });
            }
            ChunkValidationResult::ValidationError(err) => {
                return Err(CanisterManagerError::WasmChunkStoreError { message: err });
            }
        };

        let chunk_bytes = wasm_chunk_store::chunk_size();
        let new_memory_usage = canister.memory_usage() + chunk_bytes;

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled
            && canister.scheduler_state.heap_delta_debit >= self.config.heap_delta_rate_limit
        {
            return Err(CanisterManagerError::WasmChunkStoreError {
                message: format!(
                    "Canister is heap delta rate limited. Current delta debit: {}, limit: {}",
                    canister.scheduler_state.heap_delta_debit, self.config.heap_delta_rate_limit
                ),
            });
        }

        let memory_usage = canister.memory_usage();
        let validated_cycles_and_memory_usage = self.cycles_and_memory_usage_checks(
            subnet_size,
            cost_schedule,
            canister,
            sender,
            Cycles::zero(),
            round_limits,
            new_memory_usage,
            memory_usage,
            resource_saturation,
        )?;
        self.cycles_and_memory_usage_updates(
            subnet_size,
            cost_schedule,
            canister,
            sender,
            round_limits,
            validated_cycles_and_memory_usage,
        );

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled {
            canister.scheduler_state.heap_delta_debit += chunk_bytes;
        }

        round_limits.instructions -= as_round_instructions(instructions);

        let hash = validated_chunk.hash().to_vec();
        canister
            .system_state
            .wasm_chunk_store
            .insert_chunk(validated_chunk);
        Ok(UploadChunkResult {
            reply: UploadChunkReply { hash },
            heap_delta_increase: chunk_bytes,
        })
    }

    pub(crate) fn clear_chunk_store(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        resource_saturation: &ResourceSaturation,
    ) -> Result<(), CanisterManagerError> {
        // Allow the canister itself to perform this operation.
        if sender != canister.system_state.canister_id.into() {
            validate_controller(canister, &sender)?
        }

        let memory_usage = canister.memory_usage();
        let wasm_chunk_store_size = canister.wasm_chunk_store_memory_usage();
        debug_assert!(memory_usage >= wasm_chunk_store_size);
        let new_memory_usage = memory_usage.saturating_sub(&wasm_chunk_store_size);
        let validated_cycles_and_memory_usage = self.cycles_and_memory_usage_checks(
            subnet_size,
            cost_schedule,
            canister,
            sender,
            Cycles::zero(),
            round_limits,
            new_memory_usage,
            memory_usage,
            resource_saturation,
        )?;

        canister.system_state.wasm_chunk_store = WasmChunkStore::new(Arc::clone(&self.fd_factory));
        self.cycles_and_memory_usage_updates(
            subnet_size,
            cost_schedule,
            canister,
            sender,
            round_limits,
            validated_cycles_and_memory_usage,
        );

        Ok(())
    }

    pub(crate) fn stored_chunks(
        &self,
        sender: PrincipalId,
        canister: &CanisterState,
    ) -> Result<StoredChunksReply, CanisterManagerError> {
        // Allow the canister itself to perform this operation.
        if sender != canister.system_state.canister_id.into() {
            validate_controller(canister, &sender)?
        }

        let keys = canister
            .system_state
            .wasm_chunk_store
            .keys()
            .map(|k| ChunkHash { hash: k.to_vec() })
            .collect();
        Ok(StoredChunksReply(keys))
    }

    // Runs the following checks on cycles and memory usage:
    // 1. There is enough subnet available memory for the new memory usage.
    // 2. The canister is not frozen due to its new memory usage.
    // 3. Cycles for instructions can be withdrawn (in particular, the canister is not frozen afterwards).
    // 4. Storage reservation cycles can be reserved.
    fn cycles_and_memory_usage_checks(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        canister: &CanisterState,
        sender: PrincipalId,
        cycles_for_instructions: Cycles,
        round_limits: &RoundLimits,
        new_memory_usage: NumBytes,
        old_memory_usage: NumBytes,
        resource_saturation: &ResourceSaturation,
    ) -> Result<ValidatedCyclesAndMemoryUsage, CanisterManagerError> {
        // Check that there is enough subnet available memory for the new memory usage.
        let old_memory_allocated_bytes = canister
            .memory_allocation()
            .allocated_bytes(old_memory_usage);
        let new_memory_allocated_bytes = canister
            .memory_allocation()
            .allocated_bytes(new_memory_usage);
        let allocated_bytes =
            new_memory_allocated_bytes.saturating_sub(&old_memory_allocated_bytes);
        let deallocated_bytes =
            old_memory_allocated_bytes.saturating_sub(&new_memory_allocated_bytes);
        round_limits
            .subnet_available_memory
            .check_available_memory(allocated_bytes, NumBytes::from(0), NumBytes::from(0))
            .map_err(
                |_| CanisterManagerError::SubnetMemoryCapacityOverSubscribed {
                    requested: allocated_bytes,
                    available: NumBytes::from(
                        round_limits
                            .subnet_available_memory
                            .get_execution_memory()
                            .max(0) as u64,
                    ),
                },
            )?;

        // Check that the canister is not frozen due to its new memory usage.
        let threshold = self.cycles_account_manager.freeze_threshold_cycles(
            canister.system_state.freeze_threshold,
            canister.memory_allocation(),
            new_memory_usage,
            canister.message_memory_usage(),
            canister.compute_allocation(),
            subnet_size,
            cost_schedule,
            canister.system_state.reserved_balance(),
        );
        if canister.system_state.balance() < threshold {
            return Err(CanisterManagerError::InsufficientCyclesInMemoryGrow {
                bytes: allocated_bytes,
                available: canister.system_state.balance(),
                required: threshold,
            });
        }

        // Check that cycles for instructions can be withdrawn (in particular, the canister is not frozen afterwards).
        let reveal_top_up = canister.controllers().contains(&sender);
        self.cycles_account_manager
            .can_withdraw_cycles(
                &canister.system_state,
                cycles_for_instructions,
                new_memory_usage,
                canister.message_memory_usage(),
                canister.compute_allocation(),
                subnet_size,
                cost_schedule,
                reveal_top_up,
            )
            .map_err(CanisterManagerError::CanisterSnapshotNotEnoughCycles)?;

        // Check that storage reservation cycles can be reserved.
        let new_storage_reservation_cycles =
            self.cycles_account_manager.storage_reservation_cycles(
                allocated_bytes,
                resource_saturation,
                subnet_size,
                cost_schedule,
            );
        let main_balance = canister.system_state.balance() - cycles_for_instructions; // `-` on `Cycles` is saturating
        canister
            .system_state
            .can_reserve_cycles(new_storage_reservation_cycles, main_balance)
            .map_err(|err| match err {
                ReservationError::InsufficientCycles {
                    requested,
                    available,
                } => CanisterManagerError::InsufficientCyclesInMemoryGrow {
                    bytes: allocated_bytes,
                    available,
                    required: requested,
                },
                ReservationError::ReservedLimitExceed { requested, limit } => {
                    CanisterManagerError::ReservedCyclesLimitExceededInMemoryGrow {
                        bytes: allocated_bytes,
                        requested,
                        limit,
                    }
                }
            })?;

        Ok(ValidatedCyclesAndMemoryUsage {
            cycles_for_instructions,
            new_memory_usage,
            allocated_bytes,
            deallocated_bytes,
            new_storage_reservation_cycles,
        })
    }

    // IMPORTANT! This function should only be called after a successful call to `self.cycles_and_memory_usage_checks`.
    //
    // Performs the following updates:
    // 1. Update subnet available memory.
    // 2. Consume cycles for instructions.
    // 3. Reserve cycles for storage.
    fn cycles_and_memory_usage_updates(
        &self,
        subnet_size: usize,
        cost_schedule: CanisterCyclesCostSchedule,
        canister: &mut CanisterState,
        sender: PrincipalId,
        round_limits: &mut RoundLimits,
        validated_cycles_and_memory_usage: ValidatedCyclesAndMemoryUsage,
    ) {
        // Update subnet available memory:
        // - return deallocated bytes back to subnet available memory;
        // - deduct allocated bytes from subnet available memory.
        round_limits.subnet_available_memory.increment(
            validated_cycles_and_memory_usage.deallocated_bytes,
            NumBytes::from(0),
            NumBytes::from(0),
        );
        round_limits.subnet_available_memory
            .try_decrement(validated_cycles_and_memory_usage.allocated_bytes, NumBytes::from(0), NumBytes::from(0))
            .expect("Error: Cannot fail to decrement SubnetAvailableMemory after checking for availability");

        // Consume cycles for instructions.
        let message_memory_usage = canister.message_memory_usage();
        let compute_allocation = canister.compute_allocation();
        let reveal_top_up = canister.controllers().contains(&sender);
        self.cycles_account_manager
            .consume_cycles(
                &mut canister.system_state,
                validated_cycles_and_memory_usage.new_memory_usage,
                message_memory_usage,
                compute_allocation,
                validated_cycles_and_memory_usage.cycles_for_instructions,
                subnet_size,
                cost_schedule,
                CyclesUseCase::Instructions,
                reveal_top_up,
            )
            .unwrap();

        // Reserve cycles for storage.
        canister
            .system_state
            .reserve_cycles(validated_cycles_and_memory_usage.new_storage_reservation_cycles)
            .unwrap();
    }

    /// Creates a new canister snapshot.
    ///
    /// A canister snapshot can only be initiated by the controllers.
    /// In addition, if the `replace_snapshot` parameter is `Some`,
    /// the system will attempt to identify the snapshot based on the provided ID,
    /// and delete it before creating a new one.
    /// Failure to do so will result in the creation of a new snapshot being unsuccessful.
    /// Finally, if the `uninstall_code` parameter is `true`, then the system
    /// will uninstall code of the canister atomically after creating the new snapshot.
    /// In particular, the canister's memory usage will be updated atomically.
    /// This function returns a vector of system-generated responses from the uninstalled canister.
    /// This is because we cannot process the responses in this function
    /// while the `canister` is taken out of `ReplicatedState`.
    ///
    /// If the new snapshot cannot be created, an appropriate error will be returned.
    pub(crate) fn take_canister_snapshot(
        &self,
        subnet_size: usize,
        origin: CanisterChangeOrigin,
        canister: &mut CanisterState,
        replace_snapshot: Option<SnapshotId>,
        uninstall_code: bool,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
        resource_saturation: &ResourceSaturation,
    ) -> Result<(CanisterSnapshotResponse, Vec<Response>, NumInstructions), CanisterManagerError>
    {
        let sender = origin.origin();
        let time = state.time();

        // Check sender is a controller.
        validate_controller(canister, &sender)?;
        let canister_id = canister.canister_id();

        let replace_snapshot_size = match replace_snapshot {
            Some(replace_snapshot_id) => self
                .get_snapshot(canister_id, replace_snapshot_id, state)?
                .size(),
            None => {
                // No replace snapshot ID provided, check whether the maximum number of snapshots
                // has been reached.
                if state
                    .canister_snapshots
                    .count_by_canister(&canister.canister_id())
                    >= self.config.max_number_of_snapshots_per_canister
                {
                    return Err(CanisterManagerError::CanisterSnapshotLimitExceeded {
                        canister_id: canister.canister_id(),
                        limit: self.config.max_number_of_snapshots_per_canister,
                    });
                }
                NumBytes::new(0)
            }
        };

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled
            && canister.scheduler_state.heap_delta_debit >= self.config.heap_delta_rate_limit
        {
            return Err(CanisterManagerError::CanisterHeapDeltaRateLimited {
                canister_id: canister.canister_id(),
                value: canister.scheduler_state.heap_delta_debit,
                limit: self.config.heap_delta_rate_limit,
            });
        }

        let uninstalled_canister_size = if uninstall_code {
            canister.execution_memory_usage()
                + canister.log_memory_store_memory_usage() // TODO: double-check if this is correct.
                + canister.wasm_chunk_store_memory_usage()
        } else {
            NumBytes::from(0)
        };

        let new_snapshot_size = canister.snapshot_size_bytes();
        let old_memory_usage = canister.memory_usage();
        let new_memory_usage = canister
            .memory_usage()
            .saturating_add(&new_snapshot_size)
            .saturating_sub(&replace_snapshot_size)
            .saturating_sub(&uninstalled_canister_size);

        // Compute cycles for instructions spent taking a snapshot of the canister.
        let instructions = self
            .config
            .canister_snapshot_baseline_instructions
            .saturating_add(&new_snapshot_size.get().into());
        let cycles_for_instructions = self.cycles_account_manager.execution_cost(
            instructions,
            subnet_size,
            state.get_own_cost_schedule(),
            // For the `take_canister_snapshot` operation, it does not matter if this is a Wasm64 or Wasm32 module
            // since the number of instructions charged depends on constant set fee and snapshot size
            // and Wasm64 does not bring any additional overhead for this operation.
            // The only overhead is during execution time.
            WasmExecutionMode::Wasm32,
        );

        let validated_cycles_and_memory_usage = self.cycles_and_memory_usage_checks(
            subnet_size,
            state.get_own_cost_schedule(),
            canister,
            sender,
            cycles_for_instructions,
            round_limits,
            new_memory_usage,
            old_memory_usage,
            resource_saturation,
        )?;

        // Create new snapshot.
        let new_snapshot = CanisterSnapshot::from_canister(canister, state.time())
            .map_err(CanisterManagerError::from)?;

        // Delete old snapshot identified by `replace_snapshot`.
        if let Some(replace_snapshot) = replace_snapshot {
            self.remove_snapshot(canister, replace_snapshot, state, replace_snapshot_size);
        }

        self.cycles_and_memory_usage_updates(
            subnet_size,
            state.get_own_cost_schedule(),
            canister,
            sender,
            round_limits,
            validated_cycles_and_memory_usage,
        );

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled {
            canister.scheduler_state.heap_delta_debit = canister
                .scheduler_state
                .heap_delta_debit
                .saturating_add(&new_snapshot.heap_delta());
        }
        state.metadata.heap_delta_estimate = state
            .metadata
            .heap_delta_estimate
            .saturating_add(&new_snapshot.heap_delta());

        let snapshot_id =
            SnapshotId::from((canister.canister_id(), canister.new_local_snapshot_id()));
        state.take_snapshot(snapshot_id, Arc::new(new_snapshot));
        canister.system_state.snapshots_memory_usage = canister
            .system_state
            .snapshots_memory_usage
            .saturating_add(&new_snapshot_size);

        let rejects = if uninstall_code {
            let rejects = uninstall_canister(
                &self.log,
                canister,
                None, /* we don't pass RoundLimits since we update them separately via `cycles_and_memory_usage_updates` */
                time,
                Arc::clone(&self.fd_factory),
            );
            let available_execution_memory_change = canister.add_canister_change(
                time,
                origin,
                CanisterChangeDetails::CanisterCodeUninstall,
            );
            round_limits
                .subnet_available_memory
                .update_execution_memory_unchecked(available_execution_memory_change);
            rejects
        } else {
            vec![]
        };

        Ok((
            CanisterSnapshotResponse::new(
                &snapshot_id,
                state.time().as_nanos_since_unix_epoch(),
                new_snapshot_size,
            ),
            rejects,
            instructions,
        ))
    }

    /// Returns an Arc to the snapshot, if it exists.
    /// Returns an error if the snapshot given by the snapshot ID does not
    /// belong to this canister.
    fn get_snapshot(
        &self,
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        state: &ReplicatedState,
    ) -> Result<Arc<CanisterSnapshot>, CanisterManagerError> {
        // If not found, the operation fails due to invalid parameters.
        let Some(snapshot) = state.canister_snapshots.get(snapshot_id) else {
            return Err(CanisterManagerError::CanisterSnapshotNotFound {
                canister_id,
                snapshot_id,
            });
        };
        // Verify the provided `snapshot_id` belongs to this canister.
        if snapshot.canister_id() != canister_id {
            return Err(CanisterManagerError::CanisterSnapshotInvalidOwnership {
                canister_id,
                snapshot_id,
            });
        }
        Ok(Arc::clone(snapshot))
    }

    /// Returns a mutable Arc to the snapshot, if it exists.
    /// Returns an error if the snapshot given by the snapshot ID does not
    /// belong to this canister.
    pub fn get_snapshot_mut<'a>(
        &self,
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
        state: &'a mut ReplicatedState,
    ) -> Result<&'a mut Arc<CanisterSnapshot>, CanisterManagerError> {
        // If not found, the operation fails due to invalid parameters.
        let Some(snapshot) = state.canister_snapshots.get_mut(snapshot_id) else {
            return Err(CanisterManagerError::CanisterSnapshotNotFound {
                canister_id,
                snapshot_id,
            });
        };
        // Verify the provided `snapshot_id` belongs to this canister.
        if snapshot.canister_id() != canister_id {
            return Err(CanisterManagerError::CanisterSnapshotInvalidOwnership {
                canister_id,
                snapshot_id,
            });
        }
        Ok(snapshot)
    }

    pub(crate) fn load_canister_snapshot(
        &self,
        subnet_size: usize,
        sender: PrincipalId,
        canister: &mut CanisterState,
        snapshot_id: SnapshotId,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
        origin: CanisterChangeOrigin,
        resource_saturation: &ResourceSaturation,
        long_execution_already_in_progress: &IntCounter,
        snapshot_exists_without_associated_canister: &IntCounter,
    ) -> (Result<CanisterState, CanisterManagerError>, NumInstructions) {
        let canister_id = canister.canister_id();
        // Check sender is a controller.
        if let Err(err) = validate_controller(canister, &sender) {
            return (Err(err), NumInstructions::new(0));
        }

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled
            && canister.scheduler_state.heap_delta_debit >= self.config.heap_delta_rate_limit
        {
            return (
                Err(CanisterManagerError::CanisterHeapDeltaRateLimited {
                    canister_id,
                    value: canister.scheduler_state.heap_delta_debit,
                    limit: self.config.heap_delta_rate_limit,
                }),
                NumInstructions::new(0),
            );
        }

        // Check that snapshot ID exists.
        let snapshot: &Arc<CanisterSnapshot> = match state.canister_snapshots.get(snapshot_id) {
            None => {
                // If not found, the operation fails due to invalid parameters.
                return (
                    Err(CanisterManagerError::CanisterSnapshotNotFound {
                        canister_id,
                        snapshot_id,
                    }),
                    NumInstructions::new(0),
                );
            }
            Some(snapshot) => {
                // Verify the provided `snapshot_id` belongs to a canister controlled by the sender.
                // Only perform the check if target canister to load the snapshot
                // is not the same as the one owning the snapshot.
                let snapshot_canister_id = snapshot.canister_id();
                if snapshot_canister_id != canister_id {
                    match state.canister_state(&snapshot_canister_id) {
                        None => {
                            // The below case should never happen as if the snapshot still exists, it
                            // should be associated with an existing canister. If it happens, it indicates
                            // a bug, so log an error message for investigation.
                            snapshot_exists_without_associated_canister.inc();
                            error!(
                                self.log,
                                "[EXC-BUG]: Canister {} does not exist although there's a snapshot {} associated with it.",
                                snapshot_canister_id,
                                snapshot_id,
                            );
                            return (
                                Err(CanisterManagerError::CanisterNotFound(snapshot_canister_id)),
                                NumInstructions::new(0),
                            );
                        }
                        Some(canister_state) => {
                            if !canister_state.controllers().contains(&sender) {
                                return (
                                    Err(CanisterManagerError::CanisterSnapshotNotController {
                                        sender,
                                        canister_id,
                                        snapshot_id,
                                    }),
                                    NumInstructions::new(0),
                                );
                            }
                        }
                    }
                }
                snapshot
            }
        };
        let execution_snapshot = snapshot.execution_snapshot();

        // Check the precondition:
        // Unable to start executing a `load_canister_snapshot`
        // if there is already a long-running message in progress for the specified canister.
        match canister.next_execution() {
            NextExecution::None | NextExecution::StartNew => {}
            NextExecution::ContinueLong | NextExecution::ContinueInstallCode => {
                long_execution_already_in_progress.inc();
                error!(
                    self.log,
                    "[EXC-BUG] Attempted to start a new `load_canister_snapshot` execution while the previous execution is still in progress for {}.",
                    canister_id
                );
                return (
                    Err(CanisterManagerError::LongExecutionAlreadyInProgress { canister_id }),
                    NumInstructions::new(0),
                );
            }
        }

        // All basic checks have passed, charge baseline instructions.
        let old_memory_usage = canister.memory_usage();
        let mut canister_clone = canister.clone();

        if let Err(err) = self.cycles_account_manager.consume_cycles_for_instructions(
            &sender,
            &mut canister_clone,
            self.config.canister_snapshot_baseline_instructions,
            subnet_size,
            state.get_own_cost_schedule(),
            // For the `load_canister_snapshot` operation, it does not matter if this is a Wasm64 or Wasm32 module
            // since the number of instructions charged depends on constant set fee
            // and Wasm64 does not bring any additional overhead for this operation.
            // The only overhead is during execution time.
            WasmExecutionMode::Wasm32,
        ) {
            return (
                Err(CanisterManagerError::CanisterSnapshotNotEnoughCycles(err)),
                0.into(),
            );
        };

        let (_old_execution_state, mut system_state, scheduler_state) = canister_clone.into_parts();

        let (instructions_used, new_execution_state) = {
            let new_wasm_hash = WasmHash::from(&execution_snapshot.wasm_binary);
            let compilation_cost_handling = if state
                .metadata
                .expected_compiled_wasms
                .contains(&new_wasm_hash)
            {
                CompilationCostHandling::CountReducedAmount
            } else {
                CompilationCostHandling::CountFullAmount
            };

            let (instructions_used, new_execution_state) = self.hypervisor.create_execution_state(
                execution_snapshot.wasm_binary.clone(),
                "NOT_USED".into(),
                canister_id,
                round_limits,
                compilation_cost_handling,
            );

            let mut new_execution_state = match new_execution_state {
                Ok(execution_state) => execution_state,
                Err(err) => {
                    let err = CanisterManagerError::from((canister_id, err));
                    return (Err(err), instructions_used);
                }
            };

            // If the snapshot was uploaded, make sure the snapshot's exported globals match the wasm module's.
            if snapshot.source() == SnapshotSource::MetadataUpload(candid::Reserved)
                && !globals_match(
                    &new_execution_state.exported_globals,
                    &execution_snapshot.exported_globals,
                )
            {
                return (
                        Err(CanisterManagerError::CanisterSnapshotInconsistent {
                            message: "Wasm exported globals of canister module and snapshot metadata do not match.".to_string(),
                        }),
                        instructions_used,
                    );
            }

            new_execution_state.exported_globals = execution_snapshot.exported_globals.clone();

            if canister_id == snapshot.canister_id() {
                new_execution_state.stable_memory = Memory::from(&execution_snapshot.stable_memory);
                new_execution_state.wasm_memory = Memory::from(&execution_snapshot.wasm_memory);
            } else {
                let new_stable_memory = match Memory::try_from((
                    &execution_snapshot.stable_memory,
                    Arc::clone(&self.fd_factory),
                )) {
                    Ok(memory) => memory,
                    Err(_) => {
                        return (
                            Err(CanisterManagerError::CanisterSnapshotNotLoadable {
                                canister_id,
                                snapshot_id,
                            }),
                            instructions_used,
                        );
                    }
                };
                new_execution_state.stable_memory = new_stable_memory;

                let new_wasm_memory = match Memory::try_from((
                    &execution_snapshot.wasm_memory,
                    Arc::clone(&self.fd_factory),
                )) {
                    Ok(memory) => memory,
                    Err(_) => {
                        return (
                            Err(CanisterManagerError::CanisterSnapshotNotLoadable {
                                canister_id,
                                snapshot_id,
                            }),
                            instructions_used,
                        );
                    }
                };
                new_execution_state.wasm_memory = new_wasm_memory;
            }
            (instructions_used, Some(new_execution_state))
        };

        system_state.wasm_chunk_store = snapshot.chunk_store().clone();
        system_state
            .certified_data
            .clone_from(snapshot.certified_data());

        // We don't restore the state of global timer and on low wasm memory hook
        // for snapshots created via `take_canister_snapshot`
        // since that would be a breaking change.
        if snapshot.source() == SnapshotSource::MetadataUpload(candid::Reserved) {
            if let Some(global_timer) = execution_snapshot.global_timer {
                system_state.global_timer = global_timer;
            }
            if let Some(on_low_wasm_memory_hook_status) =
                execution_snapshot.on_low_wasm_memory_hook_status
            {
                system_state
                    .task_queue
                    .set_on_low_wasm_memory_hook_status_from_snapshot(
                        on_low_wasm_memory_hook_status,
                    );
            }
        }

        let wasm_execution_mode = new_execution_state
            .as_ref()
            .map_or(WasmExecutionMode::Wasm32, |exec_state| {
                exec_state.wasm_execution_mode
            });

        let mut new_canister =
            CanisterState::new(system_state, new_execution_state, scheduler_state);
        let new_memory_usage = new_canister.memory_usage();

        // If the snapshot was uploaded, make sure the snapshot's memory hook status matches the actual status.
        // Otherwise, the snapshot is invalid.
        if snapshot.source() == SnapshotSource::MetadataUpload(candid::Reserved) {
            let hook_condition = new_canister.is_low_wasm_memory_hook_condition_satisfied();
            let snapshot_hook_status = snapshot.execution_snapshot().on_low_wasm_memory_hook_status;
            if !snapshot_hook_status
                .map(|h| h.is_consistent_with(hook_condition))
                .unwrap_or(true)
            {
                return (
                    Err(CanisterManagerError::CanisterSnapshotInconsistent {
                        message: format!(
                            "Hook status ({snapshot_hook_status:?}) of uploaded snapshot is inconsistent with the canister's state (hook condition satisfied: {hook_condition})."
                        ),
                    }),
                    instructions_used,
                );
            }
        }

        // Compute cycles for instructions spent loading a snapshot of the canister.
        let instructions = instructions_used.saturating_add(&snapshot.size().get().into());
        let cycles_for_instructions = self.cycles_account_manager.execution_cost(
            instructions,
            subnet_size,
            state.get_own_cost_schedule(),
            // In this case, when the canister is actually created from the snapshot, we need to check
            // if the canister is in wasm64 mode to account for its instruction usage.
            wasm_execution_mode,
        );

        let validated_cycles_and_memory_usage = match self.cycles_and_memory_usage_checks(
            subnet_size,
            state.get_own_cost_schedule(),
            &new_canister,
            sender,
            cycles_for_instructions,
            round_limits,
            new_memory_usage,
            old_memory_usage,
            resource_saturation,
        ) {
            Ok(validated_cycles_and_memory_usage) => validated_cycles_and_memory_usage,
            Err(err) => {
                return (Err(err), instructions_used);
            }
        };

        self.cycles_and_memory_usage_updates(
            subnet_size,
            state.get_own_cost_schedule(),
            &mut new_canister,
            sender,
            round_limits,
            validated_cycles_and_memory_usage,
        );

        // The canister ID from which the snapshot was loaded in case
        // it is different from the target canister ID.
        let from_canister_id = if snapshot.canister_id() == canister_id {
            None
        } else {
            Some(snapshot.canister_id())
        };

        // Increment canister version.
        new_canister.system_state.canister_version += 1;
        let available_execution_memory_change = new_canister.add_canister_change(
            state.time(),
            origin,
            CanisterChangeDetails::load_snapshot(
                snapshot.canister_version(),
                snapshot_id,
                snapshot.taken_at_timestamp().as_nanos_since_unix_epoch(),
                snapshot.source(),
                from_canister_id,
            ),
        );
        round_limits
            .subnet_available_memory
            .update_execution_memory_unchecked(available_execution_memory_change);
        state
            .metadata
            .unflushed_checkpoint_ops
            .load_snapshot(canister_id, snapshot_id);

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled {
            new_canister.scheduler_state.heap_delta_debit = new_canister
                .scheduler_state
                .heap_delta_debit
                .saturating_add(&new_canister.heap_delta());
        }
        state.metadata.heap_delta_estimate = state
            .metadata
            .heap_delta_estimate
            .saturating_add(&new_canister.heap_delta());

        (Ok(new_canister), instructions_used)
    }

    /// Returns the canister snapshots list, or
    /// an error if it failed to retrieve the information.
    ///
    /// Retrieving the canister snapshots list can only be initiated by the controllers.
    pub(crate) fn list_canister_snapshot(
        &self,
        sender: PrincipalId,
        canister: &CanisterState,
        state: &ReplicatedState,
    ) -> Result<Vec<CanisterSnapshotResponse>, CanisterManagerError> {
        // Check sender is a controller.
        validate_controller(canister, &sender)?;

        let mut responses = vec![];
        for (snapshot_id, snapshot) in state
            .canister_snapshots
            .list_snapshots(canister.canister_id())
        {
            let snapshot_response = CanisterSnapshotResponse::new(
                &snapshot_id,
                snapshot.taken_at_timestamp().as_nanos_since_unix_epoch(),
                snapshot.size(),
            );
            responses.push(snapshot_response);
        }

        Ok(responses)
    }

    /// Deletes the specified canister snapshot if it exists,
    /// or returns an error if it failed.
    ///
    /// Deleting a canister snapshot can only be initiated by the controllers.
    pub(crate) fn delete_canister_snapshot(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
        delete_snapshot_id: SnapshotId,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        resource_saturation: &ResourceSaturation,
    ) -> Result<(), CanisterManagerError> {
        // Check sender is a controller.
        validate_controller(canister, &sender)?;

        // perform access validation, but don't use the result
        let snapshot = self.get_snapshot(canister.canister_id(), delete_snapshot_id, state)?;

        let memory_usage = canister.memory_usage();
        let old_snapshot_size = snapshot.size();
        debug_assert!(memory_usage >= old_snapshot_size);
        let new_memory_usage = memory_usage.saturating_sub(&old_snapshot_size);
        let validated_cycles_and_memory_usage = self.cycles_and_memory_usage_checks(
            subnet_size,
            state.get_own_cost_schedule(),
            canister,
            sender,
            Cycles::zero(),
            round_limits,
            new_memory_usage,
            memory_usage,
            resource_saturation,
        )?;

        self.remove_snapshot(canister, delete_snapshot_id, state, old_snapshot_size);

        self.cycles_and_memory_usage_updates(
            subnet_size,
            state.get_own_cost_schedule(),
            canister,
            sender,
            round_limits,
            validated_cycles_and_memory_usage,
        );

        Ok(())
    }

    pub(crate) fn read_snapshot_metadata(
        &self,
        sender: PrincipalId,
        snapshot_id: SnapshotId,
        canister: &CanisterState,
        state: &ReplicatedState,
    ) -> Result<ReadCanisterSnapshotMetadataResponse, CanisterManagerError> {
        // Check sender is a controller.
        validate_controller(canister, &sender)?;
        let snapshot = self.get_snapshot(canister.canister_id(), snapshot_id, state)?;
        // A snapshot also contains the instruction counter as the last global
        // (because it is *appended* during WASM instrumentation).
        // We pop that last global (which is merely an implementation detail)
        // from the list of globals returned to the user.
        let mut globals = snapshot.exported_globals().clone();
        let maybe_instruction_counter = globals.pop();
        debug_assert!(maybe_instruction_counter.is_some());

        Ok(ReadCanisterSnapshotMetadataResponse {
            source: snapshot.source(),
            taken_at_timestamp: snapshot.taken_at_timestamp().as_nanos_since_unix_epoch(),
            wasm_module_size: snapshot.execution_snapshot().wasm_binary.len() as u64,
            globals,
            wasm_memory_size: snapshot.execution_snapshot().wasm_memory.size.get() as u64
                * WASM_PAGE_SIZE_IN_BYTES as u64,
            stable_memory_size: snapshot.execution_snapshot().stable_memory.size.get() as u64
                * WASM_PAGE_SIZE_IN_BYTES as u64,
            wasm_chunk_store: snapshot
                .chunk_store()
                .keys()
                .cloned()
                .map(|x| ChunkHash { hash: x.to_vec() })
                .collect(),
            canister_version: snapshot.canister_version(),
            certified_data: snapshot.certified_data().clone(),
            global_timer: snapshot
                .execution_snapshot()
                .global_timer
                .map(GlobalTimer::from),
            on_low_wasm_memory_hook_status: snapshot
                .execution_snapshot()
                .on_low_wasm_memory_hook_status,
        })
    }

    pub(crate) fn read_snapshot_data(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
        snapshot_id: SnapshotId,
        kind: CanisterSnapshotDataKind,
        state: &ReplicatedState,
        subnet_size: usize,
    ) -> Result<ReadCanisterSnapshotDataResponse, CanisterManagerError> {
        // Check sender is a controller.
        validate_controller(canister, &sender)?;
        let snapshot = self.get_snapshot(canister.canister_id(), snapshot_id, state)?;

        // Charge upfront for the baseline plus the maximum possible size of the returned slice or fail.
        let num_response_bytes = get_response_size(&kind)?;
        if let Err(err) = self.cycles_account_manager.consume_cycles_for_instructions(
            &sender,
            canister,
            self.config
                .canister_snapshot_data_baseline_instructions
                .saturating_add(&NumInstructions::new(num_response_bytes)),
            subnet_size,
            state.get_own_cost_schedule(),
            // For the `read_snapshot_data` operation, it does not matter if this is a Wasm64 or Wasm32 module.
            WasmExecutionMode::Wasm32,
        ) {
            return Err(CanisterManagerError::CanisterSnapshotNotEnoughCycles(err));
        };

        let res = match kind {
            CanisterSnapshotDataKind::StableMemory { offset, size } => {
                let stable_memory = snapshot.execution_snapshot().stable_memory.clone();
                match CanisterSnapshot::get_memory_chunk(stable_memory, offset, size) {
                    Ok(chunk) => Ok(chunk),
                    Err(e) => Err(e.into()),
                }
            }
            CanisterSnapshotDataKind::WasmMemory { offset, size } => {
                let main_memory = snapshot.execution_snapshot().wasm_memory.clone();
                match CanisterSnapshot::get_memory_chunk(main_memory, offset, size) {
                    Ok(chunk) => Ok(chunk),
                    Err(e) => Err(e.into()),
                }
            }
            CanisterSnapshotDataKind::WasmModule { offset, size } => {
                match snapshot.get_wasm_module_chunk(offset, size) {
                    Ok(chunk) => Ok(chunk),
                    Err(e) => Err(e.into()),
                }
            }
            CanisterSnapshotDataKind::WasmChunk { hash } => {
                let Ok(hash) = <WasmChunkHash>::try_from(hash.clone()) else {
                    return Err(CanisterManagerError::WasmChunkStoreError {
                        message: format!("Bytes {hash:02x?} are not a valid WasmChunkHash."),
                    });
                };
                let Some(chunk) = snapshot.chunk_store().get_chunk_complete(&hash) else {
                    return Err(CanisterManagerError::WasmChunkStoreError {
                        message: format!("WasmChunkHash {hash:02x?} not found."),
                    });
                };
                Ok(chunk)
            }
        };
        res.map(ReadCanisterSnapshotDataResponse::new)
    }

    /// Creates a new snapshot based on the provided metadata and returns the new snapshot ID.
    /// The main/stable memory and wasm module are initialized as all-zero blobs of given sizes,
    /// and the wasm chunk store is initialized empty.
    ///
    /// The content of the all-zero blobs has to be uploaded in slices via `write_snapshot_data`.
    ///
    /// The new snapshot's memory size is determined by the metadata, and the canister is charged
    /// for the full snapshot memory usage from the beginning, as if it had the wasm module and
    /// main/stable memories as described in the metadata.
    ///
    /// Note that the new snapshot's memory size can increase later by uploading chunks to the wasm chunk store.
    pub(crate) fn create_snapshot_from_metadata(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
        args: UploadCanisterSnapshotMetadataArgs,
        state: &mut ReplicatedState,
        subnet_size: usize,
        round_limits: &mut RoundLimits,
        resource_saturation: &ResourceSaturation,
    ) -> Result<(SnapshotId, NumInstructions), UserError> {
        // Check sender is a controller.
        validate_controller(canister, &sender)?;
        let canister_id = canister.canister_id();

        // validate args:
        let wasm_mode = canister
            .execution_state
            .as_ref()
            .map(|x| x.wasm_execution_mode)
            .unwrap_or_else(|| WasmExecutionMode::Wasm32);
        let valid_args =
            ValidatedSnapshotMetadata::validate(args.clone(), wasm_mode).map_err(|e| {
                UserError::new(
                    ErrorCode::InvalidManagementPayload,
                    format!("Snapshot Metadata contains invalid data: {e:?}"),
                )
            })?;

        let replace_snapshot_size = match args.replace_snapshot() {
            Some(replace_snapshot_id) => self
                .get_snapshot(canister_id, replace_snapshot_id, state)?
                .size(),
            None => {
                // No replace snapshot ID provided, check whether the maximum number of snapshots
                // has been reached.
                if state
                    .canister_snapshots
                    .count_by_canister(&canister.canister_id())
                    >= self.config.max_number_of_snapshots_per_canister
                {
                    return Err(CanisterManagerError::CanisterSnapshotLimitExceeded {
                        canister_id: canister.canister_id(),
                        limit: self.config.max_number_of_snapshots_per_canister,
                    }
                    .into());
                }
                NumBytes::new(0)
            }
        };

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled
            && canister.scheduler_state.heap_delta_debit >= self.config.heap_delta_rate_limit
        {
            return Err(CanisterManagerError::CanisterHeapDeltaRateLimited {
                canister_id: canister.canister_id(),
                value: canister.scheduler_state.heap_delta_debit,
                limit: self.config.heap_delta_rate_limit,
            }
            .into());
        }

        let new_snapshot_size = args.snapshot_size_bytes();
        let old_memory_usage = canister.memory_usage();
        let new_memory_usage = canister
            .memory_usage()
            .saturating_add(&new_snapshot_size)
            .saturating_sub(&replace_snapshot_size);

        // Compute cycles for instructions spent creating a snapshot of the given size.
        let instructions = self
            .config
            .canister_snapshot_baseline_instructions
            .saturating_add(&new_snapshot_size.get().into());
        let cycles_for_instructions = self.cycles_account_manager.execution_cost(
            instructions,
            subnet_size,
            state.get_own_cost_schedule(),
            // For the `create_snapshot_from_metadata` operation, it does not matter if this is a Wasm64 or Wasm32 module
            // since the number of instructions charged depends on constant set fee and snapshot size
            // and Wasm64 does not bring any additional overhead for this operation.
            // The only overhead is during execution time.
            WasmExecutionMode::Wasm32,
        );

        let validated_cycles_and_memory_usage = self.cycles_and_memory_usage_checks(
            subnet_size,
            state.get_own_cost_schedule(),
            canister,
            sender,
            cycles_for_instructions,
            round_limits,
            new_memory_usage,
            old_memory_usage,
            resource_saturation,
        )?;

        // Delete old snapshot identified by `replace_snapshot`.
        if let Some(replace_snapshot) = args.replace_snapshot() {
            self.remove_snapshot(canister, replace_snapshot, state, replace_snapshot_size);
        }

        // Create new snapshot.
        let new_snapshot = CanisterSnapshot::from_metadata(
            &valid_args,
            state.time(),
            canister.system_state.canister_version,
            Arc::clone(&self.fd_factory),
        );

        self.cycles_and_memory_usage_updates(
            subnet_size,
            state.get_own_cost_schedule(),
            canister,
            sender,
            round_limits,
            validated_cycles_and_memory_usage,
        );

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled {
            canister.scheduler_state.heap_delta_debit = canister
                .scheduler_state
                .heap_delta_debit
                .saturating_add(&new_snapshot.heap_delta());
        }
        state.metadata.heap_delta_estimate = state
            .metadata
            .heap_delta_estimate
            .saturating_add(&new_snapshot.heap_delta());

        let snapshot_id =
            SnapshotId::from((canister.canister_id(), canister.new_local_snapshot_id()));
        state.create_snapshot_from_metadata(snapshot_id, Arc::new(new_snapshot));
        canister.system_state.snapshots_memory_usage = canister
            .system_state
            .snapshots_memory_usage
            .saturating_add(&new_snapshot_size);
        Ok((snapshot_id, instructions))
    }

    /// Writes `args.chunk` to the wasm module, main/stable memory or inserts `args.chunk` to the wasm chunk store.
    /// Fails if the arguments are incompatible with the memory sizes given in the metadata or if the wasm chunk store is already full.
    /// The memory used is already accounted for during `create_snapshot_from_metadata` (except
    /// for the wasm chunk store), but the instructions used to write the data must be taken
    /// into account here in any case.
    pub(crate) fn write_snapshot_data(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
        args: &UploadCanisterSnapshotDataArgs,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
        subnet_size: usize,
        resource_saturation: &ResourceSaturation,
    ) -> Result<NumInstructions, CanisterManagerError> {
        // Check sender is a controller.
        validate_controller(canister, &sender)?;
        let snapshot_id = args.get_snapshot_id();

        let cost_schedule = state.get_own_cost_schedule();
        let snapshot: &mut Arc<CanisterSnapshot> =
            self.get_snapshot_mut(canister.canister_id(), snapshot_id, state)?;

        // Ensure the snapshot was created via metadata upload, not from the canister.
        if snapshot.source() != SnapshotSource::MetadataUpload(candid::Reserved) {
            return Err(CanisterManagerError::CanisterSnapshotImmutable);
        }

        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled
            && canister.scheduler_state.heap_delta_debit >= self.config.heap_delta_rate_limit
        {
            return Err(CanisterManagerError::WasmChunkStoreError {
                message: format!(
                    "Canister is heap delta rate limited. Current delta debit: {}, limit: {}",
                    canister.scheduler_state.heap_delta_debit, self.config.heap_delta_rate_limit
                ),
            });
        }

        // Write data to the appropriate location, as specified by the `CanisterSnapshotDataOffset` variant.
        // Memory has already been reserved by `create_snapshot_from_metadata`,
        // but the instructions used to copy the data still need to be accounted for.
        // Cycles should be charged in any case, because memory is being written.
        let (bytes_written, instructions) = self.get_bytes_and_instructions(args);
        self.cycles_account_manager
            .consume_cycles_for_instructions(
                &sender,
                canister,
                NumInstructions::new(bytes_written),
                subnet_size,
                cost_schedule,
                // It does not matter if this is a Wasm64 or Wasm32 module.
                WasmExecutionMode::Wasm32,
            )
            .map_err(CanisterManagerError::CanisterSnapshotNotEnoughCycles)?;

        let snapshot_inner = Arc::make_mut(snapshot);
        match args.kind {
            CanisterSnapshotDataOffset::WasmModule { offset } => {
                let res = snapshot_inner
                    .execution_snapshot_mut()
                    .wasm_binary
                    .write(&args.chunk, offset as usize);
                if res.is_err() {
                    return Err(CanisterManagerError::InvalidSlice {
                        offset,
                        size: args.chunk.len() as u64,
                    });
                }
            }
            CanisterSnapshotDataOffset::WasmMemory { offset } => {
                let max_size_bytes =
                    snapshot_inner.wasm_memory().size.get() * WASM_PAGE_SIZE_IN_BYTES;
                if max_size_bytes < args.chunk.len().saturating_add(offset as usize) {
                    return Err(CanisterManagerError::InvalidSlice {
                        offset,
                        size: args.chunk.len() as u64,
                    });
                }
                let mut buffer = Buffer::new(snapshot_inner.wasm_memory().page_map.clone());
                buffer.write(&args.chunk, offset as usize);
                let delta = buffer.dirty_pages().collect::<Vec<_>>();
                snapshot_inner.wasm_memory_mut().page_map.update(&delta);
            }
            CanisterSnapshotDataOffset::StableMemory { offset } => {
                let max_size_bytes =
                    snapshot_inner.stable_memory().size.get() * WASM_PAGE_SIZE_IN_BYTES;
                if max_size_bytes < args.chunk.len().saturating_add(offset as usize) {
                    return Err(CanisterManagerError::InvalidSlice {
                        offset,
                        size: args.chunk.len() as u64,
                    });
                }
                let mut buffer = Buffer::new(snapshot_inner.stable_memory().page_map.clone());
                buffer.write(&args.chunk, offset as usize);
                let delta = buffer.dirty_pages().collect::<Vec<_>>();
                snapshot_inner.stable_memory_mut().page_map.update(&delta);
            }
            CanisterSnapshotDataOffset::WasmChunk => {
                // The chunk store is initialized as empty, and no memory for it has been reserved yet.
                // So we check and charge for the extra memory here.
                let validated_chunk = match snapshot_inner
                    .chunk_store_mut()
                    .can_insert_chunk(self.config.wasm_chunk_store_max_size, args.chunk.clone())
                {
                    ChunkValidationResult::Insert(validated_chunk) => validated_chunk,
                    ChunkValidationResult::AlreadyExists(_hash) => {
                        return Ok(NumInstructions::new(0));
                    }
                    ChunkValidationResult::ValidationError(err) => {
                        return Err(CanisterManagerError::WasmChunkStoreError { message: err });
                    }
                };

                let memory_usage = canister.memory_usage();
                let chunk_bytes = wasm_chunk_store::chunk_size();
                let new_memory_usage = canister.memory_usage() + chunk_bytes;
                let validated_cycles_and_memory_usage = self.cycles_and_memory_usage_checks(
                    subnet_size,
                    state.get_own_cost_schedule(),
                    canister,
                    sender,
                    Cycles::zero(),
                    round_limits,
                    new_memory_usage,
                    memory_usage,
                    resource_saturation,
                )?;
                self.cycles_and_memory_usage_updates(
                    subnet_size,
                    state.get_own_cost_schedule(),
                    canister,
                    sender,
                    round_limits,
                    validated_cycles_and_memory_usage,
                );

                if let Err(()) = state
                    .canister_snapshots
                    .insert_chunk(snapshot_id, validated_chunk)
                {
                    error!(
                        self.log,
                        "Snapshot {} not found after validation. This is a bug@write_snapshot_data",
                        snapshot_id
                    )
                }

                canister.system_state.snapshots_memory_usage = canister
                    .system_state
                    .snapshots_memory_usage
                    .saturating_add(&chunk_bytes);
            }
        };
        if self.config.rate_limiting_of_heap_delta == FlagStatus::Enabled {
            canister.scheduler_state.heap_delta_debit += NumBytes::new(bytes_written);
        }
        round_limits.instructions -= as_round_instructions(instructions);

        // Return the instructions needed to write the chunk to the destination.
        Ok(instructions)
    }

    /// Remove the specified snapshot and increase the subnet's available memory.
    fn remove_snapshot(
        &self,
        canister: &mut CanisterState,
        snapshot_id: SnapshotId,
        state: &mut ReplicatedState,
        snapshot_size: NumBytes,
    ) {
        // Delete old snapshot identified by `snapshot_id`.
        state.canister_snapshots.remove(snapshot_id);
        canister.system_state.snapshots_memory_usage = canister
            .system_state
            .snapshots_memory_usage
            .get()
            .saturating_sub(snapshot_size.get())
            .into();
        // Confirm that `snapshots_memory_usage` is updated correctly.
        debug_assert_eq!(
            canister.system_state.snapshots_memory_usage,
            state
                .canister_snapshots
                .compute_memory_usage_by_canister(canister.canister_id()),
        );
    }

    /// Returns the cycles and instructions that should be charged for this data upload operation.
    fn get_bytes_and_instructions(
        &self,
        args: &UploadCanisterSnapshotDataArgs,
    ) -> (u64, NumInstructions) {
        match args.kind {
            CanisterSnapshotDataOffset::WasmModule { .. } => (
                args.chunk.len() as u64,
                NumInstructions::new(args.chunk.len() as u64),
            ),
            CanisterSnapshotDataOffset::WasmMemory { .. } => (
                args.chunk.len() as u64,
                NumInstructions::new(args.chunk.len() as u64),
            ),
            CanisterSnapshotDataOffset::StableMemory { .. } => (
                args.chunk.len() as u64,
                NumInstructions::new(args.chunk.len() as u64),
            ),
            CanisterSnapshotDataOffset::WasmChunk => (
                wasm_chunk_store::chunk_size().get(),
                self.config.upload_wasm_chunk_instructions,
            ),
        }
    }

    /// Renames the canister from `old_id` to `new_id` and adds the appropriate entry into the canister history.
    pub(crate) fn rename_canister(
        &self,
        sender: PrincipalId,
        canister: &mut CanisterState,
        origin: CanisterChangeOrigin,
        old_id: CanisterId,
        new_id: CanisterId,
        to_version: u64,
        to_total_num_changes: u64,
        requested_by: PrincipalId,
        state: &mut ReplicatedState,
        round_limits: &mut RoundLimits,
    ) -> Result<(), CanisterManagerError> {
        // In addition to this endpoint only being available from the NNS subnet, the calling canister
        // has to be a controller of the canister to be renamed.
        validate_controller(canister, &sender)?;

        // Only the migration orchestrator should be able to be the sender.
        if sender != MIGRATION_CANISTER_ID.into() {
            return Err(CanisterManagerError::CallerNotAuthorized);
        }

        if state.canister_state(&new_id).is_some() {
            return Err(CanisterManagerError::CanisterAlreadyExists(new_id));
        }

        if canister.status() != CanisterStatusType::Stopped {
            return Err(CanisterManagerError::RenameCanisterNotStopped(old_id));
        }

        if state.canister_snapshots.count_by_canister(&old_id) > 0 {
            return Err(CanisterManagerError::RenameCanisterHasSnapshot(old_id));
        }

        canister.system_state.canister_id = new_id;
        let old_total_num_changes = canister
            .system_state
            .get_canister_history()
            .get_total_num_changes();
        // Renaming canisters overwrites the total length of the canister history to the original canister's value.
        // The canister version is bumped to be monotone w.r.t. both the original and new values.
        canister
            .system_state
            .set_canister_history_total_num_changes(to_total_num_changes);
        let old_version = canister.system_state.canister_version;
        canister.system_state.canister_version = std::cmp::max(old_version, to_version) + 1;
        let available_execution_memory_change = canister.add_canister_change(
            state.time(),
            origin,
            CanisterChangeDetails::rename_canister(
                old_id.into(),
                old_total_num_changes,
                new_id.into(),
                to_version,
                to_total_num_changes,
                requested_by,
            ),
        );
        round_limits
            .subnet_available_memory
            .update_execution_memory_unchecked(available_execution_memory_change);

        if let Some(execution_state) = canister.execution_state.as_mut() {
            execution_state.wasm_memory.sandbox_memory = SandboxMemory::new();
            execution_state.stable_memory.sandbox_memory = SandboxMemory::new();
            execution_state.wasm_binary.clear_compilation_cache();
        }

        state
            .metadata
            .unflushed_checkpoint_ops
            .rename_canister(old_id, new_id);

        Ok(())
    }
}

fn get_response_size(kind: &CanisterSnapshotDataKind) -> Result<u64, CanisterManagerError> {
    let size = match kind {
        CanisterSnapshotDataKind::WasmModule { size, .. } => *size,
        CanisterSnapshotDataKind::WasmMemory { size, .. } => *size,
        CanisterSnapshotDataKind::StableMemory { size, .. } => *size,
        CanisterSnapshotDataKind::WasmChunk { .. } => return Ok(CHUNK_SIZE),
    };
    if size > MAX_SLICE_SIZE_BYTES {
        return Err(CanisterManagerError::SliceTooLarge {
            requested: size,
            allowed: MAX_SLICE_SIZE_BYTES,
        });
    }
    Ok(size)
}

/// Uninstalls a canister.
///
/// See https://internetcomputer.org/docs/current/references/ic-interface-spec#ic-uninstall_code
///
/// Returns a list of rejects that need to be sent out to their callers.
#[doc(hidden)]
#[must_use]
pub fn uninstall_canister(
    log: &ReplicaLogger,
    canister: &mut CanisterState,
    round_limits: Option<&mut RoundLimits>,
    time: Time,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Vec<Response> {
    let old_allocated_bytes = canister.memory_allocated_bytes();

    // Drop the canister's execution state.
    canister.execution_state = None;

    // Clear log.
    canister.system_state.canister_log.clear();
    canister
        .system_state
        .log_memory_store
        .clear(fd_factory.clone());

    // Clear the Wasm chunk store.
    canister.system_state.wasm_chunk_store = WasmChunkStore::new(fd_factory);

    // Drop its certified data.
    canister.system_state.certified_data = Vec::new();

    // Deactivate global timer.
    canister.system_state.global_timer = CanisterTimer::Inactive;
    // Increment canister version.
    canister.system_state.canister_version += 1;

    let new_allocated_bytes = canister.memory_allocated_bytes();
    debug_assert!(new_allocated_bytes <= old_allocated_bytes);

    if let Some(round_limits) = round_limits {
        let deallocated_bytes = old_allocated_bytes.saturating_sub(&new_allocated_bytes);
        round_limits.subnet_available_memory.increment(
            deallocated_bytes,
            NumBytes::from(0),
            NumBytes::from(0),
        );
    }

    let canister_id = canister.canister_id();

    canister
        .system_state
        .delete_all_call_contexts(|call_context| {
            // Generate reject responses for ingress and canister messages.
            match call_context.call_origin() {
                CallOrigin::Ingress(user_id, message_id, _method_name) => {
                    Some(Response::Ingress(IngressResponse {
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
                    }))
                }
                CallOrigin::CanisterUpdate(
                    caller_canister_id,
                    callback_id,
                    deadline,
                    _method_name,
                ) => Some(Response::Canister(CanisterResponse {
                    originator: *caller_canister_id,
                    respondent: canister_id,
                    originator_reply_callback: *callback_id,
                    refund: call_context.available_cycles(),
                    response_payload: Payload::Reject(RejectContext::new(
                        RejectCode::CanisterReject,
                        "Canister has been uninstalled.",
                    )),
                    deadline: *deadline,
                })),
                CallOrigin::CanisterQuery(..) | CallOrigin::Query(..) => fatal!(
                    log,
                    "No callbacks with a query origin should be found when uninstalling"
                ),
                CallOrigin::SystemTask => {
                    // Cannot respond to system tasks. Nothing to do.
                    None
                }
            }
        })
}

fn globals_match(g1: &[Global], g2: &[Global]) -> bool {
    use std::mem::discriminant;
    if g1.len() != g2.len() {
        return false;
    }
    zip(g1.iter(), g2.iter()).all(|(a, b)| discriminant(a) == discriminant(b))
}

#[cfg(test)]
pub(crate) mod tests;
