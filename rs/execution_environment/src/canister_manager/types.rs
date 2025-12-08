use crate::execution_environment::{RoundContext, RoundLimits};
use ic_base_types::NumSeconds;
use ic_config::flag_status::FlagStatus;
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::{CanisterOutOfCyclesError, HypervisorError};
use ic_logger::ReplicaLogger;
use ic_management_canister_types_private::{
    CanisterChangeOrigin, CanisterInstallModeV2, InstallChunkedCodeArgs, InstallCodeArgsV2,
    UploadChunkReply,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    CanisterState,
    canister_snapshots::CanisterSnapshotError,
    canister_state::system_state::wasm_chunk_store::{WasmChunkStore, chunk_size},
    metadata_state::subnet_call_context_manager::InstallCodeCallId,
};
use ic_types::{
    CanisterId, ComputeAllocation, Cycles, MemoryAllocation, NumBytes, NumInstructions,
    PrincipalId, SnapshotId, SubnetId,
    ingress::IngressStatus,
    messages::{CanisterCall, MessageId, RejectContext},
};
use ic_wasm_types::{AsErrorHelp, CanisterModule, ErrorHelp, WasmHash, doc_ref};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::MAX_SLICE_SIZE_BYTES;

#[derive(Eq, PartialEq, Debug)]
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
/// * If execution did not complete, then the result contains the old canister state,
///   with some changes such reservation of execution cycles and a continuation.
#[derive(Debug)]
pub(crate) enum DtsInstallCodeResult {
    Finished {
        canister: CanisterState,
        message: CanisterCall,
        call_id: InstallCodeCallId,
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
#[derive(Eq, PartialEq, Debug)]
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

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub(crate) struct CanisterMgrConfig {
    pub(crate) subnet_memory_capacity: NumBytes,
    pub(crate) default_provisional_cycles_balance: Cycles,
    pub(crate) default_freeze_threshold: NumSeconds,
    pub(crate) compute_capacity: u64,
    pub(crate) own_subnet_id: SubnetId,
    pub(crate) own_subnet_type: SubnetType,
    pub(crate) max_controllers: usize,
    pub(crate) rate_limiting_of_instructions: FlagStatus,
    pub(crate) rate_limiting_of_heap_delta: FlagStatus,
    pub(crate) heap_delta_rate_limit: NumBytes,
    pub(crate) upload_wasm_chunk_instructions: NumInstructions,
    pub(crate) wasm_chunk_store_max_size: NumBytes,
    pub(crate) canister_snapshot_baseline_instructions: NumInstructions,
    pub(crate) canister_snapshot_data_baseline_instructions: NumInstructions,
    pub(crate) default_wasm_memory_limit: NumBytes,
    pub(crate) max_number_of_snapshots_per_canister: usize,
    pub(crate) max_environment_variables: usize,
    pub(crate) max_environment_variable_name_length: usize,
    pub(crate) max_environment_variable_value_length: usize,
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
        rate_limiting_of_heap_delta: FlagStatus,
        heap_delta_rate_limit: NumBytes,
        upload_wasm_chunk_instructions: NumInstructions,
        wasm_chunk_store_max_size: NumBytes,
        canister_snapshot_baseline_instructions: NumInstructions,
        canister_snapshot_data_baseline_instructions: NumInstructions,
        default_wasm_memory_limit: NumBytes,
        max_number_of_snapshots_per_canister: usize,
        max_environment_variables: usize,
        max_environment_variable_name_length: usize,
        max_environment_variable_value_length: usize,
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
            rate_limiting_of_heap_delta,
            heap_delta_rate_limit,
            upload_wasm_chunk_instructions,
            wasm_chunk_store_max_size,
            canister_snapshot_baseline_instructions,
            canister_snapshot_data_baseline_instructions,
            default_wasm_memory_limit,
            max_number_of_snapshots_per_canister,
            max_environment_variables,
            max_environment_variable_name_length,
            max_environment_variable_value_length,
        }
    }
}

#[derive(Clone, Debug)]
pub enum WasmSource {
    CanisterModule(CanisterModule),
    ChunkStore {
        wasm_chunk_store: WasmChunkStore,
        chunk_hashes_list: Vec<Vec<u8>>,
        wasm_module_hash: WasmHash,
    },
}

impl From<&WasmSource> for WasmHash {
    fn from(item: &WasmSource) -> Self {
        match item {
            WasmSource::CanisterModule(canister_module) => {
                Self::from(canister_module.module_hash())
            }
            WasmSource::ChunkStore {
                wasm_module_hash, ..
            } => wasm_module_hash.clone(),
        }
    }
}

impl WasmSource {
    pub fn module_hash(&self) -> [u8; 32] {
        WasmHash::from(self).to_slice()
    }

    /// The number of instructions to be charged each time we try to convert to
    /// a canister module.
    pub fn instructions_to_assemble(&self) -> NumInstructions {
        match self {
            Self::CanisterModule(_module) => NumInstructions::from(0),
            // Charge one instruction per byte, assuming each chunk is the
            // maximum size.
            Self::ChunkStore {
                chunk_hashes_list, ..
            } => NumInstructions::from((chunk_size() * chunk_hashes_list.len() as u64).get()),
        }
    }

    /// Convert the source to a canister module (assembling chunks if required).
    pub(crate) fn into_canister_module(self) -> Result<CanisterModule, CanisterManagerError> {
        match self {
            Self::CanisterModule(module) => Ok(module),
            Self::ChunkStore {
                wasm_chunk_store,
                chunk_hashes_list,
                wasm_module_hash,
            } => {
                // Assume each chunk uses the full chunk size even though the actual
                // size might be smaller.
                let mut wasm_module =
                    Vec::with_capacity(chunk_hashes_list.len() * chunk_size().get() as usize);
                for hash in chunk_hashes_list {
                    let hash = hash.as_slice().try_into().map_err(|_| {
                        CanisterManagerError::WasmChunkStoreError {
                            message: "Chunk hash is invalid. The length is not 32".to_string(),
                        }
                    })?;
                    for page in wasm_chunk_store.get_chunk_data(&hash).ok_or_else(|| {
                        CanisterManagerError::WasmChunkStoreError {
                            message: format!("Chunk hash {:?} was not found", &hash[..32]),
                        }
                    })? {
                        wasm_module.extend_from_slice(page)
                    }
                }
                let canister_module = CanisterModule::new(wasm_module);

                if canister_module.module_hash()[..] != wasm_module_hash.to_slice() {
                    return Err(CanisterManagerError::WasmChunkStoreError {
                        message: format!(
                            "Wasm module hash {:?} does not match given hash {:?}",
                            canister_module.module_hash(),
                            wasm_module_hash
                        ),
                    });
                }
                Ok(canister_module)
            }
        }
    }

    #[allow(dead_code)]
    /// Only used for tests.
    pub(crate) fn unwrap_as_slice_for_testing(&self) -> &[u8] {
        match self {
            Self::CanisterModule(module) => module.as_slice(),
            Self::ChunkStore { .. } => panic!("Can't convert WasmSource::ChunkStore to slice"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct InstallCodeContext {
    pub origin: CanisterChangeOrigin,
    pub mode: CanisterInstallModeV2,
    pub canister_id: CanisterId,
    pub wasm_source: WasmSource,
    pub arg: Vec<u8>,
}

impl InstallCodeContext {
    pub fn sender(&self) -> PrincipalId {
        self.origin.origin()
    }
}

/// Errors that can occur when converting from (sender, [`InstallCodeArgsV2`]) to
/// an [`InstallCodeContext`].
#[derive(Debug)]
pub enum InstallCodeContextError {
    InvalidHash(String),
}

impl From<InstallCodeContextError> for UserError {
    fn from(err: InstallCodeContextError) -> Self {
        match err {
            InstallCodeContextError::InvalidHash(err) => {
                UserError::new(ErrorCode::CanisterContractViolation, err)
            }
        }
    }
}

impl InstallCodeContext {
    pub(crate) fn chunked_install(
        origin: CanisterChangeOrigin,
        args: InstallChunkedCodeArgs,
        store: &WasmChunkStore,
    ) -> Result<Self, InstallCodeContextError> {
        let canister_id = args.target_canister_id();
        let wasm_module_hash = args.wasm_module_hash.try_into().map_err(|hash| {
            InstallCodeContextError::InvalidHash(format!("Invalid wasm hash {hash:?}"))
        })?;
        Ok(InstallCodeContext {
            origin,
            mode: args.mode,
            canister_id,
            wasm_source: WasmSource::ChunkStore {
                wasm_chunk_store: store.clone(),
                chunk_hashes_list: args
                    .chunk_hashes_list
                    .into_iter()
                    .map(|h| h.hash.to_vec())
                    .collect(),
                wasm_module_hash,
            },
            arg: args.arg,
        })
    }
}

impl TryFrom<(CanisterChangeOrigin, InstallCodeArgsV2)> for InstallCodeContext {
    type Error = InstallCodeContextError;

    fn try_from(input: (CanisterChangeOrigin, InstallCodeArgsV2)) -> Result<Self, Self::Error> {
        let (origin, args) = input;
        let canister_id = CanisterId::unchecked_from_principal(args.canister_id);

        Ok(InstallCodeContext {
            origin,
            mode: args.mode,
            canister_id,
            wasm_source: WasmSource::CanisterModule(CanisterModule::new(args.wasm_module)),
            arg: args.arg,
        })
    }
}

pub(crate) struct UploadChunkResult {
    pub(crate) reply: UploadChunkReply,
    pub(crate) heap_delta_increase: NumBytes,
}

#[derive(Eq, PartialEq, Debug)]
pub(crate) enum CanisterManagerError {
    CanisterInvalidController {
        canister_id: CanisterId,
        controllers_expected: BTreeSet<PrincipalId>,
        controller_provided: PrincipalId,
    },
    CallerNotAuthorized,
    CanisterAlreadyExists(CanisterId),
    CanisterIdAlreadyExists(CanisterId),
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
    SubnetWasmCustomSectionCapacityOverSubscribed {
        requested: NumBytes,
        available: NumBytes,
    },
    Hypervisor(CanisterId, HypervisorError),
    DeleteCanisterNotStopped(CanisterId),
    DeleteCanisterSelf(CanisterId),
    DeleteCanisterQueueNotEmpty(CanisterId),
    SenderNotInWhitelist(PrincipalId),
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
    InsufficientCyclesInComputeAllocation {
        compute_allocation: ComputeAllocation,
        available: Cycles,
        threshold: Cycles,
    },
    InsufficientCyclesInMemoryAllocation {
        memory_allocation: MemoryAllocation,
        available: Cycles,
        threshold: Cycles,
    },
    InsufficientCyclesInMemoryGrow {
        bytes: NumBytes,
        available: Cycles,
        required: Cycles,
    },
    ReservedCyclesLimitExceededInMemoryAllocation {
        memory_allocation: MemoryAllocation,
        requested: Cycles,
        limit: Cycles,
    },
    ReservedCyclesLimitExceededInMemoryGrow {
        bytes: NumBytes,
        requested: Cycles,
        limit: Cycles,
    },
    ReservedCyclesLimitIsTooLow {
        cycles: Cycles,
        limit: Cycles,
    },
    WasmChunkStoreError {
        message: String,
    },
    CanisterSnapshotNotFound {
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
    },
    CanisterHeapDeltaRateLimited {
        canister_id: CanisterId,
        value: NumBytes,
        limit: NumBytes,
    },
    CanisterSnapshotInvalidOwnership {
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
    },
    CanisterSnapshotNotController {
        sender: PrincipalId,
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
    },
    CanisterSnapshotNotLoadable {
        canister_id: CanisterId,
        snapshot_id: SnapshotId,
    },
    CanisterSnapshotExecutionStateNotFound {
        canister_id: CanisterId,
    },
    CanisterSnapshotLimitExceeded {
        canister_id: CanisterId,
        limit: usize,
    },
    CanisterSnapshotNotEnoughCycles(CanisterOutOfCyclesError),
    CanisterSnapshotImmutable,
    CanisterSnapshotInconsistent {
        message: String,
    },
    LongExecutionAlreadyInProgress {
        canister_id: CanisterId,
    },
    MissingUpgradeOptionError {
        message: String,
    },
    InvalidUpgradeOptionError {
        message: String,
    },
    InvalidSlice {
        offset: u64,
        size: u64,
    },
    SliceTooLarge {
        requested: u64,
        allowed: u64,
    },
    InvalidSpecifiedId {
        specified_id: CanisterId,
    },
    RenameCanisterNotStopped(CanisterId),
    RenameCanisterHasSnapshot(CanisterId),
    EnvironmentVariablesTooMany {
        max: usize,
        count: usize,
    },
    EnvironmentVariablesNameTooLong {
        name: String,
        max_name_length: usize,
    },
    EnvironmentVariablesValueTooLong {
        value: String,
        max_value_length: usize,
    },
    CanisterMetadataNoWasmModule {
        canister_id: CanisterId,
    },
    CanisterMetadataSectionNotFound {
        canister_id: CanisterId,
        section_name: String,
    },
    CanisterLogMemoryLimitIsTooLow {
        bytes: NumBytes,
        limit: NumBytes,
    },
    CanisterLogMemoryLimitIsTooHigh {
        bytes: NumBytes,
        limit: NumBytes,
    },
}

impl AsErrorHelp for CanisterManagerError {
    fn error_help(&self) -> ErrorHelp {
        match self {
            CanisterManagerError::Hypervisor(_, hypervisor_err) => hypervisor_err.error_help(),
            CanisterManagerError::CanisterAlreadyExists(_)
            | CanisterManagerError::CanisterIdAlreadyExists(_)
            | CanisterManagerError::InvalidSenderSubnet(_)
            | CanisterManagerError::SenderNotInWhitelist(_)
            | CanisterManagerError::CanisterNotHostedBySubnet { .. } => ErrorHelp::InternalError,
            CanisterManagerError::CanisterInvalidController { .. } => ErrorHelp::UserError {
                suggestion: "Execute this call from a controller of the target canister or \
                add the current caller as a controller."
                    .to_string(),
                doc_link: doc_ref("invalid-controller"),
            },
            CanisterManagerError::CanisterNotFound(_) => ErrorHelp::UserError {
                suggestion: "Check the ICP dashboard to ensure the canister exists.".to_string(),
                doc_link: doc_ref("canister-not-found"),
            },
            CanisterManagerError::CanisterNonEmpty(_) => ErrorHelp::UserError {
                suggestion: "Check that you want to overwrite the canister and, if so, \
                use mode='reinstall'."
                    .to_string(),
                doc_link: doc_ref("canister-not-empty"),
            },
            CanisterManagerError::SubnetComputeCapacityOverSubscribed { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Try moving to another subnet.".to_string(),
                    doc_link: doc_ref("subnet-compute-capacity-oversubscribed"),
                }
            }
            CanisterManagerError::SubnetMemoryCapacityOverSubscribed { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Try moving to another subnet.".to_string(),
                    doc_link: doc_ref("subnet-memory-capacity-oversubscribed"),
                }
            }
            CanisterManagerError::SubnetWasmCustomSectionCapacityOverSubscribed { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Try removing custom sections using a tool like `wasm-strip` \
                    or moving to another subnet."
                        .to_string(),
                    doc_link: doc_ref("subnet-custom-section-memory-capacity-oversubscribed"),
                }
            }
            CanisterManagerError::DeleteCanisterNotStopped(_) => ErrorHelp::UserError {
                suggestion: "Stop the canister before deleting it.".to_string(),
                doc_link: doc_ref("delete-canister-not-stopped"),
            },
            CanisterManagerError::DeleteCanisterSelf(_) => ErrorHelp::UserError {
                suggestion: "Delete the canister from one of its other controllers.".to_string(),
                doc_link: doc_ref("delete-canister-self"),
            },
            CanisterManagerError::DeleteCanisterQueueNotEmpty(_) => ErrorHelp::UserError {
                suggestion: "Wait until the queues have been cleared to delete the canister and \
                in the meantime stop the canister."
                    .to_string(),
                doc_link: doc_ref("delete-canister-queue-not-empty"),
            },
            CanisterManagerError::CreateCanisterNotEnoughCycles { .. } => ErrorHelp::UserError {
                suggestion: "Try sending more cycles with the request.".to_string(),
                doc_link: doc_ref("create-canister-not-enough-cycles"),
            },
            CanisterManagerError::InstallCodeNotEnoughCycles(_) => ErrorHelp::UserError {
                suggestion: "Top up the canister with more cycles.".to_string(),
                doc_link: doc_ref("install-code-not-enough-cycles"),
            },
            CanisterManagerError::InstallCodeRateLimited(_) => ErrorHelp::UserError {
                suggestion: "Retry the installation at a later time.".to_string(),
                doc_link: doc_ref("install-code-rate-limited"),
            },
            CanisterManagerError::SubnetOutOfCanisterIds => ErrorHelp::UserError {
                suggestion: "Try creating the canister on another subnet.".to_string(),
                doc_link: doc_ref("subnet-out-of-canister-ids"),
            },
            CanisterManagerError::InvalidSettings { .. } => ErrorHelp::UserError {
                suggestion: "Apply the described changes to make the settings valid.".to_string(),
                doc_link: doc_ref("invalid-settings"),
            },
            CanisterManagerError::MaxNumberOfCanistersReached { .. } => ErrorHelp::UserError {
                suggestion: "Try creating the canister on another subnet.".to_string(),
                doc_link: doc_ref("maximum-number-of-canisters-reached"),
            },
            CanisterManagerError::InsufficientCyclesInComputeAllocation { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Top up the canister with more cycles.".to_string(),
                    doc_link: doc_ref("insufficient-cycles-in-compute-allocation"),
                }
            }
            CanisterManagerError::InsufficientCyclesInMemoryAllocation { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Top up the canister with more cycles.".to_string(),
                    doc_link: doc_ref("insufficient-cycles-in-memory-allocation"),
                }
            }
            CanisterManagerError::InsufficientCyclesInMemoryGrow { .. } => ErrorHelp::UserError {
                suggestion: "Top up the canister with more cycles.".to_string(),
                doc_link: doc_ref("insufficient-cycles-in-memory-grow-1"),
            },
            CanisterManagerError::ReservedCyclesLimitExceededInMemoryAllocation { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Try increasing this canister's reserved cycles limit or moving \
                    it to a subnet with lower memory usage."
                        .to_string(),
                    doc_link: doc_ref("reserved-cycles-limit-exceeded-in-memory-allocation"),
                }
            }
            CanisterManagerError::ReservedCyclesLimitExceededInMemoryGrow { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Try increasing this canister's reserved cycles limit or moving \
                    it to a subnet with lower memory usage."
                        .to_string(),
                    doc_link: doc_ref("reserved-cycles-limit-exceeded-in-memory-grow"),
                }
            }
            CanisterManagerError::ReservedCyclesLimitIsTooLow { .. } => ErrorHelp::UserError {
                suggestion: "Set the reserved cycles limit in the canister settings to a value that is at least the current reserved cycles balance.".to_string(),
                doc_link: "reserved-cycles-limit-is-too-low".to_string(),
            },
            CanisterManagerError::WasmChunkStoreError { .. } => ErrorHelp::UserError {
                suggestion: "Use the `stored_chunks` API to check which hashes are present \
                or top up the canister if it is low on cycles."
                    .to_string(),
                doc_link: doc_ref("wasm-chunk-store-error"),
            },
            CanisterManagerError::CanisterSnapshotNotFound { .. } => ErrorHelp::UserError {
                suggestion:
                    "Use the `list_canister_snapshot` API to see which snapshots are present."
                        .to_string(),
                doc_link: doc_ref("canister-snapshot-not-found"),
            },
            CanisterManagerError::CanisterHeapDeltaRateLimited { .. } => ErrorHelp::UserError {
                suggestion: "Try waiting a few seconds before retrying the operation.".to_string(),
                doc_link: doc_ref("canister-heap-delta-rate-limited"),
            },
            CanisterManagerError::CanisterSnapshotInvalidOwnership { .. } => ErrorHelp::UserError {
                suggestion:
                    "Use the `list_canister_snapshot` API to see which snapshots are present."
                        .to_string(),
                doc_link: doc_ref("canister-snapshot-invalid-ownership"),
            },
            CanisterManagerError::CanisterSnapshotNotController { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Make sure you are a controller of the canister that the snapshot belongs to."
                        .to_string(),
                    doc_link: "canister-snapshot-not-controller".to_string(),
                }
            }
            CanisterManagerError::CanisterSnapshotNotLoadable { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Snapshot is not currently loadable on the specified canister. Try again later. The call should succeed if you wait sufficiently long (usually ten minutes)."
                        .to_string(),
                    doc_link: "canister-snapshot-not-loadable".to_string(),
                }
            }
            CanisterManagerError::CanisterSnapshotExecutionStateNotFound { .. } => {
                ErrorHelp::UserError {
                    suggestion: "".to_string(),
                    doc_link: "".to_string(),
                }
            }
            CanisterManagerError::CanisterSnapshotLimitExceeded { .. } => ErrorHelp::UserError {
                suggestion: "Consider deleting an unnecessary snapshot of the specified canister before creating a new one.".to_string(),
                doc_link: "canister-snapshot-limit-exceeded".to_string(),
            },
            CanisterManagerError::CanisterSnapshotNotEnoughCycles { .. } => ErrorHelp::UserError {
                suggestion: "Try sending more cycles with the request.".to_string(),
                doc_link: "canister-snapshot-not-enough-cycles".to_string(),
            },
            CanisterManagerError::CanisterSnapshotImmutable => ErrorHelp::UserError {
                suggestion: "Only canister snapshots created by metadata upload can be mutated.".to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::LongExecutionAlreadyInProgress { .. } => ErrorHelp::UserError {
                suggestion: "Try waiting for the long execution to complete.".to_string(),
                doc_link: doc_ref("long-execution-already-in-progress"),
            },
            CanisterManagerError::MissingUpgradeOptionError { .. } => ErrorHelp::UserError {
                suggestion: "Try resending the message with the required fields included."
                    .to_string(),
                doc_link: doc_ref("missing-upgrade-option"),
            },
            CanisterManagerError::InvalidUpgradeOptionError { .. } => ErrorHelp::UserError {
                suggestion:
                    "Try resending the message after omitting or modifying the invalid options."
                        .to_string(),
                doc_link: doc_ref("invalid-upgrade-option"),
            },
            CanisterManagerError::InvalidSlice { .. } => ErrorHelp::UserError {
                suggestion:
                    "Use the snapshot metadata API to learn the size of the wasm module / main memory / stable memory."
                        .to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::SliceTooLarge { .. } => ErrorHelp::UserError {
                suggestion: format!("Use a slice size at most {MAX_SLICE_SIZE_BYTES}"),
                doc_link: "".to_string(),
            },
            CanisterManagerError::InvalidSpecifiedId { .. } => ErrorHelp::UserError {
                suggestion: "Use a `specified_id` that matches a canister ID on the ICP mainnet and a test environment that supports canister creation with `specified_id` (e.g., PocketIC).".to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::CanisterSnapshotInconsistent { .. } => ErrorHelp::UserError {
                suggestion: "Make sure to upload a complete and valid snapshot. Compare with snapshot metadata from the endpoint `read_canister_snapshot_metadata`".to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::RenameCanisterNotStopped { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Stop the canister before renaming.".to_string(),
                    doc_link: "".to_string(),
                }
            },
            CanisterManagerError::RenameCanisterHasSnapshot { .. } => {
                ErrorHelp::UserError {
                    suggestion: "Delete all snapshots before renaming.".to_string(),
                    doc_link: "".to_string(),
                }
            },
            CanisterManagerError::EnvironmentVariablesTooMany { .. } => ErrorHelp::UserError {
                suggestion: "Try reducing the number of environment variables.".to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::EnvironmentVariablesNameTooLong { .. } => ErrorHelp::UserError {
                suggestion: "Shorten the environment variable name to fit within the allowed limit.".to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::EnvironmentVariablesValueTooLong { .. } => ErrorHelp::UserError {
                suggestion: "Shorten the environment variable value to fit within the allowed limit.".to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::CanisterMetadataNoWasmModule { .. } => ErrorHelp::UserError {
                suggestion: "If you are a controller of the canister, install a Wasm module containing a metadata section with the given name.".to_string(),
                doc_link: "canister-metadata-no-wasm-module".to_string(),
            },
            CanisterManagerError::CanisterMetadataSectionNotFound { .. } => ErrorHelp::UserError {
                suggestion: "If you are a controller of the canister, install a Wasm module containing a metadata section with the given name.".to_string(),
                doc_link: "canister-metadata-section-not-found".to_string(),
            },
            CanisterManagerError::CallerNotAuthorized => ErrorHelp::UserError {
                suggestion: "The caller is not authorized to call this method.".to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::CanisterLogMemoryLimitIsTooLow { .. } => ErrorHelp::UserError {
                suggestion: "Set a higher canister log memory limit.".to_string(),
                doc_link: "".to_string(),
            },
            CanisterManagerError::CanisterLogMemoryLimitIsTooHigh { .. } => ErrorHelp::UserError {
                suggestion: "Set a lower canister log memory limit.".to_string(),
                doc_link: "".to_string(),
            },
        }
    }
}

impl From<CanisterManagerError> for UserError {
    fn from(err: CanisterManagerError) -> Self {
        use CanisterManagerError::*;

        let error_help = err.error_help().to_string();
        let additional_help = if !error_help.is_empty() {
            format!("\n{error_help}")
        } else {
            "".to_string()
        };

        match err {
            CanisterAlreadyExists(canister_id) => Self::new(
                ErrorCode::CanisterAlreadyInstalled,
                format!("Canister {canister_id} is already installed.{additional_help}"),
            ),
            SubnetComputeCapacityOverSubscribed {
                requested,
                available,
            } => Self::new(
                ErrorCode::SubnetOversubscribed,
                format!(
                    "Canister requested a compute allocation of {requested} which cannot be satisfied because the Subnet's remaining compute capacity is {available}%.{additional_help}"
                ),
            ),
            CanisterNotFound(canister_id) => Self::new(
                ErrorCode::CanisterNotFound,
                format!("Canister {} not found.{additional_help}", &canister_id),
            ),
            CanisterIdAlreadyExists(canister_id) => Self::new(
                ErrorCode::CanisterIdAlreadyExists,
                format!(
                    "Unsuccessful canister creation: canister id {canister_id} already exists.{additional_help}"
                ),
            ),
            Hypervisor(canister_id, err) => err.into_user_error(&canister_id),
            SubnetMemoryCapacityOverSubscribed {
                requested,
                available,
            } => Self::new(
                ErrorCode::SubnetOversubscribed,
                format!(
                    "Canister requested {} of memory but only {} are available in the subnet.{additional_help}",
                    requested.display(),
                    available.display(),
                ),
            ),
            SubnetWasmCustomSectionCapacityOverSubscribed {
                requested,
                available,
            } => Self::new(
                ErrorCode::SubnetOversubscribed,
                format!(
                    "Canister requested {} of Wasm custom sections memory but only {} are available in the subnet.{additional_help}",
                    requested.display(),
                    available.display(),
                ),
            ),
            CanisterNonEmpty(canister_id) => Self::new(
                ErrorCode::CanisterNonEmpty,
                format!(
                    "Canister {canister_id} cannot be installed because the canister is not empty. Try installing with mode='reinstall' instead.{additional_help}"
                ),
            ),
            CanisterInvalidController {
                canister_id,
                controllers_expected,
                controller_provided,
            } => {
                let controllers_expected = controllers_expected
                    .iter()
                    .map(|id| format!("{id}"))
                    .collect::<Vec<String>>()
                    .join(" ");
                Self::new(
                    ErrorCode::CanisterInvalidController,
                    format!(
                        "Only the controllers of the canister {canister_id} can control it.\n\
                        Canister's controllers: {controllers_expected}\n\
                        Sender's ID: {controller_provided}{additional_help}"
                    ),
                )
            }
            DeleteCanisterNotStopped(canister_id) => Self::new(
                ErrorCode::CanisterNotStopped,
                format!(
                    "Canister {canister_id} must be stopped before it is deleted.{additional_help}",
                ),
            ),
            DeleteCanisterQueueNotEmpty(canister_id) => Self::new(
                ErrorCode::CanisterQueueNotEmpty,
                format!(
                    "Canister {canister_id} has messages in its queues and cannot be \
                        deleted now. Please retry after some time.{additional_help}",
                ),
            ),
            DeleteCanisterSelf(canister_id) => Self::new(
                ErrorCode::CanisterInvalidController,
                format!("Canister {canister_id} cannot delete itself.{additional_help}",),
            ),
            SenderNotInWhitelist(_) => {
                // Methods that are whitelisted are private and should be invisible to users
                // outside of the whitelist. Therefore, not finding the sender in the whitelist is
                // concealed as a "method not found" error.
                Self::new(
                    ErrorCode::CanisterMethodNotFound,
                    String::from("Sender not authorized to use method."),
                )
            }
            CreateCanisterNotEnoughCycles { sent, required } => Self::new(
                ErrorCode::InsufficientCyclesForCreateCanister,
                format!(
                    "Creating a canister requires a fee of {required} that is deducted from the canister's initial balance but only {sent} cycles were received with the create_canister request.{additional_help}",
                ),
            ),
            InvalidSenderSubnet(_subnet_id) => Self::new(
                ErrorCode::CanisterContractViolation,
                "Cannot create canister. Sender should be on the same subnet or on the NNS subnet."
                    .to_string(),
            ),
            InstallCodeNotEnoughCycles(err) => Self::new(
                ErrorCode::CanisterOutOfCycles,
                format!("Canister installation failed with `{err}`.{additional_help}"),
            ),
            InstallCodeRateLimited(canister_id) => Self::new(
                ErrorCode::CanisterInstallCodeRateLimited,
                format!(
                    "Canister {canister_id} is rate limited because it executed too many instructions in the previous install_code messages. Please retry installation after several minutes.{additional_help}"
                ),
            ),
            SubnetOutOfCanisterIds => Self::new(
                ErrorCode::SubnetOversubscribed,
                "Could not create canister. Subnet has surpassed its canister ID allocation.{additional_help}",
            ),
            InvalidSettings { message } => Self::new(
                ErrorCode::CanisterContractViolation,
                format!("Could not validate the settings: {message} {additional_help}"),
            ),
            MaxNumberOfCanistersReached {
                subnet_id,
                max_number_of_canisters,
            } => Self::new(
                ErrorCode::MaxNumberOfCanistersReached,
                format!(
                    "Subnet {subnet_id} has reached the allowed canister limit of {max_number_of_canisters} canisters. Retry creating the canister.{additional_help}"
                ),
            ),
            CanisterNotHostedBySubnet { message } => Self::new(
                ErrorCode::CanisterNotHostedBySubnet,
                format!("Unsuccessful validation of specified ID: {message}{additional_help}"),
            ),
            InsufficientCyclesInComputeAllocation {
                compute_allocation,
                available,
                threshold,
            } => Self::new(
                ErrorCode::InsufficientCyclesInComputeAllocation,
                format!(
                    "Cannot increase compute allocation to {} due to insufficient cycles. At least {} additional cycles are required.{additional_help}",
                    compute_allocation,
                    threshold - available
                ),
            ),
            InsufficientCyclesInMemoryAllocation {
                memory_allocation,
                available,
                threshold,
            } => Self::new(
                ErrorCode::InsufficientCyclesInMemoryAllocation,
                format!(
                    "Cannot increase memory allocation to {} due to insufficient cycles. At least {} additional cycles are required.{additional_help}",
                    memory_allocation,
                    threshold - available
                ),
            ),
            InsufficientCyclesInMemoryGrow {
                bytes,
                available,
                required,
            } => Self::new(
                ErrorCode::InsufficientCyclesInMemoryGrow,
                format!(
                    "Canister cannot grow memory by {} bytes due to insufficient cycles. \
                         At least {} additional cycles are required.{additional_help}",
                    bytes,
                    required - available
                ),
            ),
            ReservedCyclesLimitExceededInMemoryAllocation {
                memory_allocation,
                requested,
                limit,
            } => Self::new(
                ErrorCode::ReservedCyclesLimitExceededInMemoryAllocation,
                format!(
                    "Cannot increase memory allocation to {} due to its reserved cycles limit. \
                         The current limit ({}) would be exceeded by {}.{additional_help}",
                    memory_allocation,
                    limit,
                    requested - limit,
                ),
            ),
            ReservedCyclesLimitExceededInMemoryGrow {
                bytes,
                requested,
                limit,
            } => Self::new(
                ErrorCode::ReservedCyclesLimitExceededInMemoryGrow,
                format!(
                    "Canister cannot grow memory by {} bytes due to its reserved cycles limit. \
                         The current limit ({}) would be exceeded by {}.{additional_help}",
                    bytes,
                    limit,
                    requested - limit,
                ),
            ),
            ReservedCyclesLimitIsTooLow { cycles, limit } => Self::new(
                ErrorCode::ReservedCyclesLimitIsTooLow,
                format!(
                    "Cannot set the reserved cycles limit {limit} below the reserved cycles balance of \
                        the canister {cycles}.{additional_help}",
                ),
            ),
            WasmChunkStoreError { message } => Self::new(
                ErrorCode::CanisterContractViolation,
                format!("Error from Wasm chunk store: {message}.{additional_help}"),
            ),
            CanisterSnapshotNotFound {
                canister_id,
                snapshot_id,
            } => Self::new(
                ErrorCode::CanisterSnapshotNotFound,
                format!(
                    "Could not find the snapshot ID {snapshot_id} for canister {canister_id}.{additional_help}",
                ),
            ),
            CanisterHeapDeltaRateLimited {
                canister_id,
                value,
                limit,
            } => Self::new(
                ErrorCode::CanisterHeapDeltaRateLimited,
                format!(
                    "Canister {canister_id} is heap delta rate limited: current delta debit is {value}, but limit is {limit}.{additional_help}"
                ),
            ),
            CanisterSnapshotInvalidOwnership {
                canister_id,
                snapshot_id,
            } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "The snapshot {snapshot_id} does not belong to canister {canister_id}.{additional_help}",
                ),
            ),
            CanisterSnapshotExecutionStateNotFound { canister_id } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!("Failed to create snapshot for empty canister {canister_id}:",),
            ),
            CanisterSnapshotLimitExceeded { canister_id, limit } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Canister {canister_id} has reached the maximum number of snapshots allowed: {limit}.{additional_help}",
                ),
            ),
            CanisterSnapshotNotEnoughCycles(err) => Self::new(
                ErrorCode::CanisterOutOfCycles,
                format!("Canister snapshotting failed with: `{err}`{additional_help}"),
            ),
            CanisterSnapshotImmutable => Self::new(
                ErrorCode::CanisterSnapshotImmutable,
                "Only canister snapshots created by metadata upload can be mutated.".to_string(),
            ),
            CanisterSnapshotNotController {
                sender,
                canister_id,
                snapshot_id,
            } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Only a controller of the canister that snapshot {} belongs to can load it on canister {}. Sender: {}.{additional_help}",
                    snapshot_id, canister_id, sender,
                ),
            ),
            CanisterSnapshotNotLoadable {
                canister_id,
                snapshot_id,
            } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Snapshot {} is not currently loadable on the specified canister {}. Try again later. The call should succeed if you wait sufficiently long (usually ten minutes).",
                    snapshot_id, canister_id,
                ),
            ),
            LongExecutionAlreadyInProgress { canister_id } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "The canister {canister_id} is currently executing a long-running message.",
                ),
            ),
            MissingUpgradeOptionError { message } => Self::new(
                ErrorCode::CanisterContractViolation,
                format!("Missing upgrade option: {message}"),
            ),
            InvalidUpgradeOptionError { message } => Self::new(
                ErrorCode::CanisterContractViolation,
                format!("Invalid upgrade option: {message}"),
            ),
            InvalidSlice { offset, size } => Self::new(
                ErrorCode::InvalidManagementPayload,
                format!(
                    "Invalid subslice into wasm module / main memory / stable memory: offset: {offset}, size: {size}"
                ),
            ),
            CanisterManagerError::SliceTooLarge { requested, allowed } => Self::new(
                ErrorCode::InvalidManagementPayload,
                format!("Requested slice too large: {requested} > {allowed}"),
            ),
            RenameCanisterNotStopped(canister_id) => Self::new(
                ErrorCode::CanisterNotStopped,
                format!(
                    "Canister {canister_id} must be stopped before it is renamed.{additional_help}",
                ),
            ),
            RenameCanisterHasSnapshot(canister_id) => Self::new(
                ErrorCode::CanisterNonEmpty,
                format!(
                    "Canister {canister_id} must not have any snapshots before it is renamed.{additional_help}",
                ),
            ),
            InvalidSpecifiedId { specified_id } => Self::new(
                ErrorCode::InvalidManagementPayload,
                format!(
                    "The `specified_id` {specified_id} is invalid because it belongs to the canister allocation ranges of the test environment.{additional_help}"
                ),
            ),
            CanisterSnapshotInconsistent { message } => {
                Self::new(ErrorCode::InvalidManagementPayload, message)
            }
            EnvironmentVariablesTooMany { max, count } => Self::new(
                ErrorCode::InvalidManagementPayload,
                format!("Too many environment variables: {count} (max: {max})"),
            ),
            EnvironmentVariablesNameTooLong {
                name,
                max_name_length,
            } => Self::new(
                ErrorCode::InvalidManagementPayload,
                format!(
                    "Environment variable name \"{name}\" exceeds the maximum allowed length of {max_name_length}."
                ),
            ),
            EnvironmentVariablesValueTooLong {
                value,
                max_value_length,
            } => Self::new(
                ErrorCode::InvalidManagementPayload,
                format!(
                    "Environment variable value \"{value}\" exceeds the maximum allowed length of {max_value_length}."
                ),
            ),
            CanisterMetadataNoWasmModule { canister_id } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "The canister {canister_id} has no Wasm module and hence no metadata is available."
                ),
            ),
            CanisterMetadataSectionNotFound {
                canister_id,
                section_name,
            } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "The canister {canister_id} has no metadata section with the name {section_name}."
                ),
            ),
            CallerNotAuthorized => Self::new(
                ErrorCode::CanisterRejectedMessage,
                "The caller is not authorized to call this method.".to_string(),
            ),
            CanisterLogMemoryLimitIsTooLow { bytes, limit } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "The canister log memory limit {bytes} is too low. It must be at least {limit}."
                ),
            ),
            CanisterLogMemoryLimitIsTooHigh { bytes, limit } => Self::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "The canister log memory limit {bytes} is too high. It must be at most {limit}."
                ),
            ),
        }
    }
}

impl From<CanisterSnapshotError> for CanisterManagerError {
    fn from(err: CanisterSnapshotError) -> Self {
        match err {
            CanisterSnapshotError::EmptyExecutionState(canister_id) => {
                CanisterManagerError::CanisterSnapshotExecutionStateNotFound { canister_id }
            }
            CanisterSnapshotError::InvalidSubslice { offset, size } => {
                CanisterManagerError::InvalidSlice { offset, size }
            }
            CanisterSnapshotError::InvalidMetadata { reason } => {
                CanisterManagerError::InvalidSettings { message: reason }
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
    /// Returns the original message, the cycles prepaid for execution,
    /// and a call id that exist only for inter-canister messages.
    fn abort(self: Box<Self>, log: &ReplicaLogger) -> (CanisterCall, InstallCodeCallId, Cycles);
}
