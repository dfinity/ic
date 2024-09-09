use ic_base_types::{NumBytes, NumSeconds};
use ic_cycles_account_manager::{CyclesAccountManager, ResourceSaturation};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::execution_environment::SubnetAvailableMemory;
use ic_management_canister_types::{CanisterSettingsArgs, LogVisibilityV2};
use ic_types::{
    ComputeAllocation, Cycles, InvalidComputeAllocationError, InvalidMemoryAllocationError,
    MemoryAllocation, PrincipalId,
};
use num_traits::cast::ToPrimitive;
use std::convert::TryFrom;

use crate::canister_manager::CanisterManagerError;

/// These limit comes from the spec and is not expected to change,
/// which is why it is not part of the replica config.
const MAX_WASM_MEMORY_LIMIT: u64 = 1 << 48;
/// Struct used for decoding CanisterSettingsArgs
#[derive(Default)]
pub(crate) struct CanisterSettings {
    pub(crate) controllers: Option<Vec<PrincipalId>>,
    pub(crate) compute_allocation: Option<ComputeAllocation>,
    pub(crate) memory_allocation: Option<MemoryAllocation>,
    /// Threshold used for activation of canister_on_low_wasm_memory hook.
    pub(crate) wasm_memory_threshold: Option<NumBytes>,
    pub(crate) freezing_threshold: Option<NumSeconds>,
    pub(crate) reserved_cycles_limit: Option<Cycles>,
    pub(crate) log_visibility: Option<LogVisibilityV2>,
    pub(crate) wasm_memory_limit: Option<NumBytes>,
}

impl CanisterSettings {
    pub fn new(
        controllers: Option<Vec<PrincipalId>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        wasm_memory_threshold: Option<NumBytes>,
        freezing_threshold: Option<NumSeconds>,
        reserved_cycles_limit: Option<Cycles>,
        log_visibility: Option<LogVisibilityV2>,
        wasm_memory_limit: Option<NumBytes>,
    ) -> Self {
        Self {
            controllers,
            compute_allocation,
            memory_allocation,
            wasm_memory_threshold,
            freezing_threshold,
            reserved_cycles_limit,
            log_visibility,
            wasm_memory_limit,
        }
    }

    pub fn controllers(&self) -> Option<Vec<PrincipalId>> {
        self.controllers.clone()
    }

    pub fn compute_allocation(&self) -> Option<ComputeAllocation> {
        self.compute_allocation
    }

    pub fn memory_allocation(&self) -> Option<MemoryAllocation> {
        self.memory_allocation
    }

    pub fn wasm_memory_threshold(&self) -> Option<NumBytes> {
        self.wasm_memory_threshold
    }

    pub fn freezing_threshold(&self) -> Option<NumSeconds> {
        self.freezing_threshold
    }

    pub fn reserved_cycles_limit(&self) -> Option<Cycles> {
        self.reserved_cycles_limit
    }

    pub fn log_visibility(&self) -> Option<&LogVisibilityV2> {
        self.log_visibility.as_ref()
    }

    pub fn wasm_memory_limit(&self) -> Option<NumBytes> {
        self.wasm_memory_limit
    }
}

impl TryFrom<CanisterSettingsArgs> for CanisterSettings {
    type Error = UpdateSettingsError;

    fn try_from(input: CanisterSettingsArgs) -> Result<Self, Self::Error> {
        let compute_allocation = match input.compute_allocation {
            Some(ca) => Some(ComputeAllocation::try_from(ca.0.to_u64().ok_or_else(
                || UpdateSettingsError::ComputeAllocation(InvalidComputeAllocationError::new(ca)),
            )?)?),
            None => None,
        };

        let memory_allocation = match input.memory_allocation {
            Some(ma) => Some(MemoryAllocation::try_from(NumBytes::from(
                ma.0.to_u64().ok_or_else(|| {
                    UpdateSettingsError::MemoryAllocation(InvalidMemoryAllocationError::new(ma))
                })?,
            ))?),
            None => None,
        };

        let freezing_threshold = match input.freezing_threshold {
            Some(ft) => Some(NumSeconds::from(ft.0.to_u64().ok_or(
                UpdateSettingsError::FreezingThresholdOutOfRange { provided: ft },
            )?)),
            None => None,
        };

        let reserved_cycles_limit = match input.reserved_cycles_limit {
            Some(limit) => Some(Cycles::from(limit.0.to_u128().ok_or(
                UpdateSettingsError::ReservedCyclesLimitOutOfRange { provided: limit },
            )?)),
            None => None,
        };

        let wasm_memory_limit = match input.wasm_memory_limit {
            Some(limit) => {
                let limit = limit
                    .0
                    .to_u64()
                    .ok_or(UpdateSettingsError::WasmMemoryLimitOutOfRange { provided: limit })?;
                if limit > MAX_WASM_MEMORY_LIMIT {
                    return Err(UpdateSettingsError::WasmMemoryLimitOutOfRange {
                        provided: limit.into(),
                    });
                }
                Some(limit.into())
            }
            None => None,
        };

        let wasm_memory_threshold = match input.wasm_memory_threshold {
            Some(wmt) => {
                let wmt = wmt
                    .0
                    .to_u64()
                    .ok_or(UpdateSettingsError::WasmMemoryThresholdOutOfRange { provided: wmt })?;
                Some(NumBytes::new(wmt))
            }
            None => None,
        };

        Ok(CanisterSettings::new(
            input
                .controllers
                .map(|controllers| controllers.get().clone()),
            compute_allocation,
            memory_allocation,
            wasm_memory_threshold,
            freezing_threshold,
            reserved_cycles_limit,
            input.log_visibility,
            wasm_memory_limit,
        ))
    }
}

impl TryFrom<Option<CanisterSettingsArgs>> for CanisterSettings {
    type Error = UpdateSettingsError;

    fn try_from(input: Option<CanisterSettingsArgs>) -> Result<Self, Self::Error> {
        match input {
            Some(settings) => CanisterSettings::try_from(settings),
            None => Ok(CanisterSettings::default()),
        }
    }
}

pub(crate) struct CanisterSettingsBuilder {
    controllers: Option<Vec<PrincipalId>>,
    compute_allocation: Option<ComputeAllocation>,
    memory_allocation: Option<MemoryAllocation>,
    wasm_memory_threshold: Option<NumBytes>,
    freezing_threshold: Option<NumSeconds>,
    reserved_cycles_limit: Option<Cycles>,
    log_visibility: Option<LogVisibilityV2>,
    wasm_memory_limit: Option<NumBytes>,
}

#[allow(dead_code)]
impl CanisterSettingsBuilder {
    pub fn new() -> Self {
        Self {
            controllers: None,
            compute_allocation: None,
            memory_allocation: None,
            wasm_memory_threshold: None,
            freezing_threshold: None,
            reserved_cycles_limit: None,
            log_visibility: None,
            wasm_memory_limit: None,
        }
    }

    pub fn build(self) -> CanisterSettings {
        CanisterSettings {
            controllers: self.controllers,
            compute_allocation: self.compute_allocation,
            memory_allocation: self.memory_allocation,
            wasm_memory_threshold: self.wasm_memory_threshold,
            freezing_threshold: self.freezing_threshold,
            reserved_cycles_limit: self.reserved_cycles_limit,
            log_visibility: self.log_visibility,
            wasm_memory_limit: self.wasm_memory_limit,
        }
    }

    pub fn with_controllers(self, controllers: Vec<PrincipalId>) -> Self {
        Self {
            controllers: Some(controllers),
            ..self
        }
    }

    pub fn with_compute_allocation(self, compute_allocation: ComputeAllocation) -> Self {
        Self {
            compute_allocation: Some(compute_allocation),
            ..self
        }
    }

    pub fn with_memory_allocation(self, memory_allocation: MemoryAllocation) -> Self {
        Self {
            memory_allocation: Some(memory_allocation),
            ..self
        }
    }

    pub fn with_wasm_memory_threshold(self, wasm_memory_threshold: NumBytes) -> Self {
        Self {
            wasm_memory_threshold: Some(wasm_memory_threshold),
            ..self
        }
    }

    pub fn with_freezing_threshold(self, freezing_threshold: NumSeconds) -> Self {
        Self {
            freezing_threshold: Some(freezing_threshold),
            ..self
        }
    }

    pub fn with_reserved_cycles_limit(self, reserved_cycles_limit: Cycles) -> Self {
        Self {
            reserved_cycles_limit: Some(reserved_cycles_limit),
            ..self
        }
    }

    pub fn with_log_visibility(self, log_visibility: LogVisibilityV2) -> Self {
        Self {
            log_visibility: Some(log_visibility),
            ..self
        }
    }

    pub fn with_wasm_memory_limit(self, wasm_memory_limit: NumBytes) -> Self {
        Self {
            wasm_memory_limit: Some(wasm_memory_limit),
            ..self
        }
    }
}

pub enum UpdateSettingsError {
    ComputeAllocation(InvalidComputeAllocationError),
    MemoryAllocation(InvalidMemoryAllocationError),
    FreezingThresholdOutOfRange { provided: candid::Nat },
    ReservedCyclesLimitOutOfRange { provided: candid::Nat },
    WasmMemoryLimitOutOfRange { provided: candid::Nat },
    WasmMemoryThresholdOutOfRange { provided: candid::Nat },
}

impl From<UpdateSettingsError> for UserError {
    fn from(err: UpdateSettingsError) -> Self {
        match err {
            UpdateSettingsError::ComputeAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "ComputeAllocation expected to be in the range [{}..{}], got {}",
                    err.min(),
                    err.max(),
                    err.given()
                ),
            ),
            UpdateSettingsError::MemoryAllocation(err) => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "MemoryAllocation expected to be in the range [{}..{}], got {}",
                    err.min, err.max, err.given
                ),
            ),
            UpdateSettingsError::FreezingThresholdOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Freezing threshold expected to be in the range of [0..2^64-1], got {}",
                    provided
                ),
            ),
            UpdateSettingsError::ReservedCyclesLimitOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Reserved cycles limit expected to be in the range of [0..2^128-1], got {}",
                    provided
                ),
            ),
            UpdateSettingsError::WasmMemoryLimitOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Wasm memory limit expected to be in the range of [0..2^64-1], got {}",
                    provided
                ),
            ),
            UpdateSettingsError::WasmMemoryThresholdOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Wasm memory threshold expected to be in the range of [0..2^64-1], got {}",
                    provided
                ),
            ),
        }
    }
}

impl From<InvalidComputeAllocationError> for UpdateSettingsError {
    fn from(err: InvalidComputeAllocationError) -> Self {
        Self::ComputeAllocation(err)
    }
}

impl From<InvalidMemoryAllocationError> for UpdateSettingsError {
    fn from(err: InvalidMemoryAllocationError) -> Self {
        Self::MemoryAllocation(err)
    }
}

pub(crate) struct ValidatedCanisterSettings {
    controllers: Option<Vec<PrincipalId>>,
    compute_allocation: Option<ComputeAllocation>,
    memory_allocation: Option<MemoryAllocation>,
    wasm_memory_threshold: Option<NumBytes>,
    freezing_threshold: Option<NumSeconds>,
    reserved_cycles_limit: Option<Cycles>,
    reservation_cycles: Cycles,
    log_visibility: Option<LogVisibilityV2>,
    wasm_memory_limit: Option<NumBytes>,
}

impl ValidatedCanisterSettings {
    pub fn controllers(&self) -> Option<Vec<PrincipalId>> {
        self.controllers.clone()
    }

    pub fn compute_allocation(&self) -> Option<ComputeAllocation> {
        self.compute_allocation
    }

    pub fn memory_allocation(&self) -> Option<MemoryAllocation> {
        self.memory_allocation
    }

    pub fn wasm_memory_threshold(&self) -> Option<NumBytes> {
        self.wasm_memory_threshold
    }

    pub fn freezing_threshold(&self) -> Option<NumSeconds> {
        self.freezing_threshold
    }

    pub fn reserved_cycles_limit(&self) -> Option<Cycles> {
        self.reserved_cycles_limit
    }

    pub fn reservation_cycles(&self) -> Cycles {
        self.reservation_cycles
    }

    pub fn log_visibility(&self) -> Option<&LogVisibilityV2> {
        self.log_visibility.as_ref()
    }

    pub fn wasm_memory_limit(&self) -> Option<NumBytes> {
        self.wasm_memory_limit
    }
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
///
/// Keep this function in sync with `do_update_settings()`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_canister_settings(
    settings: CanisterSettings,
    canister_memory_usage: NumBytes,
    canister_message_memory_usage: NumBytes,
    canister_memory_allocation: MemoryAllocation,
    subnet_available_memory: &SubnetAvailableMemory,
    subnet_memory_saturation: &ResourceSaturation,
    canister_compute_allocation: ComputeAllocation,
    subnet_compute_allocation_usage: u64,
    subnet_compute_allocation_capacity: u64,
    max_controllers: usize,
    canister_freezing_threshold: NumSeconds,
    canister_cycles_balance: Cycles,
    cycles_account_manager: &CyclesAccountManager,
    subnet_size: usize,
    canister_reserved_balance: Cycles,
    canister_reserved_balance_limit: Option<Cycles>,
) -> Result<ValidatedCanisterSettings, CanisterManagerError> {
    let old_memory_bytes = canister_memory_allocation.allocated_bytes(canister_memory_usage);
    let new_memory_bytes = match settings.memory_allocation {
        None => canister_memory_usage,
        Some(new_memory_allocation) => {
            // The new memory allocation cannot be lower than the current canister
            // memory usage.
            if let MemoryAllocation::Reserved(reserved_bytes) = new_memory_allocation {
                if reserved_bytes < canister_memory_usage {
                    return Err(CanisterManagerError::NotEnoughMemoryAllocationGiven {
                        memory_allocation_given: new_memory_allocation,
                        memory_usage_needed: canister_memory_usage,
                    });
                }
            }
            new_memory_allocation.allocated_bytes(canister_memory_usage)
        }
    };

    // If the available memory in the subnet is negative, then we must cap
    // it at zero such that the new memory allocation can change between
    // zero and the old memory allocation. Note that capping at zero also
    // makes conversion from `i64` to `u64` valid.
    let subnet_available_memory = subnet_available_memory.get_execution_memory().max(0) as u64;
    let subnet_available_memory = subnet_available_memory.saturating_add(old_memory_bytes.get());
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
        let available_compute_allocation = subnet_compute_allocation_capacity
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
    match &controllers {
        Some(controllers) => {
            if controllers.len() > max_controllers {
                return Err(CanisterManagerError::InvalidSettings {
                    message: format!("Invalid settings: 'controllers' length exceeds maximum size allowed of {}.", max_controllers),
                });
            }
        }
        None => {}
    }

    if let Some(wasm_memory_limit) = settings.wasm_memory_limit() {
        if let Some(wasm_memory_threshold) = settings.wasm_memory_threshold() {
            if wasm_memory_threshold > wasm_memory_limit {
                return Err(CanisterManagerError::InvalidSettings {
                    message: format!("Invalid settings: 'wasm_memory_threshold' cannot be larger than 'wasm_memory_limit'. 'wasm_memory_threshold': {}, 'wasm_memory_limit': {}", wasm_memory_threshold, wasm_memory_limit),
                });
            }
        }
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

    let threshold = cycles_account_manager.freeze_threshold_cycles(
        freezing_threshold,
        new_memory_allocation,
        canister_memory_usage,
        canister_message_memory_usage,
        new_compute_allocation,
        subnet_size,
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

    let allocated_bytes = if new_memory_bytes > old_memory_bytes {
        new_memory_bytes - old_memory_bytes
    } else {
        NumBytes::new(0)
    };

    let reservation_cycles = cycles_account_manager.storage_reservation_cycles(
        allocated_bytes,
        subnet_memory_saturation,
        subnet_size,
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

    Ok(ValidatedCanisterSettings {
        controllers: settings.controllers(),
        compute_allocation: settings.compute_allocation(),
        memory_allocation: settings.memory_allocation(),
        wasm_memory_threshold: settings.wasm_memory_threshold(),
        freezing_threshold: settings.freezing_threshold(),
        reserved_cycles_limit: settings.reserved_cycles_limit(),
        reservation_cycles,
        log_visibility: settings.log_visibility().cloned(),
        wasm_memory_limit: settings.wasm_memory_limit(),
    })
}
