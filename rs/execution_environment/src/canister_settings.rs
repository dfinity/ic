use ic_base_types::{EnvironmentVariables, NumBytes, NumSeconds};
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::{CanisterSettingsArgs, LogVisibilityV2};
use ic_types::{
    ComputeAllocation, Cycles, InvalidComputeAllocationError, MemoryAllocation, PrincipalId,
};
use num_traits::cast::ToPrimitive;
use std::collections::BTreeMap;
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

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
    pub(crate) log_memory_limit: Option<NumBytes>,
    pub(crate) wasm_memory_limit: Option<NumBytes>,
    pub(crate) environment_variables: Option<EnvironmentVariables>,
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
        log_memory_limit: Option<NumBytes>,
        wasm_memory_limit: Option<NumBytes>,
        environment_variables: Option<EnvironmentVariables>,
    ) -> Self {
        Self {
            controllers,
            compute_allocation,
            memory_allocation,
            wasm_memory_threshold,
            freezing_threshold,
            reserved_cycles_limit,
            log_visibility,
            log_memory_limit,
            wasm_memory_limit,
            environment_variables,
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

    pub fn log_memory_limit(&self) -> Option<NumBytes> {
        self.log_memory_limit
    }

    pub fn wasm_memory_limit(&self) -> Option<NumBytes> {
        self.wasm_memory_limit
    }

    pub fn environment_variables(&self) -> Option<&EnvironmentVariables> {
        self.environment_variables.as_ref()
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
            Some(ma) => Some(MemoryAllocation::from(NumBytes::from(
                ma.0.to_u64()
                    .ok_or(UpdateSettingsError::MemoryAllocationOutOfRange { provided: ma })?,
            ))),
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

        let log_memory_limit = match input.log_memory_limit {
            Some(ls) => Some(NumBytes::from(
                ls.0.to_u64()
                    .ok_or(UpdateSettingsError::LogMemoryLimitOutOfRange { provided: ls })?,
            )),
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

        let environment_variables = match input.environment_variables {
            Some(env_vars) => {
                let original_length = env_vars.len();
                let environment_variables = env_vars
                    .into_iter()
                    .map(|e| (e.name, e.value))
                    .collect::<BTreeMap<String, String>>();
                if environment_variables.len() != original_length {
                    return Err(UpdateSettingsError::DuplicateEnvironmentVariables);
                }
                Some(EnvironmentVariables::new(environment_variables))
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
            log_memory_limit,
            wasm_memory_limit,
            environment_variables,
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
    log_memory_limit: Option<NumBytes>,
    wasm_memory_limit: Option<NumBytes>,
    environment_variables: Option<EnvironmentVariables>,
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
            log_memory_limit: None,
            wasm_memory_limit: None,
            environment_variables: None,
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
            log_memory_limit: self.log_memory_limit,
            wasm_memory_limit: self.wasm_memory_limit,
            environment_variables: self.environment_variables,
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

    pub fn with_log_memory_limit(self, log_memory_limit: NumBytes) -> Self {
        Self {
            log_memory_limit: Some(log_memory_limit),
            ..self
        }
    }

    pub fn with_wasm_memory_limit(self, wasm_memory_limit: NumBytes) -> Self {
        Self {
            wasm_memory_limit: Some(wasm_memory_limit),
            ..self
        }
    }

    pub fn with_environment_variables(self, environment_variables: EnvironmentVariables) -> Self {
        Self {
            environment_variables: Some(environment_variables),
            ..self
        }
    }
}

pub enum UpdateSettingsError {
    ComputeAllocation(InvalidComputeAllocationError),
    MemoryAllocationOutOfRange { provided: candid::Nat },
    FreezingThresholdOutOfRange { provided: candid::Nat },
    ReservedCyclesLimitOutOfRange { provided: candid::Nat },
    WasmMemoryLimitOutOfRange { provided: candid::Nat },
    WasmMemoryThresholdOutOfRange { provided: candid::Nat },
    DuplicateEnvironmentVariables,
    LogMemoryLimitOutOfRange { provided: candid::Nat },
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
            UpdateSettingsError::MemoryAllocationOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!("MemoryAllocation expected to be in the range [0..2^64-1], got {provided}"),
            ),
            UpdateSettingsError::FreezingThresholdOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Freezing threshold expected to be in the range of [0..2^64-1], got {provided}"
                ),
            ),
            UpdateSettingsError::ReservedCyclesLimitOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Reserved cycles limit expected to be in the range of [0..2^128-1], got {provided}"
                ),
            ),
            UpdateSettingsError::WasmMemoryLimitOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Wasm memory limit expected to be in the range of [0..2^64-1], got {provided}"
                ),
            ),
            UpdateSettingsError::WasmMemoryThresholdOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Wasm memory threshold expected to be in the range of [0..2^64-1], got {provided}"
                ),
            ),
            UpdateSettingsError::DuplicateEnvironmentVariables => UserError::new(
                ErrorCode::InvalidManagementPayload,
                "Duplicate environment variables are not allowed".to_string(),
            ),
            UpdateSettingsError::LogMemoryLimitOutOfRange { provided } => UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Log memory limit expected to be in the range of [0..2^64-1], got {provided}"
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

pub(crate) struct ValidatedCanisterSettings {
    controllers: Option<Vec<PrincipalId>>,
    compute_allocation: Option<ComputeAllocation>,
    memory_allocation: Option<MemoryAllocation>,
    wasm_memory_threshold: Option<NumBytes>,
    freezing_threshold: Option<NumSeconds>,
    reserved_cycles_limit: Option<Cycles>,
    reservation_cycles: Cycles,
    log_visibility: Option<LogVisibilityV2>,
    log_memory_limit: Option<NumBytes>,
    wasm_memory_limit: Option<NumBytes>,
    environment_variables: Option<EnvironmentVariables>,
}

impl ValidatedCanisterSettings {
    pub fn new(
        controllers: Option<Vec<PrincipalId>>,
        compute_allocation: Option<ComputeAllocation>,
        memory_allocation: Option<MemoryAllocation>,
        wasm_memory_threshold: Option<NumBytes>,
        freezing_threshold: Option<NumSeconds>,
        reserved_cycles_limit: Option<Cycles>,
        reservation_cycles: Cycles,
        log_visibility: Option<LogVisibilityV2>,
        log_memory_limit: Option<NumBytes>,
        wasm_memory_limit: Option<NumBytes>,
        environment_variables: Option<EnvironmentVariables>,
    ) -> Self {
        Self {
            controllers,
            compute_allocation,
            memory_allocation,
            wasm_memory_threshold,
            freezing_threshold,
            reserved_cycles_limit,
            reservation_cycles,
            log_visibility,
            log_memory_limit,
            wasm_memory_limit,
            environment_variables,
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

    pub fn reservation_cycles(&self) -> Cycles {
        self.reservation_cycles
    }

    pub fn log_visibility(&self) -> Option<&LogVisibilityV2> {
        self.log_visibility.as_ref()
    }

    pub fn log_memory_limit(&self) -> Option<NumBytes> {
        self.log_memory_limit
    }

    pub fn wasm_memory_limit(&self) -> Option<NumBytes> {
        self.wasm_memory_limit
    }

    pub fn environment_variables(&self) -> Option<&EnvironmentVariables> {
        self.environment_variables.as_ref()
    }
}
