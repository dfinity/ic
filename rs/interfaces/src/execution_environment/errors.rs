use ic_base_types::{NumBytes, PrincipalIdBlobParseError};
use ic_error_types::UserError;
use ic_types::{methods::WasmMethod, CanisterId, CountBytes, Cycles, NumInstructions};
use ic_wasm_types::{WasmEngineError, WasmInstrumentationError, WasmValidationError};
use serde::{Deserialize, Serialize};

/// Various traps that a canister can create.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrapCode {
    StackOverflow,
    HeapOutOfBounds,
    StableMemoryOutOfBounds,
    StableMemoryTooBigFor32Bit,
    IntegerDivByZero,
    Unreachable,
    TableOutOfBounds,
    CyclesAmountTooBigFor64Bit,
    Other,
}

impl std::fmt::Display for TrapCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::HeapOutOfBounds => write!(f, "heap out of bounds"),
            Self::StableMemoryOutOfBounds => write!(f, "stable memory out of bounds"),
            Self::StableMemoryTooBigFor32Bit => write!(
                f,
                "32 bit stable memory api used on a memory larger than 4GB"
            ),
            Self::IntegerDivByZero => write!(f, "integer division by 0"),
            Self::Unreachable => write!(f, "unreachable"),
            Self::TableOutOfBounds => write!(f, "table out of bounds"),
            Self::CyclesAmountTooBigFor64Bit => {
                write!(f, "cycles amount exceeds 64-bit representation")
            }
            Self::Other => write!(f, "unknown"),
        }
    }
}

/// Error when a canister's balance is too low compared to its freezing
/// threshold and cannot perform the requested action.
///
/// Should be used as the wrapped error by various components that need to
/// handle such cases.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanisterOutOfCyclesError {
    pub canister_id: CanisterId,
    pub available: Cycles,
    pub requested: Cycles,
    pub threshold: Cycles,
    pub reveal_top_up: bool,
}

impl std::error::Error for CanisterOutOfCyclesError {}

impl std::fmt::Display for CanisterOutOfCyclesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = if self.reveal_top_up {
            format!("Canister {} is out of cycles: please top up the canister with at least {} additional cycles",
            self.canister_id, (self.threshold + self.requested) - self.available)
        } else {
            format!("Canister {} is out of cycles", self.canister_id)
        };
        write!(f, "{}", msg)
    }
}

/// Errors returned by the Hypervisor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HypervisorError {
    /// The message sent to the canister refers a function not found in the
    /// table. The payload contains the index of the table and the index of the
    /// function.
    FunctionNotFound(u32, u32),
    /// The message sent to the canister refers to a method that is not
    /// exposed by this canister.
    MethodNotFound(WasmMethod),
    /// System API contract was violated. They payload contains a
    /// detailed explanation of the issue suitable for displaying it
    /// to a user of IC.
    ContractViolation(String),
    /// Wasm execution consumed too many instructions.
    InstructionLimitExceeded,
    /// We could not validate the wasm module
    InvalidWasm(WasmValidationError),
    /// We could not instrument the wasm module
    InstrumentationFailed(WasmInstrumentationError),
    /// Canister Wasm trapped (e.g. by executing the `unreachable`
    /// instruction or dividing by zero).
    Trapped(TrapCode),
    /// Canister explicitly called `ic.trap`.
    CalledTrap(String),
    /// An attempt was made to execute a message on a canister that does not
    /// contain a Wasm module.
    WasmModuleNotFound,
    /// An attempt was made to grow the canister's memory above its memory
    /// allocation.
    OutOfMemory,
    /// The principal ID specified by the canister is invalid.
    InvalidPrincipalId(PrincipalIdBlobParseError),
    /// The canister rejected the message.
    MessageRejected,
    /// An attempt was made to add more cycles to an outgoing call than
    /// available in the canister's balance.
    InsufficientCyclesBalance(CanisterOutOfCyclesError),
    Cleanup {
        callback_err: Box<HypervisorError>,
        cleanup_err: Box<HypervisorError>,
    },
    WasmEngineError(WasmEngineError),
    /// The canister is close to running out of Wasm memory and
    /// attempted to allocate reserved Wasm pages.
    WasmReservedPages,
    /// The execution was aborted by deterministic time slicing. This error is
    /// not observable by the user and should be processed before leaving Wasm
    /// execution.
    Aborted,
    /// A single operation like `stable_write()` exceeded the slice instruction
    /// limit and caused the Wasm execution to fail.
    SliceOverrun {
        instructions: NumInstructions,
        limit: NumInstructions,
    },
    /// A canister has written too much new data in a single message.
    MemoryAccessLimitExceeded(String),
    InsufficientCyclesInMemoryGrow {
        bytes: NumBytes,
        available: Cycles,
        threshold: Cycles,
        reveal_top_up: bool,
    },
    ReservedCyclesLimitExceededInMemoryGrow {
        bytes: NumBytes,
        requested: Cycles,
        limit: Cycles,
    },
    InsufficientCyclesInMessageMemoryGrow {
        bytes: NumBytes,
        available: Cycles,
        threshold: Cycles,
        reveal_top_up: bool,
    },
}

impl From<WasmInstrumentationError> for HypervisorError {
    fn from(err: WasmInstrumentationError) -> Self {
        Self::InstrumentationFailed(err)
    }
}

impl From<WasmValidationError> for HypervisorError {
    fn from(err: WasmValidationError) -> Self {
        Self::InvalidWasm(err)
    }
}

impl From<WasmEngineError> for HypervisorError {
    fn from(err: WasmEngineError) -> Self {
        Self::WasmEngineError(err)
    }
}

impl std::fmt::Display for HypervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl CountBytes for HypervisorError {
    fn count_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl HypervisorError {
    pub fn into_user_error(self, canister_id: &CanisterId) -> UserError {
        use ic_error_types::ErrorCode as E;

        match self {
            Self::FunctionNotFound(table_idx, func_idx) => UserError::new(
                E::CanisterFunctionNotFound,
                format!(
                    "Canister {} requested to invoke a non-existent Wasm function {} from table {}",
                    canister_id, func_idx, table_idx
                ),
            ),
            Self::MethodNotFound(wasm_method) => {
                let kind = match wasm_method {
                    WasmMethod::Update(_) => "update",
                    WasmMethod::Query(_) => "query",
                    WasmMethod::CompositeQuery(_) => "composite_query",
                    WasmMethod::System(_) => "system",
                };

                UserError::new(
                    E::CanisterMethodNotFound,
                    format!(
                        "Canister {} has no {} method '{}'",
                        canister_id,
                        kind,
                        wasm_method.name()
                    ),
                )
            }
            Self::ContractViolation(description) => UserError::new(
                E::CanisterContractViolation,
                format!(
                    "Canister {} violated contract: {}",
                    canister_id, description
                ),
            ),
            Self::InstructionLimitExceeded => UserError::new(
                E::CanisterInstructionLimitExceeded,
                format!(
                    "Canister {} exceeded the instruction limit for single message execution.",
                    canister_id
                ),
            ),
            Self::InvalidWasm(err) => UserError::new(
                E::CanisterInvalidWasm,
                format!(
                    "Wasm module of canister {} is not valid: {}",
                    canister_id, err
                ),
            ),
            Self::InstrumentationFailed(err) => UserError::new(
                E::CanisterInvalidWasm,
                format!(
                    "Could not instrument wasm module of canister {}: {}",
                    canister_id, err
                ),
            ),
            Self::Trapped(code) => UserError::new(
                E::CanisterTrapped,
                format!("Canister {} trapped: {}", canister_id, code),
            ),
            Self::CalledTrap(msg) => UserError::new(
                E::CanisterCalledTrap,
                format!("Canister {} trapped explicitly: {}", canister_id, msg),
            ),
            Self::WasmModuleNotFound => UserError::new(
                E::CanisterWasmModuleNotFound,
                format!(
                    "Attempt to execute a message on canister {} which contains no Wasm module",
                    canister_id,
                ),
            ),
            Self::OutOfMemory => UserError::new(
                E::CanisterOutOfMemory,
                format!(
                    "Canister {} exceeded its allowed memory allocation",
                    canister_id
                ),
            ),
            Self::InvalidPrincipalId(_) => UserError::new(
                E::CanisterContractViolation,
                format!("Canister {} provided invalid principal id", canister_id),
            ),
            // `CANISTER_REJECT` reject code.
            Self::MessageRejected => UserError::new(
                E::CanisterRejectedMessage,
                format!("Canister {} rejected the message", canister_id),
            ),
            Self::InsufficientCyclesBalance(err) => {
                UserError::new(E::CanisterContractViolation, err.to_string())
            }
            Self::Cleanup {
                callback_err,
                cleanup_err,
            } => {
                let callback_user_error = callback_err.into_user_error(canister_id);
                let cleanup_user_error = cleanup_err.into_user_error(canister_id);

                UserError::new(
                    callback_user_error.code(), // Use the same error code as the original callback error.
                    format!(
                        "{}\n\ncall_on_cleanup also failed:\n\n{}",
                        callback_user_error.description(),
                        cleanup_user_error.description()
                    ),
                )
            }
            Self::WasmEngineError(err) => UserError::new(
                E::CanisterWasmEngineError,
                format!(
                    "Canister {} encountered a Wasm engine error: {}",
                    canister_id, err
                ),
            ),
            Self::WasmReservedPages => UserError::new(
                E::CanisterOutOfMemory,
                format!("Canister {} ran out of available Wasm memory.", canister_id),
            ),
            Self::Aborted => {
                unreachable!("Aborted execution should not be visible to the user.");
            }
            Self::SliceOverrun {
                instructions,
                limit,
            } => UserError::new(
                E::CanisterInstructionLimitExceeded,
                format!(
                    "Canister {} attempted to perform \
                a large memory operation that used {} instructions and \
                exceeded the slice limit {}.",
                    canister_id, instructions, limit
                ),
            ),
            Self::MemoryAccessLimitExceeded(s) => UserError::new(
                E::CanisterMemoryAccessLimitExceeded,
                format!("Canister exceeded memory access limits: {}", s),
            ),
            Self::InsufficientCyclesInMemoryGrow {
                bytes,
                available,
                threshold,
                reveal_top_up,
            } => {
                let msg = if reveal_top_up {
                    format!(
                        " At least {} additional cycles are required.",
                        threshold - available
                    )
                } else {
                    "".to_string()
                };
                UserError::new(
                    E::InsufficientCyclesInMemoryGrow,
                    format!(
                        "Canister cannot grow memory by {} bytes due to insufficient cycles.{}",
                        bytes, msg
                    ),
                )
            }
            Self::ReservedCyclesLimitExceededInMemoryGrow {
                bytes,
                requested,
                limit,
            } => {
                UserError::new(
                    E::ReservedCyclesLimitExceededInMemoryGrow,
                    format!(
                        "Canister cannot grow memory by {} bytes due to its reserved cycles limit. \
                         The current limit ({}) would be exceeded by {}.",
                        bytes, limit, requested - limit,
                    ),
                )
            }
            Self::InsufficientCyclesInMessageMemoryGrow {
                bytes,
                available,
                threshold,
                reveal_top_up,
            } => {
                let msg = if reveal_top_up {
                    format!(
                        " At least {} additional cycles are required.",
                        threshold - available
                    )
                } else {
                    "".to_string()
                };
                UserError::new(
                    E::InsufficientCyclesInMessageMemoryGrow,
                    format!(
                    "Canister cannot grow message memory by {} bytes due to insufficient cycles.{}",
                    bytes, msg,
                ),
                )
            }
        }
    }

    /// Returns a string slice representation of the enum variant name for use
    /// e.g. as a metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            HypervisorError::FunctionNotFound(..) => "FunctionNotFound",
            HypervisorError::MethodNotFound(_) => "MethodNotFound",
            HypervisorError::ContractViolation(_) => "ContractViolation",
            HypervisorError::InstructionLimitExceeded => "InstructionLimitExceeded",
            HypervisorError::InvalidWasm(_) => "InvalidWasm",
            HypervisorError::InstrumentationFailed(_) => "InstrumentationFailed",
            HypervisorError::Trapped(_) => "Trapped",
            HypervisorError::CalledTrap(_) => "CalledTrap",
            HypervisorError::WasmModuleNotFound => "WasmModuleNotFound",
            HypervisorError::OutOfMemory => "OutOfMemory",
            HypervisorError::InvalidPrincipalId(_) => "InvalidPrincipalId",
            HypervisorError::MessageRejected => "MessageRejected",
            HypervisorError::InsufficientCyclesBalance { .. } => "InsufficientCyclesBalance",
            HypervisorError::Cleanup { .. } => "Cleanup",
            HypervisorError::WasmEngineError(_) => "WasmEngineError",
            HypervisorError::WasmReservedPages => "WasmReservedPages",
            HypervisorError::Aborted => "Aborted",
            HypervisorError::SliceOverrun { .. } => "SliceOverrun",
            HypervisorError::MemoryAccessLimitExceeded(_) => "MemoryAccessLimitExceeded",
            HypervisorError::InsufficientCyclesInMemoryGrow { .. } => {
                "InsufficientCyclesInMemoryGrow"
            }
            HypervisorError::ReservedCyclesLimitExceededInMemoryGrow { .. } => {
                "ReservedCyclesLimitExceededInMemoryGrow"
            }
            HypervisorError::InsufficientCyclesInMessageMemoryGrow { .. } => {
                "InsufficientCyclesInMessageMemoryGrow"
            }
        }
    }
}
