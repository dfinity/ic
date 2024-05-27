use ic_base_types::{NumBytes, PrincipalIdBlobParseError};
use ic_error_types::UserError;
use ic_types::{methods::WasmMethod, CanisterId, CountBytes, Cycles, NumInstructions};
use ic_wasm_types::{
    AsErrorHelp, ErrorHelp, WasmEngineError, WasmInstrumentationError, WasmValidationError,
};
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
    /// System API contract was violated. The developer toolchain or CDK is
    /// likely responsible for the error (as opposed to the canister developer).
    ToolchainContractViolation {
        error: String,
    },
    /// System API contract was violated. They payload contains a
    /// detailed explanation of the issue suitable for displaying it
    /// to a user of IC.
    UserContractViolation {
        error: String,
        suggestion: String,
        doc_link: String,
    },
    /// Wasm execution consumed too many instructions.
    InstructionLimitExceeded(NumInstructions),
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
    /// The canister is close to running out of Wasm memory and attempted to
    /// allocate reserved Wasm pages. These pages are just reserved for
    /// canisters using older versions of Motoko which could get bricked by
    /// using up the full Wasm heap.
    ReservedPagesForOldMotoko,
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
    WasmMemoryLimitExceeded {
        bytes: NumBytes,
        limit: NumBytes,
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
        match self {
            Self::FunctionNotFound(table_idx, func_idx) => write!(
                f,
                "Canister requested to invoke a non-existent Wasm function {} from table {}",
                func_idx, table_idx
            ),
            Self::MethodNotFound(wasm_method) => {
                let kind = match wasm_method {
                    WasmMethod::Update(_) => "update",
                    WasmMethod::Query(_) => "query",
                    WasmMethod::CompositeQuery(_) => "composite_query",
                    WasmMethod::System(_) => "system",
                };

                write!(
                    f,
                    "Canister has no {} method '{}'.",
                    kind,
                    wasm_method.name()
                )
            }
            Self::ToolchainContractViolation { error, .. } => {
                write!(f, "Canister violated contract: {}", error)
            }
            Self::UserContractViolation { error, .. } => {
                write!(f, "Canister violated contract: {}", error)
            }
            Self::InstructionLimitExceeded(limit) => write!(
                f,
                "Canister exceeded the limit of {} instructions for single message execution.",
                limit
            ),
            Self::InvalidWasm(err) => write!(f, "Canister's Wasm module is not valid: {}", err),
            Self::InstrumentationFailed(err) => {
                write!(f, "Could not instrument wasm module of canister: {}", err)
            }
            Self::Trapped(code) => write!(f, "Canister trapped: {}", code),
            Self::CalledTrap(msg) => {
                write!(f, "Canister called `ic0.trap` with message: {}", msg)
            }
            Self::WasmModuleNotFound => write!(
                f,
                "Attempted to execute a message, but the canister contains no Wasm module.",
            ),
            Self::OutOfMemory => write!(f, "Canister exceeded its allowed memory allocation.",),
            Self::InvalidPrincipalId(_) => {
                write!(f, "Canister provided invalid principal id")
            }
            // `CANISTER_REJECT` reject code.
            Self::MessageRejected => write!(f, "Canister rejected the message"),
            Self::InsufficientCyclesBalance(err) => write!(f, "{}", err),
            Self::Cleanup {
                callback_err,
                cleanup_err,
            } => {
                write!(
                    f,
                    "{}\n\ncall_on_cleanup also failed:\n\n{}",
                    callback_err, cleanup_err,
                )
            }
            Self::WasmEngineError(err) => {
                write!(f, "Canister encountered a Wasm engine error: {}", err)
            }
            Self::ReservedPagesForOldMotoko => {
                write!(f, "Canister tried to allocate pages reserved for upgrading older versions of Motoko.")
            }
            Self::Aborted => {
                // This error should never be visible to end users.
                write!(f, "Aborted")
            }
            Self::SliceOverrun {
                instructions,
                limit,
            } => write!(
                f,
                "Canister attempted to perform \
                a large memory operation that used {} instructions and \
                exceeded the slice limit {}.",
                instructions, limit
            ),
            Self::MemoryAccessLimitExceeded(s) => {
                write!(f, "Canister exceeded memory access limits: {}", s)
            }
            Self::InsufficientCyclesInMemoryGrow {
                bytes,
                available,
                threshold,
                reveal_top_up,
            } => {
                let msg = if *reveal_top_up {
                    format!(
                        " At least {} additional cycles are required.",
                        *threshold - *available
                    )
                } else {
                    "".to_string()
                };
                write!(
                    f,
                    "Canister cannot grow memory by {} bytes due to insufficient cycles.{}",
                    bytes, msg
                )
            }
            Self::ReservedCyclesLimitExceededInMemoryGrow {
                bytes,
                requested,
                limit,
            } => {
                write!(
                    f,
                    "Canister cannot grow memory by {} bytes due to its reserved cycles limit. \
                         The current limit ({}) would be exceeded by {}.",
                    bytes,
                    limit,
                    *requested - *limit,
                )
            }
            Self::InsufficientCyclesInMessageMemoryGrow {
                bytes,
                available,
                threshold,
                reveal_top_up,
            } => {
                let msg = if *reveal_top_up {
                    format!(
                        " At least {} additional cycles are required.",
                        *threshold - *available
                    )
                } else {
                    "".to_string()
                };
                write!(
                    f,
                    "Canister cannot grow message memory by {} bytes due to insufficient cycles.{}",
                    bytes, msg,
                )
            }
            Self::WasmMemoryLimitExceeded { bytes, limit } => {
                write!(f,
                        "Canister exceeded its current Wasm memory limit of {} bytes. \
                        The peak Wasm memory usage was {} bytes.\
                        If the canister reaches 4GiB, then it may stop functioning and may become unrecoverable. \
                        Please reach out to the canister owner to investigate the reason for the increased memory usage. \
                        It might be necessary to move data from the Wasm memory to the stable memory. \
                        If such high Wasm memory usage is expected and safe, then the developer can increase \
                        the Wasm memory limit in the canister settings.",
                        limit.get(), bytes.get()
                )
            }
        }
    }
}

impl CountBytes for HypervisorError {
    fn count_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl AsErrorHelp for HypervisorError {
    fn error_help(&self) -> ErrorHelp {
        let empty_user_error = ErrorHelp::UserError {
            suggestion: "".to_string(),
            doc_link: "".to_string(),
        };
        match self {
            Self::FunctionNotFound(_, _)
            | Self::ToolchainContractViolation { .. } => ErrorHelp::ToolchainError,
            Self::MethodNotFound(_) => ErrorHelp::UserError {
                suggestion: "Check that the method being called is exported by the target canister.".to_string(),
                doc_link: "http://internetcomputer.org/docs/current/references/execution-errors#method-not-found".to_string(),
            },
            Self::InstructionLimitExceeded(_)
            | Self::Trapped(_)
            | Self::CalledTrap(_)
            | Self::WasmModuleNotFound
            | Self::OutOfMemory
            | Self::InvalidPrincipalId(_)
            | Self::MessageRejected
            | Self::InsufficientCyclesBalance(_)
            | Self::Cleanup { .. }
            | Self::WasmEngineError(_)
            | Self::ReservedPagesForOldMotoko
            | Self::Aborted
            | Self::SliceOverrun { .. }
            | Self::MemoryAccessLimitExceeded(_)
            | Self::InsufficientCyclesInMemoryGrow { .. }
            | Self::ReservedCyclesLimitExceededInMemoryGrow { .. }
            | Self::InsufficientCyclesInMessageMemoryGrow { .. }
            | Self::WasmMemoryLimitExceeded { .. } => empty_user_error,
            Self::UserContractViolation {
                suggestion,
                doc_link,
                ..
            } => ErrorHelp::UserError {
                suggestion: suggestion.to_string(),
                doc_link: doc_link.to_string(),
            },
            Self::InvalidWasm(inner) => inner.error_help(),
            Self::InstrumentationFailed(inner) => inner.error_help(),
        }
    }
}

impl HypervisorError {
    pub fn into_user_error(self, canister_id: &CanisterId) -> UserError {
        use ic_error_types::ErrorCode as E;

        let help = format!("{}", self.error_help());
        let description = if help.is_empty() {
            format!("Error from Canister {}: {}", canister_id, &self,)
        } else {
            format!("Error from Canister {}: {}.\n{}", canister_id, &self, help)
        };

        let code = match self {
            Self::FunctionNotFound(_, _) => E::CanisterFunctionNotFound,
            Self::MethodNotFound(_) => E::CanisterMethodNotFound,
            Self::ToolchainContractViolation { .. } => E::CanisterContractViolation,
            Self::UserContractViolation { .. } => E::CanisterContractViolation,
            Self::InstructionLimitExceeded(_) => E::CanisterInstructionLimitExceeded,
            Self::InvalidWasm(_) => E::CanisterInvalidWasm,
            Self::InstrumentationFailed(_) => E::CanisterInvalidWasm,
            Self::Trapped(_) => E::CanisterTrapped,
            Self::CalledTrap(_) => E::CanisterCalledTrap,
            Self::WasmModuleNotFound => E::CanisterWasmModuleNotFound,
            Self::OutOfMemory => E::CanisterOutOfMemory,
            Self::InvalidPrincipalId(_) => E::CanisterContractViolation,
            Self::MessageRejected => E::CanisterRejectedMessage,
            Self::InsufficientCyclesBalance(_) => E::CanisterContractViolation,
            Self::Cleanup { callback_err, .. } => {
                // Use the same error code as the original callback error.
                callback_err.into_user_error(canister_id).code()
            }
            Self::WasmEngineError(_) => E::CanisterWasmEngineError,
            Self::ReservedPagesForOldMotoko => E::CanisterOutOfMemory,
            Self::Aborted => {
                unreachable!("Aborted execution should not be visible to the user.");
            }
            Self::SliceOverrun { .. } => E::CanisterInstructionLimitExceeded,
            Self::MemoryAccessLimitExceeded(_) => E::CanisterMemoryAccessLimitExceeded,
            Self::InsufficientCyclesInMemoryGrow { .. } => E::InsufficientCyclesInMemoryGrow,
            Self::ReservedCyclesLimitExceededInMemoryGrow { .. } => {
                E::ReservedCyclesLimitExceededInMemoryGrow
            }
            Self::InsufficientCyclesInMessageMemoryGrow { .. } => {
                E::InsufficientCyclesInMessageMemoryGrow
            }
            Self::WasmMemoryLimitExceeded { .. } => E::CanisterWasmMemoryLimitExceeded,
        };
        UserError::new(code, description)
    }

    /// Returns a string slice representation of the enum variant name for use
    /// e.g. as a metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            HypervisorError::FunctionNotFound(..) => "FunctionNotFound",
            HypervisorError::MethodNotFound(_) => "MethodNotFound",
            HypervisorError::ToolchainContractViolation { .. } => "ToolchainContractViolation",
            HypervisorError::UserContractViolation { .. } => "UserContractViolation",
            HypervisorError::InstructionLimitExceeded(_) => "InstructionLimitExceeded",
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
            HypervisorError::ReservedPagesForOldMotoko => "ReservedPagesForOldMotoko",
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
            HypervisorError::WasmMemoryLimitExceeded { .. } => "WasmMemoryLimitExceeded",
        }
    }
}
