use ic_base_types::{CanisterIdError, PrincipalIdBlobParseError};
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    methods::WasmMethod, user_error::UserError, CanisterId, CanisterStatusType, Cycles,
};
use ic_wasm_types::{WasmEngineError, WasmInstrumentationError, WasmValidationError};
use serde::{Deserialize, Serialize};

/// Various traps that a canister can create.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrapCode {
    StackOverflow,
    HeapOutOfBounds,
    StableMemoryOutOfBounds,
    IntegerDivByZero,
    Unreachable,
    TableOutOfBounds,
    Other,
}

impl std::fmt::Display for TrapCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::HeapOutOfBounds => write!(f, "heap out of bounds"),
            Self::StableMemoryOutOfBounds => write!(f, "stable memory out of bounds"),
            Self::IntegerDivByZero => write!(f, "integer division by 0"),
            Self::Unreachable => write!(f, "unreachable"),
            Self::TableOutOfBounds => write!(f, "table out of bounds"),
            Self::Other => write!(f, "unknown"),
        }
    }
}

/// Errors when executing `canister_heartbeat`.
#[derive(Debug, Eq, PartialEq)]
pub enum CanisterHeartbeatError {
    /// The canister isn't running.
    CanisterNotRunning {
        status: CanisterStatusType,
    },

    /// The subnet type isn't a system subnet.
    NotSystemSubnet {
        subnet_type_given: SubnetType,
    },

    OutOfCycles,

    /// Execution failed while executing the `canister_heartbeat`.
    CanisterExecutionFailed(HypervisorError),
}

/// Different types of errors that can be returned from the function(s) that
/// check if messages should be accepted or not.
#[derive(Debug, Eq, PartialEq)]
pub enum MessageAcceptanceError {
    /// The canister that the message is destined for was not found. So no
    /// checks could be performed.
    CanisterNotFound,

    /// The canister that the message is destined for does not have a wasm
    /// module. So it will not be able to handle the message even if the message
    /// was accepted.
    CanisterHasNoWasmModule,

    /// The canister explicitly rejected the message.
    CanisterRejected,

    /// The canister doesn't have enough cycles to execute the message.
    CanisterOutOfCycles,

    /// The canister experienced a failure while executing the `inspect_message`
    /// method
    CanisterExecutionFailed(HypervisorError),
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
    OutOfInstructions,
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
    /// An attempt to perform an operation that isn't allowed when the canister
    /// is stopped.
    CanisterStopped,
    /// An attempt was made to use more cycles than was available in a call
    /// context.
    InsufficientCyclesInCall {
        available: Cycles,
        requested: Cycles,
    },
    /// The principal ID specified by the canister is invalid.
    InvalidPrincipalId(PrincipalIdBlobParseError),
    /// The canister ID specified by the canister is invalid.
    InvalidCanisterId(CanisterIdError),
    /// The canister rejected the message.
    MessageRejected,
    /// An attempt was made to add more cycles to an outgoing call than
    /// available in the canister's balance.
    InsufficientCyclesBalance {
        available: Cycles,
        requested: Cycles,
    },
    Cleanup {
        callback_err: Box<HypervisorError>,
        cleanup_err: Box<HypervisorError>,
    },
    WasmEngineError(WasmEngineError),
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

impl HypervisorError {
    pub fn into_user_error(self, canister_id: &CanisterId) -> UserError {
        use ic_types::user_error::ErrorCode as E;

        match self {
            Self::MessageRejected => UserError::new(
                E::CanisterRejectedMessage,
                format!("Canister {} rejected the message", canister_id),
            ),
            Self::FunctionNotFound(table_idx, func_idx) => UserError::new(
                E::CanisterFunctionNotFound,
                format!(
                    "Canister {} requested to invoke a non-existent Wasm function {} from table {}",
                    canister_id, func_idx, table_idx
                ),
            ),
            Self::WasmModuleNotFound => UserError::new(
                E::CanisterWasmModuleNotFound,
                format!(
                    "Attempt to execute a message on canister {} which contains no Wasm module",
                    canister_id,
                ),
            ),
            Self::MethodNotFound(wasm_method) => {
                let kind = match wasm_method {
                    WasmMethod::Update(_) => "update",
                    WasmMethod::Query(_) => "query",
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
            Self::OutOfInstructions => UserError::new(
                E::CanisterOutOfCycles,
                format!("Canister {} exceeded the cycles limit for single message execution.", canister_id),
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
            Self::OutOfMemory => UserError::new(
                E::CanisterOutOfMemory,
                format!(
                    "Canister {} exceeded its allowed memory allocation",
                    canister_id
                ),
            ),
            Self::CanisterStopped => UserError::new(
                E::CanisterStopped,
                format!("Canister {} is stopped", canister_id,),
            ),
            Self::InsufficientCyclesInCall {
                available,
                requested,
            } => UserError::new(
                E::InsufficientCyclesInCall,
                format!(
                    "Canister {} attempted to keep {} cycles from a call when only {} was available",
                    canister_id, requested, available
                ),
            ),
            Self::InvalidPrincipalId(_) => UserError::new(
                E::CanisterTrapped,
                format!("Canister {} provided invalid principal id", canister_id),
            ),
            Self::InvalidCanisterId(_) => UserError::new(
                E::CanisterTrapped,
                format!("Canister {} provided invalid canister id", canister_id),
            ),
            Self::InsufficientCyclesBalance {
                available,
                requested,
            } => UserError::new(
                E::CanisterOutOfCycles,
                format!(
                    "Canister {} attempted to send {} cycles when only {} were available in its balance",
                    canister_id, requested, available
                ),
            ),
            Self::Cleanup {
                callback_err,
                cleanup_err,
            } => {
                let callback_user_error = callback_err.into_user_error(canister_id);
                let cleanup_user_error = cleanup_err.into_user_error(canister_id);

                UserError::new(
                    callback_user_error.code(), // Use the same error code as the original callback error.
                    format!("{}\n\ncall_on_cleanup also failed:\n\n{}",
                        callback_user_error.description(),
                        cleanup_user_error.description()
                    )
                )
            }
            Self::WasmEngineError(err) => UserError::new(
                E::CanisterWasmEngineError,
                format!(
                    "Canister {} encountered a Wasm engine error: {}", canister_id, err
                ),
            ),
        }
    }

    /// Returns a string slice representation of the enum variant name for use
    /// e.g. as a metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            HypervisorError::FunctionNotFound(..) => "FunctionNotFound",
            HypervisorError::MethodNotFound(_) => "MethodNotFound",
            HypervisorError::ContractViolation(_) => "ContractViolation",
            HypervisorError::OutOfInstructions => "OutOfInstructions",
            HypervisorError::InvalidWasm(_) => "InvalidWasm",
            HypervisorError::InstrumentationFailed(_) => "InstrumentationFailed",
            HypervisorError::Trapped(_) => "Trapped",
            HypervisorError::CalledTrap(_) => "CalledTrap",
            HypervisorError::WasmModuleNotFound => "WasmModuleNotFound",
            HypervisorError::OutOfMemory => "OutOfMemory",
            HypervisorError::CanisterStopped => "CanisterStopped",
            HypervisorError::InsufficientCyclesInCall { .. } => "InsufficientCyclesInCall",
            HypervisorError::InvalidPrincipalId(_) => "InvalidPrincipalId",
            HypervisorError::InvalidCanisterId(_) => "InvalidCanisterId",
            HypervisorError::MessageRejected => "MessageRejected",
            HypervisorError::InsufficientCyclesBalance { .. } => "InsufficientCyclesBalance",
            HypervisorError::Cleanup { .. } => "Cleanup",
            HypervisorError::WasmEngineError(_) => "WasmEngineError",
        }
    }
}
