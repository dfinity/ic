use serde::{Deserialize, Serialize};

/// Represents an error that can happen when parsing a Wasm module using
/// `parity_wasm`.
///
/// Note that ideally we would wrap a `parity_wasm::elements:Error` here but
/// unfortunately it does not derive `Serialize` and `Deserialize` which is
/// required by other types that this error gets embedded in. So, instead wrap
/// only the error message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityWasmError(String);

impl ParityWasmError {
    /// Creates a new `ParityWasmError` out of an error message.
    pub fn new(error_message: String) -> Self {
        Self(error_message)
    }
}

impl std::fmt::Display for ParityWasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Different errors that be returned by `validate_wasm_binary`
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WasmValidationError {
    /// Failure in party_wasm when deserializing the wasm module.  
    ParityDeserializeError(ParityWasmError),
    /// wasmtime::Module::validate() failed
    WasmtimeValidation(String),
    /// Module contains an invalid function signature
    InvalidFunctionSignature(String),
    /// Module contains an invalid import section
    InvalidImportSection(String),
    /// Module contains an invalid export section
    InvalidExportSection(String),
    /// Module contains an invalid data section
    InvalidDataSection(String),
    /// Module contains an invalid custom section
    InvalidCustomSection(String),
    /// Module contains too many globals.
    TooManyGlobals { defined: usize, allowed: usize },
    /// Module contains too many functions.
    TooManyFunctions { defined: usize, allowed: usize },
    /// Module contains too many custom sections.
    TooManyCustomSections { defined: usize, allowed: usize },
    /// Module defines an invalid index for a local function.
    InvalidFunctionIndex { index: usize, import_count: usize },
}

impl std::fmt::Display for WasmValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParityDeserializeError(err) => {
                write!(f, "Failed to deserialize wasm module with {}", err)
            }
            Self::WasmtimeValidation(err) => {
                write!(f, "Wasmtime failed to validate wasm module {}", err)
            }
            Self::InvalidFunctionSignature(err) => {
                write!(f, "Wasm module has an invalid function signature. {}", err)
            }
            Self::InvalidImportSection(err) => {
                write!(f, "Wasm module has an invalid import section. {}", err)
            }
            Self::InvalidExportSection(err) => {
                write!(f, "Wasm module has an invalid export section. {}", err)
            }
            Self::InvalidDataSection(err) => {
                write!(f, "Wasm module has an invalid data section. {}", err)
            }
            Self::InvalidCustomSection(err) => {
                write!(f, "Wasm module has an invalid custom section. {}", err)
            }
            Self::TooManyGlobals { defined, allowed } => write!(
                f,
                "Wasm module defined {} globals which exceeds the maximum number allowed {}.",
                defined, allowed
            ),
            Self::TooManyFunctions { defined, allowed } => write!(
                f,
                "Wasm module defined {} functions which exceeds the maximum number allowed {}.",
                defined, allowed
            ),
            Self::TooManyCustomSections { defined, allowed } => write!(
                f,
                "Wasm module defined {} custom sections which exceeds the maximum number allowed {}.",
                defined, allowed
            ),
            Self::InvalidFunctionIndex {
                index,
                import_count,
            } => write!(
                f,
                "Function has index {} but should start from {}.",
                index, import_count
            ),
        }
    }
}

/// Different errors that can be returned by `instrument`
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WasmInstrumentationError {
    /// Failure in party_wasm when deserializing the wasm module
    ParityDeserializeError(ParityWasmError),
    /// Failure in party_wasm when serializing the wasm module
    ParitySerializeError(ParityWasmError),
    /// Incorrect number of memory sections
    IncorrectNumberMemorySections {
        expected: usize,
        got: usize,
    },
    InvalidDataSegment {
        offset: usize,
        len: usize,
    },
}

impl std::fmt::Display for WasmInstrumentationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParityDeserializeError(err) => {
                write!(f, "Failed to deserialize wasm module with {}", err)
            }
            Self::ParitySerializeError(err) => {
                write!(f, "Failed to serialize wasm module with {}", err)
            }
            Self::IncorrectNumberMemorySections { expected, got } => write!(
                f,
                "Wasm module has {} memory sections but should have had {}",
                got, expected
            ),
            Self::InvalidDataSegment { offset, len } => write!(
                f,
                "Wasm module has invalid data segment of {} bytes at {}",
                len, offset
            ),
        }
    }
}

/// Different errors that be returned by the Wasm engine
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WasmEngineError {
    FailedToInitializeEngine,
    FailedToInstantiateModule,
    FailedToSetAsyncStack,
    FailedToSetWasmStack,
}

impl std::fmt::Display for WasmEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FailedToInitializeEngine => {
                write!(f, "Failed to initialize engine")
            }
            Self::FailedToInstantiateModule => {
                write!(f, "Failed to instantiate module")
            }
            Self::FailedToSetWasmStack => {
                write!(f, "Failed to set Wasm stack")
            }
            Self::FailedToSetAsyncStack => {
                write!(f, "Failed to set async stack")
            }
        }
    }
}
