use serde::{Deserialize, Serialize};

/// Represents an error that can happen when parsing or encoding a Wasm module
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WasmError(String);

impl WasmError {
    /// Creates a new `WasmError` out of an error message.
    pub fn new(error_message: String) -> Self {
        Self(error_message)
    }
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Different errors that be returned by `validate_wasm_binary`
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WasmValidationError {
    /// Failure in deserialization of the wasm module.
    WasmDeserializeError(WasmError),
    /// wasmtime::Module::validate() failed
    WasmtimeValidation(String),
    /// Failed to decode the canister module.
    DecodingError(String),
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
    /// A function was too complex.
    FunctionComplexityTooHigh {
        index: usize,
        complexity: usize,
        allowed: usize,
    },
    /// A function was too large.
    FunctionTooLarge {
        index: usize,
        size: usize,
        allowed: usize,
    },
}

impl std::fmt::Display for WasmValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WasmDeserializeError(err) => {
                write!(f, "Failed to deserialize wasm module with {}", err)
            }
            Self::WasmtimeValidation(err) => {
                write!(f, "Wasmtime failed to validate wasm module {}", err)
            }
            Self::DecodingError(err) => {
                write!(f, "Failed to decode wasm module: {}", err)
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
            Self::FunctionComplexityTooHigh{ index, complexity, allowed } => write!(
                f,
                "Wasm module contains a function at index {} with complexity {} which exceeds the maximum complexity allowed {}",
                index, complexity, allowed
            ),
            Self::FunctionTooLarge{index, size, allowed} => write!(
                f,
                "Wasm module contains a function at index {} of size {} that exceeds the maximum allowed size of {}",
                index, size, allowed,
            ),
        }
    }
}

/// Different errors that can be returned by `instrument`
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WasmInstrumentationError {
    /// Failure in deserialization the wasm module
    WasmDeserializeError(WasmError),
    /// Failure in serialization the wasm module
    WasmSerializeError(WasmError),
    /// Incorrect number of memory sections
    IncorrectNumberMemorySections {
        expected: usize,
        got: usize,
    },
    InvalidDataSegment {
        offset: usize,
        len: usize,
    },
    InvalidExport(String),
}

impl std::fmt::Display for WasmInstrumentationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WasmDeserializeError(err) => {
                write!(f, "Failed to deserialize wasm module with {}", err)
            }
            Self::WasmSerializeError(err) => {
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
            Self::InvalidExport(err) => {
                write!(f, "Failed to export: {}", err)
            }
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
    FailedToSerializeModule(String),
    FailedToDeserializeModule(String),
    FailedToApplySystemChanges(String),
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
            Self::FailedToSerializeModule(s) => {
                write!(f, "Failed to serialize module: {}", s)
            }
            Self::FailedToDeserializeModule(s) => {
                write!(f, "Failed to deserialize module: {}", s)
            }
            Self::FailedToApplySystemChanges(s) => {
                write!(f, "Failed to apply system changes: {}", s)
            }
        }
    }
}
