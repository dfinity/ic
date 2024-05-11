use serde::{Deserialize, Serialize};

pub enum ErrorHelp {
    UserError {
        suggestion: String,
        doc_link: String,
    },
    ToolchainError,
    InternalError,
}

impl std::fmt::Display for ErrorHelp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorHelp::UserError { suggestion, doc_link } => { if !suggestion.is_empty() {
                write!(f, "{} See documentation: {}", suggestion, doc_link)
            } else { Ok(())}             },
            ErrorHelp::ToolchainError => write!(f, "This is likely an error with the compiler/CDK toolchain being used to build the canister. Please report the error to IC devs on the forum: https://forum.dfinity.org and include which language/CDK was used to create the canister."),
            ErrorHelp::InternalError => write!(f, "This is an internal error on the IC. Please report it to IC devs on the forum: https://forum.dfinity.org"),
        }
    }
}

pub trait AsErrorHelp {
    fn error_help(&self) -> ErrorHelp;
}

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
    /// Module contains an invalid global section
    InvalidGlobalSection(String),
    /// Module contains too many globals.
    TooManyGlobals { defined: usize, allowed: usize },
    /// Module contains too many functions.
    TooManyFunctions { defined: usize, allowed: usize },
    /// Module contains too many custom sections.
    TooManyCustomSections { defined: usize, allowed: usize },
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
    /// The code section is too large.
    CodeSectionTooLarge { size: u32, allowed: u32 },
}

impl std::fmt::Display for WasmValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            },
            Self::InvalidGlobalSection(err) => {
                write!(f, "Wasm module has an invalid global section. {}", err)
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
            Self::CodeSectionTooLarge{size, allowed} => write!(
                f,
                "Wasm module code section size of {} exceeds the maximum allowed size of {}",
                size, allowed,
            ),
        }
    }
}

impl AsErrorHelp for WasmValidationError {
    fn error_help(&self) -> ErrorHelp {
        match self {
            WasmValidationError::WasmtimeValidation(_)
            | WasmValidationError::InvalidFunctionSignature(_)
            | WasmValidationError::InvalidImportSection(_)
            | WasmValidationError::InvalidDataSection(_)
            | WasmValidationError::InvalidCustomSection(_)
            | WasmValidationError::InvalidGlobalSection(_)
            | WasmValidationError::TooManyGlobals { .. }
            | WasmValidationError::TooManyCustomSections { .. } => ErrorHelp::ToolchainError,
            WasmValidationError::DecodingError(_)
            | WasmValidationError::InvalidExportSection(_)
            | WasmValidationError::TooManyFunctions { .. }
            | WasmValidationError::FunctionComplexityTooHigh { .. }
            | WasmValidationError::FunctionTooLarge { .. }
            | WasmValidationError::CodeSectionTooLarge { .. } => ErrorHelp::UserError {
                suggestion: "".to_string(),
                doc_link: "".to_string(),
            },
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
    InvalidFunctionType(String),
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
            Self::InvalidFunctionType(err) => write!(f, "Invalid function type: {}", err),
        }
    }
}

impl AsErrorHelp for WasmInstrumentationError {
    fn error_help(&self) -> ErrorHelp {
        match self {
            WasmInstrumentationError::WasmDeserializeError(_)
            | WasmInstrumentationError::WasmSerializeError(_) => ErrorHelp::InternalError,
            WasmInstrumentationError::IncorrectNumberMemorySections { .. }
            | WasmInstrumentationError::InvalidDataSegment { .. }
            | WasmInstrumentationError::InvalidFunctionType(_) => ErrorHelp::ToolchainError,
        }
    }
}

/// Different errors that be returned by the Wasm engine
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WasmEngineError {
    FailedToInitializeEngine,
    FailedToInstantiateModule(String),
    FailedToSetAsyncStack,
    FailedToSetWasmStack,
    FailedToSerializeModule(String),
    FailedToDeserializeModule(String),
    FailedToApplySystemChanges(String),
    Other(String),
    Unexpected(String),
}

impl std::fmt::Display for WasmEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FailedToInitializeEngine => {
                write!(f, "Failed to initialize engine")
            }
            Self::FailedToInstantiateModule(s) => {
                write!(f, "Failed to instantiate module: {}", s)
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
            Self::Other(s) => {
                write!(f, "WasmEngineError: {}", s)
            }
            Self::Unexpected(s) => {
                write!(f, "Unexpected WasmEngineError: {}", s)
            }
        }
    }
}
