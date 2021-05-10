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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Different errors that be returned by `validate_wasm_binary`
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
    /// Failure when trying to compile in Lucet
    LucetCompilerErr(String),
    /// Module contains too many globals.
    TooManyGlobals { defined: usize, allowed: usize },
    /// Module contains too many functions.
    TooManyFunctions { defined: usize, allowed: usize },
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
            Self::LucetCompilerErr(err) => write!(
                f,
                "Validation failed due to \"{}\" compile error in Lucet",
                err
            ),
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
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Different errors that can be returned by `instrument`
pub enum WasmInstrumentationError {
    /// Failure in party_wasm when deserializing the wasm module
    ParityDeserializeError(ParityWasmError),
    /// Failure in party_wasm when serializing the wasm module
    ParitySerializeError(ParityWasmError),
    /// Incorrect number of memory sections
    IncorrectNumberMemorySections { expected: usize, got: usize },
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
        }
    }
}
