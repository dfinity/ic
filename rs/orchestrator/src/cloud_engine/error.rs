//! The single error type of the engine configuration lookup.

use crate::error::OrchestratorError;
use std::fmt;

pub(super) type CloudEngineResult<T> = Result<T, CloudEngineError>;

/// The variants are the three ways CloudEngineManager reacts, not
/// the steps that can fail.
#[derive(Debug)]
pub(super) enum CloudEngineError {
    /// A field the configuration needs is not set on the operator yet.
    Incomplete(&'static str),
    /// The operator rejected the request because it does not recognize this node yet.
    NotReady,
    /// Everything else: a registry lookup, the transport, the decoding, or a
    /// configured value `ic-gateway` could not run with.
    Failed(String),
}

impl CloudEngineError {
    pub(super) fn failed(msg: impl ToString) -> Self {
        Self::Failed(msg.to_string())
    }
}

impl fmt::Display for CloudEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete(field) => write!(f, "{field} is not configured yet"),
            Self::NotReady => write!(f, "the operator does not recognize this node yet"),
            Self::Failed(msg) => write!(f, "{msg}"),
        }
    }
}

/// The registry helper answers with the crate-wide error, and none of what it
/// reports is one of the two expected outcomes above.
impl From<OrchestratorError> for CloudEngineError {
    fn from(err: OrchestratorError) -> Self {
        Self::failed(err)
    }
}
