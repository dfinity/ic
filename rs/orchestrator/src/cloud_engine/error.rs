//! The single error type of the engine configuration lookup.

use crate::error::OrchestratorError;
use ic_types::registry::RegistryClientError;
use std::fmt;

pub(super) type CloudEngineResult<T> = Result<T, CloudEngineError>;

/// Why a run of the engine configuration lookup did not produce a configuration.
///
/// The variants are the three ways [`super::CloudEngineManager`] reacts, not the
/// steps that can fail: wait for the engine to be configured, wait for the
/// operator to recognize this node, or count it as a failure and resolve the
/// operator again.
#[derive(Debug)]
pub(super) enum CloudEngineError {
    /// A field the engine configuration needs is not set on the operator yet.
    /// Nothing to apply, not a failure.
    Incomplete(&'static str),
    /// The operator did not (yet) recognise us as one of its engine's nodes.
    /// Its access control answers from the subnet's node list, which it keeps
    /// in a transient cache that stays empty until its first successful
    /// registry refetch after an install or upgrade, so this is expected right
    /// after either and never fatal.
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

/// The registry helper answers with the crate-wide error, which cannot express
/// any of the two expected outcomes above.
impl From<OrchestratorError> for CloudEngineError {
    fn from(err: OrchestratorError) -> Self {
        Self::failed(err)
    }
}

impl From<RegistryClientError> for CloudEngineError {
    fn from(err: RegistryClientError) -> Self {
        Self::failed(err)
    }
}
