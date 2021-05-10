//! Validation related types.

use crate::crypto::ErrorReplication;

/// Validation errors can be either permanent (invalid) or transient.
#[derive(Debug)]
pub enum ValidationError<P, T> {
    Permanent(P),
    Transient(T),
}

impl<P, T> ValidationError<P, T> {
    /// The inner types of ValidationError can be mapped to another types by
    /// applying two map functions for error and transient errors respectively.
    pub fn map<Q, S, F: Fn(P) -> Q, G: Fn(T) -> S>(self, f: F, g: G) -> ValidationError<Q, S> {
        match self {
            ValidationError::Permanent(p) => ValidationError::Permanent(f(p)),
            ValidationError::Transient(t) => ValidationError::Transient(g(t)),
        }
    }
}

/// Validation result is result type where `Ok(())` means valid, and `Err(err)`
/// means error, which is of the parameter type.
///
/// To differentiate between permanent and transient errors, we can use
/// [ValidationError] as the `Error` type.
pub type ValidationResult<Error> = Result<(), Error>;

/// An error that implements [ErrorReplication] trait can be casted to either
/// permanent [ValidationError] if it is "replicated", or transient otherwise.
impl<Error: ErrorReplication, P: From<Error>, T: From<Error>> From<Error>
    for ValidationError<P, T>
{
    fn from(err: Error) -> ValidationError<P, T> {
        if err.is_replicated() {
            // If an error was returned, which is not a transient one, we consider the
            // validation as failed. There is no reason to retry such a
            // validation.
            ValidationError::Permanent(err.into())
        } else {
            // A transient re-triable error.
            ValidationError::Transient(err.into())
        }
    }
}
