//! Validation related types.

use crate::crypto::ErrorReproducibility;

/// Validation error can either mean that the validated object is invalid or that the validation
/// failed to establish the validity of the object.
#[derive(Debug, Eq, PartialEq)]
pub enum ValidationError<Reason, Failure> {
    /// The artifact was determined to be invalid.
    InvalidArtifact(Reason),
    /// The validation failed to determine whether the artifact is valid or invalid.
    ValidationFailed(Failure),
}

impl<P, T> ValidationError<P, T> {
    /// The inner types of ValidationError can be mapped to another types by
    /// applying two map functions for invalid artifacts and payload validation
    /// failures respectively.
    pub fn map<Q, S, F: Fn(P) -> Q, G: Fn(T) -> S>(self, f: F, g: G) -> ValidationError<Q, S> {
        match self {
            ValidationError::InvalidArtifact(p) => ValidationError::InvalidArtifact(f(p)),
            ValidationError::ValidationFailed(t) => ValidationError::ValidationFailed(g(t)),
        }
    }
}

/// Validation result is result type where `Ok(())` means valid, and `Err(err)`
/// means error, which is of the parameter type.
pub type ValidationResult<Error> = Result<(), Error>;

/// An error that implements the [`ErrorReproducibility`] trait can either be
/// cast to a permanent [ValidationError] if it is "reproducible"; or to a
/// transient one otherwise.
impl<Error: ErrorReproducibility, P: From<Error>, T: From<Error>> From<Error>
    for ValidationError<P, T>
{
    fn from(err: Error) -> ValidationError<P, T> {
        if err.is_reproducible() {
            // If an error was returned, which is not a transient one, we consider the
            // artifact to be invalid. There is no reason to retry such an error.
            ValidationError::InvalidArtifact(err.into())
        } else {
            // A transient re-triable error.
            ValidationError::ValidationFailed(err.into())
        }
    }
}
