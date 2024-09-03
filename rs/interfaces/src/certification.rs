//! The certification public interface.
use crate::validation::{ValidationError, ValidationResult};
use ic_types::{
    consensus::certification::{Certification, CertificationMessage, CertificationShare},
    crypto::CryptoError,
    CryptoHashOfPartialState, Height, RegistryVersion, SubnetId,
};
use std::collections::HashSet;

/// Contains all possible change actions applicable to the certification pool.
pub type ChangeSet = Vec<ChangeAction>;

/// Change actions applicable to the certification pool.
#[derive(Eq, PartialEq, Debug)]
pub enum ChangeAction {
    /// Adds the artifact to the validated pool.
    AddToValidated(CertificationMessage),
    /// Moves an artifact from the unvalidated to the validated section.
    MoveToValidated(CertificationMessage),
    /// Removes an artifact from the unvalidated pool section.
    RemoveFromUnvalidated(CertificationMessage),
    /// Removes all artifacts below the given height.
    RemoveAllBelow(Height),
    /// This action marks an invalid artifact, e.g. if the signature check
    /// failed.
    HandleInvalid(CertificationMessage, String),
}

/// Trait containing only immutable functions wrt. Certification Pool
pub trait CertificationPool {
    /// Returns the certification for the given height, if available.
    fn certification_at_height(&self, height: Height) -> Option<Certification>;

    /// Returns an iterator over all shares for the given height.
    fn shares_at_height(&self, height: Height)
        -> Box<dyn Iterator<Item = CertificationShare> + '_>;

    /// Returns all validated certification shares.
    fn validated_shares(&self) -> Box<dyn Iterator<Item = CertificationShare> + '_>;

    /// Returns an iterator of all unvalidated full certification for the given
    /// height.
    fn unvalidated_certifications_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &Certification> + '_>;

    /// Returns an iterator of all unvalidated shares for the given height.
    fn unvalidated_shares_at_height(
        &self,
        height: Height,
    ) -> Box<dyn Iterator<Item = &CertificationShare> + '_>;

    /// Returns all heights (sorted, ascending), where at least a single
    /// artifact is present. Intended to be used by the purger.
    fn all_heights_with_artifacts(&self) -> Vec<Height>;

    /// Returns all heights which have a full validated certification.
    fn certified_heights(&self) -> HashSet<Height>;
}

/// Reasons for why a certification might be invalid.
#[derive(Eq, PartialEq, Debug)]
pub enum InvalidCertificationReason {
    CryptoError(CryptoError),
    UnexpectedCertificationHash(CryptoHashOfPartialState),
    RejectedByRejectingVerifier, // for testing only
}

/// Possible failures of validating a certification. Doesn't necessarily mean the certification is
/// invalid.
#[derive(Eq, PartialEq, Debug)]
pub enum CertificationValidationFailure {
    CryptoError(CryptoError),
}

impl From<CryptoError> for CertificationValidationFailure {
    fn from(err: CryptoError) -> CertificationValidationFailure {
        CertificationValidationFailure::CryptoError(err)
    }
}

impl From<CryptoError> for InvalidCertificationReason {
    fn from(err: CryptoError) -> InvalidCertificationReason {
        InvalidCertificationReason::CryptoError(err)
    }
}

impl<T> From<InvalidCertificationReason> for ValidationError<InvalidCertificationReason, T> {
    fn from(err: InvalidCertificationReason) -> ValidationError<InvalidCertificationReason, T> {
        ValidationError::InvalidArtifact(err)
    }
}

impl<P> From<CertificationValidationFailure>
    for ValidationError<P, CertificationValidationFailure>
{
    fn from(
        err: CertificationValidationFailure,
    ) -> ValidationError<P, CertificationValidationFailure> {
        ValidationError::ValidationFailed(err)
    }
}

pub type VerifierError =
    ValidationError<InvalidCertificationReason, CertificationValidationFailure>;

/// Verifier is used to verify state hash certifications. It will be injected
/// into XNet and StateSync components so that they can ensure the authenticity
/// of parts of the replicated state sent over from other sub-networks.
pub trait Verifier: Send + Sync {
    /// This method verifies whether the given certification contains a valid
    /// signature on the given hash on behalf of the subnet specified in
    /// subnet_id with respect to the `registry_version`.
    fn validate(
        &self,
        subnet_id: SubnetId,
        certification: &Certification,
        registry_version: RegistryVersion,
    ) -> ValidationResult<VerifierError>;
}
