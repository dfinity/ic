//! The consensus public interface.
use crate::{
    canister_http::{
        CanisterHttpPayloadValidationError, CanisterHttpPermanentValidationError,
        CanisterHttpTransientValidationError,
    },
    ingress_manager::{
        IngressPayloadValidationError, IngressPermanentError, IngressTransientError,
    },
    messaging::{InvalidXNetPayload, XNetPayloadValidationError, XNetTransientValidationError},
    self_validating_payload::{
        InvalidSelfValidatingPayload, SelfValidatingPayloadValidationError,
        SelfValidatingTransientValidationError,
    },
    validation::ValidationError,
};
use ic_base_types::{NumBytes, SubnetId};
use ic_types::registry::RegistryClientError;

#[derive(Debug)]
pub enum PayloadPermanentError {
    XNetPayloadValidationError(InvalidXNetPayload),
    IngressPayloadValidationError(IngressPermanentError),
    PayloadTooBig {
        expected: NumBytes,
        received: NumBytes,
    },
    SelfValidatingPayloadValidationError(InvalidSelfValidatingPayload),
    CanisterHttpPayloadValidationError(CanisterHttpPermanentValidationError),
}

#[derive(Debug)]
pub enum PayloadTransientError {
    XNetPayloadValidationError(XNetTransientValidationError),
    IngressPayloadValidationError(IngressTransientError),
    RegistryUnavailable(RegistryClientError),
    SubnetNotFound(SubnetId),
    SelfValidatingPayloadValidationError(SelfValidatingTransientValidationError),
    CanisterHttpPayloadValidationError(CanisterHttpTransientValidationError),
}

/// Payload validation error
pub type PayloadValidationError = ValidationError<PayloadPermanentError, PayloadTransientError>;

impl From<IngressPayloadValidationError> for PayloadValidationError {
    fn from(err: IngressPayloadValidationError) -> Self {
        err.map(
            PayloadPermanentError::IngressPayloadValidationError,
            PayloadTransientError::IngressPayloadValidationError,
        )
    }
}

impl From<XNetPayloadValidationError> for PayloadValidationError {
    fn from(err: XNetPayloadValidationError) -> Self {
        err.map(
            PayloadPermanentError::XNetPayloadValidationError,
            PayloadTransientError::XNetPayloadValidationError,
        )
    }
}

impl From<SelfValidatingPayloadValidationError> for PayloadValidationError {
    fn from(err: SelfValidatingPayloadValidationError) -> Self {
        err.map(
            PayloadPermanentError::SelfValidatingPayloadValidationError,
            PayloadTransientError::SelfValidatingPayloadValidationError,
        )
    }
}

impl From<CanisterHttpPayloadValidationError> for PayloadValidationError {
    fn from(err: CanisterHttpPayloadValidationError) -> Self {
        err.map(
            PayloadPermanentError::CanisterHttpPayloadValidationError,
            PayloadTransientError::CanisterHttpPayloadValidationError,
        )
    }
}
