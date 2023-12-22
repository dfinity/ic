//! The consensus public interface.
use crate::{
    batch_payload::ProposalContext,
    canister_http::{
        CanisterHttpPayloadValidationError, CanisterHttpPermanentValidationError,
        CanisterHttpTransientValidationError,
    },
    ingress_manager::{
        IngressPayloadValidationError, IngressPermanentError, IngressTransientError,
    },
    messaging::{InvalidXNetPayload, XNetPayloadValidationError, XNetTransientValidationError},
    query_stats::{QueryStatsPermanentValidationError, QueryStatsTransientValidationError},
    self_validating_payload::{
        InvalidSelfValidatingPayload, SelfValidatingPayloadValidationError,
        SelfValidatingTransientValidationError,
    },
    validation::{ValidationError, ValidationResult},
};
use ic_base_types::{NumBytes, SubnetId};
use ic_types::{
    batch::{BatchPayload, ValidationContext},
    consensus::{block_maker::SubnetRecords, Payload},
    registry::RegistryClientError,
    Height, Time,
};

/// The [`PayloadBuilder`] is responsible for creating and validating payload that
/// is included in consensus blocks.
pub trait PayloadBuilder: Send + Sync {
    /// Produces a payload that is valid given `past_payloads` and `context`.
    ///
    /// `past_payloads` contains the `Payloads` from all blocks above the
    /// certified height provided in `context`, in descending block height
    /// order.
    fn get_payload(
        &self,
        height: Height,
        past_payloads: &[(Height, Time, Payload)],
        context: &ValidationContext,
        subnet_records: &SubnetRecords,
    ) -> BatchPayload;

    /// Checks whether the provided `payload` is valid given `past_payloads` and
    /// `context`.
    ///
    /// `past_payloads` contains the `Payloads` from all blocks above the
    /// certified height provided in `context`, in descending block height
    /// order.
    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &Payload,
        past_payloads: &[(Height, Time, Payload)],
    ) -> ValidationResult<PayloadValidationError>;
}

#[derive(Debug)]
pub enum PayloadPermanentError {
    XNetPayloadValidationError(InvalidXNetPayload),
    IngressPayloadValidationError(IngressPermanentError),
    /// The overall block size is too large, even though the individual payloads are valid
    PayloadTooBig {
        expected: NumBytes,
        received: NumBytes,
    },
    SelfValidatingPayloadValidationError(InvalidSelfValidatingPayload),
    CanisterHttpPayloadValidationError(CanisterHttpPermanentValidationError),
    QueryStatsPayloadValidationError(QueryStatsPermanentValidationError),
}

#[derive(Debug)]
pub enum PayloadTransientError {
    XNetPayloadValidationError(XNetTransientValidationError),
    IngressPayloadValidationError(IngressTransientError),
    RegistryUnavailable(RegistryClientError),
    SubnetNotFound(SubnetId),
    SelfValidatingPayloadValidationError(SelfValidatingTransientValidationError),
    CanisterHttpPayloadValidationError(CanisterHttpTransientValidationError),
    QueryStatsPayloadValidationError(QueryStatsTransientValidationError),
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
