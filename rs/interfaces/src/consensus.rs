//! The consensus public interface.
use crate::{
    batch_payload::ProposalContext,
    canister_http::{
        CanisterHttpPayloadValidationError, CanisterHttpPayloadValidationFailure,
        InvalidCanisterHttpPayloadReason,
    },
    ingress_manager::{
        IngressPayloadValidationError, IngressPayloadValidationFailure, InvalidIngressPayloadReason,
    },
    messaging::{InvalidXNetPayload, XNetPayloadValidationError, XNetPayloadValidationFailure},
    query_stats::{InvalidQueryStatsPayloadReason, QueryStatsPayloadValidationFailure},
    self_validating_payload::{
        InvalidSelfValidatingPayloadReason, SelfValidatingPayloadValidationError,
        SelfValidatingPayloadValidationFailure,
    },
    validation::{ValidationError, ValidationResult},
    vetkd::{InvalidVetKdPayloadReason, VetKdPayloadValidationFailure},
};
use ic_base_types::{NumBytes, SubnetId};
use ic_types::{
    Height, Time,
    batch::{BatchPayload, ValidationContext},
    consensus::{Payload, block_maker::SubnetRecords},
    registry::RegistryClientError,
};

pub mod errors;

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
pub enum InvalidPayloadReason {
    InvalidXNetPayload(InvalidXNetPayload),
    InvalidIngressPayload(InvalidIngressPayloadReason),
    InvalidSelfValidatingPayload(InvalidSelfValidatingPayloadReason),
    InvalidCanisterHttpPayload(InvalidCanisterHttpPayloadReason),
    InvalidQueryStatsPayload(InvalidQueryStatsPayloadReason),
    InvalidVetKdPayload(InvalidVetKdPayloadReason),
    /// The overall block size is too large, even though the individual payloads are valid
    PayloadTooBig {
        expected: NumBytes,
        received: NumBytes,
    },
}

#[derive(Debug)]
pub enum PayloadValidationFailure {
    XNetPayloadValidationFailed(XNetPayloadValidationFailure),
    IngressPayloadValidationFailed(IngressPayloadValidationFailure),
    SelfValidatingPayloadValidationFailed(SelfValidatingPayloadValidationFailure),
    CanisterHttpPayloadValidationFailed(CanisterHttpPayloadValidationFailure),
    QueryStatsPayloadValidationFailed(QueryStatsPayloadValidationFailure),
    VetKdPayloadValidationFailed(VetKdPayloadValidationFailure),
    RegistryUnavailable(RegistryClientError),
    SubnetNotFound(SubnetId),
}

/// Payload validation error
pub type PayloadValidationError = ValidationError<InvalidPayloadReason, PayloadValidationFailure>;

impl From<IngressPayloadValidationError> for PayloadValidationError {
    fn from(err: IngressPayloadValidationError) -> Self {
        err.map(
            InvalidPayloadReason::InvalidIngressPayload,
            PayloadValidationFailure::IngressPayloadValidationFailed,
        )
    }
}

impl From<XNetPayloadValidationError> for PayloadValidationError {
    fn from(err: XNetPayloadValidationError) -> Self {
        err.map(
            InvalidPayloadReason::InvalidXNetPayload,
            PayloadValidationFailure::XNetPayloadValidationFailed,
        )
    }
}

impl From<SelfValidatingPayloadValidationError> for PayloadValidationError {
    fn from(err: SelfValidatingPayloadValidationError) -> Self {
        err.map(
            InvalidPayloadReason::InvalidSelfValidatingPayload,
            PayloadValidationFailure::SelfValidatingPayloadValidationFailed,
        )
    }
}

impl From<CanisterHttpPayloadValidationError> for PayloadValidationError {
    fn from(err: CanisterHttpPayloadValidationError) -> Self {
        err.map(
            InvalidPayloadReason::InvalidCanisterHttpPayload,
            PayloadValidationFailure::CanisterHttpPayloadValidationFailed,
        )
    }
}
